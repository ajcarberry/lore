// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! `OpenID` Connect authentication for the `oidc+https` and `oidc+http` schemes:
//! authorization code with PKCE over a loopback redirect, the device authorization grant
//! for [`LoginFlow::NoBrowser`], and the refresh grant. Stripping `oidc+` from the
//! advertised auth URL recovers the issuer identifier byte for byte; the server verifies
//! token signatures, so this module checks only `state` and `nonce`.
use std::time::Duration;

use async_trait::async_trait;
use lore_base::error::NotSupported;
use lore_base::lore_debug;
use lore_base::types::RepositoryId;
use reqwest::StatusCode;
use serde::Deserialize;
use url::Host;
use url::Url;

use crate::error::ProtocolError;
use crate::traits::Authentication;
use crate::traits::LoginFlow;
use crate::types::*;

/// Where a provider publishes its metadata (`OpenID` Connect Discovery 1.0 §4).
const DISCOVERY_PATH: &str = "/.well-known/openid-configuration";

/// Cap on a provider response body, so a broken or hostile endpoint cannot stream
/// unbounded bytes into memory.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// What the advertised auth URL says about the provider.
#[derive(Clone, Debug, PartialEq, Eq)]
struct AuthUrlParts {
    /// The issuer identifier, byte for byte as the provider publishes it.
    issuer: String,
    /// Derived exactly as the token-recipient guard derives a remote's, so the two are
    /// comparable without normalizing either.
    #[allow(dead_code)] // Read by the login flows in the following phases.
    issuer_domain: String,
    #[allow(dead_code)] // Read by the login flows in the following phases.
    client_id: String,
}

/// Splits an advertised auth URL into the issuer and its parameters.
///
/// `oidc+http` is accepted only for a loopback host: plain HTTP anywhere else would put an
/// authorization code and an ID token on the wire in the clear.
fn parse_auth_url(auth_url: &str) -> Result<AuthUrlParts, ProtocolError> {
    let scheme = crate::auth::authentication::parse_scheme(auth_url)?;
    let transport = match scheme {
        "oidc+https" => "https",
        "oidc+http" => "http",
        _ => {
            return Err(ProtocolError::internal(format!(
                "'{scheme}' is not an OIDC auth URL scheme (expected 'oidc+https' or 'oidc+http')"
            )));
        }
    };
    let rest = &auth_url[scheme.len() + "://".len()..];

    // Recovered textually rather than by re-serializing a parsed URL, so the issuer
    // survives byte for byte. It carries no query or fragment (Discovery §2), so everything
    // up to the first `?` or `#` is the issuer.
    let issuer_tail = rest.split_once(['?', '#']).map_or(rest, |(head, _)| head);
    let issuer = format!("{transport}://{issuer_tail}");

    let url = Url::parse(&format!("{transport}://{rest}"))
        .map_err(|e| ProtocolError::internal(format!("invalid OIDC auth URL '{auth_url}': {e}")))?;
    // Parsed separately from `url`: the domain derivation below must not see the query
    // string, because for an IP host it falls back to the whole URL.
    let issuer_url = Url::parse(&issuer)
        .map_err(|e| ProtocolError::internal(format!("invalid OIDC issuer '{issuer}': {e}")))?;

    if transport == "http" && !is_loopback(issuer_url.host()) {
        return Err(ProtocolError::internal(format!(
            "'oidc+http' is accepted only for a loopback issuer, not '{issuer}' -- \
             a code and an ID token would travel in the clear"
        )));
    }

    // Not a legal issuer component (Discovery §2), and the discovery fetch
    // would otherwise send whatever a hostile auth URL embedded.
    if !issuer_url.username().is_empty() || issuer_url.password().is_some() {
        return Err(ProtocolError::internal(format!(
            "OIDC auth URL '{auth_url}' embeds credentials in the issuer -- refused"
        )));
    }

    let mut client_id = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "client_id" => client_id = Some(value.into_owned()),
            _ => lore_debug!("Ignoring unknown OIDC auth URL parameter '{key}'"),
        }
    }

    let client_id = client_id.filter(|id| !id.is_empty()).ok_or_else(|| {
        ProtocolError::internal(format!(
            "OIDC auth URL '{auth_url}' names no client_id, so no flow can be started"
        ))
    })?;

    Ok(AuthUrlParts {
        issuer,
        issuer_domain: lore_credential::domain_from_url_or_url(&issuer_url),
        client_id,
    })
}

/// Whether a host is this machine. `localhost` counts: it resolves to a loopback address.
fn is_loopback(host: Option<Host<&str>>) -> bool {
    match host {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

/// The members of the discovery document this client uses.
#[derive(Debug, Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    /// OPTIONAL; its absence makes the device authorization grant unavailable.
    #[serde(default)]
    device_authorization_endpoint: Option<String>,
}

/// Parses a discovery document and pins it to the issuer that was configured.
///
/// The `issuer` member must equal the configured issuer byte for byte (Discovery §4.3), which
/// refuses a *different provider's* genuine document. A forged response echoes the expected
/// issuer, so the pin is paired with transport-level checks: the client follows no redirects,
/// and every advertised endpoint is held to https-or-loopback by `check_endpoint`.
fn parse_discovery(body: &str, expected_issuer: &str) -> Result<Discovery, ProtocolError> {
    let discovery: Discovery = serde_json::from_str(body).map_err(|e| {
        ProtocolError::internal(format!(
            "provider discovery document at {expected_issuer}{DISCOVERY_PATH} is not usable: {e}"
        ))
    })?;

    if discovery.issuer != expected_issuer {
        return Err(ProtocolError::internal(format!(
            "provider discovery document declares issuer '{}' but '{expected_issuer}' was \
             configured -- refusing to follow it",
            discovery.issuer
        )));
    }

    check_endpoint("authorization_endpoint", &discovery.authorization_endpoint)?;
    check_endpoint("token_endpoint", &discovery.token_endpoint)?;
    if let Some(endpoint) = &discovery.device_authorization_endpoint {
        check_endpoint("device_authorization_endpoint", endpoint)?;
    }

    Ok(discovery)
}

/// Holds an endpoint the provider advertised to the rule `parse_auth_url` holds a
/// configured issuer to: https, or http only to a loopback host.
///
/// A discovery document is remote input, so anything else -- a `javascript:` or `file:`
/// endpoint, for one -- is refused here rather than opened or dialed later.
fn check_endpoint(member: &str, endpoint: &str) -> Result<(), ProtocolError> {
    let url = Url::parse(endpoint).map_err(|e| {
        ProtocolError::internal(format!(
            "provider advertises an unusable {member} '{endpoint}': {e}"
        ))
    })?;

    let dialable = match url.scheme() {
        "https" => true,
        "http" => is_loopback(url.host()),
        _ => false,
    };
    if !dialable {
        return Err(ProtocolError::internal(format!(
            "provider advertises {member} '{endpoint}', which this client will not open or \
             dial -- an endpoint has to be https, or http to a loopback host"
        )));
    }

    // Embedded credentials would ride along on every request to the endpoint,
    // and nothing legitimate puts them in a discovery document.
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ProtocolError::internal(format!(
            "provider advertises {member} '{endpoint}', which embeds credentials -- refused"
        )));
    }

    Ok(())
}

/// The HTTP client, built on the net runtime and pooled so a login's several requests to
/// the same provider share one TLS handshake.
async fn http_client() -> Result<reqwest::Client, ProtocolError> {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    if let Some(client) = CLIENT.get() {
        return Ok(client.clone());
    }

    let client = lore_base::lore_spawn_net!(async move {
        reqwest::Client::builder()
            .use_rustls_tls()
            .tls_built_in_webpki_certs(true)
            .tls_built_in_native_certs(true)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            // The discovery pin inspects a body field the responder authors, so
            // origin integrity has to come from the transport: no redirects,
            // which could otherwise carry a fetch across origins or down to
            // plaintext.
            .redirect(reqwest::redirect::Policy::none())
            .build()
    })
    .await
    .map_err(|e| ProtocolError::internal(format!("HTTP client construction task: {e}")))?
    .map_err(|e| ProtocolError::internal(format!("could not construct an HTTP client: {e}")))?;

    Ok(CLIENT.get_or_init(|| client).clone())
}

/// Issues a request and reads a capped response body. Awaited inside `lore_spawn_net!`
/// rather than merely built there: reqwest connects while the request future is polled.
async fn send(request: reqwest::RequestBuilder) -> Result<(StatusCode, String), ProtocolError> {
    lore_base::lore_spawn_net!(async move {
        let mut response = request
            .send()
            .await
            .map_err(|e| ProtocolError::internal(format!("provider request failed: {e}")))?;
        let status = response.status();

        // Accumulated rather than read through `Content-Length`, which the endpoint
        // controls.
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| ProtocolError::internal(format!("provider response failed: {e}")))?
        {
            if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(ProtocolError::internal(format!(
                    "provider response exceeds {MAX_RESPONSE_BYTES} bytes"
                )));
            }
            body.extend_from_slice(&chunk);
        }

        Ok((status, String::from_utf8_lossy(&body).into_owned()))
    })
    .await
    .map_err(|e| ProtocolError::internal(format!("provider request task: {e}")))?
}

/// Authentication against a standard `OpenID` Connect provider.
///
/// Registered under `oidc+https`, and under `oidc+http` for a loopback provider. One
/// instance will hold the state of every login in flight; the flows land in the
/// following phases.
#[derive(Default)]
pub struct OidcAuthentication {}

/// The discovery document URL for an issuer (Discovery §4). The `.well-known`
/// suffix joins the issuer with no normalization beyond avoiding a doubled
/// slash — the same rule the server's fetch applies, so both sides resolve a
/// trailing-slash issuer to the same document while pinning the untrimmed
/// string.
fn discovery_url(issuer: &str) -> String {
    format!("{}{DISCOVERY_PATH}", issuer.trim_end_matches('/'))
}

impl OidcAuthentication {
    /// Fetches and pins the provider's discovery document.
    async fn discover(&self, parts: &AuthUrlParts) -> Result<Discovery, ProtocolError> {
        let url = discovery_url(&parts.issuer);
        let client = http_client().await?;
        let (status, body) = send(client.get(&url)).await?;

        if !status.is_success() {
            return Err(ProtocolError::internal(format!(
                "provider discovery at {url} answered {status}"
            )));
        }

        parse_discovery(&body, &parts.issuer)
    }
}

#[async_trait]
impl Authentication for OidcAuthentication {
    /// Locates and pins the provider; the login flows land in the following phases.
    async fn start_auth_session(
        &self,
        auth_url: &str,
        _client_state: &str,
        _flow: LoginFlow,
        _correlation_id: &str,
    ) -> Result<AuthSession, ProtocolError> {
        let parts = parse_auth_url(auth_url)?;
        let _discovery = self.discover(&parts).await?;
        Err(ProtocolError::from(NotSupported {
            operation: "start_auth_session".to_string(),
        }))
    }

    async fn poll_auth_session(
        &self,
        _auth_url: &str,
        _client_state: &str,
        _session_code: &str,
        _correlation_id: &str,
    ) -> Result<Option<AuthenticationToken>, ProtocolError> {
        Err(ProtocolError::from(NotSupported {
            operation: "poll_auth_session".to_string(),
        }))
    }

    /// There is no external token to exchange: the provider issues the credential directly.
    async fn exchange_external_token(
        &self,
        _auth_url: &str,
        _token: &str,
        _token_type: &str,
        _correlation_id: &str,
    ) -> Result<AuthenticationToken, ProtocolError> {
        Err(ProtocolError::from(NotSupported {
            operation: "exchange_external_token".to_string(),
        }))
    }

    /// The refresh grant lands in a following phase.
    async fn refresh_authentication(
        &self,
        _auth_url: &str,
        _refresh_token: &str,
        _correlation_id: &str,
    ) -> Result<AuthenticationToken, ProtocolError> {
        Err(ProtocolError::from(NotSupported {
            operation: "refresh_authentication".to_string(),
        }))
    }

    async fn exchange_for_repository(
        &self,
        _auth_url: &str,
        _authn_token: &str,
        _repository: RepositoryId,
        _correlation_id: &str,
    ) -> Result<AuthorizationToken, ProtocolError> {
        Err(ProtocolError::from(NotSupported {
            operation: "exchange_for_repository".to_string(),
        }))
    }

    async fn exchange_for_custom_resource(
        &self,
        _auth_url: &str,
        _authn_token: &str,
        _resource_id: &str,
        _correlation_id: &str,
    ) -> Result<AuthorizationToken, ProtocolError> {
        Err(ProtocolError::from(NotSupported {
            operation: "exchange_for_custom_resource".to_string(),
        }))
    }

    /// The provider owns identity resolution and this design reads no directory.
    async fn get_user_info(
        &self,
        _auth_url: &str,
        _authz_token: &str,
        _repository: RepositoryId,
        _user_ids: &[String],
        _correlation_id: &str,
    ) -> Result<Vec<ResolvedUser>, ProtocolError> {
        Err(ProtocolError::from(NotSupported {
            operation: "get_user_info".to_string(),
        }))
    }

    /// The provider owns identity resolution and this design reads no directory.
    async fn get_user_id(
        &self,
        _auth_url: &str,
        _authz_token: &str,
        _repository: RepositoryId,
        _display_name: &str,
        _correlation_id: &str,
    ) -> Result<Option<ResolvedUser>, ProtocolError> {
        Err(ProtocolError::from(NotSupported {
            operation: "get_user_id".to_string(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const DISCOVERY_JSON: &str = r#"{
        "issuer": "https://id.example.com",
        "authorization_endpoint": "https://id.example.com/authorize",
        "token_endpoint": "https://id.example.com/token",
        "device_authorization_endpoint": "https://id.example.com/device",
        "jwks_uri": "https://id.example.com/jwks.json"
    }"#;

    fn discovery() -> Discovery {
        parse_discovery(DISCOVERY_JSON, "https://id.example.com").expect("discovery should parse")
    }

    #[test]
    fn auth_url_parses_the_issuer_and_client_id() {
        let parsed = parse_auth_url("oidc+https://id.example.com?client_id=lore")
            .expect("auth URL should parse");
        assert_eq!(
            parsed,
            AuthUrlParts {
                issuer: "https://id.example.com".to_string(),
                issuer_domain: "id.example.com".to_string(),
                client_id: "lore".to_string(),
            }
        );
    }

    #[test]
    fn auth_url_keeps_a_path_issuer_byte_for_byte() {
        let parsed = parse_auth_url("oidc+https://id.example.com/realms/studio?client_id=lore")
            .expect("auth URL should parse");
        assert_eq!(parsed.issuer, "https://id.example.com/realms/studio");
    }

    #[test]
    fn auth_url_requires_a_client_id() {
        parse_auth_url("oidc+https://id.example.com").expect_err("client_id is required");
    }

    #[test]
    fn auth_url_rejects_an_unknown_scheme() {
        parse_auth_url("ucs-auth://auth.example.com?client_id=lore")
            .expect_err("only the oidc+ schemes belong to this implementation");
    }

    #[test]
    fn auth_url_accepts_oidc_http_for_a_loopback_host() {
        for issuer in [
            "oidc+http://127.0.0.1:1411?client_id=lore",
            "oidc+http://localhost:1411?client_id=lore",
            "oidc+http://[::1]:1411?client_id=lore",
        ] {
            parse_auth_url(issuer).unwrap_or_else(|e| panic!("{issuer} should parse: {e}"));
        }
    }

    #[test]
    fn auth_url_rejects_oidc_http_for_a_non_loopback_host() {
        parse_auth_url("oidc+http://id.example.com?client_id=lore")
            .expect_err("oidc+http is loopback-only");
    }

    #[test]
    fn discovery_reads_the_endpoints_the_client_needs() {
        let discovery = discovery();
        assert_eq!(
            discovery.authorization_endpoint,
            "https://id.example.com/authorize"
        );
        assert_eq!(discovery.token_endpoint, "https://id.example.com/token");
        assert_eq!(
            discovery.device_authorization_endpoint.as_deref(),
            Some("https://id.example.com/device")
        );
    }

    #[test]
    fn discovery_rejects_an_issuer_mismatch() {
        parse_discovery(DISCOVERY_JSON, "https://id.example.invalid")
            .expect_err("a discovery document for another issuer must be refused");
    }

    #[test]
    fn discovery_issuer_comparison_is_byte_for_byte() {
        parse_discovery(DISCOVERY_JSON, "https://id.example.com/")
            .expect_err("a trailing slash is a different issuer identifier");
    }

    #[test]
    fn discovery_without_a_token_endpoint_is_refused() {
        let body = r#"{"issuer":"https://id.example.com","authorization_endpoint":"https://id.example.com/authorize"}"#;
        parse_discovery(body, "https://id.example.com")
            .expect_err("a provider with no token endpoint cannot complete any flow");
    }

    #[test]
    fn discovery_endpoints_that_must_not_be_dialed_are_refused() {
        let cases = [
            (
                "authorization_endpoint",
                "javascript:fetch('https://elsewhere.example.com')",
            ),
            ("authorization_endpoint", "file:///etc/passwd"),
            ("authorization_endpoint", "http://id.example.com/authorize"),
            ("token_endpoint", "http://id.example.com/token"),
            ("device_authorization_endpoint", "file:///etc/passwd"),
        ];

        for (member, endpoint) in cases {
            let mut endpoints = HashMap::from([
                (
                    "authorization_endpoint",
                    "https://id.example.com/authorize".to_string(),
                ),
                ("token_endpoint", "https://id.example.com/token".to_string()),
                (
                    "device_authorization_endpoint",
                    "https://id.example.com/device".to_string(),
                ),
            ]);
            endpoints.insert(member, endpoint.to_string());
            let document = format!(
                r#"{{"issuer":"https://id.example.com",
                     "authorization_endpoint":"{}",
                     "token_endpoint":"{}",
                     "device_authorization_endpoint":"{}"}}"#,
                endpoints["authorization_endpoint"],
                endpoints["token_endpoint"],
                endpoints["device_authorization_endpoint"],
            );

            let Err(error) = parse_discovery(&document, "https://id.example.com") else {
                panic!("'{endpoint}' must not be usable as {member}");
            };
            assert!(
                error.to_string().contains(member),
                "the diagnostic must name the member at fault, got: {error}"
            );
        }
    }

    /// The server's fetch trims trailing slashes the same way, so a provider
    /// publishing `https://id.example.com/realms/studio/` verifies server-side
    /// *and* logs in client-side, while the issuer pin still compares the
    /// untrimmed string.
    #[test]
    fn discovery_url_trims_a_trailing_slash_without_touching_the_issuer() {
        assert_eq!(
            discovery_url("https://id.example.com/realms/studio/"),
            "https://id.example.com/realms/studio/.well-known/openid-configuration"
        );
        assert_eq!(
            discovery_url("https://id.example.com"),
            "https://id.example.com/.well-known/openid-configuration"
        );
    }

    #[test]
    fn discovery_endpoints_embedding_credentials_are_refused() {
        let body = r#"{"issuer":"https://id.example.com",
            "authorization_endpoint":"https://user:pass@id.example.com/authorize",
            "token_endpoint":"https://id.example.com/token"}"#;
        let error = parse_discovery(body, "https://id.example.com")
            .expect_err("credentials embedded in an endpoint must be refused");
        assert!(error.to_string().contains("credentials"), "{error}");
    }

    #[test]
    fn auth_url_embedding_credentials_is_refused() {
        let error = parse_auth_url("oidc+https://user:pass@id.example.com?client_id=lore")
            .expect_err("credentials embedded in the issuer must be refused");
        assert!(error.to_string().contains("credentials"), "{error}");
    }

    #[test]
    fn a_loopback_provider_may_advertise_http_endpoints() {
        parse_discovery(
            r#"{"issuer":"http://127.0.0.1:1411",
                "authorization_endpoint":"http://127.0.0.1:1411/authorize",
                "token_endpoint":"http://127.0.0.1:1411/api/oidc/token",
                "device_authorization_endpoint":"http://localhost:1411/api/oidc/device"}"#,
            "http://127.0.0.1:1411",
        )
        .expect("a loopback provider is the case oidc+http exists for");
    }

    #[test]
    fn discovery_may_omit_the_device_endpoint() {
        let body = r#"{"issuer":"https://id.example.com","authorization_endpoint":"https://id.example.com/authorize","token_endpoint":"https://id.example.com/token"}"#;
        let discovery =
            parse_discovery(body, "https://id.example.com").expect("discovery should parse");
        assert_eq!(discovery.device_authorization_endpoint, None);
    }

    #[test]
    fn both_oidc_schemes_resolve_through_the_registry() {
        use crate::auth::authentication;

        authentication::find("oidc+https://id.example.com?client_id=lore")
            .expect("oidc+https should be registered");
        authentication::find("oidc+http://127.0.0.1:1411?client_id=lore")
            .expect("oidc+http should be registered");
    }
}

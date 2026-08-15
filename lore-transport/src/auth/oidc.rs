// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! `OpenID` Connect authentication for the `oidc+https` and `oidc+http` schemes:
//! authorization code with PKCE over a loopback redirect, the device authorization grant
//! for [`LoginFlow::NoBrowser`], and the refresh grant. Stripping `oidc+` from the
//! advertised auth URL recovers the issuer identifier byte for byte; the server verifies
//! token signatures, so this module checks only `state` and `nonce`.
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
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

#[allow(dead_code)] // Consumed by the login flows in the following phases.
/// `offline_access` asks a conformant provider for a refresh token. `profile` and `email`
/// carry the optional display claims; the code falls back to `sub` without them.
const SCOPES: &str = "openid profile email offline_access";

/// Cap on a provider response body, so a broken or hostile endpoint cannot stream
/// unbounded bytes into memory.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[allow(dead_code)] // Consumed by the login flows in the following phases.
/// Bytes of entropy behind a code verifier and a `state`. 32 bytes base64url-encode to 43
/// characters, the minimum RFC 7636 §4.1 allows for a verifier.
const RANDOM_BYTES: usize = 32;

/// What the advertised auth URL says about the provider.
#[derive(Clone, Debug, PartialEq, Eq)]
struct AuthUrlParts {
    /// The issuer identifier, byte for byte as the provider publishes it.
    issuer: String,
    /// Derived exactly as the token-recipient guard derives a remote's, so the two are
    /// comparable without normalizing either.
    issuer_domain: String,
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

#[allow(dead_code)] // Consumed by the login flows in the following phases.
/// The S256 code challenge for a verifier (RFC 7636 §4.2).
fn code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(ring::digest::digest(
        &ring::digest::SHA256,
        verifier.as_bytes(),
    ))
}

#[allow(dead_code)] // Consumed by the login flows in the following phases.
/// `RANDOM_BYTES` of entropy, base64url without padding: 43 characters from the unreserved
/// set, which is what RFC 7636 §4.1 asks of a code verifier.
fn random_token() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; RANDOM_BYTES]>())
}

#[allow(dead_code)] // Consumed by the login flows in the following phases.
/// Builds the provider's authorization URL for a PKCE login.
fn authorization_url(
    discovery: &Discovery,
    parts: &AuthUrlParts,
    redirect_uri: &str,
    state: &str,
    nonce: &str,
    challenge: &str,
) -> Result<String, ProtocolError> {
    let mut url = Url::parse(&discovery.authorization_endpoint).map_err(|e| {
        ProtocolError::internal(format!(
            "provider advertises an unusable authorization_endpoint '{}': {e}",
            discovery.authorization_endpoint
        ))
    })?;

    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", &parts.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", SCOPES)
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256");
    }

    Ok(url.into())
}

#[allow(dead_code)] // Consumed by the login flows in the following phases.
/// What the browser delivered to the loopback redirect.
#[derive(Debug, Default, PartialEq, Eq)]
struct CallbackOutcome {
    state: Option<String>,
    code: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[allow(dead_code)] // Consumed by the login flows in the following phases.
/// Reads the query out of a redirect's request target (`/callback?code=...&state=...`).
fn callback_outcome(request_target: &str) -> Result<CallbackOutcome, ProtocolError> {
    // The target is origin-form (`/callback?...`), which is not a URL on its own. The
    // authority is irrelevant -- only the query is read.
    let url = Url::parse("http://localhost")
        .and_then(|base| base.join(request_target))
        .map_err(|e| {
            ProtocolError::internal(format!("redirect request target is not usable: {e}"))
        })?;

    let mut outcome = CallbackOutcome::default();
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "state" => outcome.state = Some(value.into_owned()),
            "code" => outcome.code = Some(value.into_owned()),
            "error" => outcome.error = Some(value.into_owned()),
            "error_description" => outcome.error_description = Some(value.into_owned()),
            _ => {}
        }
    }

    Ok(outcome)
}

#[allow(dead_code)] // Consumed by the login flows in the following phases.
/// Returns the authorization code, having first established that the response belongs to
/// this session.
///
/// The `state` comparison runs before the code and before any provider-reported error is
/// read: a response from another session is not evidence about this one either way.
fn authorization_code(
    outcome: &CallbackOutcome,
    expected_state: &str,
) -> Result<String, ProtocolError> {
    if outcome.state.as_deref() != Some(expected_state) {
        return Err(ProtocolError::internal(
            "authorization response carries the wrong state and does not belong to this login",
        ));
    }

    if let Some(error) = &outcome.error {
        let description = outcome
            .error_description
            .as_deref()
            .unwrap_or("no description");
        // `error_description` is the only place the user learns what to fix.
        return Err(ProtocolError::internal(format!(
            "provider refused the authorization request: {error} ({description})"
        )));
    }

    outcome
        .code
        .clone()
        .filter(|code| !code.is_empty())
        .ok_or_else(|| {
            ProtocolError::internal("authorization response carries neither a code nor an error")
        })
}

#[allow(dead_code)] // Consumed by the login flows in the following phases.
/// A token endpoint success response. The ID token is the credential.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
struct TokenResponse {
    /// Optional on a refresh: `OpenID` Connect Core §12.2 does not oblige a provider to
    /// reissue an ID token for a refresh grant.
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
}

#[allow(dead_code)] // Consumed by the login flows in the following phases.
/// A token endpoint error response (RFC 6749 §5.2).
#[derive(Debug, Default, Deserialize)]
struct TokenError {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

#[allow(dead_code)] // Consumed by the login flows in the following phases.
/// The ID token claims this client reads. Only `sub` and `exp` are required of it; `name`
/// and `preferred_username` arrive with the `profile` scope.
#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    sub: String,
    exp: u64,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
}

#[allow(dead_code)] // Consumed by the login flows in the following phases.
/// Reads an ID token's claims without verifying its signature, which is the server's job.
fn id_token_claims(id_token: &str) -> Result<IdTokenClaims, ProtocolError> {
    lore_credential::insecure_decode_token_as::<IdTokenClaims>(id_token)
        .map(|data| data.claims)
        .map_err(|e| ProtocolError::internal(format!("ID token claims are not readable: {e}")))
}

#[allow(dead_code)] // Consumed by the login flows in the following phases.
/// The form fields of one request to the provider's token or device authorization
/// endpoint.
type GrantForm = Vec<(&'static str, String)>;

#[allow(dead_code)] // Consumed by the login flows in the following phases.
/// Turns a token response into an [`AuthenticationToken`].
///
/// `expected_nonce` is `Some` for a login and `None` for a refresh, where `OpenID` Connect
/// Core §12.2 makes the claim optional. The ID token is always the credential.
fn authentication_token(
    tokens: TokenResponse,
    expected_nonce: Option<&str>,
    parts: &AuthUrlParts,
) -> Result<AuthenticationToken, ProtocolError> {
    let Some(id_token) = tokens.id_token.as_deref() else {
        return Err(ProtocolError::internal(
            "the token endpoint returned no id_token, so this deployment has no \
             credential to present",
        ));
    };
    let claims = id_token_claims(id_token)?;

    // Core §3.1.3.3: a login response always carries an ID token, and the nonce travels
    // on it.
    if let Some(expected) = expected_nonce
        && claims.nonce.as_deref() != Some(expected)
    {
        return Err(ProtocolError::internal(
            "ID token does not echo this login's nonce and may be a replay",
        ));
    }

    let user_id = claims.sub.clone();
    let expires = claims.exp;
    let user_name = claims
        .name
        .or(claims.preferred_username)
        .unwrap_or(claims.sub);

    Ok(AuthenticationToken {
        token: id_token.to_string(),
        user_id,
        user_name,
        // Claims count seconds since the epoch; every other Lore timestamp is milliseconds.
        expires_ms: expires.saturating_mul(1000),
        // The issuer already holds the token. The orchestration layer adds the remote the
        // login was performed against.
        recipients: TokenRecipients::Explicit(vec![parts.issuer_domain.clone()]),
        refresh_token: tokens.refresh_token,
    })
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
    use crate::types::unsigned_jwt;

    const DISCOVERY_JSON: &str = r#"{
        "issuer": "https://id.example.com",
        "authorization_endpoint": "https://id.example.com/authorize",
        "token_endpoint": "https://id.example.com/token",
        "device_authorization_endpoint": "https://id.example.com/device",
        "jwks_uri": "https://id.example.com/jwks.json"
    }"#;

    fn parts() -> AuthUrlParts {
        AuthUrlParts {
            issuer: "https://id.example.com".to_string(),
            issuer_domain: "id.example.com".to_string(),
            client_id: "lore".to_string(),
        }
    }

    fn discovery() -> Discovery {
        parse_discovery(DISCOVERY_JSON, "https://id.example.com").expect("discovery should parse")
    }

    /// Pinned to RFC 7636 Appendix B's worked example rather than to this code's output.
    #[test]
    fn code_challenge_matches_the_rfc_7636_test_vector() {
        assert_eq!(
            code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn code_verifier_uses_the_rfc_7636_length_and_alphabet() {
        let verifier = random_token();
        assert!(
            (43..=128).contains(&verifier.len()),
            "verifier length {} is outside 43..=128",
            verifier.len()
        );
        assert!(
            verifier
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~')),
            "verifier {verifier} uses characters outside the unreserved set"
        );
        assert_ne!(verifier, random_token(), "verifier is not random");
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
    fn authorization_url_carries_pkce_state_and_nonce() {
        let url = authorization_url(
            &discovery(),
            &parts(),
            "http://127.0.0.1:49152/callback",
            "the-state",
            "the-nonce",
            "the-challenge",
        )
        .expect("authorization URL should build");

        let url = Url::parse(&url).expect("authorization URL should be a URL");
        let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(
            url.origin(),
            Url::parse("https://id.example.com").unwrap().origin()
        );
        assert_eq!(url.path(), "/authorize");
        assert_eq!(query.get("response_type").map(String::as_str), Some("code"));
        assert_eq!(query.get("client_id").map(String::as_str), Some("lore"));
        assert_eq!(
            query.get("redirect_uri").map(String::as_str),
            Some("http://127.0.0.1:49152/callback")
        );
        assert_eq!(query.get("state").map(String::as_str), Some("the-state"));
        assert_eq!(query.get("nonce").map(String::as_str), Some("the-nonce"));
        assert_eq!(
            query.get("code_challenge").map(String::as_str),
            Some("the-challenge")
        );
        assert_eq!(
            query.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
        assert!(
            query
                .get("scope")
                .is_some_and(|scope| scope.split(' ').any(|s| s == "offline_access")),
            "offline_access is what asks for a refresh token"
        );
    }

    #[test]
    fn callback_query_is_read_from_the_request_target() {
        let outcome = callback_outcome("/callback?code=the-code&state=the-state")
            .expect("the target should parse");
        assert_eq!(
            outcome,
            CallbackOutcome {
                state: Some("the-state".to_string()),
                code: Some("the-code".to_string()),
                error: None,
                error_description: None,
            }
        );
    }

    #[test]
    fn callback_code_is_returned_when_the_state_matches() {
        let outcome =
            callback_outcome("/callback?code=the-code&state=the-state").expect("should parse");
        assert_eq!(
            authorization_code(&outcome, "the-state").expect("the code should be accepted"),
            "the-code"
        );
    }

    #[test]
    fn callback_with_a_mismatched_state_is_refused() {
        let outcome =
            callback_outcome("/callback?code=the-code&state=another-state").expect("should parse");
        authorization_code(&outcome, "the-state")
            .expect_err("a response from another session must not be accepted");
    }

    #[test]
    fn callback_without_a_state_is_refused() {
        let outcome = callback_outcome("/callback?code=the-code").expect("should parse");
        authorization_code(&outcome, "the-state").expect_err("an unbound response is not ours");
    }

    #[test]
    fn callback_error_with_a_wrong_state_is_refused_as_a_state_mismatch() {
        let outcome = callback_outcome("/callback?error=access_denied&state=another-state")
            .expect("should parse");
        let error = authorization_code(&outcome, "the-state")
            .expect_err("a foreign error response must not be accepted");
        assert!(
            error.to_string().contains("state"),
            "the state mismatch should be the reported cause, got: {error}"
        );
    }

    #[test]
    fn callback_error_is_reported_when_the_state_matches() {
        let outcome = callback_outcome(
            "/callback?error=access_denied&error_description=User%20said%20no&state=the-state",
        )
        .expect("should parse");
        let error = authorization_code(&outcome, "the-state").expect_err("the provider refused");
        assert!(
            error.to_string().contains("access_denied"),
            "the provider's error should be reported, got: {error}"
        );
    }

    #[test]
    fn callback_without_a_code_is_refused() {
        let outcome = callback_outcome("/callback?state=the-state").expect("should parse");
        authorization_code(&outcome, "the-state").expect_err("there is nothing to exchange");
    }

    #[test]
    fn id_token_nonce_mismatch_is_refused() {
        let tokens = TokenResponse {
            id_token: Some(unsigned_jwt(
                r#"{"sub":"user-1","exp":1000,"nonce":"another-nonce"}"#,
            )),
            refresh_token: None,
        };
        authentication_token(tokens, Some("the-nonce"), &parts())
            .expect_err("a replayed token from another exchange must not be accepted");
    }

    #[test]
    fn id_token_without_a_nonce_is_refused_on_a_login() {
        let tokens = TokenResponse {
            id_token: Some(unsigned_jwt(r#"{"sub":"user-1","exp":1000}"#)),
            refresh_token: None,
        };
        authentication_token(tokens, Some("the-nonce"), &parts())
            .expect_err("a login's ID token has to echo the nonce that was sent");
    }

    #[test]
    fn id_token_becomes_the_credential_with_the_issuer_as_its_recipient() {
        let id_token = unsigned_jwt(
            r#"{"sub":"user-1","exp":1000,"nonce":"the-nonce","name":"Ada Lovelace"}"#,
        );
        let tokens = TokenResponse {
            id_token: Some(id_token.clone()),
            refresh_token: Some("the-refresh-token".to_string()),
        };
        let token = authentication_token(tokens, Some("the-nonce"), &parts())
            .expect("the token should be accepted");

        assert_eq!(token.token, id_token, "the ID token is the credential");
        assert_eq!(token.user_id, "user-1");
        assert_eq!(token.user_name, "Ada Lovelace");
        assert_eq!(token.expires_ms, 1_000_000);
        assert_eq!(token.refresh_token.as_deref(), Some("the-refresh-token"));
        assert_eq!(
            token.recipients,
            TokenRecipients::Explicit(vec!["id.example.com".to_string()])
        );
    }

    #[test]
    fn display_name_falls_back_through_preferred_username_to_sub() {
        let tokens = TokenResponse {
            id_token: Some(unsigned_jwt(
                r#"{"sub":"user-1","exp":1,"preferred_username":"ada"}"#,
            )),
            refresh_token: None,
        };
        let token = authentication_token(tokens, None, &parts()).expect("should be accepted");
        assert_eq!(token.user_name, "ada");

        let tokens = TokenResponse {
            id_token: Some(unsigned_jwt(r#"{"sub":"user-1","exp":1}"#)),
            refresh_token: None,
        };
        let token = authentication_token(tokens, None, &parts()).expect("should be accepted");
        assert_eq!(token.user_name, "user-1");
    }

    #[test]
    fn a_refreshed_id_token_need_not_carry_a_nonce() {
        let tokens = TokenResponse {
            id_token: Some(unsigned_jwt(r#"{"sub":"user-1","exp":1000}"#)),
            refresh_token: Some("rotated".to_string()),
        };
        let token =
            authentication_token(tokens, None, &parts()).expect("refresh should be accepted");
        assert_eq!(token.user_id, "user-1");
    }

    #[test]
    fn a_refresh_without_an_id_token_is_refused_where_the_id_token_is_the_credential() {
        let tokens = TokenResponse {
            id_token: None,
            refresh_token: Some("rotated".to_string()),
        };
        let error = authentication_token(tokens, None, &parts())
            .expect_err("there is no credential to store");
        assert!(
            error.to_string().contains("id_token"),
            "the diagnostic should name the missing member: {error}"
        );
    }

    #[test]
    fn a_login_without_an_id_token_is_refused() {
        let tokens = TokenResponse {
            id_token: None,
            ..Default::default()
        };
        let error = authentication_token(tokens, Some("the-nonce"), &parts())
            .expect_err("a login cannot complete without an ID token");
        assert!(
            error.to_string().contains("id_token"),
            "the diagnostic should name the missing member: {error}"
        );
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

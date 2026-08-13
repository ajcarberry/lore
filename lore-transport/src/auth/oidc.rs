// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! OpenID Connect authentication for the `oidc+https` and `oidc+http` schemes.
//!
//! The provider is named by the auth URL the server advertises through
//! `EnvironmentEndpoint.auth_url`:
//!
//! ```text
//! oidc+https://id.example.com?client_id=lore
//! oidc+https://id.example.com/realms/studio?client_id=lore&resource=lore.example.com
//! ```
//!
//! Stripping `oidc+` from the scheme leaves the issuer identifier byte for byte, which
//! matters because every issuer check in the design is a byte comparison: the value the
//! operator configured, the `issuer` member of the discovery document, and the `iss` claim
//! must all be the same string. The query is safe to append because an issuer identifier
//! "MUST NOT contain a query or fragment component" (OpenID Connect Discovery 1.0 §2).
//!
//! Three flows fit onto the [`Authentication`] trait's start-and-poll shape:
//!
//! * **Authorization code with PKCE over a loopback redirect** ([RFC 7636], [RFC 8252] §7.3)
//!   for a host with a browser. `start_auth_session` binds `127.0.0.1:0` and hands back the
//!   provider's authorization URL; `poll_auth_session` returns `None` until the redirect
//!   arrives.
//! * **The device authorization grant** ([RFC 8628]) for `lore login --no-browser`, selected
//!   by [`LoginFlow::NoBrowser`].
//! * **The refresh grant**, through `refresh_authentication`.
//!
//! The credential presented to a Lore server is the **ID token**: it is the only token
//! OpenID Connect guarantees is a signed JWT carrying the client id in `aud`, which is the
//! value a server pins. Nothing here verifies that signature -- the server does, against the
//! issuer's published key set. What this module checks is what only it can: that the
//! authorization response belongs to the session it started (`state`) and that the ID token
//! belongs to that same exchange (`nonce`).
//!
//! [RFC 7636]: https://www.rfc-editor.org/rfc/rfc7636
//! [RFC 8252]: https://www.rfc-editor.org/rfc/rfc8252
//! [RFC 8628]: https://www.rfc-editor.org/rfc/rfc8628
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;
use std::time::Instant;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use lore_base::error::NotAuthenticated;
use lore_base::error::NotAuthorized;
use lore_base::error::NotSupported;
use lore_base::lore_debug;
use lore_base::lore_info;
use lore_base::types::RepositoryId;
use parking_lot::Mutex;
use reqwest::StatusCode;
use serde::Deserialize;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use url::Host;
use url::Url;

use crate::error::ProtocolError;
use crate::traits::Authentication;
use crate::traits::LoginFlow;
use crate::types::*;

/// Where a provider publishes its metadata (OpenID Connect Discovery 1.0 §4).
const DISCOVERY_PATH: &str = "/.well-known/openid-configuration";

/// `offline_access` is what asks a conformant provider for a refresh token, so a session
/// outlives its first ID token. `profile` and `email` are what make a display name
/// available; both are optional claims and the code falls back to `sub` without them.
const SCOPES: &str = "openid profile email offline_access";

/// Path the loopback listener answers on, so the redirect URI names something specific
/// rather than the bare root.
const CALLBACK_PATH: &str = "/callback";

/// Cap on a provider response. Discovery documents and token responses are kilobytes; this
/// only exists so a broken or hostile endpoint cannot stream unbounded bytes into memory.
/// Matches the server's `JWKS_MAX_RESPONSE_BYTES`.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Cap on the redirect request's start line. A browser sends one short GET; anything
/// longer is not the redirect being waited for.
const MAX_REQUEST_LINE_BYTES: usize = 8 * 1024;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Poll interval to use when a device authorization response omits `interval`
/// (RFC 8628 §3.2 makes it OPTIONAL and names 5 seconds as the default).
const DEFAULT_DEVICE_INTERVAL: Duration = Duration::from_secs(5);

/// What a `slow_down` adds to the poll interval (RFC 8628 §3.5).
const SLOW_DOWN_INCREMENT: Duration = Duration::from_secs(5);

/// Bytes of entropy behind a code verifier and a `state`. 32 bytes base64url-encode to 43
/// characters, the minimum RFC 7636 §4.1 allows for a verifier.
const RANDOM_BYTES: usize = 32;

/// What the advertised auth URL says about the provider.
#[derive(Clone, Debug, PartialEq, Eq)]
struct AuthUrlParts {
    /// The issuer identifier, byte for byte as the provider publishes it.
    issuer: String,
    /// The issuer's domain, derived exactly as the token-recipient guard derives a
    /// remote's, so the two are comparable without normalizing either.
    issuer_domain: String,
    /// The public client registered for Lore.
    client_id: String,
    /// RFC 8707 resource indicator, when the deployment advertises one.
    resource: Option<String>,
}

/// Splits an advertised auth URL into the issuer and its parameters.
///
/// `oidc+http` is accepted only for a loopback host: plain HTTP to anywhere else would put
/// an authorization code and an ID token on the wire in the clear. A local provider in a
/// test harness or a development deployment is the case it exists for.
fn parse_auth_url(auth_url: &str) -> Result<AuthUrlParts, ProtocolError> {
    let (scheme, rest) = auth_url.split_once("://").ok_or_else(|| {
        ProtocolError::internal(format!(
            "invalid OIDC auth URL (missing scheme): '{auth_url}'"
        ))
    })?;
    let transport = match scheme {
        "oidc+https" => "https",
        "oidc+http" => "http",
        _ => {
            return Err(ProtocolError::internal(format!(
                "'{scheme}' is not an OIDC auth URL scheme (expected 'oidc+https' or 'oidc+http')"
            )));
        }
    };

    // The issuer is recovered textually rather than by re-serializing a parsed URL, so
    // it survives byte for byte: an issuer identifier carries no query or fragment
    // (Discovery §2), so everything up to the first `?` or `#` is the issuer.
    let issuer_tail = rest.split(['?', '#']).next().unwrap_or(rest);
    let issuer = format!("{transport}://{issuer_tail}");

    let url = Url::parse(&format!("{transport}://{rest}"))
        .map_err(|e| ProtocolError::internal(format!("invalid OIDC auth URL '{auth_url}': {e}")))?;
    // Parsed separately from `url` because the domain derivation below must not see the
    // query string: for an IP host it falls back to the whole URL.
    let issuer_url = Url::parse(&issuer)
        .map_err(|e| ProtocolError::internal(format!("invalid OIDC issuer '{issuer}': {e}")))?;

    if transport == "http" && !is_loopback(issuer_url.host()) {
        return Err(ProtocolError::internal(format!(
            "'oidc+http' is accepted only for a loopback issuer, not '{issuer}' -- \
             a code and an ID token would travel in the clear"
        )));
    }

    let mut client_id = None;
    let mut resource = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "client_id" => client_id = Some(value.into_owned()),
            "resource" => resource = Some(value.into_owned()),
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
        // The same derivation the recipient guard applies to a remote URL
        // (`domain_from_url_or_url`), so the issuer's entry and the remote's entry in a
        // token's acceptable set are directly comparable.
        issuer_domain: lore_credential::domain_from_url_or_url(&issuer_url),
        client_id,
        resource,
    })
}

/// Whether a host is this machine. `localhost` counts because a provider in a development
/// deployment is commonly reached that way, and it resolves to a loopback address.
fn is_loopback(host: Option<Host<&str>>) -> bool {
    match host {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

/// The members of the discovery document this client uses. The server reads its own copy for
/// `jwks_uri`; nothing is relayed between them, so neither can serve the other a stale
/// endpoint.
#[derive(Clone, Debug, Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    /// OPTIONAL, and its absence is what makes `--no-browser` impossible against a
    /// provider rather than merely slower.
    #[serde(default)]
    device_authorization_endpoint: Option<String>,
}

/// Parses a discovery document and pins it to the issuer that was configured.
///
/// The `issuer` member must equal the configured issuer byte for byte (Discovery §4.3).
/// Without that check, a redirect or a compromised well-known path could hand back another
/// provider's endpoints, and a login would complete against the wrong party.
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

    Ok(discovery)
}

/// A fresh code verifier: 32 random bytes, base64url without padding, which is 43
/// characters drawn from the unreserved set RFC 7636 §4.1 requires.
fn code_verifier() -> String {
    random_token()
}

/// The S256 code challenge for a verifier (RFC 7636 §4.2).
fn code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(ring::digest::digest(
        &ring::digest::SHA256,
        verifier.as_bytes(),
    ))
}

/// An unguessable value for `state`, generated here rather than taken from the caller so
/// the binding between an authorization response and this session does not depend on how
/// the caller chose its own session identifier.
fn random_state() -> String {
    random_token()
}

/// `RANDOM_BYTES` of entropy, base64url without padding.
fn random_token() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; RANDOM_BYTES]>())
}

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
        if let Some(resource) = &parts.resource {
            query.append_pair("resource", resource);
        }
    }

    Ok(url.into())
}

/// What the browser delivered to the loopback redirect.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct CallbackOutcome {
    state: Option<String>,
    code: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

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

/// Returns the authorization code, having first established that the response belongs to
/// this session.
///
/// The `state` comparison happens before the code is read, and before a provider-reported
/// error is reported, because a response from another session is not evidence about this
/// one either way.
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
        // Reported as the provider's own words rather than a bare `NotAuthorized`,
        // because `error_description` is the only place the user learns what to fix.
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

/// A token endpoint success response.
///
/// Which of the two tokens becomes the credential depends on the deployment: without a
/// resource indicator it is the ID token, the only token OpenID Connect guarantees is a
/// verifiable JWT; with one it is the access token, which is the token RFC 8707 lets a
/// client bind to a particular resource server. The refresh token keeps the session alive
/// either way.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
struct TokenResponse {
    id_token: String,
    /// REQUIRED of a successful response by RFC 6749 §5.1, but optional here so a
    /// provider that omits it produces this module's own diagnostic rather than a
    /// deserialization error naming a field the operator has never heard of.
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
}

/// A token endpoint error response (RFC 6749 §5.2).
#[derive(Clone, Debug, Default, Deserialize)]
struct TokenError {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

/// The ID token claims this client reads. Only `sub` and `exp` are required of it: `nonce`
/// is present when the request carried one, and `name` and `preferred_username` are
/// optional claims delivered with the `profile` scope.
#[derive(Clone, Debug, Deserialize)]
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

/// Reads a JWT's claims without verifying its signature.
///
/// Verification is the server's job, against the issuer's published key set. What the
/// client needs from a payload is the `nonce` it has to compare, the identity it has to
/// display, and the expiry the credential store keys on -- and it has just received the
/// token over TLS from the token endpoint it found through a pinned discovery document.
fn decode_unverified<T: serde::de::DeserializeOwned>(
    token: &str,
) -> Result<T, jsonwebtoken::errors::Error> {
    let header = jsonwebtoken::decode_header(token)?;

    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.insecure_disable_signature_validation();
    validation.validate_aud = false;
    validation.validate_exp = false;
    validation.validate_nbf = false;
    // Nothing here is a security check, so a shape that omits a claim this client does
    // not read must not be rejected on `jsonwebtoken`'s default required set.
    validation.required_spec_claims.clear();

    jsonwebtoken::decode::<T>(
        token,
        &jsonwebtoken::DecodingKey::from_secret(&[]),
        &validation,
    )
    .map(|data| data.claims)
}

/// Reads an ID token's claims without verifying its signature.
fn id_token_claims(id_token: &str) -> Result<IdTokenClaims, ProtocolError> {
    decode_unverified(id_token)
        .map_err(|e| ProtocolError::internal(format!("ID token claims are not readable: {e}")))
}

/// The form fields of one request to the provider's token or device authorization
/// endpoint.
type GrantForm = Vec<(&'static str, String)>;

/// Appends the RFC 8707 resource indicator, when the deployment advertises one.
///
/// §2 puts the parameter on the authorization request *and* on the token request of every
/// grant type, and a provider audience-restricts what it mints from what the request
/// carried — so a form that omits it gets a token this deployment will refuse. Every form
/// this module builds ends here for that reason, which is what makes "all five request
/// kinds" a property of the code rather than of five separate memories.
fn with_resource(mut form: GrantForm, parts: &AuthUrlParts) -> GrantForm {
    if let Some(resource) = &parts.resource {
        form.push(("resource", resource.clone()));
    }
    form
}

/// The device authorization request (RFC 8628 §3.1).
fn device_authorization_form(parts: &AuthUrlParts) -> GrantForm {
    with_resource(
        vec![
            ("client_id", parts.client_id.clone()),
            ("scope", SCOPES.to_string()),
        ],
        parts,
    )
}

/// The authorization-code exchange (RFC 6749 §4.1.3, with RFC 7636 §4.5's verifier).
fn authorization_code_form(session: &PkceSession, code: &str) -> GrantForm {
    with_resource(
        vec![
            ("grant_type", "authorization_code".to_string()),
            ("code", code.to_string()),
            ("redirect_uri", session.redirect_uri.clone()),
            ("client_id", session.parts.client_id.clone()),
            ("code_verifier", session.verifier.clone()),
        ],
        &session.parts,
    )
}

/// One poll of an approved device code (RFC 8628 §3.4).
fn device_token_form(parts: &AuthUrlParts, device_code: &str) -> GrantForm {
    with_resource(
        vec![
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            ),
            ("device_code", device_code.to_string()),
            ("client_id", parts.client_id.clone()),
        ],
        parts,
    )
}

/// The refresh grant (RFC 6749 §6).
fn refresh_form(parts: &AuthUrlParts, refresh_token: &str) -> GrantForm {
    with_resource(
        vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", refresh_token.to_string()),
            ("client_id", parts.client_id.clone()),
        ],
        parts,
    )
}

/// `aud` is a set, and providers differ over whether they collapse a single-element one to
/// a bare string (OpenID Connect Core §2). Both encodings have to read.
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn contains(&self, value: &str) -> bool {
        match self {
            Audience::One(one) => one == value,
            Audience::Many(many) => many.iter().any(|entry| entry == value),
        }
    }
}

/// The claims an access token has to carry for this client to be able to tell whether it
/// is the credential the server asked for.
#[derive(Clone, Debug, Deserialize)]
struct AccessTokenClaims {
    exp: u64,
    #[serde(default)]
    aud: Option<Audience>,
}

/// Picks the access token out of a token response and checks it is the one a
/// resource-bound deployment asked for, returning it with its expiry.
///
/// **This is a diagnostic, not a security control.** The Lore server verifies the token
/// itself, against the issuer's published key set, and its verdict is the only one that
/// decides anything. What this catches is a failure that is otherwise silent and badly
/// timed: RFC 8707 puts a provider under no obligation to announce that it does not
/// implement resource indicators, and one that ignores the parameter answers with an
/// ordinary client-audienced token and a `200`. Without the check, `lore login` succeeds,
/// stores a credential, prints a user name -- and then every repository operation is
/// refused, with the cause two layers away and nothing in the login transcript pointing at
/// it. PocketID 2.6.2 behaves exactly this way.
fn resource_bound_credential(
    tokens: &TokenResponse,
    resource: &str,
) -> Result<(String, u64), ProtocolError> {
    let access_token = tokens
        .access_token
        .as_deref()
        .filter(|token| !token.is_empty())
        .ok_or_else(|| {
            ProtocolError::internal(format!(
                "this Lore server requires an access token bound to '{resource}' \
                 (RFC 8707), but the provider's token response carried none"
            ))
        })?;

    let header = jsonwebtoken::decode_header(access_token).map_err(|e| {
        ProtocolError::internal(format!(
            "this Lore server requires an RFC 9068 JWT access token bound to \
             '{resource}', but the provider issued an access token that is not a JWT \
             at all: {e}"
        ))
    })?;
    if !header.typ.as_deref().is_some_and(|typ| {
        typ.eq_ignore_ascii_case("at+jwt") || typ.eq_ignore_ascii_case("application/at+jwt")
    }) {
        return Err(ProtocolError::internal(format!(
            "the provider issued an access token typed '{}' rather than the RFC 9068 \
             'at+jwt', so this Lore server will refuse it -- the provider does not \
             implement RFC 9068 access tokens",
            header.typ.as_deref().unwrap_or("(absent)")
        )));
    }

    let claims: AccessTokenClaims = decode_unverified(access_token).map_err(|e| {
        ProtocolError::internal(format!("access token claims are not readable: {e}"))
    })?;

    // The parameter was sent on every request of this grant; an `aud` that does not name
    // the resource means the provider ignored it rather than refused it, which is the
    // case worth naming out loud.
    if !claims
        .aud
        .as_ref()
        .is_some_and(|aud| aud.contains(resource))
    {
        return Err(ProtocolError::internal(format!(
            "the provider issued an access token whose audience is not '{resource}', so \
             this Lore server will refuse it -- the provider appears to ignore the \
             RFC 8707 'resource' parameter"
        )));
    }

    Ok((access_token.to_string(), claims.exp))
}

/// Turns a token response into an [`AuthenticationToken`].
///
/// `expected_nonce` is `Some` for a login, where the ID token has to be tied to the
/// authorization request that produced it, and `None` for a refresh, where OpenID Connect
/// Core §12.2 makes the claim optional.
///
/// The ID token is always the *identity*: it is the assertion carrying `nonce` and the
/// display claims, and it is what is checked here. What changes under a resource indicator
/// is only which token is the *credential* -- the thing stored, presented, and refreshed
/// on expiry -- because that is what the server verifies.
fn authentication_token(
    tokens: TokenResponse,
    expected_nonce: Option<&str>,
    parts: &AuthUrlParts,
) -> Result<AuthenticationToken, ProtocolError> {
    let claims = id_token_claims(&tokens.id_token)?;

    if let Some(expected) = expected_nonce
        && claims.nonce.as_deref() != Some(expected)
    {
        return Err(ProtocolError::internal(
            "ID token does not echo this login's nonce and may be a replay",
        ));
    }

    let (token, expires) = match parts.resource.as_deref() {
        Some(resource) => resource_bound_credential(&tokens, resource)?,
        None => (tokens.id_token, claims.exp),
    };

    Ok(AuthenticationToken {
        token,
        user_id: claims.sub.clone(),
        // `name` and `preferred_username` are optional claims delivered with the `profile`
        // scope. Falling back to `sub` keeps a login from failing over a display string.
        user_name: claims
            .name
            .or(claims.preferred_username)
            .unwrap_or(claims.sub),
        // Claims count seconds since the epoch; every other Lore timestamp is milliseconds.
        expires_ms: expires.saturating_mul(1000),
        // The party that issued the token already has it, so it can always go back there.
        // The orchestration layer adds the remote the login was performed against -- the
        // only layer that knows it.
        acceptable_root_domains: vec![parts.issuer_domain.clone()],
        refresh_token: tokens.refresh_token,
    })
}

/// A device authorization response (RFC 8628 §3.2).
#[derive(Clone, Debug, Deserialize)]
struct DeviceAuthorization {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    #[serde(default)]
    interval: Option<u64>,
}

/// The URL to put in front of the user.
///
/// `verification_uri_complete` already carries the user code, which is the whole reason
/// RFC 8628 §3.3.1 defines it. Without it the code is appended as `user_code`, so the user
/// still gets one thing to open rather than a URL and a code to retype.
fn device_login_url(authorization: &DeviceAuthorization) -> String {
    if let Some(complete) = &authorization.verification_uri_complete {
        return complete.clone();
    }

    match Url::parse(&authorization.verification_uri) {
        Ok(mut url) => {
            url.query_pairs_mut()
                .append_pair("user_code", &authorization.user_code);
            url.into()
        }
        // The provider gave something that is not a URL. Hand it over as it is rather than
        // dropping it: the user can still read it.
        Err(_) => format!(
            "{} (user code: {})",
            authorization.verification_uri, authorization.user_code
        ),
    }
}

/// What one poll of the token endpoint established, during a device grant.
#[derive(Clone, Debug, PartialEq, Eq)]
enum DeviceStep {
    /// Nobody has approved yet: keep polling at the current interval.
    Pending,
    /// The provider asked for a longer interval (RFC 8628 §3.5).
    SlowDown,
    /// Approved, with tokens.
    Granted(TokenResponse),
}

/// Classifies a token endpoint response during a device grant (RFC 8628 §3.5).
fn device_poll_step(status: StatusCode, body: &str) -> Result<DeviceStep, ProtocolError> {
    if status.is_success() {
        return serde_json::from_str::<TokenResponse>(body)
            .map(DeviceStep::Granted)
            .map_err(|e| {
                ProtocolError::internal(format!("token endpoint response is not usable: {e}"))
            });
    }

    let error = serde_json::from_str::<TokenError>(body).unwrap_or_default();
    let description = error
        .error_description
        .as_deref()
        .unwrap_or("no description");

    match error.error.as_deref() {
        // Nobody has approved yet. This is the steady state of the whole flow, not a
        // failure, and the orchestration layer's polling loop reads `None` as "keep going".
        Some("authorization_pending") => Ok(DeviceStep::Pending),
        Some("slow_down") => Ok(DeviceStep::SlowDown),
        Some("access_denied") => {
            lore_debug!("Device authorization was refused: {description}");
            Err(ProtocolError::from(NotAuthorized))
        }
        Some("expired_token") => {
            lore_debug!("Device code expired before it was approved: {description}");
            Err(ProtocolError::from(NotAuthenticated))
        }
        Some(other) => Err(ProtocolError::internal(format!(
            "token endpoint refused the device code: {other} ({description})"
        ))),
        None => Err(ProtocolError::internal(format!(
            "token endpoint answered {status} with no error code"
        ))),
    }
}

/// When the next poll of a device grant is allowed.
///
/// RFC 8628 §3.5 makes honoring `interval` a client obligation, not a courtesy: a client
/// that ignores it is indistinguishable from one hammering the token endpoint. The
/// orchestration layer's own polling loop has its own period, so this gate is what keeps
/// the provider's number authoritative whatever that period is.
#[derive(Clone, Debug)]
struct PollSchedule {
    interval: Duration,
    last_poll: Option<Instant>,
}

impl PollSchedule {
    fn new(interval_secs: Option<u64>) -> Self {
        PollSchedule {
            interval: interval_secs
                .map(Duration::from_secs)
                .unwrap_or(DEFAULT_DEVICE_INTERVAL),
            last_poll: None,
        }
    }

    /// Whether enough time has passed since the last poll. The first poll is always due.
    fn due(&self, now: Instant) -> bool {
        match self.last_poll {
            Some(last) => now.saturating_duration_since(last) >= self.interval,
            None => true,
        }
    }

    fn mark(&mut self, now: Instant) {
        self.last_poll = Some(now);
    }

    /// Lengthens the interval after a `slow_down`.
    fn slow_down(&mut self) {
        self.interval = self.interval.saturating_add(SLOW_DOWN_INCREMENT);
    }
}

/// A listener on `127.0.0.1:0` waiting for one authorization response.
struct LoopbackRedirect {
    port: u16,
    /// Resolves with the redirect's request target once the browser arrives.
    target: oneshot::Receiver<Result<String, String>>,
}

/// Binds a loopback listener and waits, on the net runtime, for the browser to arrive.
///
/// Loopback interface redirection is the mechanism RFC 8252 §7.3 specifies for a native
/// application, and it is the reason this client needs no client secret and no registered
/// public callback host: the kernel binds the response to the process holding the port.
async fn bind_loopback_redirect() -> Result<LoopbackRedirect, ProtocolError> {
    let (port_sender, port_receiver) = oneshot::channel();
    let (target_sender, target_receiver) = oneshot::channel();

    // Bound and accepted inside one net-runtime task: a tokio listener registers with the
    // reactor of the runtime that created it, so binding here is what puts the socket on
    // the net runtime rather than on whichever runtime called this.
    lore_base::lore_spawn_net!(async move {
        let listener = match TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await {
            Ok(listener) => listener,
            Err(e) => {
                let _ = port_sender.send(Err(format!("could not bind a loopback listener: {e}")));
                return;
            }
        };
        match listener.local_addr() {
            Ok(address) => {
                if port_sender.send(Ok(address.port())).is_err() {
                    // Nobody is waiting for the login any more.
                    return;
                }
            }
            Err(e) => {
                let _ = port_sender.send(Err(format!("loopback listener has no address: {e}")));
                return;
            }
        }

        let _ = target_sender.send(accept_authorization_response(listener).await);
    });

    let port = port_receiver
        .await
        .map_err(|_| ProtocolError::internal("loopback listener task ended before it bound"))?
        .map_err(ProtocolError::internal)?;

    Ok(LoopbackRedirect {
        port,
        target: target_receiver,
    })
}

/// Accepts connections until one carries an authorization response, and answers each with
/// a page the user sees in the browser they were sent to.
async fn accept_authorization_response(listener: TcpListener) -> Result<String, String> {
    loop {
        let (mut stream, _) = listener
            .accept()
            .await
            .map_err(|e| format!("loopback listener failed: {e}"))?;

        let target = read_request_target(&mut stream).await?;
        // A browser asks for more than the redirect -- a favicon, most often -- so only a
        // request actually carrying an authorization response ends the wait.
        let is_response = callback_outcome(&target)
            .is_ok_and(|outcome| outcome.code.is_some() || outcome.error.is_some());

        respond(&mut stream, is_response).await;
        if is_response {
            return Ok(target);
        }
    }
}

/// Answers the browser, so the user is left looking at a page rather than a failed request.
async fn respond(stream: &mut TcpStream, is_response: bool) {
    const DONE: &str = "Signed in to Lore. You can close this tab and return to the terminal.";
    let (status, body) = if is_response {
        ("200 OK", DONE)
    } else {
        ("404 Not Found", "Not found.")
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );

    // A browser that has already gone away is not a failure of the login: the code is in
    // hand either way, so a write error is only worth a debug line.
    if let Err(e) = stream.write_all(response.as_bytes()).await {
        lore_debug!("Could not answer the loopback redirect: {e}");
    }
    let _ = stream.shutdown().await;
}

/// Reads an HTTP request's target out of its start line.
async fn read_request_target(stream: &mut TcpStream) -> Result<String, String> {
    let mut request = Vec::new();
    let mut chunk = [0u8; 1024];

    let line = loop {
        if let Some(end) = request.windows(2).position(|pair| pair == b"\r\n") {
            break request[..end].to_vec();
        }
        if request.len() > MAX_REQUEST_LINE_BYTES {
            return Err("redirect request start line is implausibly long".to_string());
        }
        match stream.read(&mut chunk).await {
            Ok(0) => return Err("redirect connection closed before it sent a request".to_string()),
            Ok(read) => request.extend_from_slice(&chunk[..read]),
            Err(e) => return Err(format!("could not read the redirect request: {e}")),
        }
    };

    let line = String::from_utf8_lossy(&line);
    // "GET /callback?code=...&state=... HTTP/1.1"
    line.split_whitespace()
        .nth(1)
        .map(str::to_string)
        .ok_or_else(|| format!("redirect request start line is malformed: '{line}'"))
}

/// The pooled HTTP client, built on the net runtime.
///
/// Pooled because a login makes several requests to the same provider -- discovery, then
/// the token endpoint, then a refresh -- and building a client per request means a fresh
/// TLS handshake each time.
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
            .build()
    })
    .await
    .map_err(|e| ProtocolError::internal(format!("HTTP client construction task: {e}")))?
    .map_err(|e| ProtocolError::internal(format!("could not construct an HTTP client: {e}")))?;

    Ok(CLIENT.get_or_init(|| client).clone())
}

/// Issues a request from the net runtime and reads a capped response body.
///
/// Awaited inside `lore_spawn_net!` rather than merely built there: reqwest establishes a
/// connection while the request future is polled, so this is what binds the connection to
/// the net runtime (runtime-split LEP).
async fn send(request: reqwest::RequestBuilder) -> Result<(StatusCode, String), ProtocolError> {
    lore_base::lore_spawn_net!(async move {
        let mut response = request
            .send()
            .await
            .map_err(|e| ProtocolError::internal(format!("provider request failed: {e}")))?;
        let status = response.status();

        // Accumulated rather than read through `Content-Length`, which a hostile or broken
        // endpoint controls. Discovery documents and token responses are kilobytes.
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

/// A login this process started and is polling for.
enum PendingSession {
    Pkce(PkceSession),
    Device(DeviceSession),
}

struct PkceSession {
    parts: AuthUrlParts,
    token_endpoint: String,
    verifier: String,
    state: String,
    nonce: String,
    redirect_uri: String,
    redirect: oneshot::Receiver<Result<String, String>>,
}

struct DeviceSession {
    parts: AuthUrlParts,
    token_endpoint: String,
    schedule: PollSchedule,
}

/// Authentication against a standard OpenID Connect provider.
///
/// Registered under `oidc+https`, and under `oidc+http` for a loopback provider. One
/// instance serves the whole process and holds the state of any login in flight: the code
/// verifier, `state`, `nonce`, and loopback listener of a PKCE flow, or the poll schedule
/// of a device grant. All of it is process-local and dies with the command; only tokens
/// outlive it, in the credential store that already holds them.
#[derive(Default)]
pub struct OidcAuthentication {
    sessions: Mutex<HashMap<String, PendingSession>>,
}

impl OidcAuthentication {
    /// Fetches and pins the provider's discovery document.
    async fn discover(&self, parts: &AuthUrlParts) -> Result<Discovery, ProtocolError> {
        let url = format!("{}{DISCOVERY_PATH}", parts.issuer);
        let client = http_client().await?;
        let (status, body) = send(client.get(&url)).await?;

        if !status.is_success() {
            return Err(ProtocolError::internal(format!(
                "provider discovery at {url} answered {status}"
            )));
        }

        parse_discovery(&body, &parts.issuer)
    }

    /// Starts the authorization code flow: binds the loopback redirect, generates the PKCE
    /// verifier, `state`, and `nonce`, and hands back the provider's authorization URL.
    async fn start_pkce(
        &self,
        parts: AuthUrlParts,
        discovery: Discovery,
    ) -> Result<AuthSession, ProtocolError> {
        let redirect = bind_loopback_redirect().await?;
        let redirect_uri = format!("http://127.0.0.1:{}{CALLBACK_PATH}", redirect.port);

        let verifier = code_verifier();
        let state = random_state();
        let nonce = random_state();
        let login_url = authorization_url(
            &discovery,
            &parts,
            &redirect_uri,
            &state,
            &nonce,
            &code_challenge(&verifier),
        )?;

        // Opaque to the caller: the flow's secrets never leave this process, so the handle
        // is only an index into them.
        let session_code = random_token();
        self.sessions.lock().insert(
            session_code.clone(),
            PendingSession::Pkce(PkceSession {
                parts,
                token_endpoint: discovery.token_endpoint,
                verifier,
                state,
                nonce,
                redirect_uri,
                redirect: redirect.target,
            }),
        );

        Ok(AuthSession {
            session_code,
            login_url,
        })
    }

    /// Starts the device authorization grant (RFC 8628 §3.1).
    async fn start_device(
        &self,
        parts: AuthUrlParts,
        discovery: Discovery,
    ) -> Result<AuthSession, ProtocolError> {
        // The provider has no headless ceremony, and there is no fallback: the browser
        // flow's redirect goes to a loopback listener on *this* host, so an authorization
        // URL for another device to open could never complete. This fails immediately and
        // names the missing capability, rather than polling for a redirect that can never
        // arrive.
        let endpoint = discovery
            .device_authorization_endpoint
            .clone()
            .ok_or_else(|| {
                ProtocolError::from(NotSupported {
                    operation: format!(
                        "login without a browser against {}: the provider advertises no \
                         device_authorization_endpoint, so the device authorization grant \
                         (RFC 8628) is unavailable. Log in from a host with a browser, \
                         without --no-browser",
                        parts.issuer
                    ),
                })
            })?;

        let form = device_authorization_form(&parts);

        let client = http_client().await?;
        let (status, body) = send(client.post(&endpoint).form(&form)).await?;
        if !status.is_success() {
            let error = serde_json::from_str::<TokenError>(&body).unwrap_or_default();
            return Err(ProtocolError::internal(format!(
                "device authorization at {endpoint} answered {status}: {}",
                error.error.as_deref().unwrap_or("no error code")
            )));
        }

        let authorization: DeviceAuthorization = serde_json::from_str(&body).map_err(|e| {
            ProtocolError::internal(format!("device authorization response is not usable: {e}"))
        })?;

        // RFC 8628 §5.2: the user has to be able to compare the code the terminal shows
        // with the one the provider shows, or an approval prompt arriving out of nowhere is
        // indistinguishable from a phishing attempt.
        lore_info!(
            "Enter code {} at {} to authorize this login",
            authorization.user_code,
            authorization.verification_uri
        );

        let login_url = device_login_url(&authorization);
        let session_code = authorization.device_code.clone();
        self.sessions.lock().insert(
            session_code.clone(),
            PendingSession::Device(DeviceSession {
                parts,
                token_endpoint: discovery.token_endpoint,
                schedule: PollSchedule::new(authorization.interval),
            }),
        );

        Ok(AuthSession {
            session_code,
            login_url,
        })
    }

    /// Takes the PKCE session's secrets out of the map, with the redirect the browser
    /// delivered. `None` while the browser has not come back. A login completes at most
    /// once, so the entry does not survive the attempt.
    fn take_pkce(
        &self,
        session_code: &str,
    ) -> Result<Option<(PkceSession, String)>, ProtocolError> {
        let mut sessions = self.sessions.lock();

        // `try_recv` rather than an await, so the map's lock is never held across one.
        let delivered = match sessions.get_mut(session_code) {
            Some(PendingSession::Pkce(session)) => match session.redirect.try_recv() {
                Ok(delivered) => delivered,
                Err(oneshot::error::TryRecvError::Empty) => return Ok(None),
                Err(oneshot::error::TryRecvError::Closed) => {
                    Err("loopback listener ended without delivering a redirect".to_string())
                }
            },
            _ => {
                return Err(ProtocolError::internal(
                    "no interactive login is in flight for this session",
                ));
            }
        };

        let Some(PendingSession::Pkce(session)) = sessions.remove(session_code) else {
            return Err(ProtocolError::internal("login session vanished mid-poll"));
        };
        drop(sessions);

        Ok(Some((session, delivered.map_err(ProtocolError::internal)?)))
    }

    /// Exchanges an authorization code for tokens (RFC 6749 §4.1.3, with RFC 7636 §4.5's
    /// verifier).
    async fn complete_pkce(
        &self,
        session: PkceSession,
        code: &str,
    ) -> Result<AuthenticationToken, ProtocolError> {
        let form = authorization_code_form(&session, code);

        let tokens = self
            .post_token_request(&session.token_endpoint, &form)
            .await?;
        authentication_token(tokens, Some(&session.nonce), &session.parts)
    }

    /// Posts to the token endpoint and reads a success response.
    async fn post_token_request(
        &self,
        token_endpoint: &str,
        form: &[(&str, String)],
    ) -> Result<TokenResponse, ProtocolError> {
        let client = http_client().await?;
        let (status, body) = send(client.post(token_endpoint).form(form)).await?;

        if !status.is_success() {
            let error = serde_json::from_str::<TokenError>(&body).unwrap_or_default();
            return Err(ProtocolError::internal(format!(
                "token endpoint answered {status}: {} ({})",
                error.error.as_deref().unwrap_or("no error code"),
                error
                    .error_description
                    .as_deref()
                    .unwrap_or("no description")
            )));
        }

        serde_json::from_str(&body).map_err(|e| {
            ProtocolError::internal(format!("token endpoint response is not usable: {e}"))
        })
    }

    /// One poll of a device grant. Returns `None` while approval is outstanding.
    async fn poll_device(
        &self,
        session_code: &str,
    ) -> Result<Option<AuthenticationToken>, ProtocolError> {
        // The provider's interval is authoritative, whatever period the caller's own
        // polling loop runs at, so a poll that is not due yet does not reach the network.
        let (token_endpoint, parts) = {
            let mut sessions = self.sessions.lock();
            let Some(PendingSession::Device(session)) = sessions.get_mut(session_code) else {
                return Err(ProtocolError::internal(
                    "no device authorization is in flight for this session",
                ));
            };
            let now = Instant::now();
            if !session.schedule.due(now) {
                return Ok(None);
            }
            session.schedule.mark(now);
            (session.token_endpoint.clone(), session.parts.clone())
        };

        let form = device_token_form(&parts, session_code);

        let client = http_client().await?;
        let (status, body) = send(client.post(&token_endpoint).form(&form)).await?;

        match device_poll_step(status, &body) {
            Ok(DeviceStep::Pending) => Ok(None),
            Ok(DeviceStep::SlowDown) => {
                if let Some(PendingSession::Device(session)) =
                    self.sessions.lock().get_mut(session_code)
                {
                    session.schedule.slow_down();
                }
                Ok(None)
            }
            Ok(DeviceStep::Granted(tokens)) => {
                self.sessions.lock().remove(session_code);
                // RFC 8628 carries no nonce: there is no authorization request for one to
                // have travelled on. The device code itself is the binding.
                Ok(Some(authentication_token(tokens, None, &parts)?))
            }
            Err(e) => {
                self.sessions.lock().remove(session_code);
                Err(e)
            }
        }
    }

    /// Returns the authentication token as its own authorization token.
    ///
    /// There is nothing to exchange it with and nothing to mint: the server authorizes a
    /// verified token for every repository, from its own configuration. The call shape
    /// survives, which is the seam the per-repository follow-up works at.
    ///
    /// The token is whichever credential the deployment uses -- an ID token, or an
    /// RFC 9068 access token where a resource is advertised. Both carry `sub` and `exp`,
    /// which is all this reads.
    fn passthrough(
        &self,
        auth_url: &str,
        authn_token: &str,
    ) -> Result<AuthorizationToken, ProtocolError> {
        let parts = parse_auth_url(auth_url)?;
        let claims = id_token_claims(authn_token)?;

        Ok(AuthorizationToken {
            token: authn_token.to_string(),
            expires_ms: claims.exp.saturating_mul(1000),
            acceptable_root_domains: vec![parts.issuer_domain],
        })
    }
}

#[async_trait]
impl Authentication for OidcAuthentication {
    /// `client_state` is not used as the OAuth `state`: this implementation generates its
    /// own, so the binding between an authorization response and this session does not
    /// depend on how the caller chose its session identifier.
    async fn start_auth_session(
        &self,
        auth_url: &str,
        _client_state: &str,
        flow: LoginFlow,
        _correlation_id: &str,
    ) -> Result<AuthSession, ProtocolError> {
        let parts = parse_auth_url(auth_url)?;
        let discovery = self.discover(&parts).await?;

        match flow {
            LoginFlow::Browser => self.start_pkce(parts, discovery).await,
            LoginFlow::NoBrowser => self.start_device(parts, discovery).await,
        }
    }

    async fn poll_auth_session(
        &self,
        _auth_url: &str,
        _client_state: &str,
        session_code: &str,
        _correlation_id: &str,
    ) -> Result<Option<AuthenticationToken>, ProtocolError> {
        let is_pkce = matches!(
            self.sessions.lock().get(session_code),
            Some(PendingSession::Pkce(_))
        );
        if !is_pkce {
            return self.poll_device(session_code).await;
        }

        // The browser has not come back yet. The orchestration layer's polling loop reads
        // `None` as "keep waiting".
        let Some((session, target)) = self.take_pkce(session_code)? else {
            return Ok(None);
        };

        // The state is compared before the code is read, so a response belonging to another
        // session is refused rather than exchanged.
        let code = authorization_code(&callback_outcome(&target)?, &session.state)?;
        self.complete_pkce(session, &code).await.map(Some)
    }

    /// There is no external token to exchange: the provider issues the credential
    /// directly, and Lore mints nothing.
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

    /// The refresh grant (RFC 6749 §6). A rotated refresh token comes back on the returned
    /// token, and the credential store already treats refresh tokens as separately stored
    /// and rotated.
    async fn refresh_authentication(
        &self,
        auth_url: &str,
        refresh_token: &str,
        _correlation_id: &str,
    ) -> Result<AuthenticationToken, ProtocolError> {
        let parts = parse_auth_url(auth_url)?;
        let discovery = self.discover(&parts).await?;

        let form = refresh_form(&parts, refresh_token);

        let tokens = self
            .post_token_request(&discovery.token_endpoint, &form)
            .await?;
        // OpenID Connect Core §12.2 makes `nonce` optional on a refreshed ID token, and the
        // original request's nonce did not outlive the process that sent it.
        authentication_token(tokens, None, &parts)
    }

    async fn exchange_for_repository(
        &self,
        auth_url: &str,
        authn_token: &str,
        _repository: RepositoryId,
        _correlation_id: &str,
    ) -> Result<AuthorizationToken, ProtocolError> {
        self.passthrough(auth_url, authn_token)
    }

    async fn exchange_for_custom_resource(
        &self,
        auth_url: &str,
        authn_token: &str,
        _resource_id: &str,
        _correlation_id: &str,
    ) -> Result<AuthorizationToken, ProtocolError> {
        self.passthrough(auth_url, authn_token)
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
    use super::*;

    const DISCOVERY_JSON: &str = r#"{
        "issuer": "https://id.example.com",
        "authorization_endpoint": "https://id.example.com/authorize",
        "token_endpoint": "https://id.example.com/token",
        "device_authorization_endpoint": "https://id.example.com/device",
        "jwks_uri": "https://id.example.com/jwks.json"
    }"#;

    /// A JWT with the given claims and a signature nothing checks -- which is exactly the
    /// shape the client reads, since the server owns verification.
    fn unsigned_jwt(claims: &str) -> String {
        unsigned_jwt_typed("JWT", claims)
    }

    /// As [`unsigned_jwt`], with the `typ` header the resource-mode checks read.
    fn unsigned_jwt_typed(typ: &str, claims: &str) -> String {
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"RS256","typ":"{typ}"}}"#)),
            URL_SAFE_NO_PAD.encode(claims),
            URL_SAFE_NO_PAD.encode("not-a-signature"),
        )
    }

    fn parts() -> AuthUrlParts {
        AuthUrlParts {
            issuer: "https://id.example.com".to_string(),
            issuer_domain: "id.example.com".to_string(),
            client_id: "lore".to_string(),
            resource: None,
        }
    }

    fn discovery() -> Discovery {
        parse_discovery(DISCOVERY_JSON, "https://id.example.com").expect("discovery should parse")
    }

    /// RFC 7636 Appendix B's worked example. Getting the challenge derivation wrong is
    /// silent -- the provider simply refuses every exchange -- so it is pinned to the
    /// specification's own vector rather than to this code's output.
    #[test]
    fn code_challenge_matches_the_rfc_7636_test_vector() {
        assert_eq!(
            code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn code_verifier_satisfies_rfc_7636_section_4_1() {
        let verifier = code_verifier();
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
        assert_ne!(verifier, code_verifier(), "verifier is not random");
    }

    #[test]
    fn auth_url_parses_the_issuer_client_id_and_resource() {
        let parsed =
            parse_auth_url("oidc+https://id.example.com?client_id=lore&resource=lore.example.com")
                .expect("auth URL should parse");
        assert_eq!(
            parsed,
            AuthUrlParts {
                issuer: "https://id.example.com".to_string(),
                issuer_domain: "id.example.com".to_string(),
                client_id: "lore".to_string(),
                resource: Some("lore.example.com".to_string()),
            }
        );
    }

    /// Stripping `oidc+` has to leave the issuer alone, path and all, because every issuer
    /// check downstream is a byte comparison.
    #[test]
    fn auth_url_keeps_a_path_issuer_byte_for_byte() {
        let parsed = parse_auth_url("oidc+https://id.example.com/realms/studio?client_id=lore")
            .expect("auth URL should parse");
        assert_eq!(parsed.issuer, "https://id.example.com/realms/studio");
        assert_eq!(parsed.resource, None);
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

    /// Plain HTTP to anywhere but this machine would put the authorization code and the ID
    /// token on the wire in the clear.
    #[test]
    fn auth_url_rejects_oidc_http_for_a_non_loopback_host() {
        parse_auth_url("oidc+http://id.example.com?client_id=lore")
            .expect_err("oidc+http is loopback-only");
    }

    /// A token can always go back to the party that issued it -- the token and refresh
    /// endpoints are exactly that -- and nowhere else on this implementation's say-so. The
    /// remote's own host is added by the orchestration layer, the only layer that knows it.
    #[test]
    fn acceptable_root_domains_are_the_issuer_domain() {
        let parsed =
            parse_auth_url("oidc+https://id.example.com?client_id=lore").expect("should parse");
        assert_eq!(parsed.issuer_domain, "id.example.com");
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

    /// Without this check a redirect or a compromised well-known path could hand back
    /// another provider's endpoints, and the login would complete against the wrong party.
    #[test]
    fn discovery_rejects_an_issuer_mismatch() {
        parse_discovery(DISCOVERY_JSON, "https://id.example.invalid")
            .expect_err("a discovery document for another issuer must be refused");
    }

    /// Byte for byte, so a trailing slash is a mismatch rather than a normalization.
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
        assert_eq!(query.get("resource"), None);
    }

    /// Two deployments sharing an issuer and a client id share a credential-store bucket
    /// unless they advertise different `resource` values, so the parameter has to reach
    /// the provider.
    #[test]
    fn authorization_url_forwards_a_resource_indicator() {
        let mut parts = parts();
        parts.resource = Some("lore.example.com".to_string());
        let url = authorization_url(
            &discovery(),
            &parts,
            "http://127.0.0.1:49152/callback",
            "s",
            "n",
            "c",
        )
        .expect("authorization URL should build");
        let url = Url::parse(&url).expect("should be a URL");
        let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(
            query.get("resource").map(String::as_str),
            Some("lore.example.com")
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

    /// The state comparison happens first: a response carrying somebody else's state is
    /// not evidence about this session, whether it reports success or failure.
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
            id_token: unsigned_jwt(r#"{"sub":"user-1","exp":1000,"nonce":"another-nonce"}"#),
            refresh_token: None,
            ..Default::default()
        };
        authentication_token(tokens, Some("the-nonce"), &parts())
            .expect_err("a replayed token from another exchange must not be accepted");
    }

    #[test]
    fn id_token_without_a_nonce_is_refused_on_a_login() {
        let tokens = TokenResponse {
            id_token: unsigned_jwt(r#"{"sub":"user-1","exp":1000}"#),
            refresh_token: None,
            ..Default::default()
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
            id_token: id_token.clone(),
            refresh_token: Some("the-refresh-token".to_string()),
            ..Default::default()
        };
        let token = authentication_token(tokens, Some("the-nonce"), &parts())
            .expect("the token should be accepted");

        assert_eq!(token.token, id_token, "the ID token is the credential");
        assert_eq!(token.user_id, "user-1");
        assert_eq!(token.user_name, "Ada Lovelace");
        assert_eq!(token.expires_ms, 1_000_000);
        assert_eq!(token.refresh_token.as_deref(), Some("the-refresh-token"));
        assert_eq!(token.acceptable_root_domains, vec!["id.example.com"]);
    }

    /// `name` is an optional claim delivered with the `profile` scope, so a provider that
    /// omits it must not fail the login.
    #[test]
    fn display_name_falls_back_through_preferred_username_to_sub() {
        let tokens = TokenResponse {
            id_token: unsigned_jwt(r#"{"sub":"user-1","exp":1,"preferred_username":"ada"}"#),
            refresh_token: None,
            ..Default::default()
        };
        let token = authentication_token(tokens, None, &parts()).expect("should be accepted");
        assert_eq!(token.user_name, "ada");

        let tokens = TokenResponse {
            id_token: unsigned_jwt(r#"{"sub":"user-1","exp":1}"#),
            refresh_token: None,
            ..Default::default()
        };
        let token = authentication_token(tokens, None, &parts()).expect("should be accepted");
        assert_eq!(token.user_name, "user-1");
    }

    #[test]
    fn a_refreshed_id_token_need_not_carry_a_nonce() {
        let tokens = TokenResponse {
            id_token: unsigned_jwt(r#"{"sub":"user-1","exp":1000}"#),
            refresh_token: Some("rotated".to_string()),
            ..Default::default()
        };
        let token =
            authentication_token(tokens, None, &parts()).expect("refresh should be accepted");
        assert_eq!(token.user_id, "user-1");
    }

    /// A deployment that names itself gets the `resource` parameter on every grant
    /// request and presents the access token the provider audience-restricted to it.
    mod resource_mode {
        use super::*;

        const RESOURCE: &str = "https://lore.example.com";

        fn resource_parts() -> AuthUrlParts {
            AuthUrlParts {
                resource: Some(RESOURCE.to_string()),
                ..parts()
            }
        }

        fn access_token(aud: &str) -> String {
            unsigned_jwt_typed(
                "at+jwt",
                &format!(
                    r#"{{"sub":"user-1","exp":2000,"aud":"{aud}","client_id":"lore","iat":1,"jti":"j"}}"#
                ),
            )
        }

        fn tokens_for(access_token: Option<String>) -> TokenResponse {
            TokenResponse {
                id_token: unsigned_jwt(r#"{"sub":"user-1","exp":1000,"name":"Ada Lovelace"}"#),
                access_token,
                refresh_token: Some("the-refresh-token".to_string()),
            }
        }

        /// Also checked by `authorization_url_forwards_a_resource_indicator`.
        #[test]
        fn the_authorization_request_carries_the_resource() {
            let url = authorization_url(
                &discovery(),
                &resource_parts(),
                "http://127.0.0.1:49152/callback",
                "s",
                "n",
                "c",
            )
            .expect("builds");
            let url = Url::parse(&url).expect("a URL");
            let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
            assert_eq!(query.get("resource").map(String::as_str), Some(RESOURCE));
        }

        /// A PKCE session standing in for one `start_pkce` produced, so the
        /// authorization-code form can be built without a live provider.
        fn pkce_session(parts: AuthUrlParts) -> PkceSession {
            let (_sender, receiver) = oneshot::channel();
            PkceSession {
                parts,
                token_endpoint: "https://id.example.com/token".to_string(),
                verifier: "the-verifier".to_string(),
                state: "the-state".to_string(),
                nonce: "the-nonce".to_string(),
                redirect_uri: "http://127.0.0.1:49152/callback".to_string(),
                redirect: receiver,
            }
        }

        fn sent_resource(form: &GrantForm) -> Option<&str> {
            form.iter()
                .find(|(key, _)| *key == "resource")
                .map(|(_, value)| value.as_str())
        }

        /// Every form this module sends to a provider except the authorization request
        /// itself (a URL, checked above): the authorization-code exchange, the device
        /// authorization request, the device token poll, and the refresh grant.
        #[test]
        fn every_grant_form_carries_the_resource() {
            let parts = resource_parts();
            let forms = [
                authorization_code_form(&pkce_session(parts.clone()), "the-code"),
                device_authorization_form(&parts),
                device_token_form(&parts, "the-device-code"),
                refresh_form(&parts, "the-refresh-token"),
            ];

            for form in &forms {
                assert_eq!(
                    sent_resource(form),
                    Some(RESOURCE),
                    "a grant request without the resource gets a token this server \
                     refuses: {form:?}"
                );
            }
        }

        /// And none of them carries it when the deployment advertises none, which is what
        /// keeps this opt-in from touching an existing deployment's requests at all.
        #[test]
        fn no_grant_form_carries_a_resource_when_none_is_advertised() {
            let parts = parts();
            let forms = [
                authorization_code_form(&pkce_session(parts.clone()), "the-code"),
                device_authorization_form(&parts),
                device_token_form(&parts, "the-device-code"),
                refresh_form(&parts, "the-refresh-token"),
            ];

            for form in &forms {
                assert_eq!(sent_resource(form), None, "unchanged behavior: {form:?}");
            }
        }

        /// Each form still carries its own grant-specific parameters alongside the shared
        /// `resource` parameter.
        #[test]
        fn the_grant_forms_keep_their_own_parameters() {
            let parts = resource_parts();
            let code_form = authorization_code_form(&pkce_session(parts.clone()), "the-code");
            assert!(code_form.contains(&("grant_type", "authorization_code".to_string())));
            assert!(code_form.contains(&("code", "the-code".to_string())));
            assert!(code_form.contains(&("code_verifier", "the-verifier".to_string())));
            assert!(code_form.contains(&(
                "redirect_uri",
                "http://127.0.0.1:49152/callback".to_string()
            )));

            let device_form = device_token_form(&parts, "the-device-code");
            assert!(device_form.contains(&(
                "grant_type",
                "urn:ietf:params:oauth:grant-type:device_code".to_string()
            )));
            assert!(device_form.contains(&("device_code", "the-device-code".to_string())));

            assert!(
                refresh_form(&parts, "rt").contains(&("grant_type", "refresh_token".to_string()))
            );
            assert!(device_authorization_form(&parts).contains(&("scope", SCOPES.to_string())));
        }

        /// The switch this mode exists for: the credential stored and presented becomes
        /// the access token, and its expiry — not the ID token's — is what the credential
        /// store counts down.
        #[test]
        fn the_access_token_becomes_the_credential() {
            let access = access_token(RESOURCE);
            let token =
                authentication_token(tokens_for(Some(access.clone())), None, &resource_parts())
                    .expect("a resource-bound access token is accepted");

            assert_eq!(token.token, access, "the access token is the credential");
            assert_eq!(
                token.expires_ms, 2_000_000,
                "the credential's own expiry governs refresh, not the ID token's"
            );
            // The ID token is still the identity assertion.
            assert_eq!(token.user_id, "user-1");
            assert_eq!(token.user_name, "Ada Lovelace");
            assert_eq!(token.acceptable_root_domains, vec!["id.example.com"]);
        }

        /// And without a resource nothing moves: the ID token is still the credential.
        #[test]
        fn the_id_token_stays_the_credential_without_a_resource() {
            let tokens = tokens_for(Some(access_token(RESOURCE)));
            let id_token = tokens.id_token.clone();
            let token = authentication_token(tokens, None, &parts()).expect("unchanged behavior");

            assert_eq!(token.token, id_token);
            assert_eq!(token.expires_ms, 1_000_000);
        }

        /// The nonce is checked against the ID token even when the access token is what
        /// gets presented — the ID token is the only one that carries it.
        #[test]
        fn the_nonce_is_still_checked_against_the_id_token() {
            let tokens = TokenResponse {
                id_token: unsigned_jwt(r#"{"sub":"user-1","exp":1000,"nonce":"another"}"#),
                access_token: Some(access_token(RESOURCE)),
                refresh_token: None,
            };
            authentication_token(tokens, Some("the-nonce"), &resource_parts())
                .expect_err("a replayed identity assertion is refused whatever is presented");
        }

        /// PocketID 2.6.2's behavior: `resource` is accepted with a `200` on both the
        /// device authorization and token requests, silently ignored, and the access
        /// token comes back audienced to the client id with `typ: "JWT"`. Failing here
        /// names the cause; not failing here means a successful login followed by
        /// uniformly denied requests.
        #[test]
        fn a_provider_that_ignores_the_resource_parameter_is_named() {
            let ignored = unsigned_jwt_typed(
                "JWT",
                r#"{"sub":"user-1","exp":2000,"aud":["lore"],"jti":"j"}"#,
            );
            let error = authentication_token(tokens_for(Some(ignored)), None, &resource_parts())
                .expect_err("a client-audienced token is not what was asked for");

            assert!(
                error.to_string().contains("at+jwt"),
                "the message has to name what the provider did not do, got: {error}"
            );
        }

        /// A provider that implements RFC 9068 but not RFC 8707 gets its own message,
        /// because the fix is a different one.
        #[test]
        fn an_access_token_for_another_audience_is_refused() {
            let error = authentication_token(
                tokens_for(Some(access_token("https://lore.other.example.com"))),
                None,
                &resource_parts(),
            )
            .expect_err("an access token audienced elsewhere will not verify");

            assert!(
                error.to_string().contains("resource"),
                "the message has to name the resource parameter, got: {error}"
            );
        }

        #[test]
        fn a_missing_access_token_is_refused() {
            let error = authentication_token(tokens_for(None), None, &resource_parts())
                .expect_err("there is no credential to present");
            assert!(error.to_string().contains("RFC 8707"), "got: {error}");
        }

        #[test]
        fn an_opaque_access_token_is_refused() {
            let tokens = tokens_for(Some("an-opaque-string".to_string()));
            let error = authentication_token(tokens, None, &resource_parts())
                .expect_err("an opaque access token cannot be an RFC 9068 one");
            assert!(error.to_string().contains("not a JWT"), "got: {error}");
        }

        /// An array audience containing the resource is the encoding PocketID and others
        /// use, so it has to satisfy the check as readily as the bare string.
        #[test]
        fn an_array_audience_containing_the_resource_is_accepted() {
            let access = unsigned_jwt_typed(
                "at+jwt",
                &format!(r#"{{"sub":"u","exp":2000,"aud":["other","{RESOURCE}"]}}"#),
            );
            authentication_token(tokens_for(Some(access)), None, &resource_parts())
                .expect("membership, not equality");
        }

        /// Both spellings of the RFC 9068 media type, case-insensitively — the same rule
        /// the server applies, since the point of the client check is to predict the
        /// server's verdict rather than to invent a stricter one.
        #[test]
        fn both_spellings_of_the_media_type_are_accepted() {
            for typ in ["at+jwt", "application/at+jwt", "AT+JWT"] {
                let access = unsigned_jwt_typed(
                    typ,
                    &format!(r#"{{"sub":"u","exp":2000,"aud":"{RESOURCE}"}}"#),
                );
                authentication_token(tokens_for(Some(access)), None, &resource_parts())
                    .unwrap_or_else(|e| panic!("typ '{typ}' must be accepted: {e}"));
            }
        }
    }

    /// A provider with no device authorization endpoint gets an immediate, typed refusal
    /// naming the missing capability, not a poll loop waiting on a redirect that can never
    /// arrive.
    #[tokio::test]
    async fn no_browser_login_against_a_provider_without_the_device_grant_fails_cleanly() {
        let auth = OidcAuthentication::default();
        let discovery = parse_discovery(
            r#"{"issuer":"https://id.example.com",
                "authorization_endpoint":"https://id.example.com/authorize",
                "token_endpoint":"https://id.example.com/token"}"#,
            "https://id.example.com",
        )
        .expect("discovery should parse");
        assert_eq!(discovery.device_authorization_endpoint, None);

        let error = auth
            .start_device(parts(), discovery)
            .await
            .expect_err("there is no headless ceremony to run");

        assert!(
            error.is_not_supported(),
            "the CLI has to be able to tell this from a transport failure, got: {error}"
        );
        let message = error.to_string();
        assert!(
            message.contains("device_authorization_endpoint"),
            "the message must name the missing capability, got: {message}"
        );
        assert!(
            message.contains("browser"),
            "the message must say what to do instead, got: {message}"
        );
    }

    #[test]
    fn device_login_url_prefers_the_complete_verification_uri() {
        let authorization = DeviceAuthorization {
            device_code: "device".to_string(),
            user_code: "WDJB-MJHT".to_string(),
            verification_uri: "https://id.example.com/device".to_string(),
            verification_uri_complete: Some(
                "https://id.example.com/device?code=WDJB-MJHT".to_string(),
            ),
            interval: Some(5),
        };
        assert_eq!(
            device_login_url(&authorization),
            "https://id.example.com/device?code=WDJB-MJHT"
        );
    }

    #[test]
    fn device_login_url_falls_back_to_the_uri_and_user_code() {
        let authorization = DeviceAuthorization {
            device_code: "device".to_string(),
            user_code: "WDJB-MJHT".to_string(),
            verification_uri: "https://id.example.com/device".to_string(),
            verification_uri_complete: None,
            interval: None,
        };
        let url = device_login_url(&authorization);
        assert!(
            url.starts_with("https://id.example.com/device"),
            "fallback should stay on the verification URI, got {url}"
        );
        assert!(
            url.contains("WDJB-MJHT"),
            "fallback should carry the user code, got {url}"
        );
    }

    #[test]
    fn device_poll_maps_authorization_pending_to_pending() {
        assert_eq!(
            device_poll_step(
                StatusCode::BAD_REQUEST,
                r#"{"error":"authorization_pending"}"#
            )
            .expect("pending is not a failure"),
            DeviceStep::Pending
        );
    }

    #[test]
    fn device_poll_maps_slow_down_to_a_longer_interval() {
        assert_eq!(
            device_poll_step(StatusCode::BAD_REQUEST, r#"{"error":"slow_down"}"#)
                .expect("slow_down is not a failure"),
            DeviceStep::SlowDown
        );
    }

    #[test]
    fn device_poll_maps_access_denied_to_not_authorized() {
        let error = device_poll_step(StatusCode::BAD_REQUEST, r#"{"error":"access_denied"}"#)
            .expect_err("a refusal is terminal");
        assert!(error.is_not_authorized(), "got {error}");
    }

    #[test]
    fn device_poll_maps_expired_token_to_not_authenticated() {
        let error = device_poll_step(StatusCode::BAD_REQUEST, r#"{"error":"expired_token"}"#)
            .expect_err("an expired device code is terminal");
        assert!(error.is_not_authenticated(), "got {error}");
    }

    #[test]
    fn device_poll_reports_an_unknown_error() {
        device_poll_step(StatusCode::BAD_REQUEST, r#"{"error":"invalid_client"}"#)
            .expect_err("an unrecognized error must not be mistaken for pending");
    }

    #[test]
    fn device_poll_returns_the_tokens_once_approved() {
        let step = device_poll_step(
            StatusCode::OK,
            r#"{"id_token":"the-id-token","refresh_token":"the-refresh-token","token_type":"Bearer"}"#,
        )
        .expect("approval should parse");
        let DeviceStep::Granted(tokens) = step else {
            panic!("expected tokens, got {step:?}");
        };
        assert_eq!(tokens.id_token, "the-id-token");
        assert_eq!(tokens.refresh_token.as_deref(), Some("the-refresh-token"));
    }

    #[test]
    fn poll_schedule_honors_the_advertised_interval() {
        let start = Instant::now();
        let mut schedule = PollSchedule::new(Some(7));

        assert!(schedule.due(start), "the first poll is always due");
        schedule.mark(start);
        assert!(!schedule.due(start + Duration::from_secs(6)));
        assert!(schedule.due(start + Duration::from_secs(7)));
    }

    #[test]
    fn poll_schedule_defaults_the_interval_when_the_provider_omits_it() {
        let start = Instant::now();
        let mut schedule = PollSchedule::new(None);
        schedule.mark(start);
        assert!(!schedule.due(start + DEFAULT_DEVICE_INTERVAL - Duration::from_millis(1)));
        assert!(schedule.due(start + DEFAULT_DEVICE_INTERVAL));
    }

    #[test]
    fn poll_schedule_backs_off_on_slow_down() {
        let start = Instant::now();
        let mut schedule = PollSchedule::new(Some(5));
        schedule.mark(start);
        schedule.slow_down();

        assert!(
            !schedule.due(start + Duration::from_secs(9)),
            "slow_down must lengthen the interval"
        );
        assert!(schedule.due(start + Duration::from_secs(10)));
    }

    /// There is nothing to exchange the authentication token for and nothing to mint, so
    /// the same token comes back -- and it comes back naming the issuer as its recipient,
    /// which is what keeps the guard holding on the exchange path too.
    #[tokio::test]
    async fn exchange_for_repository_returns_the_authentication_token() {
        let auth = OidcAuthentication::default();
        let id_token = unsigned_jwt(r#"{"sub":"user-1","exp":1000}"#);

        let authz = auth
            .exchange_for_repository(
                "oidc+https://id.example.com?client_id=lore",
                &id_token,
                RepositoryId::default(),
                "",
            )
            .await
            .expect("the passthrough should succeed");

        assert_eq!(authz.token, id_token);
        assert_eq!(authz.expires_ms, 1_000_000);
        assert_eq!(authz.acceptable_root_domains, vec!["id.example.com"]);
    }

    #[tokio::test]
    async fn exchange_for_custom_resource_returns_the_authentication_token() {
        let auth = OidcAuthentication::default();
        let id_token = unsigned_jwt(r#"{"sub":"user-1","exp":1000}"#);

        let authz = auth
            .exchange_for_custom_resource(
                "oidc+https://id.example.com?client_id=lore",
                &id_token,
                "urc-something",
                "",
            )
            .await
            .expect("the passthrough should succeed");

        assert_eq!(authz.token, id_token);
    }

    #[tokio::test]
    async fn identity_resolution_and_token_exchange_report_not_supported() {
        let auth = OidcAuthentication::default();
        let auth_url = "oidc+https://id.example.com?client_id=lore";

        assert!(
            auth.exchange_external_token(auth_url, "token", "type", "")
                .await
                .expect_err("no external token exchange exists")
                .is_not_supported()
        );
        assert!(
            auth.get_user_info(auth_url, "token", RepositoryId::default(), &[], "")
                .await
                .expect_err("the provider owns identity resolution")
                .is_not_supported()
        );
        assert!(
            auth.get_user_id(auth_url, "token", RepositoryId::default(), "ada", "")
                .await
                .expect_err("the provider owns identity resolution")
                .is_not_supported()
        );
    }

    /// The scheme is the whole extension mechanism, so both spellings have to resolve.
    #[test]
    fn both_oidc_schemes_resolve_through_the_registry() {
        use crate::auth::authentication;

        authentication::find("oidc+https://id.example.com?client_id=lore")
            .expect("oidc+https should be registered");
        authentication::find("oidc+http://127.0.0.1:1411?client_id=lore")
            .expect("oidc+http should be registered");
    }

    /// An unknown session is not a login in progress. Polling one is a caller bug, and
    /// answering `None` would let it spin until the orchestration layer's timeout instead
    /// of saying so.
    #[tokio::test]
    async fn polling_an_unknown_session_is_an_error() {
        let auth = OidcAuthentication::default();
        auth.poll_auth_session(
            "oidc+https://id.example.com?client_id=lore",
            "client-state",
            "no-such-session",
            "",
        )
        .await
        .expect_err("there is no such login in flight");
    }
}

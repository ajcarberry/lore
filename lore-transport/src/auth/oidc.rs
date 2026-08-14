// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! `OpenID` Connect authentication for the `oidc+https` and `oidc+http` schemes.
//!
//! The provider is named by the auth URL the server advertises, such as
//! `oidc+https://id.example.com/realms/studio?client_id=lore`.
//! Stripping `oidc+` leaves the issuer identifier byte for byte, which every issuer check
//! downstream compares as bytes; an issuer identifier carries no query or fragment
//! (`OpenID` Connect Discovery 1.0 §2), so the parameters are safe to append.
//!
//! Three grants fit the [`Authentication`] start-and-poll shape: authorization code with
//! PKCE over a loopback redirect ([RFC 7636], [RFC 8252] §7.3), the device authorization
//! grant ([RFC 8628]) for [`LoginFlow::NoBrowser`], and the refresh grant.
//!
//! The server verifies token signatures. This module checks only what it alone can: that the
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

/// Where a provider publishes its metadata (`OpenID` Connect Discovery 1.0 §4).
const DISCOVERY_PATH: &str = "/.well-known/openid-configuration";

/// `offline_access` asks a conformant provider for a refresh token. `profile` and `email`
/// carry the optional display claims; the code falls back to `sub` without them.
const SCOPES: &str = "openid profile email offline_access";

/// Path the loopback listener answers on.
const CALLBACK_PATH: &str = "/callback";

/// Cap on a provider response body, so a broken or hostile endpoint cannot stream
/// unbounded bytes into memory.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Cap on the redirect request's start line.
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

    // Recovered textually rather than by re-serializing a parsed URL, so the issuer
    // survives byte for byte. It carries no query or fragment (Discovery §2), so everything
    // up to the first `?` or `#` is the issuer.
    let issuer_tail = rest.split(['?', '#']).next().unwrap_or(rest);
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
        // The same derivation the recipient guard applies to a remote URL, so both entries
        // in a token's acceptable set are directly comparable.
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
#[derive(Clone, Debug, Deserialize)]
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
/// The `issuer` member must equal the configured issuer byte for byte (Discovery §4.3), so a
/// redirect or a compromised well-known path cannot substitute another provider's endpoints.
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
/// A discovery document is remote input, and the authorization endpoint is handed to
/// `open::that`: unchecked, a `javascript:` or `file:` endpoint is a local-code-execution
/// primitive.
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

    Ok(())
}

/// A fresh code verifier, drawn from the unreserved set RFC 7636 §4.1 requires.
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

/// An unguessable value for `state`, generated here rather than taken from the caller.
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

/// A token endpoint success response. The ID token is the credential.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
struct TokenResponse {
    /// Optional on a refresh: `OpenID` Connect Core §12.2 does not oblige a provider to
    /// reissue an ID token for a refresh grant.
    #[serde(default)]
    id_token: Option<String>,
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

/// The ID token claims this client reads. Only `sub` and `exp` are required of it; `name`
/// and `preferred_username` arrive with the `profile` scope.
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
/// Verification is the server's job. This client reads only the `nonce` it compares, the
/// identity it displays, and the expiry the credential store keys on, out of a token it has
/// just received over TLS from a pinned discovery document's token endpoint.
fn decode_unverified<T: serde::de::DeserializeOwned>(
    token: &str,
) -> Result<T, jsonwebtoken::errors::Error> {
    let header = jsonwebtoken::decode_header(token)?;

    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.insecure_disable_signature_validation();
    validation.validate_aud = false;
    validation.validate_exp = false;
    validation.validate_nbf = false;
    // Nothing here is a security check, so a shape that omits a claim this client does not
    // read must not be rejected on `jsonwebtoken`'s default required set.
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

/// The device authorization request (RFC 8628 §3.1).
fn device_authorization_form(parts: &AuthUrlParts) -> GrantForm {
    vec![
        ("client_id", parts.client_id.clone()),
        ("scope", SCOPES.to_string()),
    ]
}

/// The authorization-code exchange (RFC 6749 §4.1.3, with RFC 7636 §4.5's verifier).
fn authorization_code_form(session: &PkceSession, code: &str) -> GrantForm {
    vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.to_string()),
        ("redirect_uri", session.redirect_uri.clone()),
        ("client_id", session.parts.client_id.clone()),
        ("code_verifier", session.verifier.clone()),
    ]
}

/// One poll of an approved device code (RFC 8628 §3.4).
fn device_token_form(parts: &AuthUrlParts, device_code: &str) -> GrantForm {
    vec![
        (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:device_code".to_string(),
        ),
        ("device_code", device_code.to_string()),
        ("client_id", parts.client_id.clone()),
    ]
}

/// The refresh grant (RFC 6749 §6).
fn refresh_form(parts: &AuthUrlParts, refresh_token: &str) -> GrantForm {
    vec![
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", refresh_token.to_string()),
        ("client_id", parts.client_id.clone()),
    ]
}

/// Turns a token response into an [`AuthenticationToken`].
///
/// `expected_nonce` is `Some` for a login and `None` for a refresh, where `OpenID` Connect
/// Core §12.2 makes the claim optional. The ID token is always the credential.
fn authentication_token(
    tokens: TokenResponse,
    expected_nonce: Option<&str>,
    parts: &AuthUrlParts,
) -> Result<AuthenticationToken, ProtocolError> {
    let (id_token, claims) = tokens
        .id_token
        .as_deref()
        .map(|token| id_token_claims(token).map(|claims| (token.to_string(), claims)))
        .transpose()?
        .ok_or_else(|| {
            ProtocolError::internal(
                "the token endpoint returned no id_token, so this deployment has no \
                 credential to present",
            )
        })?;

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
        token: id_token,
        user_id,
        user_name,
        // Claims count seconds since the epoch; every other Lore timestamp is milliseconds.
        expires_ms: expires.saturating_mul(1000),
        // The issuer already holds the token. The orchestration layer adds the remote the
        // login was performed against.
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
/// `verification_uri_complete` already carries the user code (RFC 8628 §3.3.1). Without it
/// the code is appended, so the user still gets one thing to open.
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
        // Not a URL. Handed over as it is, because the user can still read it.
        Err(_) => format!(
            "{} (user code: {})",
            authorization.verification_uri, authorization.user_code
        ),
    }
}

/// What one poll of the token endpoint established, during a device grant.
#[derive(Clone, Debug, PartialEq, Eq)]
enum DeviceStep {
    Pending,
    /// The provider asked for a longer interval (RFC 8628 §3.5).
    SlowDown,
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
/// RFC 8628 §3.5 makes honoring `interval` a client obligation. The caller's own polling
/// loop runs at a separate period, so this gate keeps the provider's number authoritative.
#[derive(Clone, Debug)]
struct PollSchedule {
    interval: Duration,
    last_poll: Option<Instant>,
}

impl PollSchedule {
    fn new(interval_secs: Option<u64>) -> Self {
        PollSchedule {
            interval: interval_secs.map_or(DEFAULT_DEVICE_INTERVAL, Duration::from_secs),
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
/// RFC 8252 §7.3 specifies loopback redirection for a native application: the kernel binds
/// the response to the process holding the port, so no client secret is needed.
async fn bind_loopback_redirect() -> Result<LoopbackRedirect, ProtocolError> {
    let (port_sender, port_receiver) = oneshot::channel();
    let (target_sender, target_receiver) = oneshot::channel();

    // Bound and accepted inside one net-runtime task: a tokio listener registers with the
    // reactor of the runtime that created it.
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
        .map_err(|e| {
            ProtocolError::internal(format!("loopback listener task ended before it bound: {e}"))
        })?
        .map_err(ProtocolError::internal)?;

    Ok(LoopbackRedirect {
        port,
        target: target_receiver,
    })
}

/// Accepts connections until one carries an authorization response, answering each with a
/// page the user sees in the browser.
async fn accept_authorization_response(listener: TcpListener) -> Result<String, String> {
    loop {
        let (mut stream, _) = listener
            .accept()
            .await
            .map_err(|e| format!("loopback listener failed: {e}"))?;

        let target = read_request_target(&mut stream).await?;
        // A browser also asks for a favicon, so only a request carrying an authorization
        // response ends the wait.
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

    // A write error is not a failure of the login: the code is already in hand.
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
/// Pooled so a login's several requests to the same provider share one TLS handshake.
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
/// Awaited inside `lore_spawn_net!` rather than merely built there: reqwest connects while
/// the request future is polled, so this is what binds the connection to the net runtime.
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
    /// RFC 8628 §3.4's credential for redeeming this login's tokens. It stays in here: the
    /// handle the caller polls with is a separate, opaque string.
    device_code: String,
    schedule: PollSchedule,
}

/// Authentication against a standard `OpenID` Connect provider.
///
/// Registered under `oidc+https`, and under `oidc+http` for a loopback provider. One
/// instance holds the state of every login in flight; all of it is process-local and dies
/// with the command.
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

        // Opaque to the caller: the flow's secrets never leave this process.
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
        // There is no fallback: the browser flow's redirect goes to a loopback listener on
        // this host, so an authorization URL for another device could never complete.
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
        // with the one the provider shows.
        lore_info!(
            "Enter code {} at {} to authorize this login",
            authorization.user_code,
            authorization.verification_uri
        );

        let login_url = device_login_url(&authorization);
        // Opaque, as in the PKCE flow: the handle travels out through a layer that logs it,
        // and the device code redeems this login's tokens on its own.
        let session_code = random_token();
        self.sessions.lock().insert(
            session_code.clone(),
            PendingSession::Device(DeviceSession {
                parts,
                token_endpoint: discovery.token_endpoint,
                device_code: authorization.device_code,
                schedule: PollSchedule::new(authorization.interval),
            }),
        );

        Ok(AuthSession {
            session_code,
            login_url,
        })
    }

    /// Takes the PKCE session's secrets out of the map, with the redirect the browser
    /// delivered. `None` while the browser has not come back.
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
        // The provider's interval is authoritative, so a poll that is not due yet does not
        // reach the network.
        let (token_endpoint, parts, device_code) = {
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
            (
                session.token_endpoint.clone(),
                session.parts.clone(),
                session.device_code.clone(),
            )
        };

        let form = device_token_form(&parts, &device_code);

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
                // RFC 8628 carries no nonce; the device code is the binding.
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
    /// verified token for every repository, from its own configuration. Both credential
    /// shapes carry `sub` and `exp`, which is all this reads.
    fn passthrough(auth_url: &str, authn_token: &str) -> Result<AuthorizationToken, ProtocolError> {
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
    /// own.
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

        let Some((session, target)) = self.take_pkce(session_code)? else {
            return Ok(None);
        };

        let code = authorization_code(&callback_outcome(&target)?, &session.state)?;
        self.complete_pkce(session, &code).await.map(Some)
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

    /// The refresh grant (RFC 6749 §6). A rotated refresh token comes back on the returned
    /// token.
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
        // OpenID Connect Core §12.2 makes `nonce` optional on a refreshed ID token.
        authentication_token(tokens, None, &parts)
    }

    async fn exchange_for_repository(
        &self,
        auth_url: &str,
        authn_token: &str,
        _repository: RepositoryId,
        _correlation_id: &str,
    ) -> Result<AuthorizationToken, ProtocolError> {
        Self::passthrough(auth_url, authn_token)
    }

    async fn exchange_for_custom_resource(
        &self,
        auth_url: &str,
        authn_token: &str,
        _resource_id: &str,
        _correlation_id: &str,
    ) -> Result<AuthorizationToken, ProtocolError> {
        Self::passthrough(auth_url, authn_token)
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

    /// A JWT with the given claims and a signature nothing checks.
    fn unsigned_jwt(claims: &str) -> String {
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#),
            URL_SAFE_NO_PAD.encode(claims),
            URL_SAFE_NO_PAD.encode("not-a-signature"),
        )
    }

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
        assert_eq!(token.acceptable_root_domains, vec!["id.example.com"]);
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

    /// Answers one HTTP request on a loopback port with a canned body.
    async fn one_shot_provider(body: impl Into<String>) -> String {
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncWriteExt;

        let body = body.into();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("a bound address").port();

        #[allow(clippy::disallowed_methods)]
        // Test-only throwaway listener; no runtime split to honor.
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("a request");

            // Drain the whole request before answering: a client still writing its body
            // into a closed socket sees a transport error rather than the response.
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let read = stream.read(&mut chunk).await.unwrap_or(0);
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                let text = String::from_utf8_lossy(&request);
                if let Some(headers_end) = text.find("\r\n\r\n") {
                    let length: usize = text
                        .to_ascii_lowercase()
                        .split("content-length:")
                        .nth(1)
                        .and_then(|rest| rest.split("\r\n").next())
                        .and_then(|value| value.trim().parse().ok())
                        .unwrap_or(0);
                    if request.len() >= headers_end + 4 + length {
                        break;
                    }
                }
            }

            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.flush().await;
        });

        format!("http://127.0.0.1:{port}/device")
    }

    /// RFC 8628's `device_code` is a bearer credential and the session handle is logged, so
    /// the two must not be the same string.
    #[tokio::test]
    async fn a_device_login_hands_back_a_handle_that_is_not_the_device_code() {
        let endpoint = one_shot_provider(
            r#"{"device_code":"the-device-code","user_code":"WDJB-MJHT",
                "verification_uri":"https://id.example.com/device","interval":5}"#,
        )
        .await;
        let auth = OidcAuthentication::default();
        let discovery = Discovery {
            issuer: "https://id.example.com".to_string(),
            authorization_endpoint: "https://id.example.com/authorize".to_string(),
            token_endpoint: "https://id.example.com/token".to_string(),
            device_authorization_endpoint: Some(endpoint),
        };

        let session = auth
            .start_device(parts(), discovery)
            .await
            .expect("the device authorization should start");

        assert_ne!(
            session.session_code, "the-device-code",
            "the device code is the session handle, and the handle gets logged"
        );
    }

    /// The nonce the session generated has to reach the check the exchange performs.
    /// Passing `None` there leaves every unit test of the check itself green while a
    /// login completes on an ID token minted for a different one.
    #[tokio::test]
    async fn completing_a_login_refuses_an_id_token_carrying_another_nonce() {
        let id_token = unsigned_jwt(r#"{"sub":"user-1","exp":1000,"nonce":"another-nonce"}"#);
        let token_endpoint = one_shot_provider(format!(r#"{{"id_token":"{id_token}"}}"#)).await;

        let (_sender, receiver) = oneshot::channel();
        let session = PkceSession {
            parts: parts(),
            token_endpoint,
            verifier: "the-verifier".to_string(),
            state: "the-state".to_string(),
            nonce: "the-nonce".to_string(),
            redirect_uri: "http://127.0.0.1:49152/callback".to_string(),
            redirect: receiver,
        };

        let error = OidcAuthentication::default()
            .complete_pkce(session, "the-code")
            .await
            .expect_err("this ID token answers some other login");

        assert!(
            error.to_string().contains("nonce"),
            "the refusal has to be the nonce check, got: {error}"
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
    fn device_poll_maps_slow_down_to_the_back_off_step() {
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
        assert_eq!(tokens.id_token.as_deref(), Some("the-id-token"));
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

    #[test]
    fn both_oidc_schemes_resolve_through_the_registry() {
        use crate::auth::authentication;

        authentication::find("oidc+https://id.example.com?client_id=lore")
            .expect("oidc+https should be registered");
        authentication::find("oidc+http://127.0.0.1:1411?client_id=lore")
            .expect("oidc+http should be registered");
    }

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

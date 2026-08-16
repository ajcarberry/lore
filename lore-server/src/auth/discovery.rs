// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! `OpenID` Connect Discovery §4: fetching a provider's
//! `.well-known/openid-configuration` document so `[server.auth.oidc]` needs
//! only an issuer and a client id.
//!
//! The server reads two members: `issuer`, checked against the configured
//! issuer, and `jwks_uri`, which becomes the `JWKService` endpoint —
//! resolved through [`DiscoveringJwkService`] on first use, so a provider
//! that is down when the server starts delays verification instead of
//! preventing startup.
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use std::time::Instant;

use async_trait::async_trait;
use jsonwebtoken::DecodingKey;
use serde::Deserialize;
use thiserror::Error;
use tracing::warn;

use crate::auth::jwk::JWKService;
use crate::auth::jwk::JWKServiceError;
use crate::auth::jwk::JWKServiceSettings;
use crate::auth::jwk::JwkServiceImpl;
use crate::auth::jwk::body_excerpt;
use crate::auth::jwk::http_client;
use crate::auth::jwk::read_capped_body;

/// The two members of a discovery document this server reads.
#[derive(Debug, Deserialize, PartialEq)]
pub(crate) struct DiscoveryDocument {
    pub issuer: String,
    pub jwks_uri: String,
}

#[derive(Debug, Error)]
pub(crate) enum DiscoveryError {
    #[error("failed to reach the discovery endpoint")]
    FetchFailed,
    #[error("discovery endpoint returned status {0}")]
    HttpStatus(u16),
    #[error("discovery document is larger than this server will read")]
    ResponseTooLarge,
    #[error("could not parse the discovery document")]
    ParseFailed(#[from] serde_json::Error),
    #[error(
        "discovery document issuer {actual:?} does not match the configured issuer {expected:?}"
    )]
    IssuerMismatch { expected: String, actual: String },
    #[error("discovery document jwks_uri {0:?} must be https, or http to a loopback host")]
    JwksUriRefused(String),
}

/// Whether a `jwks_uri` may be fetched: https, or http only to a loopback host.
/// The document is remote input, and the keys it points at are the trust root,
/// so a hostile document must not be able to route the key fetch to a plaintext
/// endpoint or a non-HTTP scheme (the JWKS fetcher honors `file://` for the
/// operator's explicit escape hatch, which a provider must not reach).
fn jwks_uri_permitted(jwks_uri: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(jwks_uri) else {
        return false;
    };
    match url.scheme() {
        "https" => true,
        "http" => url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        }),
        _ => false,
    }
}

/// The discovery document URL for an issuer (Discovery §4). The `.well-known`
/// suffix joins the issuer with no normalization beyond avoiding a doubled slash.
fn discovery_url(issuer: &str) -> String {
    format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    )
}

/// The discovery counterpart of a failure from the shared JWKS fetch helpers, so
/// an oversized document is still reported as one.
fn discovery_fetch_error(error: JWKServiceError) -> DiscoveryError {
    match error {
        JWKServiceError::ResponseTooLarge => DiscoveryError::ResponseTooLarge,
        _ => DiscoveryError::FetchFailed,
    }
}

/// Fetch and validate the discovery document for `issuer`.
///
/// The document's own `issuer` member must equal the configured issuer byte for
/// byte (Discovery §4.3), which refuses a *different provider's* genuine
/// document. A forged response echoes the configured issuer, so the pin is
/// paired with two checks on what a forger could smuggle: the shared client
/// follows no redirects, and the returned `jwks_uri` is held to
/// https-or-loopback before it becomes the key endpoint.
pub(crate) async fn fetch_discovery_document(
    issuer: &str,
) -> Result<DiscoveryDocument, DiscoveryError> {
    let url = discovery_url(issuer);
    let client = http_client().map_err(discovery_fetch_error)?;

    let mut response = client.get(&url).send().await.map_err(|e| {
        warn!("failed to fetch OIDC discovery endpoint {url}: {e:?}");
        DiscoveryError::FetchFailed
    })?;

    let status = response.status();
    let body = read_capped_body(&mut response)
        .await
        .map_err(discovery_fetch_error)?;

    if !status.is_success() {
        warn!(
            status = %status.as_u16(),
            "OIDC discovery endpoint {url} returned an error, response: {}",
            body_excerpt(&body)
        );
        return Err(DiscoveryError::HttpStatus(status.as_u16()));
    }

    let document: DiscoveryDocument = serde_json::from_str(&body).inspect_err(|e| {
        warn!(
            "could not parse the discovery document from {url}: {e}, response: {}",
            body_excerpt(&body)
        );
    })?;

    if document.issuer != issuer {
        return Err(DiscoveryError::IssuerMismatch {
            expected: issuer.to_string(),
            actual: document.issuer,
        });
    }

    if !jwks_uri_permitted(&document.jwks_uri) {
        return Err(DiscoveryError::JwksUriRefused(document.jwks_uri));
    }

    Ok(document)
}

/// Shortest interval between discovery attempts after a failure. Verification
/// requests arrive from unauthenticated callers, so a down provider must not
/// turn every bad token into an outbound discovery fetch.
const DISCOVERY_RETRY_INTERVAL: Duration = Duration::from_secs(10);

/// A `JWKService` that resolves the provider's `jwks_uri` through discovery on
/// first use rather than at construction.
///
/// The server's availability must not be coupled to the provider's at start-up
/// — a self-hosted deployment restarting Lore and its provider together is a
/// boot-order deadlock otherwise. Until discovery succeeds, every lookup fails
/// and verification therefore fails closed; once it succeeds, the resolved
/// service is permanent and this wrapper is a pointer indirection.
pub(crate) struct DiscoveringJwkService {
    issuer: String,
    resolved: OnceLock<Arc<JwkServiceImpl>>,
    /// Serializes resolution attempts and records when the last one failed.
    attempt: tokio::sync::Mutex<Option<Instant>>,
    retry_interval: Duration,
}

impl DiscoveringJwkService {
    pub(crate) fn new(issuer: String) -> Self {
        Self {
            issuer,
            resolved: OnceLock::new(),
            attempt: tokio::sync::Mutex::new(None),
            retry_interval: DISCOVERY_RETRY_INTERVAL,
        }
    }

    /// The resolved key service, running discovery if no attempt has succeeded
    /// yet. Failed attempts are throttled to [`DISCOVERY_RETRY_INTERVAL`].
    async fn resolve(&self) -> Result<Arc<JwkServiceImpl>, JWKServiceError> {
        if let Some(inner) = self.resolved.get() {
            return Ok(inner.clone());
        }

        let mut attempt = self.attempt.lock().await;
        // A concurrent caller may have resolved while this one waited.
        if let Some(inner) = self.resolved.get() {
            return Ok(inner.clone());
        }
        if let Some(last_failure) = *attempt
            && last_failure.elapsed() < self.retry_interval
        {
            return Err(JWKServiceError::InternalError);
        }

        match fetch_discovery_document(&self.issuer).await {
            Ok(document) => {
                let service = Arc::new(JwkServiceImpl::new(JWKServiceSettings {
                    endpoint: document.jwks_uri,
                }));
                *attempt = None;
                Ok(self.resolved.get_or_init(|| service).clone())
            }
            Err(error) => {
                warn!(
                    "OIDC discovery for {} has not succeeded yet; token verification fails \
                     until the provider is reachable: {error}",
                    self.issuer
                );
                *attempt = Some(Instant::now());
                Err(JWKServiceError::InternalError)
            }
        }
    }

    /// Startup warm-up: resolve discovery and prefetch the key set. Failure is
    /// the caller's to log — the server starts either way.
    pub(crate) async fn warm(&self) -> Result<(), JWKServiceError> {
        self.resolve().await?.fetch_new_keys(None).await
    }
}

#[async_trait]
impl JWKService for DiscoveringJwkService {
    async fn get_key(
        &self,
        kid: &str,
    ) -> Result<(DecodingKey, jsonwebtoken::Algorithm), JWKServiceError> {
        self.resolve().await?.get_key(kid).await
    }

    fn get_cached_key(&self, kid: &str) -> Option<(DecodingKey, jsonwebtoken::Algorithm)> {
        self.resolved.get()?.get_cached_key(kid)
    }

    async fn refresh_key(
        &self,
        kid: &str,
    ) -> Result<Option<(DecodingKey, jsonwebtoken::Algorithm)>, JWKServiceError> {
        self.resolve().await?.refresh_key(kid).await
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use axum::Json;
    use axum::Router;
    use axum::extract::State;
    use axum::routing::get;
    use serde_json::json;
    use tokio::net::TcpListener;

    use super::*;
    use crate::auth::jwk::PROVIDER_MAX_RESPONSE_BYTES;

    #[test]
    fn discovery_url_trims_a_trailing_slash_on_the_issuer() {
        assert_eq!(
            discovery_url("https://id.example.com/"),
            "https://id.example.com/.well-known/openid-configuration"
        );
    }

    #[test]
    fn discovery_url_preserves_an_issuer_path() {
        assert_eq!(
            discovery_url("https://id.example.com/realms/studio"),
            "https://id.example.com/realms/studio/.well-known/openid-configuration"
        );
    }

    async fn discovery_handler(State(body): State<serde_json::Value>) -> Json<serde_json::Value> {
        Json(body)
    }

    /// Binds the listener first, so `make_body` can bake in the address the test
    /// server will answer on.
    async fn spawn_discovery_server(
        make_body: impl FnOnce(&str) -> serde_json::Value,
    ) -> (SocketAddr, String) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test discovery server");
        let address = listener
            .local_addr()
            .expect("test discovery server address");
        let issuer = format!("http://{address}");
        let body = make_body(&issuer);

        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery_handler))
            .with_state(body);

        lore_base::lore_spawn!(async move {
            axum::serve(listener, app)
                .await
                .expect("serve test discovery server");
        });

        (address, issuer)
    }

    #[tokio::test]
    async fn fetches_and_returns_jwks_uri_when_issuer_matches() {
        let (_address, issuer) = spawn_discovery_server(
            |issuer| json!({ "issuer": issuer, "jwks_uri": "https://issuer.invalid/jwks.json" }),
        )
        .await;

        let document = fetch_discovery_document(&issuer)
            .await
            .expect("discovery succeeds");

        assert_eq!(document.jwks_uri, "https://issuer.invalid/jwks.json");
    }

    #[tokio::test]
    async fn a_loopback_http_jwks_uri_is_accepted() {
        let (_address, issuer) = spawn_discovery_server(
            |issuer| json!({ "issuer": issuer, "jwks_uri": "http://127.0.0.1:9/jwks.json" }),
        )
        .await;

        let document = fetch_discovery_document(&issuer)
            .await
            .expect("a loopback http jwks_uri is a dev fixture, not a downgrade");

        assert_eq!(document.jwks_uri, "http://127.0.0.1:9/jwks.json");
    }

    #[tokio::test]
    async fn a_file_scheme_jwks_uri_is_refused() {
        let (_address, issuer) = spawn_discovery_server(
            |issuer| json!({ "issuer": issuer, "jwks_uri": "file:///etc/passwd" }),
        )
        .await;

        let error = fetch_discovery_document(&issuer)
            .await
            .expect_err("a document must not route the key fetch to a local file");

        assert!(
            matches!(error, DiscoveryError::JwksUriRefused(_)),
            "{error:?}"
        );
    }

    /// A discovery + JWKS provider in one app: `jwks_uri` points back at the
    /// same listener, serving one Ed25519 signing key (RFC 8037's test vector).
    async fn spawn_provider() -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test provider");
        let address = listener.local_addr().expect("test provider address");
        let issuer = format!("http://{address}");

        let discovery = json!({
            "issuer": issuer.clone(),
            "jwks_uri": format!("{issuer}/jwks"),
        });
        let jwks = json!({
            "keys": [{
                "kty": "OKP", "crv": "Ed25519", "use": "sig", "kid": "k1",
                "alg": "EdDSA",
                "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            }]
        });

        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery_handler))
            .with_state(discovery)
            .route("/jwks", get(discovery_handler).with_state(jwks));

        lore_base::lore_spawn!(async move {
            axum::serve(listener, app)
                .await
                .expect("serve test provider");
        });

        issuer
    }

    /// The startup path may fail; verification then resolves discovery on
    /// first use, with no warm-up having happened.
    #[tokio::test]
    async fn discovery_resolves_on_first_use() {
        let issuer = spawn_provider().await;
        let service = DiscoveringJwkService::new(issuer);

        let (_key, algorithm) = service
            .get_key("k1")
            .await
            .expect("the key resolves through on-demand discovery");
        assert_eq!(algorithm, jsonwebtoken::Algorithm::EdDSA);
        assert!(
            service.get_cached_key("k1").is_some(),
            "once resolved, the cache serves the synchronous path"
        );
    }

    /// Failed discovery is throttled: unauthenticated callers can present
    /// arbitrary tokens, and each must not become an outbound discovery fetch.
    #[tokio::test]
    async fn failed_discovery_is_throttled() {
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counting = requests.clone();

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind failing provider");
        let address = listener.local_addr().expect("failing provider address");
        let app = Router::new().route(
            "/.well-known/openid-configuration",
            get(move || {
                let counting = counting.clone();
                async move {
                    counting.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    (axum::http::StatusCode::SERVICE_UNAVAILABLE, "down")
                }
            }),
        );
        lore_base::lore_spawn!(async move {
            axum::serve(listener, app)
                .await
                .expect("serve failing provider");
        });

        let service = DiscoveringJwkService::new(format!("http://{address}"));
        assert!(
            service.get_key("k1").await.is_err(),
            "a down provider cannot serve keys"
        );
        assert!(
            service.get_key("k1").await.is_err(),
            "still failing, and throttled"
        );

        assert_eq!(
            requests.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the second failure within the retry interval must not fetch"
        );
    }

    #[tokio::test]
    async fn a_plaintext_non_loopback_jwks_uri_is_refused() {
        let (_address, issuer) = spawn_discovery_server(
            |issuer| json!({ "issuer": issuer, "jwks_uri": "http://issuer.invalid/jwks.json" }),
        )
        .await;

        let error = fetch_discovery_document(&issuer)
            .await
            .expect_err("keys must not be fetched over plaintext off the host");

        assert!(
            matches!(error, DiscoveryError::JwksUriRefused(_)),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn issuer_mismatch_is_rejected() {
        let (_address, issuer) = spawn_discovery_server(|_issuer| {
            json!({
                "issuer": "http://not-the-configured-issuer.invalid",
                "jwks_uri": "http://issuer.invalid/jwks.json",
            })
        })
        .await;

        let error = fetch_discovery_document(&issuer)
            .await
            .expect_err("a mismatched issuer must be rejected");

        assert!(
            matches!(error, DiscoveryError::IssuerMismatch { .. }),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn missing_jwks_uri_is_rejected() {
        let (_address, issuer) = spawn_discovery_server(|issuer| json!({ "issuer": issuer })).await;

        let error = fetch_discovery_document(&issuer)
            .await
            .expect_err("a document with no jwks_uri must be rejected");

        assert!(matches!(error, DiscoveryError::ParseFailed(_)), "{error:?}");
    }

    #[tokio::test]
    async fn a_document_declaring_more_than_the_cap_is_refused() {
        let (_address, issuer) = spawn_discovery_server(|issuer| {
            json!({
                "issuer": issuer,
                "jwks_uri": "http://issuer.invalid/jwks.json",
                "padding": "x".repeat(PROVIDER_MAX_RESPONSE_BYTES),
            })
        })
        .await;

        let error = fetch_discovery_document(&issuer)
            .await
            .expect_err("an oversized document must be refused");

        assert!(
            matches!(error, DiscoveryError::ResponseTooLarge),
            "{error:?}"
        );
    }
}

// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! `OpenID` Connect Discovery §4: fetching a provider's
//! `.well-known/openid-configuration` document at server start-up so
//! `[server.auth.oidc]` needs only an issuer and a client id.
//!
//! The server reads two members: `issuer`, checked against the configured
//! issuer, and `jwks_uri`, which becomes the `JWKService` endpoint.
use serde::Deserialize;
use thiserror::Error;
use tracing::warn;

use crate::auth::jwk::JWKServiceError;
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
/// byte (Discovery §4.3), so a redirect or a compromised well-known path cannot
/// point the server at somebody else's key set.
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

    let document: DiscoveryDocument = serde_json::from_str(&body)?;

    if document.issuer != issuer {
        return Err(DiscoveryError::IssuerMismatch {
            expected: issuer.to_string(),
            actual: document.issuer,
        });
    }

    Ok(document)
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
            |issuer| json!({ "issuer": issuer, "jwks_uri": "http://issuer.invalid/jwks.json" }),
        )
        .await;

        let document = fetch_discovery_document(&issuer)
            .await
            .expect("discovery succeeds");

        assert_eq!(document.jwks_uri, "http://issuer.invalid/jwks.json");
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

// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! OIDC-secured server mode against a real `PocketID` instance: a `JwtVerifier` built
//! from the provider's discovery document, wired into an in-process gRPC or HTTP server.

#[cfg(all(test, feature = "oidc_integration_tests"))]
mod oidc_auth_common {
    use std::error::Error;
    use std::sync::Arc;

    use lore_base::runtime::LORE_CONTEXT;
    use lore_server::auth::jwk::JWKService;
    use lore_server::auth::jwk::JWKServiceSettings;
    use lore_server::auth::jwk::JwkServiceImpl;
    use lore_server::auth::jwt::JwtVerifier;
    use lore_storage::local::immutable_store::ImmutableStoreCreateOptions;
    use lore_storage::local::immutable_store::ImmutableStoreSettings;

    use crate::common::oidc as oidc_common;
    use crate::setup_execution;

    pub type TestResult = Result<(), Box<dyn Error>>;

    pub async fn make_backends(
        immutable_settings: ImmutableStoreSettings,
    ) -> (
        Arc<dyn lore_storage::ImmutableStore>,
        Arc<dyn lore_storage::MutableStore>,
    ) {
        let execution = setup_execution("test".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let backend_immutable = lore_storage::local::immutable_store::create(
                    None::<&str>,
                    ImmutableStoreCreateOptions::none(),
                    false,
                    immutable_settings,
                )
                .await
                .unwrap();

                let backend_mutable: Arc<dyn lore_storage::MutableStore> =
                    lore_storage::local::mutable_store::create(
                        None::<&str>,
                        lore_storage::MutableStoreSettings::default(),
                        backend_immutable.clone(),
                    )
                    .await
                    .unwrap();

                (backend_immutable, backend_mutable)
            })
            .await
    }

    /// A `JwtVerifier` pointed at `PocketID`'s real JWKS, discovered rather than hardcoded.
    pub async fn oidc_jwt_verifier(
        fixture: &oidc_common::OidcFixture,
        audience: &str,
    ) -> Result<JwtVerifier, Box<dyn Error>> {
        let issuer = fixture.issuer().to_string();
        oidc_jwt_verifier_expecting_issuer(fixture, audience, &issuer).await
    }

    /// Same, but pinned to `issuer` rather than the fixture's — how the issuer
    /// check is exercised against a token whose signature and audience pass.
    pub async fn oidc_jwt_verifier_expecting_issuer(
        fixture: &oidc_common::OidcFixture,
        audience: &str,
        issuer: &str,
    ) -> Result<JwtVerifier, Box<dyn Error>> {
        let discovery = fixture.discovery().await?;
        let jwks_uri = discovery["jwks_uri"]
            .as_str()
            .ok_or("PocketID discovery document has no jwks_uri")?
            .to_string();

        let jwk_service: Arc<dyn JWKService> = Arc::new(JwkServiceImpl::new(JWKServiceSettings {
            endpoint: jwks_uri,
        }));

        // The symmetric-algorithm refusal lives inside the verifier itself, so
        // this bare `JwkServiceImpl` carries the same gates production's
        // `build_jwt_verifier` path does.
        Ok(JwtVerifier::oidc(
            jwk_service,
            issuer.to_string(),
            vec![audience.to_string()],
        ))
    }

    /// A locally-signed forgery naming a kid `PocketID` never issued. Verification dies
    /// at key lookup, so the claims are irrelevant — only the unknown kid matters.
    pub fn forged_token_with_unknown_kid() -> String {
        use jsonwebtoken::Algorithm;
        use jsonwebtoken::EncodingKey;
        use jsonwebtoken::Header;
        use jsonwebtoken::encode;

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("attacker-controlled-kid-not-in-pocketid-jwks".to_string());
        let claims = serde_json::json!({ "sub": "attacker" });
        encode(
            &header,
            &claims,
            &EncodingKey::from_secret(b"attacker-controlled-secret"),
        )
        .expect("encode forged token")
    }

    /// The same token with one bit of its signature changed: real kid, real issuer,
    /// real claims, wrong signature. The one shape only the signature check refuses.
    pub fn tamper_signature(token: &str) -> String {
        let (head, signature) = token.rsplit_once('.').expect("a JWT has three parts");
        let mut bytes: Vec<u8> = signature.bytes().collect();
        // A middle character, so the change lands in real signature bits rather
        // than the base64 tail's padding bits, which decoders may ignore.
        let middle = bytes.len() / 2;
        bytes[middle] = if bytes[middle] == b'A' { b'B' } else { b'A' };
        format!(
            "{head}.{}",
            String::from_utf8(bytes).expect("still base64url")
        )
    }
}

#[cfg(all(test, feature = "oidc_integration_tests"))]
mod oidc_auth_tests {
    use std::time::Duration;

    use lore_server::auth::jwt::JwtVerifier;
    use lore_server::http::server::LoreHttpServerSettings;
    use lore_server::http::server::ServerHealth;
    use lore_server::http::server::ServerState;
    use lore_server::http::server::create_router;
    use lore_storage::local::immutable_store::ImmutableStoreSettings;

    use super::oidc_auth_common::TestResult;
    use super::oidc_auth_common::forged_token_with_unknown_kid;
    use super::oidc_auth_common::make_backends;
    use super::oidc_auth_common::oidc_jwt_verifier;
    use crate::common::oidc as oidc_common;

    /// Start a real HTTP server, in process, over fresh in-memory backends.
    async fn start_http_server(
        jwt_verifier: Option<JwtVerifier>,
    ) -> (String, tokio::sync::oneshot::Sender<()>) {
        let (immutable_store, mutable_store) = make_backends(ImmutableStoreSettings {
            implicit_durable_stored: true,
            ..Default::default()
        })
        .await;
        let state = ServerState {
            immutable_store,
            mutable_store,
            jwt_verifier,
            max_file_size: 10 * 1024 * 1024,
            presign_config: None,
        };
        let health = ServerHealth::new_without_availability(state.immutable_store.clone());
        // `test_default` is `#[cfg(test)]` inside `lore-server` and not visible here.
        let settings = LoreHttpServerSettings {
            request_timeout_seconds: 30,
            request_body_timeout_seconds: 30,
            ..Default::default()
        };
        let app = create_router(state, health, &settings);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://127.0.0.1:{}", addr.port());

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let (stopped_tx, mut stopped_rx) = tokio::sync::oneshot::channel::<String>();
        // Background server task in a test; LORE_CONTEXT propagation is unnecessary here.
        #[allow(clippy::disallowed_methods)]
        tokio::spawn(async move {
            let outcome = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    shutdown_rx.await.ok();
                })
                .await;
            let _ = stopped_tx.send(match outcome {
                Ok(()) => "stopped before the test finished".to_string(),
                Err(error) => format!("failed: {error}"),
            });
        });

        let mut ready = false;
        for _ in 0..50 {
            if let Ok(reason) = stopped_rx.try_recv() {
                panic!("test server on {addr} {reason}");
            }
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(ready, "test server on {addr} never accepted a connection");

        (base_url, shutdown_tx)
    }

    /// The authenticated route with the fewest preconditions: the repository id only
    /// needs valid hex, since auth runs before the handler parses it.
    fn put_content_url(base_url: &str) -> String {
        let repository_id = lore_base::types::Context::from([0xacu8; 16]);
        format!("{base_url}/v1/repository/{repository_id}/content")
    }

    #[tokio::test]
    async fn http_anonymous_request_is_rejected() -> TestResult {
        let fixture = oidc_common::setup().await?;
        let verifier = oidc_jwt_verifier(&fixture, oidc_common::TEST_CLIENT_ID).await?;
        let (base_url, _shutdown) = start_http_server(Some(verifier)).await;

        let response = reqwest::Client::new()
            .put(put_content_url(&base_url))
            .body("no bearer token at all")
            .send()
            .await?;

        assert_eq!(
            response.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "a request with no bearer token at all must be refused as unauthenticated"
        );
        Ok(())
    }

    #[tokio::test]
    async fn http_token_signed_by_unknown_key_is_rejected() -> TestResult {
        let fixture = oidc_common::setup().await?;
        let verifier = oidc_jwt_verifier(&fixture, oidc_common::TEST_CLIENT_ID).await?;
        let (base_url, _shutdown) = start_http_server(Some(verifier)).await;

        let forged = forged_token_with_unknown_kid();
        let response = reqwest::Client::new()
            .put(put_content_url(&base_url))
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {forged}"))
            .body("unknown signing key")
            .send()
            .await?;

        assert_eq!(
            response.status(),
            reqwest::StatusCode::FORBIDDEN,
            "a token naming a key PocketID never issued must be refused"
        );
        Ok(())
    }

    /// The one shape only the signature check refuses: a genuine `PocketID` token —
    /// real kid, real issuer, real audience, unexpired — with one changed
    /// signature bit. Every other rejection test dies earlier (key lookup,
    /// audience, issuer), so without this nothing proves the signature is
    /// actually verified.
    #[tokio::test]
    async fn http_tampered_signature_token_is_rejected() -> TestResult {
        let fixture = oidc_common::setup().await?;
        let verifier = oidc_jwt_verifier(&fixture, oidc_common::TEST_CLIENT_ID).await?;
        let (base_url, _shutdown) = start_http_server(Some(verifier)).await;

        let user = fixture.create_user("httptampered").await?;
        let tokens = fixture.issue_token(&user).await?;
        let tampered = super::oidc_auth_common::tamper_signature(&tokens.id_token);

        let response = reqwest::Client::new()
            .put(put_content_url(&base_url))
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {tampered}"))
            .body("tampered signature")
            .send()
            .await?;

        assert_eq!(
            response.status(),
            reqwest::StatusCode::FORBIDDEN,
            "a genuine token with a tampered signature must be refused"
        );
        Ok(())
    }

    /// A real, correctly-signed token against a verifier pinned to a different
    /// issuer: the `iss` check itself, which no other rejection test reaches.
    #[tokio::test]
    async fn http_issuer_mismatch_token_is_rejected() -> TestResult {
        let fixture = oidc_common::setup().await?;
        let verifier = super::oidc_auth_common::oidc_jwt_verifier_expecting_issuer(
            &fixture,
            oidc_common::TEST_CLIENT_ID,
            "https://a-different-issuer.example.invalid",
        )
        .await?;
        let (base_url, _shutdown) = start_http_server(Some(verifier)).await;

        let user = fixture.create_user("httpissuermismatch").await?;
        let tokens = fixture.issue_token(&user).await?;

        let response = reqwest::Client::new()
            .put(put_content_url(&base_url))
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", tokens.id_token),
            )
            .body("issuer mismatch")
            .send()
            .await?;

        assert_eq!(
            response.status(),
            reqwest::StatusCode::FORBIDDEN,
            "a token from an issuer other than the pinned one must be refused"
        );
        Ok(())
    }

    #[tokio::test]
    async fn http_wrong_audience_token_is_rejected() -> TestResult {
        let fixture = oidc_common::setup().await?;
        let verifier = oidc_jwt_verifier(&fixture, oidc_common::TEST_CLIENT_ID).await?;
        let (base_url, _shutdown) = start_http_server(Some(verifier)).await;

        let http_wrong_audience_client = "lore-integration-tests-oidc-http-other-audience";
        fixture
            .ensure_client(
                http_wrong_audience_client,
                &[oidc_common::TEST_REDIRECT_URI],
            )
            .await?;
        let user = fixture.create_user("httpwrongaudience").await?;
        let tokens = fixture
            .issue_token_for_client(&user, http_wrong_audience_client)
            .await?;

        let response = reqwest::Client::new()
            .put(put_content_url(&base_url))
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", tokens.id_token),
            )
            .body("wrong audience")
            .send()
            .await?;

        assert_eq!(
            response.status(),
            reqwest::StatusCode::FORBIDDEN,
            "a real PocketID token minted for a different client id must be refused"
        );
        Ok(())
    }

    /// In authn-only mode, a verified token gets the `urc-*` wildcard resource on the
    /// in-process `AuthorizationToken`, leaving `verify_authorization` unchanged; this
    /// asserts the end behavior only.
    #[tokio::test]
    async fn http_valid_pocketid_token_is_accepted_for_repository_operations() -> TestResult {
        let fixture = oidc_common::setup().await?;
        let verifier = oidc_jwt_verifier(&fixture, oidc_common::TEST_CLIENT_ID).await?;
        let (base_url, _shutdown) = start_http_server(Some(verifier)).await;

        let user = fixture.create_user("httpvalid").await?;
        let tokens = fixture.issue_token(&user).await?;

        let response = reqwest::Client::new()
            .put(put_content_url(&base_url))
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", tokens.id_token),
            )
            .body("a real, correctly-audienced PocketID token")
            .send()
            .await?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        assert_eq!(
            status,
            reqwest::StatusCode::OK,
            "authn-only mode must accept any verified token from the trusted issuer for any \
             repository; instead got {status}: {body}"
        );
        Ok(())
    }

    /// Regression: an unconfigured server (`jwt_verifier: None`) must behave unchanged on
    /// the same route the tests above exercise.
    #[tokio::test]
    async fn http_unconfigured_server_is_unchanged() -> TestResult {
        let (base_url, _shutdown) = start_http_server(None).await;

        let response = reqwest::Client::new()
            .put(put_content_url(&base_url))
            .body("no auth configured on this server at all")
            .send()
            .await?;

        assert_eq!(
            response.status(),
            reqwest::StatusCode::OK,
            "an unconfigured server must not demand authentication"
        );
        Ok(())
    }
}

// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Integration tests for OIDC-secured server mode, exercised against a real `PocketID`
//! instance.
//!
//! A real `JwtVerifier` (`lore_server::auth::jwt`) is pointed at the `PocketID` instance in
//! `lore-integration-tests/compose.yaml`, following the discovery document rather than a
//! hardcoded JWKS path, and wired into an in-process gRPC or HTTP server. The verifier is
//! built by hand here rather than through `build_jwt_verifier`
//! (`lore-server/src/server.rs`), which builds the identical verifier from
//! `[server.auth.oidc]`.
//!
//! Attaching an arbitrary bearer token needs the raw generated gRPC clients, so
//! `integration_tests` activates the optional `tonic`/`tokio-stream` dependencies and the
//! whole matrix below runs under that feature alone.

#[cfg(all(test, feature = "integration_tests"))]
mod oidc_auth_tests {
    use std::error::Error;
    use std::sync::Arc;
    use std::time::Duration;

    use lore_server::auth::jwk::JWKService;
    use lore_server::auth::jwk::JWKServiceSettings;
    use lore_server::auth::jwk::JwkServiceImpl;
    use lore_server::auth::jwt::AuthorizationToken;
    use lore_server::auth::jwt::JWTUserInfo;
    use lore_server::auth::jwt::JwtVerifier;
    use lore_server::http::server::LoreHttpServerSettings;
    use lore_server::http::server::ServerHealth;
    use lore_server::http::server::ServerState;
    use lore_server::http::server::create_router;
    use lore_storage::local::immutable_store::ImmutableStoreCreateOptions;
    use lore_storage::local::immutable_store::ImmutableStoreSettings;

    use crate::common::oidc::oidc_common;

    type TestResult = Result<(), Box<dyn Error>>;

    async fn make_backends() -> (
        Arc<dyn lore_storage::ImmutableStore>,
        Arc<dyn lore_storage::MutableStore>,
    ) {
        let backend_immutable = lore_storage::local::immutable_store::create(
            None::<&str>,
            ImmutableStoreCreateOptions::none(),
            false,
            ImmutableStoreSettings {
                implicit_durable_stored: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let backend_mutable = lore_storage::local::mutable_store::create(
            None::<&str>,
            lore_storage::MutableStoreSettings::default(),
            backend_immutable.clone(),
        )
        .await
        .unwrap();

        (backend_immutable, backend_mutable)
    }

    /// A `JwtVerifier` pointed at `PocketID`'s real JWKS, discovered rather than hardcoded.
    async fn oidc_jwt_verifier(
        fixture: &oidc_common::OidcFixture,
        audience: &str,
    ) -> Result<JwtVerifier, Box<dyn Error>> {
        let discovery = fixture.discovery().await?;
        let jwks_uri = discovery["jwks_uri"]
            .as_str()
            .ok_or("PocketID discovery document has no jwks_uri")?
            .to_string();

        let jwk_service: Arc<dyn JWKService> = Arc::new(JwkServiceImpl::new(JWKServiceSettings {
            endpoint: jwks_uri,
        }));

        // `[server.auth.oidc]`'s authn-only mode — the premise this whole matrix
        // tests against — is what `JwtVerifier::oidc` builds; `build_jwt_verifier`
        // (`lore-server/src/server.rs`) builds the identical verifier from real
        // settings via the same constructor.
        Ok(JwtVerifier::oidc(
            jwk_service,
            Some(fixture.issuer().to_string()),
            Some(vec![audience.to_string()]),
        ))
    }

    /// Start a real HTTP server, in process, over fresh in-memory backends.
    async fn start_http_server(
        jwt_verifier: Option<JwtVerifier>,
    ) -> (String, tokio::sync::oneshot::Sender<()>) {
        let (immutable_store, mutable_store) = make_backends().await;
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
        // Background server task in a test; LORE_CONTEXT propagation is unnecessary here.
        #[allow(clippy::disallowed_methods)]
        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    shutdown_rx.await.ok();
                })
                .await
                .unwrap();
        });

        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
        }

        (base_url, shutdown_tx)
    }

    /// The route under the authenticated router with the fewest preconditions. The
    /// repository id only has to be valid hex: the auth middleware runs, and decides,
    /// before the handler ever parses it.
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
    async fn http_forged_issuer_token_is_rejected() -> TestResult {
        let fixture = oidc_common::setup().await?;
        let verifier = oidc_jwt_verifier(&fixture, oidc_common::TEST_CLIENT_ID).await?;
        let (base_url, _shutdown) = start_http_server(Some(verifier)).await;

        let forged = forged_token_with_unknown_kid();
        let response = reqwest::Client::new()
            .put(put_content_url(&base_url))
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {forged}"))
            .body("forged issuer")
            .send()
            .await?;

        assert_eq!(
            response.status(),
            reqwest::StatusCode::FORBIDDEN,
            "a token naming a key PocketID never issued must be refused"
        );
        Ok(())
    }

    #[tokio::test]
    async fn http_algorithm_confusion_forgery_is_rejected() -> TestResult {
        let fixture = oidc_common::setup().await?;
        let verifier = oidc_jwt_verifier(&fixture, oidc_common::TEST_CLIENT_ID).await?;
        let (base_url, _shutdown) = start_http_server(Some(verifier)).await;

        let forged =
            algorithm_confusion_forged_token(&fixture, oidc_common::TEST_CLIENT_ID).await?;
        let response = reqwest::Client::new()
            .put(put_content_url(&base_url))
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {forged}"))
            .body("hmac-signed with a real key's public modulus as the secret")
            .send()
            .await?;

        assert_eq!(
            response.status(),
            reqwest::StatusCode::FORBIDDEN,
            "an HS256 token naming a real RSA kid, signed with that key's own public \
             modulus as an HMAC secret, must never be accepted"
        );
        Ok(())
    }

    #[tokio::test]
    async fn http_wrong_audience_token_is_rejected() -> TestResult {
        let fixture = oidc_common::setup().await?;
        let verifier = oidc_jwt_verifier(&fixture, oidc_common::TEST_CLIENT_ID).await?;
        let (base_url, _shutdown) = start_http_server(Some(verifier)).await;

        let other_client_id = "lore-integration-tests-oidc-p3-http-other";
        fixture
            .ensure_client(other_client_id, &[oidc_common::TEST_REDIRECT_URI])
            .await?;
        let user = fixture.create_user("p3httpwrongaud").await?;
        let tokens = fixture
            .issue_token_for_client(&user, other_client_id)
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

    /// In authn-only mode `JwtVerifier` populates the existing `urc-*` wildcard resource
    /// onto the in-process `AuthorizationToken` once a token verifies, leaving
    /// `verify_authorization` unchanged. Asserts the end behavior only.
    #[tokio::test]
    async fn http_valid_pocketid_token_is_accepted_for_repository_operations() -> TestResult {
        let fixture = oidc_common::setup().await?;
        let verifier = oidc_jwt_verifier(&fixture, oidc_common::TEST_CLIENT_ID).await?;
        let (base_url, _shutdown) = start_http_server(Some(verifier)).await;

        let user = fixture.create_user("p3httpvalid").await?;
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

    /// `[server.auth.oidc].resource` end to end, over the real HTTP plug point.
    ///
    /// `PocketID` 2.6.2 does not implement RFC 8707: it answers `200` to a `resource`
    /// parameter, ignores it, and mints an access token audienced to the client id with
    /// header `typ: "JWT"`. The tokens here are therefore minted synthetically against a
    /// `file://` key set.
    mod resource_mode {
        use jsonwebtoken::EncodingKey;
        use jsonwebtoken::Header;
        use lore_server::auth::jwk::OidcJwkService;

        use super::*;

        const ISSUER: &str = "https://id.example.com";
        const RESOURCE: &str = "https://lore.example.com";
        const OTHER_RESOURCE: &str = "https://lore.other.example.com";
        const CLIENT_ID: &str = "lore";
        const KID: &str = "resource-mode-test-key";

        /// An Ed25519 signing key and the one-key JWKS that publishes its public half.
        ///
        /// Generated per test rather than embedded. `EdDSA` because it is in the OIDC-mode
        /// algorithm allowlist and `ring` will generate one, where it will not generate RSA.
        fn signing_key_and_jwks() -> (EncodingKey, String) {
            use base64::Engine;
            use ring::signature::KeyPair;

            let rng = ring::rand::SystemRandom::new();
            let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
                .expect("generate an ed25519 key");
            let key_pair =
                ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("read it back");
            let public = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(key_pair.public_key().as_ref());

            let jwks = format!(
                r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","use":"sig","alg":"EdDSA",
                   "kid":"{KID}","x":"{public}"}}]}}"#
            );
            (EncodingKey::from_ed_der(pkcs8.as_ref()), jwks)
        }

        /// A verifier in resource-bound mode over a `file://` key set, assembled the way
        /// `build_jwt_verifier` assembles one from `[server.auth.oidc]` with a `resource`.
        fn resource_mode_verifier(jwks: &str) -> (JwtVerifier, tempfile::NamedTempFile) {
            use std::io::Write;

            let mut file = tempfile::NamedTempFile::new().expect("temp jwks file");
            file.write_all(jwks.as_bytes()).expect("write jwks");
            let endpoint = reqwest::Url::from_file_path(file.path())
                .expect("jwks path as a file url")
                .to_string();

            let jwk_service: Arc<dyn JWKService> = Arc::new(OidcJwkService::new(Arc::new(
                JwkServiceImpl::new(JWKServiceSettings { endpoint }),
            )));

            (
                JwtVerifier::oidc_resource(
                    jwk_service,
                    Some(ISSUER.to_string()),
                    Some(vec![RESOURCE.to_string()]),
                ),
                file,
            )
        }

        fn expires_in_an_hour() -> u64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_secs()
                + 3600
        }

        /// A token signed by the test key, with a caller-chosen media type and audience.
        fn mint(key: &EncodingKey, typ: &str, audience: &str) -> String {
            let mut header = Header::new(jsonwebtoken::Algorithm::EdDSA);
            header.kid = Some(KID.to_string());
            header.typ = Some(typ.to_string());

            jsonwebtoken::encode(
                &header,
                &serde_json::json!({
                    "iss": ISSUER,
                    "sub": "the-subject",
                    "aud": audience,
                    "client_id": CLIENT_ID,
                    "iat": 1,
                    "jti": "the-token-id",
                    "exp": expires_in_an_hour(),
                }),
                key,
            )
            .expect("sign the test token")
        }

        async fn put_with(
            base_url: &str,
            token: &str,
        ) -> Result<reqwest::StatusCode, Box<dyn Error>> {
            Ok(reqwest::Client::new()
                .put(put_content_url(base_url))
                .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
                .body("a resource-mode request")
                .send()
                .await?
                .status())
        }

        /// A token audienced to the client id no longer opens this server, while one
        /// audienced to this deployment does.
        #[tokio::test]
        async fn only_a_token_bound_to_this_deployment_is_admitted() -> TestResult {
            let (key, jwks) = signing_key_and_jwks();
            let (verifier, _jwks_file) = resource_mode_verifier(&jwks);
            let (base_url, _shutdown) = start_http_server(Some(verifier)).await;

            assert_eq!(
                put_with(&base_url, &mint(&key, "at+jwt", RESOURCE)).await?,
                reqwest::StatusCode::OK,
                "an RFC 9068 access token bound to this deployment must be admitted"
            );
            assert_eq!(
                put_with(&base_url, &mint(&key, "at+jwt", CLIENT_ID)).await?,
                reqwest::StatusCode::FORBIDDEN,
                "a token audienced to the client id must no longer open this server"
            );
            assert_eq!(
                put_with(&base_url, &mint(&key, "at+jwt", OTHER_RESOURCE)).await?,
                reqwest::StatusCode::FORBIDDEN,
                "nor must one minted for the deployment next door"
            );
            Ok(())
        }

        /// The media type is what turns ID-token acceptance off: `typ: "JWT"` is what
        /// every ID token and every Lore-issued token carries.
        #[tokio::test]
        async fn a_token_without_the_rfc_9068_media_type_is_refused() -> TestResult {
            let (key, jwks) = signing_key_and_jwks();
            let (verifier, _jwks_file) = resource_mode_verifier(&jwks);
            let (base_url, _shutdown) = start_http_server(Some(verifier)).await;

            assert_eq!(
                put_with(&base_url, &mint(&key, "JWT", RESOURCE)).await?,
                reqwest::StatusCode::FORBIDDEN,
                "a correctly-audienced token that is not an access token must be refused"
            );
            assert_eq!(
                put_with(&base_url, &mint(&key, "application/at+jwt", RESOURCE)).await?,
                reqwest::StatusCode::OK,
                "both spellings of the media type are conformant (RFC 9068 §4 step 1)"
            );
            Ok(())
        }

        /// The media type and audience checks are additions to verification rather than a
        /// path around it.
        #[tokio::test]
        async fn a_token_from_an_unknown_key_is_still_refused() -> TestResult {
            let (_key, jwks) = signing_key_and_jwks();
            let (other_key, _other_jwks) = signing_key_and_jwks();
            let (verifier, _jwks_file) = resource_mode_verifier(&jwks);
            let (base_url, _shutdown) = start_http_server(Some(verifier)).await;

            assert_eq!(
                put_with(&base_url, &mint(&other_key, "at+jwt", RESOURCE)).await?,
                reqwest::StatusCode::FORBIDDEN,
                "a perfectly-shaped token signed by nobody the server trusts is still no"
            );
            Ok(())
        }
    }

    /// Quick regression: an unconfigured server (`jwt_verifier: None`) must keep behaving
    /// exactly as it does today, on the same route the tests above exercise.
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

    /// The algorithm-confusion forgery against a real `PocketID` key: sign an HS256 token
    /// using a published RSA key's own modulus as the HMAC secret. `jwk.rs` proves the same
    /// defense against a synthetic key.
    async fn algorithm_confusion_forged_token(
        fixture: &oidc_common::OidcFixture,
        audience: &str,
    ) -> Result<String, Box<dyn Error>> {
        use jsonwebtoken::Algorithm;
        use jsonwebtoken::EncodingKey;
        use jsonwebtoken::Header;
        use jsonwebtoken::encode;

        let discovery = fixture.discovery().await?;
        let jwks_uri = discovery["jwks_uri"]
            .as_str()
            .ok_or("PocketID discovery document has no jwks_uri")?;
        let jwks_body = reqwest::get(jwks_uri).await?.text().await?;
        let jwks: serde_json::Value = serde_json::from_str(&jwks_body)?;
        let key = jwks["keys"]
            .as_array()
            .and_then(|keys| keys.first())
            .ok_or("PocketID JWKS has no keys")?;
        let kid = key["kid"].as_str().ok_or("JWK has no kid")?.to_string();
        let modulus = key["n"]
            .as_str()
            .ok_or("JWK has no RSA modulus")?
            .to_string();

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(kid);
        let claims = serde_json::json!({
            "sub": "attacker",
            "iss": fixture.issuer(),
            "aud": audience,
            "iat": 1,
            "exp": 9_999_999_999u64,
            "env": "test",
            "name": "test",
            "preferred_username": "test",
        });
        Ok(encode(
            &header,
            &claims,
            &EncodingKey::from_secret(modulus.as_bytes()),
        )?)
    }

    /// A self-signed forgery naming a key id `PocketID` never served and an issuer it never
    /// claimed, standing in for a token from a second provider.
    fn forged_token_with_unknown_kid() -> String {
        use jsonwebtoken::Algorithm;
        use jsonwebtoken::EncodingKey;
        use jsonwebtoken::Header;
        use jsonwebtoken::encode;

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("attacker-controlled-kid-not-in-pocketid-jwks".to_string());
        let claims = serde_json::json!({
            "sub": "attacker",
            "iss": "https://not-pocket-id.example.invalid",
            "aud": oidc_common::TEST_CLIENT_ID,
            "iat": 1,
            "exp": 9_999_999_999u64,
            "env": "test",
            "name": "test",
            "preferred_username": "test",
        });
        encode(
            &header,
            &claims,
            &EncodingKey::from_secret(b"attacker-controlled-secret"),
        )
        .expect("encode forged token")
    }

    /// `PocketID` emits `aud` as a JSON array, not a bare string. Supplying
    /// `env`/`name`/`preferred_username` isolates the `aud` shape from the mandatory-claims
    /// question.
    #[test]
    fn pocketid_style_array_audience_deserializes_into_authorization_token() {
        let claims = serde_json::json!({
            "sub": "the-subject",
            "iss": "http://127.0.0.1:1411",
            "iat": 1,
            "exp": 9_999_999_999u64,
            "aud": ["lore-integration-tests"],
            "env": "test",
            "name": "test",
            "preferred_username": "test",
            "idp": "test",
        });

        let token: AuthorizationToken =
            serde_json::from_value(claims).expect("array-shaped aud must deserialize");
        assert_eq!(token.audience, vec!["lore-integration-tests".to_string()]);
    }

    /// The same array `aud`, for the plain-authn claim shape (`JWTUserInfo`).
    #[test]
    fn pocketid_style_array_audience_deserializes_into_jwt_user_info() {
        let claims = serde_json::json!({
            "sub": "the-subject",
            "iss": "http://127.0.0.1:1411",
            "iat": 1,
            "exp": 9_999_999_999u64,
            "aud": ["lore-integration-tests"],
            "env": "test",
            "name": "test",
            "preferred_username": "test",
        });

        let token: JWTUserInfo =
            serde_json::from_value(claims).expect("array-shaped aud must deserialize");
        assert_eq!(token.audience, vec!["lore-integration-tests".to_string()]);
    }
}

/// Raw-tonic gRPC coverage of the same matrix, against `StorageService` — the enforcement
/// point that actually calls `verify_authorization` today (`RepositoryService` runs behind
/// the still-unfinished `JWTAuthnInterceptor` placeholder and never calls it).
#[cfg(all(test, feature = "integration_tests"))]
mod oidc_auth_grpc_tests {
    use std::collections::HashMap;
    use std::error::Error;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use lore_proto::lore::storage::v1::QueryRequest;
    use lore_proto::lore::storage::v1::storage_service_client::StorageServiceClient;
    use lore_revision::environment::EnvironmentConfig;
    use lore_server::auth::jwk::JWKService;
    use lore_server::auth::jwk::JWKServiceSettings;
    use lore_server::auth::jwk::JwkServiceImpl;
    use lore_server::auth::jwt::JwtVerifier;
    use lore_server::grpc::server::FeatureSettings;
    use lore_server::grpc::server::GrpcServerBuilder;
    use lore_server::hooks::HookDispatcher;
    use lore_storage::local::immutable_store::ImmutableStoreCreateOptions;
    use lore_storage::local::immutable_store::ImmutableStoreSettings;
    use tonic::Code;
    use tonic::Request;
    use tonic::metadata::MetadataValue;
    use tonic::transport::Channel;

    use crate::common::oidc::oidc_common;

    type TestResult = Result<(), Box<dyn Error>>;

    async fn make_backends() -> (
        Arc<dyn lore_storage::ImmutableStore>,
        Arc<dyn lore_storage::MutableStore>,
    ) {
        let backend_immutable = lore_storage::local::immutable_store::create(
            None::<&str>,
            ImmutableStoreCreateOptions::none(),
            false,
            ImmutableStoreSettings {
                allow_partial_fragment: false,
                protect_local_fragment: false,
                implicit_durable_stored: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let backend_mutable = lore_storage::local::mutable_store::create(
            None::<&str>,
            lore_storage::MutableStoreSettings::default(),
            backend_immutable.clone(),
        )
        .await
        .unwrap();

        (backend_immutable, backend_mutable)
    }

    /// Same discovery-driven construction as the HTTP half.
    async fn oidc_jwt_verifier(
        fixture: &oidc_common::OidcFixture,
        audience: &str,
    ) -> Result<JwtVerifier, Box<dyn Error>> {
        let discovery = fixture.discovery().await?;
        let jwks_uri = discovery["jwks_uri"]
            .as_str()
            .ok_or("PocketID discovery document has no jwks_uri")?
            .to_string();

        let jwk_service: Arc<dyn JWKService> = Arc::new(JwkServiceImpl::new(JWKServiceSettings {
            endpoint: jwks_uri,
        }));

        // `[server.auth.oidc]`'s authn-only mode — the premise this whole matrix
        // tests against — is what `JwtVerifier::oidc` builds; `build_jwt_verifier`
        // (`lore-server/src/server.rs`) builds the identical verifier from real
        // settings via the same constructor.
        Ok(JwtVerifier::oidc(
            jwk_service,
            Some(fixture.issuer().to_string()),
            Some(vec![audience.to_string()]),
        ))
    }

    /// Start a real gRPC server, in process, with a caller-supplied verifier so
    /// `StorageService` is reached through `JWTInterceptor` when `Some`.
    async fn start_grpc_server(
        jwt_verifier: Option<JwtVerifier>,
    ) -> (String, tokio::sync::oneshot::Sender<()>) {
        let (backend_immutable, backend_mutable) = make_backends().await;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let signal = async {
            shutdown_rx.await.ok();
        };

        let notification_sender: Arc<dyn lore_revision::notification::NotificationSender> =
            Arc::new(lore_server::notification::local::NotificationSender::default());
        let hook_dispatcher = Arc::new(HookDispatcher::empty());

        let (stopped_tx, mut stopped_rx) = tokio::sync::oneshot::channel::<String>();
        // Background server task in a test; LORE_CONTEXT propagation is unnecessary here.
        #[allow(clippy::disallowed_methods)]
        tokio::spawn(async move {
            let outcome = GrpcServerBuilder::new()
                .with_environment(EnvironmentConfig::default(), EnvironmentConfig::default())
                .with_feature(FeatureSettings::default())
                .with_immutable_store(backend_immutable.clone(), backend_immutable)
                .with_mutable_store(backend_mutable)
                .with_lock_store(None)
                .with_notification(notification_sender, None)
                .with_hook_dispatcher(hook_dispatcher)
                .with_tls_config(None, None, None)
                .unwrap()
                .with_admin_endpoints(HashMap::new(), vec![])
                .with_http2_config(
                    None,
                    None,
                    Duration::from_secs(30),
                    None,
                    Default::default(),
                    None,
                )
                .with_jwt_verifier(jwt_verifier)
                .unwrap()
                .serve_with_listener(listener, signal)
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
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(ready, "test server on {addr} never accepted a connection");

        (format!("http://127.0.0.1:{}", addr.port()), shutdown_tx)
    }

    async fn connect(url: &str) -> StorageServiceClient<Channel> {
        StorageServiceClient::connect(url.to_string())
            .await
            .expect("connect to in-process test server")
    }

    /// An empty `Query` — the lightest unary call `StorageService` exposes — optionally
    /// bearing a token. The repository id metadata is always set because the `Query` handler
    /// answers `InvalidArgument` without it, which would be a false rejection signal.
    fn query_request(token: Option<&str>) -> Request<QueryRequest> {
        let mut request = Request::new(QueryRequest { addresses: vec![] });

        // `lore_transport::grpc::PARTITION_ID_KEY`, inlined because `lore-transport` is
        // not a dependency of this crate.
        const PARTITION_ID_KEY: &str = "lore-partition-bin";
        let repository = lore_base::types::Partition::from([0xacu8; 16]);
        let repository_id = MetadataValue::from_bytes(repository.data());
        request
            .metadata_mut()
            .append_bin(PARTITION_ID_KEY, repository_id);

        if let Some(token) = token {
            let value =
                MetadataValue::try_from(format!("Bearer {token}")).expect("bearer header value");
            request.metadata_mut().insert("authorization", value);
        }
        request
    }

    fn forged_token_with_unknown_kid() -> String {
        use jsonwebtoken::Algorithm;
        use jsonwebtoken::EncodingKey;
        use jsonwebtoken::Header;
        use jsonwebtoken::encode;

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("attacker-controlled-kid-not-in-pocketid-jwks".to_string());
        let claims = serde_json::json!({
            "sub": "attacker",
            "iss": "https://not-pocket-id.example.invalid",
            "aud": oidc_common::TEST_CLIENT_ID,
            "iat": 1,
            "exp": 9_999_999_999u64,
            "env": "test",
            "name": "test",
            "preferred_username": "test",
        });
        encode(
            &header,
            &claims,
            &EncodingKey::from_secret(b"attacker-controlled-secret"),
        )
        .expect("encode forged token")
    }

    #[tokio::test]
    async fn grpc_anonymous_request_to_authenticated_service_is_rejected() -> TestResult {
        let fixture = oidc_common::setup().await?;
        let verifier = oidc_jwt_verifier(&fixture, oidc_common::TEST_CLIENT_ID).await?;
        let (url, _shutdown) = start_grpc_server(Some(verifier)).await;
        let mut client = connect(&url).await;

        let status = client
            .query(query_request(None))
            .await
            .expect_err("a request with no bearer token at all must be rejected");
        assert_eq!(
            status.code(),
            Code::Unauthenticated,
            "missing token is its own signal, not the uniform post-token rejection: {status:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn grpc_forged_issuer_token_is_rejected() -> TestResult {
        let fixture = oidc_common::setup().await?;
        let verifier = oidc_jwt_verifier(&fixture, oidc_common::TEST_CLIENT_ID).await?;
        let (url, _shutdown) = start_grpc_server(Some(verifier)).await;
        let mut client = connect(&url).await;

        let forged = forged_token_with_unknown_kid();
        let status = client
            .query(query_request(Some(&forged)))
            .await
            .expect_err("a token naming a key PocketID never issued must be rejected");
        assert_eq!(status.code(), Code::PermissionDenied, "{status:?}");
        Ok(())
    }

    #[tokio::test]
    async fn grpc_wrong_audience_token_is_rejected() -> TestResult {
        let fixture = oidc_common::setup().await?;
        let verifier = oidc_jwt_verifier(&fixture, oidc_common::TEST_CLIENT_ID).await?;
        let (url, _shutdown) = start_grpc_server(Some(verifier)).await;
        let mut client = connect(&url).await;

        let other_client_id = "lore-integration-tests-oidc-p3-grpc-other";
        fixture
            .ensure_client(other_client_id, &[oidc_common::TEST_REDIRECT_URI])
            .await?;
        let user = fixture.create_user("p3grpcwrongaud").await?;
        let tokens = fixture
            .issue_token_for_client(&user, other_client_id)
            .await?;

        let status = client
            .query(query_request(Some(&tokens.id_token)))
            .await
            .expect_err("a real token minted for a different client id must be rejected");
        assert_eq!(status.code(), Code::PermissionDenied, "{status:?}");
        Ok(())
    }

    /// The wildcard-resource population of the HTTP half, exercised over gRPC.
    #[tokio::test]
    async fn grpc_valid_pocketid_token_is_accepted_for_storage_operations() -> TestResult {
        let fixture = oidc_common::setup().await?;
        let verifier = oidc_jwt_verifier(&fixture, oidc_common::TEST_CLIENT_ID).await?;
        let (url, _shutdown) = start_grpc_server(Some(verifier)).await;
        let mut client = connect(&url).await;

        let user = fixture.create_user("p3grpcvalid").await?;
        let tokens = fixture.issue_token(&user).await?;

        let response = client.query(query_request(Some(&tokens.id_token))).await;
        assert!(
            response.is_ok(),
            "authn-only mode must accept any verified token from the trusted issuer for any \
             repository; instead: {response:?}"
        );
        Ok(())
    }

    /// An unconfigured server (`jwt_verifier: None`) must keep admitting anonymous
    /// requests to `StorageService`.
    #[tokio::test]
    async fn grpc_unconfigured_server_is_unchanged() -> TestResult {
        let (url, _shutdown) = start_grpc_server(None).await;
        let mut client = connect(&url).await;

        let response = client.query(query_request(None)).await;
        assert!(
            response.is_ok(),
            "an unconfigured server must not demand authentication: {response:?}"
        );
        Ok(())
    }
}

// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
/// Auth exchange integration tests.
///
/// These tests verify the `Authentication` trait's error handling patterns
/// that the orchestration layer depends on for identity probing and
/// authorization exchange. They use `MockAuthentication` registered in the
/// global authentication registry.
///
/// The original `AuthExchange` trait tests (identity selection, domain
/// filtering) operated on an in-memory mock of the token store. Those
/// scenarios are now covered by:
/// - Unit tests in `protocol::tests` (mock trait method responses)
/// - Smoke tests (end-to-end with real token store)
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use lore_base::error::NotAuthenticated;
    use lore_base::error::NotAuthorized;
    use lore_base::error::NotSupported;
    use lore_credential::token_store;
    use lore_revision::lore::RepositoryId;
    use lore_transport::AuthSession;
    use lore_transport::Authentication;
    use lore_transport::AuthenticationToken;
    use lore_transport::AuthorizationToken;
    use lore_transport::LoginFlow;
    use lore_transport::ProtocolError;
    use lore_transport::ResolvedUser;
    use lore_transport::auth::authentication;

    include!("helper.rs");

    struct TestAuthentication {
        exchange_result:
            Box<dyn Fn(RepositoryId) -> Result<AuthorizationToken, ProtocolError> + Send + Sync>,
    }

    impl TestAuthentication {
        fn always_succeed() -> Self {
            Self {
                exchange_result: Box::new(|_| {
                    Ok(AuthorizationToken {
                        token: "authz-token".into(),
                        expires_ms: u64::MAX,
                        acceptable_root_domains: vec![],
                    })
                }),
            }
        }

        /// The shape an OpenID Connect provider produces: the authorization token is the
        /// authentication token, and the only domain it can name for itself is the
        /// issuer's.
        fn oidc_shaped(issuer_domain: &'static str) -> Self {
            Self {
                exchange_result: Box::new(move |_| {
                    Ok(AuthorizationToken {
                        token: unsigned_jwt("user-1"),
                        expires_ms: u64::MAX,
                        acceptable_root_domains: vec![issuer_domain.to_string()],
                    })
                }),
            }
        }

        fn always_not_authorized() -> Self {
            Self {
                exchange_result: Box::new(|_| Err(ProtocolError::from(NotAuthorized))),
            }
        }

        fn always_not_authenticated() -> Self {
            Self {
                exchange_result: Box::new(|_| Err(ProtocolError::from(NotAuthenticated))),
            }
        }
    }

    #[async_trait]
    impl Authentication for TestAuthentication {
        async fn start_auth_session(
            &self,
            _auth_url: &str,
            _client_state: &str,
            _flow: LoginFlow,
            _correlation_id: &str,
        ) -> Result<AuthSession, ProtocolError> {
            Err(ProtocolError::from(NotSupported {
                operation: "start_auth_session".into(),
            }))
        }

        async fn poll_auth_session(
            &self,
            _auth_url: &str,
            _client_state: &str,
            _session_code: &str,
            _correlation_id: &str,
        ) -> Result<Option<AuthenticationToken>, ProtocolError> {
            Ok(None)
        }

        async fn exchange_external_token(
            &self,
            _auth_url: &str,
            _token: &str,
            _token_type: &str,
            _correlation_id: &str,
        ) -> Result<AuthenticationToken, ProtocolError> {
            Err(ProtocolError::from(NotSupported {
                operation: "exchange_external_token".into(),
            }))
        }

        async fn refresh_authentication(
            &self,
            _auth_url: &str,
            _refresh_token: &str,
            _correlation_id: &str,
        ) -> Result<AuthenticationToken, ProtocolError> {
            Err(ProtocolError::from(NotSupported {
                operation: "refresh_authentication".into(),
            }))
        }

        async fn exchange_for_repository(
            &self,
            _auth_url: &str,
            _authn_token: &str,
            repository: RepositoryId,
            _correlation_id: &str,
        ) -> Result<AuthorizationToken, ProtocolError> {
            (self.exchange_result)(repository)
        }

        async fn exchange_for_custom_resource(
            &self,
            _auth_url: &str,
            _authn_token: &str,
            _resource_id: &str,
            _correlation_id: &str,
        ) -> Result<AuthorizationToken, ProtocolError> {
            (self.exchange_result)(RepositoryId::default())
        }

        async fn get_user_info(
            &self,
            _auth_url: &str,
            _authz_token: &str,
            _repository: RepositoryId,
            user_ids: &[String],
            _correlation_id: &str,
        ) -> Result<Vec<ResolvedUser>, ProtocolError> {
            Ok(user_ids
                .iter()
                .map(|id| ResolvedUser {
                    user_id: id.clone(),
                    user_name: format!("User {id}"),
                })
                .collect())
        }

        async fn get_user_id(
            &self,
            _auth_url: &str,
            _authz_token: &str,
            _repository: RepositoryId,
            display_name: &str,
            _correlation_id: &str,
        ) -> Result<Option<ResolvedUser>, ProtocolError> {
            Ok(Some(ResolvedUser {
                user_id: format!("id-for-{display_name}"),
                user_name: display_name.to_string(),
            }))
        }
    }

    #[test]
    fn test_auth_registration_and_lookup() {
        let scheme = "test-auth-exchange";
        let mock = Arc::new(TestAuthentication::always_succeed());
        authentication::add(scheme, mock).unwrap();

        let found = authentication::find(&format!("{scheme}://auth.test.com"));
        assert!(found.is_ok());
    }

    #[tokio::test]
    async fn exchange_for_repository_success_returns_token() {
        let scheme = "test-exchange-success";
        authentication::add(scheme, Arc::new(TestAuthentication::always_succeed())).unwrap();

        let auth = authentication::find(&format!("{scheme}://auth.test.com")).unwrap();
        let result = auth
            .exchange_for_repository(
                &format!("{scheme}://auth.test.com"),
                "authn-tok",
                RepositoryId::default(),
                "corr",
            )
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().token, "authz-token");
    }

    #[tokio::test]
    async fn exchange_for_custom_resource_success_returns_token() {
        let scheme = "test-exchange-custom-success";
        authentication::add(scheme, Arc::new(TestAuthentication::always_succeed())).unwrap();

        let auth = authentication::find(&format!("{scheme}://auth.test.com")).unwrap();
        let result = auth
            .exchange_for_custom_resource(
                &format!("{scheme}://auth.test.com"),
                "authn-tok",
                "bespoke-urc:uefn:some-stream",
                "corr",
            )
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().token, "authz-token");
    }

    #[tokio::test]
    async fn exchange_not_authorized_is_matchable() {
        let scheme = "test-exchange-not-authz";
        authentication::add(
            scheme,
            Arc::new(TestAuthentication::always_not_authorized()),
        )
        .unwrap();

        let auth = authentication::find(&format!("{scheme}://auth.test.com")).unwrap();
        let result = auth
            .exchange_for_repository(
                &format!("{scheme}://auth.test.com"),
                "authn-tok",
                RepositoryId::default(),
                "corr",
            )
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().is_not_authorized());
    }

    #[tokio::test]
    async fn exchange_not_authenticated_is_matchable() {
        let scheme = "test-exchange-not-authn";
        authentication::add(
            scheme,
            Arc::new(TestAuthentication::always_not_authenticated()),
        )
        .unwrap();

        let auth = authentication::find(&format!("{scheme}://auth.test.com")).unwrap();
        let result = auth
            .exchange_for_repository(
                &format!("{scheme}://auth.test.com"),
                "authn-tok",
                RepositoryId::default(),
                "corr",
            )
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().is_not_authenticated());
    }

    #[tokio::test]
    async fn get_user_info_returns_resolved_users() {
        let scheme = "test-userinfo";
        authentication::add(scheme, Arc::new(TestAuthentication::always_succeed())).unwrap();

        let auth = authentication::find(&format!("{scheme}://auth.test.com")).unwrap();
        let users = auth
            .get_user_info(
                &format!("{scheme}://auth.test.com"),
                "authz-tok",
                RepositoryId::default(),
                &["u1".into(), "u2".into()],
                "corr",
            )
            .await
            .unwrap();
        assert_eq!(users.len(), 2);
        assert_eq!(users[0].user_id, "u1");
        assert_eq!(users[1].user_name, "User u2");
    }

    #[tokio::test]
    async fn get_user_id_returns_resolved_user() {
        let scheme = "test-userid";
        authentication::add(scheme, Arc::new(TestAuthentication::always_succeed())).unwrap();

        let auth = authentication::find(&format!("{scheme}://auth.test.com")).unwrap();
        let user = auth
            .get_user_id(
                &format!("{scheme}://auth.test.com"),
                "authz-tok",
                RepositoryId::default(),
                "Alice",
                "corr",
            )
            .await
            .unwrap();
        assert!(user.is_some());
        assert_eq!(user.unwrap().user_id, "id-for-Alice");
    }

    /// A JWT with a far-future expiry and a signature nothing checks -- the credential
    /// store reads the claims, and the server owns verification.
    fn unsigned_jwt(subject: &str) -> String {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#),
            URL_SAFE_NO_PAD.encode(format!(
                r#"{{"iss":"https://id.example.com","sub":"{subject}","exp":9999999999,"aud":["lore-cli"]}}"#
            )),
            URL_SAFE_NO_PAD.encode("not-a-signature"),
        )
    }

    /// Points the credential store at a directory of its own, with the encryption key in a
    /// file rather than the OS keyring, so the test neither reads nor writes the
    /// developer's real credentials.
    fn isolated_credential_store() -> TempDir {
        let auth_dir = generate_tempdir();
        unsafe {
            std::env::set_var("LORE_AUTH_PATH", auth_dir.display().to_string());
            std::env::set_var("LORE_AUTH_STORE", "fallback");
        }
        auth_dir
    }

    /// The token-recipient guard, on the path an explicit identity takes.
    ///
    /// `exchange` loads the stored authentication token by the *auth service's* domain, so
    /// nothing in it consults the set of domains that token was stored as acceptable for.
    /// A remote that advertises the auth URL the user logged in against therefore asks for,
    /// and under an OIDC passthrough receives, the user's own credential -- which is the
    /// leak the guard exists to prevent.
    #[tokio::test]
    async fn exchange_refuses_a_recipient_the_stored_token_does_not_name() {
        let scheme = "test-exchange-recipient-guard";
        let auth_url = format!("{scheme}://id.example.com");
        let identity = "user-1";
        let _auth_dir = isolated_credential_store();
        authentication::add(
            scheme,
            Arc::new(TestAuthentication::oidc_shaped("id.example.com")),
        )
        .unwrap();

        // What a login persists: the issuer, plus the remote the login was performed
        // against. `repo-b.example.com` is not among them.
        token_store::store_user_token(
            &auth_url,
            identity,
            &unsigned_jwt(identity),
            vec!["id.example.com".into(), "repo-a.example.com".into()],
        )
        .await
        .expect("Failed to store authentication token");

        let refused = lore_transport::auth::exchange::exchange(
            &auth_url,
            identity,
            RepositoryId::default(),
            "repo-b.example.com".to_string(),
        )
        .await;
        assert!(
            refused.is_err(),
            "a token stored for repo-a was handed to repo-b"
        );

        let allowed = lore_transport::auth::exchange::exchange(
            &auth_url,
            identity,
            RepositoryId::default(),
            "repo-a.example.com".to_string(),
        )
        .await;
        assert!(
            allowed.is_ok(),
            "the remote the login named was refused its own token: {:?}",
            allowed.unwrap_err()
        );
    }

    #[tokio::test]
    async fn not_supported_interactive_login() {
        let scheme = "test-no-interactive";
        authentication::add(scheme, Arc::new(TestAuthentication::always_succeed())).unwrap();

        let auth = authentication::find(&format!("{scheme}://auth.test.com")).unwrap();
        let result = auth
            .start_auth_session(
                &format!("{scheme}://auth.test.com"),
                "state",
                LoginFlow::Browser,
                "corr",
            )
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().is_not_supported());
    }
}

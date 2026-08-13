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
    use std::sync::Mutex;
    use std::sync::OnceLock;

    use async_trait::async_trait;
    use lore_base::error::NotAuthenticated;
    use lore_base::error::NotAuthorized;
    use lore_base::error::NotSupported;
    use lore_credential::token_store;
    use lore_credential::token_store::tokens_only_for_recipient_domain;
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
        /// What the backend's refresh grant answers. `NotSupported` is `ucs-auth`'s answer
        /// and the default here, so a test that says nothing about refreshing gets the
        /// behavior a backend without the grant has.
        refresh_result: Box<dyn Fn() -> Result<AuthenticationToken, ProtocolError> + Send + Sync>,
        /// The authentication token the last exchange was handed, so a test can tell which
        /// credential the operation actually proceeded with.
        exchanged_with: Mutex<Option<String>>,
    }

    impl TestAuthentication {
        fn exchanging(
            exchange_result: Box<
                dyn Fn(RepositoryId) -> Result<AuthorizationToken, ProtocolError> + Send + Sync,
            >,
        ) -> Self {
            Self {
                exchange_result,
                refresh_result: Box::new(|| {
                    Err(ProtocolError::from(NotSupported {
                        operation: "refresh_authentication".into(),
                    }))
                }),
                exchanged_with: Mutex::new(None),
            }
        }

        fn always_succeed() -> Self {
            Self::exchanging(Box::new(|_| {
                Ok(AuthorizationToken {
                    token: "authz-token".into(),
                    expires_ms: u64::MAX,
                    acceptable_root_domains: vec![],
                })
            }))
        }

        /// The shape an OpenID Connect provider produces: the authorization token is the
        /// authentication token, and the only domain it can name for itself is the
        /// issuer's.
        fn oidc_shaped(issuer_domain: &'static str) -> Self {
            Self::exchanging(Box::new(move |_| {
                Ok(AuthorizationToken {
                    token: unsigned_jwt("user-1"),
                    expires_ms: u64::MAX,
                    acceptable_root_domains: vec![issuer_domain.to_string()],
                })
            }))
        }

        /// A backend whose refresh grant succeeds, returning `token` and rotating the
        /// refresh token when the provider issued a new one.
        fn refreshing_to(mut self, token: &str, rotated: Option<&str>) -> Self {
            let token = token.to_string();
            let rotated = rotated.map(str::to_string);
            self.refresh_result = Box::new(move || {
                Ok(AuthenticationToken {
                    token: token.clone(),
                    user_id: "user-1".into(),
                    user_name: "user-1".into(),
                    expires_ms: u64::MAX,
                    // The issuer is all a provider can name; the remote the login was
                    // performed against is not something it knows.
                    acceptable_root_domains: vec!["id.example.com".into()],
                    refresh_token: rotated.clone(),
                })
            });
            self
        }

        fn always_not_authorized() -> Self {
            Self::exchanging(Box::new(|_| Err(ProtocolError::from(NotAuthorized))))
        }

        fn always_not_authenticated() -> Self {
            Self::exchanging(Box::new(|_| Err(ProtocolError::from(NotAuthenticated))))
        }

        fn exchanged_with(&self) -> Option<String> {
            self.exchanged_with.lock().unwrap().clone()
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
            (self.refresh_result)()
        }

        async fn exchange_for_repository(
            &self,
            _auth_url: &str,
            authn_token: &str,
            repository: RepositoryId,
            _correlation_id: &str,
        ) -> Result<AuthorizationToken, ProtocolError> {
            *self.exchanged_with.lock().unwrap() = Some(authn_token.to_string());
            (self.exchange_result)(repository)
        }

        async fn exchange_for_custom_resource(
            &self,
            _auth_url: &str,
            authn_token: &str,
            _resource_id: &str,
            _correlation_id: &str,
        ) -> Result<AuthorizationToken, ProtocolError> {
            *self.exchanged_with.lock().unwrap() = Some(authn_token.to_string());
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
        jwt_expiring_at(subject, 9999999999)
    }

    /// The same token, long since expired: the state a login reaches when it is left alone
    /// for longer than the provider's token lifetime.
    fn expired_jwt(subject: &str) -> String {
        jwt_expiring_at(subject, 1000000000)
    }

    fn jwt_expiring_at(subject: &str, expires: u64) -> String {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#),
            URL_SAFE_NO_PAD.encode(format!(
                r#"{{"iss":"https://id.example.com","sub":"{subject}","exp":{expires},"aud":["lore-cli"]}}"#
            )),
            URL_SAFE_NO_PAD.encode("not-a-signature"),
        )
    }

    /// Points the credential store at a directory of its own, with the encryption key in a
    /// file rather than the OS keyring, so a test neither reads nor writes the developer's
    /// real credentials.
    ///
    /// One directory for the whole binary, because `LORE_AUTH_PATH` and the loaded token map
    /// are both process-wide: a directory per test would have concurrently running tests
    /// writing to each other's store. Tests stay independent by using an auth URL of their
    /// own instead.
    fn isolated_credential_store() -> &'static TempDir {
        static AUTH_DIR: OnceLock<TempDir> = OnceLock::new();
        AUTH_DIR.get_or_init(|| {
            let auth_dir = generate_tempdir();
            unsafe {
                std::env::set_var("LORE_AUTH_PATH", auth_dir.display().to_string());
                std::env::set_var("LORE_AUTH_STORE", "fallback");
            }
            auth_dir
        })
    }

    /// The state a login leaves behind once its token has expired: the token itself, the
    /// domains it may be sent to, and -- when the provider issued one -- a refresh token.
    async fn store_expired_login(auth_url: &str, identity: &str, refresh_token: Option<&str>) {
        token_store::store_user_token(
            auth_url,
            identity,
            &expired_jwt(identity),
            vec!["id.example.com".into(), "repo-a.example.com".into()],
        )
        .await
        .expect("Failed to store authentication token");

        if let Some(refresh_token) = refresh_token {
            token_store::store_refresh_token(auth_url, identity, refresh_token)
                .await
                .expect("Failed to store refresh token");
        }
    }

    async fn stored_authn_token(auth_url: &str, identity: &str, recipient: &str) -> Option<String> {
        token_store::load_user_token(
            auth_url,
            identity,
            tokens_only_for_recipient_domain(recipient.to_string()),
        )
        .await
        .ok()
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

    /// The point of the refresh grant: a token that has expired since the last command is
    /// traded for a new one, and the operation the user asked for goes through on it rather
    /// than stopping to demand an interactive login.
    #[tokio::test]
    async fn an_expired_token_is_refreshed_and_the_operation_proceeds() {
        let scheme = "test-refresh-proceeds";
        let auth_url = format!("{scheme}://id.example.com");
        let identity = "user-1";
        let _auth_dir = isolated_credential_store();
        let backend = Arc::new(
            TestAuthentication::oidc_shaped("id.example.com")
                .refreshing_to(&unsigned_jwt(identity), None),
        );
        authentication::add(scheme, backend.clone()).unwrap();

        store_expired_login(&auth_url, identity, Some("refresh-one")).await;

        lore_transport::auth::exchange::exchange(
            &auth_url,
            identity,
            RepositoryId::default(),
            "repo-a.example.com".to_string(),
        )
        .await
        .expect("The operation should proceed on a refreshed credential");

        assert_eq!(
            backend.exchanged_with(),
            Some(unsigned_jwt(identity)),
            "The exchange was handed the expired credential rather than the refreshed one"
        );
        assert_eq!(
            stored_authn_token(&auth_url, identity, "repo-a.example.com").await,
            Some(unsigned_jwt(identity)),
            "The refreshed token was not persisted, so the next command refreshes again"
        );
    }

    /// The producer half of the token-recipient guard, on a refreshed token: what a refresh
    /// persists has to be what the login persisted, because the acceptable set names the
    /// remote the login was performed against and the provider cannot know it. Persist the
    /// refreshed token's own set and the credential is either unusable at its own remote or,
    /// worse, usable somewhere it never was.
    #[tokio::test]
    async fn a_refreshed_token_keeps_the_recipients_the_login_recorded() {
        let scheme = "test-refresh-recipient-guard";
        let auth_url = format!("{scheme}://id.example.com");
        let identity = "user-1";
        let _auth_dir = isolated_credential_store();
        authentication::add(
            scheme,
            Arc::new(
                TestAuthentication::oidc_shaped("id.example.com")
                    .refreshing_to(&unsigned_jwt(identity), None),
            ),
        )
        .unwrap();

        store_expired_login(&auth_url, identity, Some("refresh-one")).await;

        lore_transport::auth::exchange::exchange(
            &auth_url,
            identity,
            RepositoryId::default(),
            "repo-a.example.com".to_string(),
        )
        .await
        .expect("The operation should proceed on a refreshed credential");

        assert_eq!(
            stored_authn_token(&auth_url, identity, "repo-a.example.com").await,
            Some(unsigned_jwt(identity)),
            "The remote the login named was refused the refreshed token"
        );
        assert!(
            stored_authn_token(&auth_url, identity, "repo-b.example.com")
                .await
                .is_none(),
            "The refresh widened the acceptable set, so a third party can now be handed the token"
        );
    }

    /// Providers rotate refresh tokens, and a rotated one is single-use: keep the old one and
    /// the next refresh fails against a provider that has already retired it.
    #[tokio::test]
    async fn a_rotated_refresh_token_replaces_the_one_it_was_issued_for() {
        let scheme = "test-refresh-rotation";
        let auth_url = format!("{scheme}://id.example.com");
        let identity = "user-1";
        let _auth_dir = isolated_credential_store();
        authentication::add(
            scheme,
            Arc::new(
                TestAuthentication::oidc_shaped("id.example.com")
                    .refreshing_to(&unsigned_jwt(identity), Some("refresh-two")),
            ),
        )
        .unwrap();

        store_expired_login(&auth_url, identity, Some("refresh-one")).await;

        lore_transport::auth::exchange::exchange(
            &auth_url,
            identity,
            RepositoryId::default(),
            "repo-a.example.com".to_string(),
        )
        .await
        .expect("The operation should proceed on a refreshed credential");

        assert_eq!(
            token_store::load_refresh_token(&auth_url, identity)
                .await
                .ok()
                .as_deref(),
            Some("refresh-two"),
            "The rotated refresh token was not stored, so the session dies at the next expiry"
        );
    }

    /// An identity whose login can be kept alive is no longer skipped -- which is the
    /// difference between a command that works and one that sends the user back to
    /// `lore auth login`.
    #[tokio::test]
    async fn identity_resolution_refreshes_rather_than_skipping() {
        let scheme = "test-refresh-identity";
        let auth_url = format!("{scheme}://id.example.com");
        let identity = "user-1";
        let _auth_dir = isolated_credential_store();
        authentication::add(
            scheme,
            Arc::new(
                TestAuthentication::oidc_shaped("id.example.com")
                    .refreshing_to(&unsigned_jwt(identity), None),
            ),
        )
        .unwrap();

        store_expired_login(&auth_url, identity, Some("refresh-one")).await;

        let (authn, _authz, resolved) = lore_transport::auth::exchange::auth_exchange(
            &auth_url,
            "repo-a.example.com",
            identity,
            RepositoryId::default(),
        )
        .await;

        assert_eq!(
            authn,
            unsigned_jwt(identity),
            "The identity was skipped although its login could have been kept alive"
        );
        assert_eq!(resolved, identity);
    }

    /// A resource that is not a repository takes its own path to the same seam.
    #[tokio::test]
    async fn a_custom_resource_exchange_refreshes_too() {
        let scheme = "test-refresh-custom-resource";
        let auth_url = format!("{scheme}://id.example.com");
        let identity = "user-1";
        let _auth_dir = isolated_credential_store();
        let backend = Arc::new(
            TestAuthentication::oidc_shaped("id.example.com")
                .refreshing_to(&unsigned_jwt(identity), None),
        );
        authentication::add(scheme, backend.clone()).unwrap();

        store_expired_login(&auth_url, identity, Some("refresh-one")).await;

        lore_transport::auth::exchange::exchange_custom_resource(
            &auth_url,
            identity,
            "bespoke-urc:uefn:some-stream",
            "repo-a.example.com".to_string(),
        )
        .await
        .expect("The operation should proceed on a refreshed credential");

        assert_eq!(
            backend.exchanged_with(),
            Some(unsigned_jwt(identity)),
            "The exchange was handed the expired credential rather than the refreshed one"
        );
    }

    /// Nothing to refresh with: the identity is skipped exactly as it is today, and the
    /// stored login is left alone. Failing to refresh is not a new way to fail.
    #[tokio::test]
    async fn an_expired_token_with_no_refresh_token_is_skipped_as_before() {
        let scheme = "test-refresh-absent";
        let auth_url = format!("{scheme}://id.example.com");
        let identity = "user-1";
        let _auth_dir = isolated_credential_store();
        authentication::add(
            scheme,
            Arc::new(
                TestAuthentication::oidc_shaped("id.example.com")
                    .refreshing_to(&unsigned_jwt(identity), None),
            ),
        )
        .unwrap();

        store_expired_login(&auth_url, identity, None).await;

        let (authn, authz, resolved) = lore_transport::auth::exchange::auth_exchange(
            &auth_url,
            "repo-a.example.com",
            identity,
            RepositoryId::default(),
        )
        .await;

        assert!(
            authn.is_empty() && authz.is_empty() && resolved.is_empty(),
            "An expired token with nothing to refresh it must still be skipped"
        );
        assert_eq!(
            stored_authn_token(&auth_url, identity, "repo-a.example.com").await,
            Some(expired_jwt(identity)),
            "The stored login was disturbed by a refresh that could not happen"
        );
    }

    /// A backend without the grant -- `ucs-auth` answers `NotSupported` -- behaves exactly as
    /// it does today, which is the whole of what this change may do to it.
    #[tokio::test]
    async fn a_backend_without_a_refresh_grant_is_unaffected() {
        let scheme = "test-refresh-not-supported";
        let auth_url = format!("{scheme}://id.example.com");
        let identity = "user-1";
        let _auth_dir = isolated_credential_store();
        authentication::add(scheme, Arc::new(TestAuthentication::always_succeed())).unwrap();

        store_expired_login(&auth_url, identity, Some("refresh-one")).await;

        let (authn, authz, resolved) = lore_transport::auth::exchange::auth_exchange(
            &auth_url,
            "repo-a.example.com",
            identity,
            RepositoryId::default(),
        )
        .await;

        assert!(
            authn.is_empty() && authz.is_empty() && resolved.is_empty(),
            "A backend that does not support refreshing changed behavior"
        );
        assert_eq!(
            stored_authn_token(&auth_url, identity, "repo-a.example.com").await,
            Some(expired_jwt(identity)),
            "A refusal to refresh must leave the stored login untouched"
        );
        assert_eq!(
            token_store::load_refresh_token(&auth_url, identity)
                .await
                .ok()
                .as_deref(),
            Some("refresh-one"),
            "A refusal to refresh must leave the stored refresh token untouched"
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

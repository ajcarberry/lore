// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! The client-side OIDC flows against a real provider.
//!
//! Everything here drives `lore_transport::auth::oidc::OidcAuthentication` through the
//! `Authentication` trait, exactly as `lore login` does, against the `PocketID` container in
//! `compose.yaml`. Nothing is stubbed.
//!
//! Two properties of the flows shape the harness. RFC 8252 §7.3 has the client bind
//! `127.0.0.1:0`, so no client registration written ahead of time can name the redirect URI;
//! the test client is registered once with the wildcard `http://127.0.0.1:*/callback`.
//! And `PocketID`'s only interactive login is a passkey ceremony, so
//! `OidcFixture::follow_authorization_url` stands in for the browser, completing the consent
//! leg over `PocketID`'s JSON API and returning the URL the provider would have redirected
//! to.
#[cfg(all(test, feature = "integration_tests"))]
mod oidc_client_tests {
    use std::error::Error;
    use std::time::Duration;

    use lore_base::types::RepositoryId;
    use lore_credential::token_store;
    use lore_credential::token_store::tokens_only_for_recipient_domain;
    use lore_transport::Authentication;
    use lore_transport::AuthenticationToken;
    use lore_transport::LoginFlow;
    use lore_transport::auth::oidc::OidcAuthentication;

    use crate::common::oidc::oidc_common;
    use crate::common::oidc::oidc_common::OidcFixture;
    use crate::common::oidc::oidc_common::TestUser;

    /// A client of its own, registered with a wildcard port so any loopback redirect the
    /// kernel hands out is a registered callback.
    const CLIENT_ID: &str = "lore-oidc-client-tests";

    /// The wildcard that makes RFC 8252 §7.3's ephemeral port workable against a provider
    /// that validates redirect URIs.
    const CALLBACK_URL: &str = "http://127.0.0.1:*/callback";

    /// `oidc+http` rather than `oidc+https`, which the implementation accepts only because
    /// the issuer is loopback.
    fn auth_url(issuer: &str) -> String {
        format!(
            "oidc+{}?client_id={CLIENT_ID}",
            issuer.trim_end_matches('/')
        )
    }

    async fn setup() -> Result<(OidcFixture, TestUser, String), Box<dyn Error + 'static>> {
        let fixture = oidc_common::setup().await?;
        fixture.ensure_client(CLIENT_ID, &[CALLBACK_URL]).await?;
        let user = fixture.create_user("loreclient").await?;
        let auth_url = auth_url(fixture.issuer());
        Ok((fixture, user, auth_url))
    }

    /// Runs the browser half of a PKCE login and returns the token the implementation
    /// produced.
    async fn login_with_pkce(
        auth: &OidcAuthentication,
        fixture: &OidcFixture,
        user: &TestUser,
        auth_url: &str,
    ) -> Result<AuthenticationToken, Box<dyn Error + 'static>> {
        let session = auth
            .start_auth_session(auth_url, "client-state", LoginFlow::Browser, "")
            .await?;

        // Nothing has arrived at the listener yet, so the flow is genuinely pending.
        assert_eq!(
            auth.poll_auth_session(auth_url, "client-state", &session.session_code, "")
                .await?
                .map(|token| token.user_id),
            None,
            "poll answered before the browser had been anywhere"
        );

        let redirect = fixture
            .follow_authorization_url(user, &session.login_url)
            .await?;
        deliver(&redirect).await?;

        auth.poll_auth_session(auth_url, "client-state", &session.session_code, "")
            .await?
            .ok_or_else(|| anyhow::anyhow!("Poll returned no token after the redirect").into())
    }

    /// Fetches a redirect URL, which is what puts the authorization response in front of the
    /// implementation's loopback listener.
    async fn deliver(redirect: &str) -> Result<(), Box<dyn Error + 'static>> {
        let response = reqwest::Client::new().get(redirect).send().await?;
        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Loopback listener answered {} for the redirect",
                response.status()
            )
            .into());
        }
        Ok(())
    }

    /// The authorization code flow with PKCE over a loopback redirect, end to end against a
    /// real provider.
    ///
    /// Requires the compose stack:
    /// `docker compose --file lore-integration-tests/compose.yaml up --detach pocket-id`
    #[tokio::test]
    async fn pkce_login_yields_a_verifiable_id_token() {
        let (fixture, user, auth_url) = setup().await.expect("PocketID fixture setup failed");
        let auth = OidcAuthentication::default();

        let token = login_with_pkce(&auth, &fixture, &user, &auth_url)
            .await
            .expect("The PKCE login should complete");

        // The credential is the ID token, verified against the provider's own JWKS, which
        // is the path the server takes.
        let claims = fixture
            .validate_token(&token.token, CLIENT_ID)
            .await
            .expect("The credential did not verify against the issuer's JWKS")
            .claims;
        assert_eq!(claims.sub, user.id, "Token is for the wrong subject");
        assert_eq!(claims.iss, fixture.issuer(), "Wrong issuer");
        assert_eq!(claims.aud, vec![CLIENT_ID.to_string()], "Wrong audience");
        assert!(
            claims.nonce.is_some(),
            "The implementation asked for no nonce, so a replay would be undetectable"
        );

        assert_eq!(token.user_id, user.id, "user_id should be the subject");
        assert!(token.expires_ms > 0, "Token carries no expiry");
        // `offline_access` is requested precisely so the session outlives the first token.
        assert!(
            token.refresh_token.is_some(),
            "No refresh token, so the session cannot be kept alive"
        );

        // The token may go back to its issuer, and the orchestration layer adds the remote.
        assert_eq!(
            token.acceptable_root_domains,
            vec![format!("{}/", fixture.issuer())],
            "The implementation should name the issuer as a recipient, and nothing else"
        );
    }

    /// An authorization response belonging to another session must not be exchanged; the
    /// `state` check refuses it before the code is ever used (RFC 9700).
    ///
    /// Requires the compose stack (see above).
    #[tokio::test]
    async fn pkce_refuses_a_response_with_the_wrong_state() {
        let (fixture, user, auth_url) = setup().await.expect("PocketID fixture setup failed");
        let auth = OidcAuthentication::default();

        let session = auth
            .start_auth_session(&auth_url, "client-state", LoginFlow::Browser, "")
            .await
            .expect("The login should start");

        // A real code from a real consent, delivered under somebody else's state.
        let redirect = fixture
            .follow_authorization_url(&user, &session.login_url)
            .await
            .expect("The consent leg should complete");
        let mut tampered = reqwest::Url::parse(&redirect).expect("The redirect should be a URL");
        let query: Vec<(String, String)> = tampered
            .query_pairs()
            .map(|(key, value)| {
                if key == "state" {
                    (key.into_owned(), "another-sessions-state".to_string())
                } else {
                    (key.into_owned(), value.into_owned())
                }
            })
            .collect();
        tampered.query_pairs_mut().clear().extend_pairs(&query);
        deliver(tampered.as_str())
            .await
            .expect("The listener should still answer the request");

        auth.poll_auth_session(&auth_url, "client-state", &session.session_code, "")
            .await
            .expect_err("A response carrying another session's state must not be exchanged");
    }

    /// The device authorization grant behind `lore login --no-browser`, driven with no
    /// browser and no human.
    ///
    /// Requires the compose stack (see above).
    #[tokio::test]
    async fn device_grant_login_yields_a_verifiable_id_token() {
        let (fixture, user, auth_url) = setup().await.expect("PocketID fixture setup failed");
        let auth = OidcAuthentication::default();

        let session = auth
            .start_auth_session(&auth_url, "client-state", LoginFlow::NoBrowser, "")
            .await
            .expect("The device authorization should start");

        // `login_url` is the provider's complete verification URI, which carries the user
        // code.
        assert!(
            session.login_url.starts_with(fixture.issuer()),
            "Verification URI {} is not on the issuer",
            session.login_url
        );
        let user_code = reqwest::Url::parse(&session.login_url)
            .expect("The verification URI should be a URL")
            .query_pairs()
            .find(|(key, _)| key == "code" || key == "user_code")
            .map(|(_, value)| value.into_owned())
            .expect("The verification URI carries no user code");

        // RFC 8628 §3.5 reports an unapproved code as `authorization_pending`, which the
        // trait reports as `None` rather than as a failure.
        assert!(
            auth.poll_auth_session(&auth_url, "client-state", &session.session_code, "")
                .await
                .expect("authorization_pending is not a failure")
                .is_none(),
            "Poll returned a token before anybody approved"
        );

        // The human half: reading the code off the terminal and confirming it.
        fixture
            .approve_user_code(&user, &user_code)
            .await
            .expect("Could not approve the device user code");

        // The provider's advertised interval is honored, so an immediate second poll would
        // not reach the network at all.
        tokio::time::sleep(Duration::from_secs(6)).await;

        let token = auth
            .poll_auth_session(&auth_url, "client-state", &session.session_code, "")
            .await
            .expect("The approved device code should redeem")
            .expect("The approved device code returned no token");

        let claims = fixture
            .validate_token(&token.token, CLIENT_ID)
            .await
            .expect("The credential did not verify against the issuer's JWKS")
            .claims;
        assert_eq!(claims.sub, user.id, "Token is for the wrong subject");
        assert_eq!(token.user_id, user.id);
        assert!(
            token.refresh_token.is_some(),
            "A headless host would have to re-run the whole ceremony on every expiry"
        );
    }

    /// The refresh grant: a stored refresh token yields a new ID token and a rotated
    /// refresh token.
    ///
    /// Requires the compose stack (see above).
    #[tokio::test]
    async fn refresh_grant_yields_a_new_token_and_rotates_the_refresh_token() {
        let (fixture, user, auth_url) = setup().await.expect("PocketID fixture setup failed");
        let auth = OidcAuthentication::default();

        let token = login_with_pkce(&auth, &fixture, &user, &auth_url)
            .await
            .expect("The PKCE login should complete");
        let refresh_token = token
            .refresh_token
            .clone()
            .expect("The login issued no refresh token");

        let refreshed = auth
            .refresh_authentication(&auth_url, &refresh_token, "")
            .await
            .expect("The refresh grant should succeed");

        let claims = fixture
            .validate_token(&refreshed.token, CLIENT_ID)
            .await
            .expect("The refreshed credential did not verify against the issuer's JWKS")
            .claims;
        assert_eq!(
            claims.sub, user.id,
            "Refreshed token is for another subject"
        );
        assert_eq!(refreshed.user_id, user.id);
        assert_eq!(
            refreshed.acceptable_root_domains, token.acceptable_root_domains,
            "A refreshed token has the same recipients as the one it replaces"
        );

        let rotated = refreshed
            .refresh_token
            .expect("The refresh grant returned no new refresh token");
        assert_ne!(
            rotated, refresh_token,
            "The refresh token was not rotated, so a stolen one stays usable"
        );
    }

    /// The refresh grant reached the way it is in production: by an ordinary repository
    /// operation whose stored login has aged out.
    ///
    /// Expiry is staged rather than waited for, since `PocketID`'s token lifetimes are
    /// measured in hours. The client verifies no signatures, so a stored token whose `exp`
    /// is in the past is expired as far as every client-side check is concerned.
    ///
    /// Requires the compose stack (see above).
    #[tokio::test]
    async fn an_expired_login_is_refreshed_by_the_exchange_path() {
        let (fixture, user, auth_url) = setup().await.expect("PocketID fixture setup failed");
        isolated_credential_store();
        let auth = OidcAuthentication::default();

        let token = login_with_pkce(&auth, &fixture, &user, &auth_url)
            .await
            .expect("The PKCE login should complete");
        let refresh_token = token
            .refresh_token
            .clone()
            .expect("The login issued no refresh token");
        let expired = with_expiry_in_the_past(&token.token);

        // What a login leaves behind, some hours later.
        token_store::store_user_token(
            &auth_url,
            &token.user_id,
            &expired,
            vec![REMOTE_DOMAIN.to_string()],
        )
        .await
        .expect("Failed to store the expired authentication token");
        token_store::store_refresh_token(&auth_url, &token.user_id, &refresh_token)
            .await
            .expect("Failed to store the refresh token");

        let authz = lore_transport::auth::exchange::exchange(
            &auth_url,
            &token.user_id,
            RepositoryId::default(),
            REMOTE_DOMAIN.to_string(),
        )
        .await
        .expect("The operation should proceed on a refreshed credential, with no new login");

        assert_ne!(
            authz, expired,
            "The expired credential was presented, so the server would refuse the operation"
        );
        let claims = fixture
            .validate_token(&authz, CLIENT_ID)
            .await
            .expect("The refreshed credential did not verify against the issuer's JWKS")
            .claims;

        // A different token is not necessarily a live one: only `exp` says the refresh
        // bought the caller time.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("The clock is before the epoch")
            .as_secs() as i64;
        assert!(
            claims.exp > now,
            "The refreshed credential expired at {} and it is now {now}",
            claims.exp
        );

        // Rotated, and kept: PocketID retires the refresh token it was given, so storing
        // the new one is what makes the next expiry survivable too.
        let stored_refresh = token_store::load_refresh_token(&auth_url, &token.user_id)
            .await
            .expect("The refresh token is gone, so the next expiry needs a login");
        assert_ne!(
            stored_refresh, refresh_token,
            "The rotated refresh token was not stored, so the session dies at the next expiry"
        );

        // And the refresh did not widen where the credential may be sent.
        assert!(
            token_store::load_user_token(
                &auth_url,
                &token.user_id,
                tokens_only_for_recipient_domain("elsewhere.example.com".to_string()),
            )
            .await
            .is_err(),
            "The refreshed token is offered to a remote the login never named"
        );
    }

    /// The remote the staged login was performed against.
    const REMOTE_DOMAIN: &str = "repo.example.com";

    /// Points the credential store at a directory of its own, with the encryption key in a
    /// file rather than the OS keyring, which on macOS also raises no keychain prompt.
    fn isolated_credential_store() {
        static AUTH_DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
        AUTH_DIR.get_or_init(|| {
            let auth_dir = tempfile::tempdir().expect("Failed to create a credential store dir");
            unsafe {
                std::env::set_var("LORE_AUTH_PATH", auth_dir.path());
                std::env::set_var("LORE_AUTH_STORE", "fallback");
            }
            auth_dir
        });
    }

    /// The same token with its `exp` moved into the past. The signature no longer matches
    /// the claims, which is immaterial: no client-side check reads it.
    fn with_expiry_in_the_past(token: &str) -> String {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let mut parts = token.split('.');
        let header = parts.next().expect("A JWT has a header");
        let payload = parts.next().expect("A JWT has a payload");
        let signature = parts.next().expect("A JWT has a signature");

        let decoded = URL_SAFE_NO_PAD
            .decode(payload)
            .expect("The payload should be base64url");
        let mut claims: serde_json::Value =
            serde_json::from_slice(&decoded).expect("The payload should be JSON");
        claims["exp"] = serde_json::json!(1000000000);

        format!(
            "{header}.{}.{signature}",
            URL_SAFE_NO_PAD.encode(claims.to_string())
        )
    }

    /// `exchange_for_repository` returns the authentication token unchanged: there is
    /// nothing to exchange it with and nothing to mint.
    ///
    /// Requires the compose stack (see above).
    #[tokio::test]
    async fn exchange_for_repository_passes_the_id_token_through() {
        let (fixture, user, auth_url) = setup().await.expect("PocketID fixture setup failed");
        let auth = OidcAuthentication::default();

        let token = login_with_pkce(&auth, &fixture, &user, &auth_url)
            .await
            .expect("The PKCE login should complete");

        let authz = auth
            .exchange_for_repository(&auth_url, &token.token, RepositoryId::default(), "")
            .await
            .expect("The passthrough should succeed");

        assert_eq!(
            authz.token, token.token,
            "The authorization token is the authentication token"
        );
        assert_eq!(authz.expires_ms, token.expires_ms);
        assert_eq!(authz.acceptable_root_domains, token.acceptable_root_domains);

        // And it is still the provider's own signed token, not something Lore minted.
        fixture
            .validate_token(&authz.token, CLIENT_ID)
            .await
            .expect("The passed-through token did not verify against the issuer's JWKS");
    }

    /// `PocketID` 2.6.2 does not implement RFC 8707: it answers `200` to the parameter on
    /// every leg of the grant, ignores it, and mints an access token audienced to the client
    /// id with header `typ: "JWT"`. That silence is why the client checks the token it got
    /// back rather than trusting the flow's success, and this asserts the failure is raised
    /// at login, naming what the provider did not do.
    ///
    /// Requires the compose stack (see above).
    #[tokio::test]
    async fn a_provider_without_resource_indicator_support_fails_the_login_by_name() {
        let (fixture, user, _) = setup().await.expect("PocketID fixture setup failed");
        let auth = OidcAuthentication::default();
        let auth_url = format!(
            "oidc+{}?client_id={CLIENT_ID}&resource=https%3A%2F%2Flore.example.com",
            fixture.issuer().trim_end_matches('/')
        );

        let session = auth
            .start_auth_session(&auth_url, "client-state", LoginFlow::Browser, "")
            .await
            .expect("The login should start: the parameter only matters at the token endpoint");

        // The authorization URL really does carry it, so the provider had every chance.
        assert!(
            session.login_url.contains("resource="),
            "The authorization request dropped the resource indicator: {}",
            session.login_url
        );

        let redirect = fixture
            .follow_authorization_url(&user, &session.login_url)
            .await
            .expect("The consent leg should complete");
        deliver(&redirect)
            .await
            .expect("The listener should answer the redirect");

        let error = auth
            .poll_auth_session(&auth_url, "client-state", &session.session_code, "")
            .await
            .expect_err("A token the server will refuse must not be reported as a login");

        let message = error.to_string();
        assert!(
            message.contains("at+jwt") || message.contains("resource"),
            "The failure has to name what the provider did not do, or an operator has \
             nothing to act on; got: {message}"
        );
    }
}

// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Client-side OIDC flows against the `PocketID` container, driving [`OidcAuthentication`]
//! through the `Authentication` trait exactly as `lore login` does;
//! `OidcFixture::follow_authorization_url` stands in for the browser.
#[cfg(all(test, feature = "oidc_integration_tests"))]
mod oidc_client_tests {
    use std::error::Error;
    use std::time::Duration;

    use lore_base::runtime::LORE_CONTEXT;
    use lore_transport::Authentication;
    use lore_transport::AuthenticationToken;
    use lore_transport::LoginFlow;
    use lore_transport::TokenRecipients;
    use lore_transport::auth::oidc::OidcAuthentication;

    use crate::common::oidc as oidc_common;
    use crate::common::oidc::OidcFixture;
    use crate::common::oidc::TestUser;
    use crate::setup_execution;

    /// A client of its own, registered with a wildcard port so any loopback redirect is
    /// registered.
    const CLIENT_ID: &str = "lore-oidc-client-tests";

    /// The wildcard that makes RFC 8252 §7.3's ephemeral port workable against redirect-URI
    /// validation.
    const CALLBACK_URL: &str = "http://127.0.0.1:*/callback";

    /// The ceiling on every poll loop below, in 500ms steps.
    const POLL_ATTEMPTS: usize = 60;
    const POLL_INTERVAL: Duration = Duration::from_millis(500);

    /// `oidc+http`, accepted only because the issuer is loopback. The issuer is kept
    /// byte for byte, as the server derives it.
    fn auth_url(issuer: &str) -> String {
        format!("oidc+{issuer}?client_id={CLIENT_ID}")
    }

    async fn setup() -> Result<(OidcFixture, TestUser, String), Box<dyn Error + 'static>> {
        let fixture = oidc_common::setup().await?;
        fixture.ensure_client(CLIENT_ID, &[CALLBACK_URL]).await?;
        let user = fixture.create_user("loreclient").await?;
        let auth_url = auth_url(fixture.issuer());
        Ok((fixture, user, auth_url))
    }

    /// Runs the browser half of a PKCE login and returns the resulting token.
    async fn login_with_pkce(
        auth: &OidcAuthentication,
        fixture: &OidcFixture,
        user: &TestUser,
        auth_url: &str,
    ) -> Result<AuthenticationToken, Box<dyn Error + 'static>> {
        let session = auth
            .start_auth_session(auth_url, "client-state", LoginFlow::Browser, "")
            .await?;

        // The listener has been given nothing yet, so the flow is pending.
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

        // The listener records the delivered code on its own task, so poll until it has.
        for _ in 0..POLL_ATTEMPTS {
            if let Some(token) = auth
                .poll_auth_session(auth_url, "client-state", &session.session_code, "")
                .await?
            {
                return Ok(token);
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
        Err(anyhow::anyhow!("Poll returned no token after the redirect").into())
    }

    /// Fetches a redirect URL, putting the authorization response in front of the loopback
    /// listener.
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
    /// Requires the compose stack (`docker compose --file lore-integration-tests/compose.yaml
    /// up --detach pocket-id`).
    #[tokio::test]
    async fn pkce_login_yields_a_verifiable_id_token() {
        LORE_CONTEXT
            .scope(setup_execution("test".to_string()), async move {
                let (fixture, user, auth_url) =
                    setup().await.expect("PocketID fixture setup failed");
                let auth = OidcAuthentication::default();

                let token = login_with_pkce(&auth, &fixture, &user, &auth_url)
                    .await
                    .expect("The PKCE login should complete");

                // The credential is the ID token, verified against the provider's own JWKS
                // — the same path the server takes.
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
                // `offline_access` is requested precisely so the session outlives the first
                // token.
                assert!(
                    token.refresh_token.is_some(),
                    "No refresh token, so the session cannot be kept alive"
                );

                // The token may go back to its issuer, and the orchestration layer adds the
                // remote. For this loopback issuer the recipient is the whole URL
                // (an IP host has no domain to extract); against a real
                // `oidc+https` issuer it is the bare host.
                assert_eq!(
                    token.recipients,
                    TokenRecipients::Explicit(vec![format!("{}/", fixture.issuer())]),
                    "The implementation should name the issuer as a recipient, and nothing else"
                );
            })
            .await;
    }

    /// An authorization response belonging to another session must not be exchanged, and
    /// must not end the login either: the listener answers 404 and keeps waiting (a forged
    /// callback cannot close it ahead of the real redirect), and the genuine redirect that
    /// follows still completes the login (RFC 9700; RFC 8252 §8.3).
    ///
    /// Requires the compose stack (see above).
    #[tokio::test]
    async fn pkce_ignores_a_response_with_the_wrong_state() {
        LORE_CONTEXT
            .scope(setup_execution("test".to_string()), async move {
                let (fixture, user, auth_url) =
                    setup().await.expect("PocketID fixture setup failed");
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
                let mut tampered =
                    reqwest::Url::parse(&redirect).expect("The redirect should be a URL");
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
                let status = reqwest::Client::new()
                    .get(tampered.as_str())
                    .send()
                    .await
                    .expect("The listener should still answer the request")
                    .status();
                assert_eq!(
                    status,
                    reqwest::StatusCode::NOT_FOUND,
                    "A response carrying another session's state must not be treated as this \
                     login's"
                );

                // The forged response neither completed nor killed the login.
                assert!(
                    auth.poll_auth_session(&auth_url, "client-state", &session.session_code, "")
                        .await
                        .expect("A forged response must not fail the login")
                        .is_none(),
                    "A response carrying another session's state was exchanged"
                );

                // The genuine redirect still lands, so a local forger cannot
                // deny the login either.
                deliver(&redirect)
                    .await
                    .expect("The listener should accept the genuine redirect");
                let mut completed = None;
                for _ in 0..POLL_ATTEMPTS {
                    if let Some(token) = auth
                        .poll_auth_session(&auth_url, "client-state", &session.session_code, "")
                        .await
                        .expect("The genuine redirect should complete the login")
                    {
                        completed = Some(token);
                        break;
                    }
                    tokio::time::sleep(POLL_INTERVAL).await;
                }
                let token = completed.expect("The login never completed after the real redirect");
                assert_eq!(token.user_id, user.id, "user_id should be the subject");
            })
            .await;
    }

    /// The device authorization grant behind `lore login --no-browser`, driven with no
    /// browser and no human.
    ///
    /// Requires the compose stack (see above).
    #[tokio::test]
    async fn device_grant_login_yields_a_verifiable_id_token() {
        LORE_CONTEXT
            .scope(setup_execution("test".to_string()), async move {
                let (fixture, user, auth_url) =
                    setup().await.expect("PocketID fixture setup failed");
                let auth = OidcAuthentication::default();

                let session = auth
                    .start_auth_session(&auth_url, "client-state", LoginFlow::NoBrowser, "")
                    .await
                    .expect("The device authorization should start");

                // `login_url` is the provider's complete verification URI, carrying the user
                // code.
                assert!(
                    session.login_url.starts_with(fixture.issuer()),
                    "Verification URI {} is not on the issuer",
                    session.login_url
                );
                // RFC 8628 §3.3.1: the session surfaces the code for display,
                // which is also what a person would approve with.
                let user_code = session
                    .user_code
                    .clone()
                    .expect("A device session must surface its user code");

                // RFC 8628 §3.5's `authorization_pending` is reported by the trait as
                // `None`, not a failure.
                assert!(
                    auth.poll_auth_session(&auth_url, "client-state", &session.session_code, "")
                        .await
                        .expect("authorization_pending is not a failure")
                        .is_none(),
                    "Poll returned a token before anybody approved"
                );

                // The approval a person would give after reading the code off the terminal.
                fixture
                    .approve_user_code(&user, &user_code)
                    .await
                    .expect("Could not approve the device user code");

                let mut redeemed = None;
                for _ in 0..POLL_ATTEMPTS {
                    if let Some(token) = auth
                        .poll_auth_session(&auth_url, "client-state", &session.session_code, "")
                        .await
                        .expect("The approved device code should redeem")
                    {
                        redeemed = Some(token);
                        break;
                    }
                    tokio::time::sleep(POLL_INTERVAL).await;
                }
                let token = redeemed.expect("The approved device code returned no token");

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
            })
            .await;
    }
}

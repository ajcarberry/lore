// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Provisioning helpers for the `PocketID` instance in `lore-integration-tests/compose.yaml`.
//!
//! `PocketID` only supports passkey login interactively, so this drives its documented
//! admin API instead: a one-time access token substitutes for the passkey session cookie,
//! which then drives the same `authorize` endpoint the web UI and device-grant approval use.
//! Every token returned is minted and signed by the real `PocketID` instance.
#[cfg(all(test, feature = "integration_tests"))]
pub(crate) mod oidc_common {
    use std::error::Error;

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use jsonwebtoken::Algorithm;
    use jsonwebtoken::DecodingKey;
    use jsonwebtoken::TokenData;
    use jsonwebtoken::Validation;
    use jsonwebtoken::jwk::AlgorithmParameters;
    use jsonwebtoken::jwk::JwkSet;
    use reqwest::StatusCode;
    use serde::Deserialize;
    use serde_json::Value;
    use serde_json::json;
    use tracing::info;

    /// Must match the port published for `pocket-id` in `compose.yaml`.
    const POCKET_ID_URL: &str = "http://127.0.0.1:1411";

    /// Hardcoded in lore-integration-tests/compose.yaml as `STATIC_API_KEY`.
    const API_KEY: &str = "lorelocaltestapikeylorelocaltestapikey";

    /// The OIDC client every test shares; stable across runs since `PocketID` accepts a
    /// caller-chosen id.
    pub const TEST_CLIENT_ID: &str = "lore-integration-tests";

    /// Loopback redirect for the authorization-code flow; nothing listens on it since the
    /// code comes back in the JSON response, not a real redirect.
    pub const TEST_REDIRECT_URI: &str = "http://127.0.0.1:19999/callback";

    const SCOPE: &str = "openid profile email";

    /// A user provisioned in `PocketID`, along with the id `PocketID` will put in `sub`.
    #[derive(Clone, Debug)]
    pub struct TestUser {
        pub id: String,
        pub username: String,
        pub email: String,
    }

    /// The token endpoint's response.
    #[derive(Clone, Debug, Deserialize)]
    pub struct TokenSet {
        pub access_token: String,
        pub id_token: String,
        pub refresh_token: Option<String>,
        pub expires_in: i64,
    }

    /// A pending RFC 8628 device authorization.
    #[derive(Clone, Debug, Deserialize)]
    pub struct DeviceAuthorization {
        pub device_code: String,
        pub user_code: String,
        pub verification_uri: String,
        pub expires_in: i64,
        /// Seconds a conforming client must wait between polls of the token endpoint.
        pub interval: i64,
    }

    /// The claims Lore cares about; `aud` is `Vec<String>` because `PocketID` sends it as
    /// an array.
    #[derive(Clone, Debug, Deserialize)]
    pub struct PocketIdClaims {
        pub sub: String,
        pub iss: String,
        pub aud: Vec<String>,
        pub exp: i64,
        #[serde(default)]
        pub nonce: Option<String>,
        #[serde(default)]
        pub preferred_username: Option<String>,
        #[serde(default)]
        pub email: Option<String>,
        /// `id-token` or `oauth-access-token`.
        #[serde(rename = "type", default)]
        pub token_type: Option<String>,
    }

    pub struct OidcFixture {
        client: reqwest::Client,
        base_url: String,
    }

    /// Points the fixture at the compose-managed `PocketID` and ensures the shared OIDC
    /// client exists.
    ///
    /// Idempotent under parallel tests: a losing racer treats `PocketID`'s duplicate-client
    /// rejection as success.
    pub async fn setup() -> Result<OidcFixture, Box<dyn Error + 'static>> {
        let _ = tracing_subscriber::fmt::try_init();

        let fixture = OidcFixture {
            client: reqwest::Client::builder().build()?,
            base_url: POCKET_ID_URL.to_string(),
        };

        fixture.wait_until_ready().await?;
        fixture
            .ensure_client(TEST_CLIENT_ID, &[TEST_REDIRECT_URI])
            .await?;

        Ok(fixture)
    }

    impl OidcFixture {
        /// The issuer `PocketID` signs tokens with.
        pub fn issuer(&self) -> &str {
            &self.base_url
        }

        fn url(&self, path: &str) -> String {
            format!("{}{path}", self.base_url)
        }

        /// Waits until the container serves and accepts the admin API key. `/healthz`
        /// answering does not mean the static admin has been provisioned, so an admin call
        /// issued at healthz can still get a 401 — both conditions are polled.
        async fn wait_until_ready(&self) -> Result<(), Box<dyn Error + 'static>> {
            let mut healthy = false;
            for attempt in 1..=30 {
                if !healthy {
                    match self.client.get(self.url("/healthz")).send().await {
                        Ok(response) if response.status().is_success() => healthy = true,
                        Ok(response) => info!(
                            "PocketID health check returned {} on attempt {attempt}",
                            response.status()
                        ),
                        Err(e) => info!("PocketID not reachable on attempt {attempt}: {e}"),
                    }
                }
                if healthy {
                    // An authenticated read the admin user is provisioned for. A 401 means
                    // the admin does not exist yet; anything else means the key is accepted.
                    match self
                        .client
                        .get(self.url("/api/oidc/clients"))
                        .header("X-API-KEY", API_KEY)
                        .send()
                        .await
                    {
                        Ok(response) if response.status() != reqwest::StatusCode::UNAUTHORIZED => {
                            return Ok(());
                        }
                        Ok(_) => info!("PocketID admin API not ready on attempt {attempt}"),
                        Err(e) => {
                            info!("PocketID admin API not reachable on attempt {attempt}: {e}");
                        }
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }

            Err(anyhow::anyhow!(
                "PocketID at {} did not become ready. Start it with: \
                 docker compose --file lore-integration-tests/compose.yaml up --detach pocket-id",
                self.base_url
            )
            .into())
        }

        /// Send a JSON request authenticated as the static admin user.
        async fn admin_post(
            &self,
            path: &str,
            body: Value,
        ) -> Result<reqwest::Response, Box<dyn Error + 'static>> {
            Ok(self
                .client
                .post(self.url(path))
                .header("X-API-KEY", API_KEY)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(serde_json::to_vec(&body)?)
                .send()
                .await?)
        }

        /// Fails with the endpoint's own error text, the only place `PocketID` explains
        /// validation failures.
        async fn json_or_error(
            path: &str,
            response: reqwest::Response,
        ) -> Result<Value, Box<dyn Error + 'static>> {
            let status = response.status();
            let body = response.text().await?;
            if !status.is_success() {
                return Err(anyhow::anyhow!("POST {path} failed with {status}: {body}").into());
            }
            Ok(serde_json::from_str(if body.is_empty() {
                "{}"
            } else {
                &body
            })?)
        }

        /// Register a public PKCE client, tolerating one that is already there.
        pub async fn ensure_client(
            &self,
            client_id: &str,
            callback_urls: &[&str],
        ) -> Result<(), Box<dyn Error + 'static>> {
            let response = self
                .admin_post(
                    "/api/oidc/clients",
                    json!({
                        "id": client_id,
                        "name": client_id,
                        "callbackURLs": callback_urls,
                        // Public + PKCE is what a CLI is: no client secret to ship.
                        "isPublic": true,
                        "pkceEnabled": true,
                    }),
                )
                .await?;

            // Losing this race is normal: the container persists across runs, and
            // PocketID reports the collision as a 400 naming the id.
            if response.status() == StatusCode::BAD_REQUEST {
                let body = response.text().await?;
                if body.contains("already in use") {
                    return Ok(());
                }
                return Err(anyhow::anyhow!("Could not create OIDC client: {body}").into());
            }

            Self::json_or_error("/api/oidc/clients", response).await?;
            Ok(())
        }

        /// Provisions a user; a random suffix keeps parallel tests from colliding on the
        /// unique username and email.
        pub async fn create_user(
            &self,
            prefix: &str,
        ) -> Result<TestUser, Box<dyn Error + 'static>> {
            let username = format!("{prefix}{}", uuid::Uuid::new_v4().simple());
            let email = format!("{username}@example.invalid");

            let response = self
                .admin_post(
                    "/api/users",
                    json!({
                        "username": &username,
                        "email": &email,
                        "emailVerified": true,
                        "firstName": "Lore",
                        "lastName": "Test",
                        "isAdmin": false,
                    }),
                )
                .await?;

            let user = Self::json_or_error("/api/users", response).await?;
            let id = user["id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Created user has no id: {user}"))?
                .to_string();

            Ok(TestUser {
                id,
                username,
                email,
            })
        }

        /// Logs `user` in without a passkey, returning the session cookie rather than
        /// keeping it in a cookie jar: `PocketID` marks it `Secure` even over plain HTTP,
        /// which a conforming jar would drop.
        async fn login(&self, user: &TestUser) -> Result<String, Box<dyn Error + 'static>> {
            let path = format!("/api/users/{}/one-time-access-token", user.id);
            let response = self.admin_post(&path, json!({ "ttl": "1h" })).await?;
            let token = Self::json_or_error(&path, response).await?;
            let token = token["token"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("No one-time access token in response: {token}"))?
                .to_string();

            // Unauthenticated by design: the one-time token is the credential.
            let exchange_path = format!("/api/one-time-access-token/{token}");
            let response = self.client.post(self.url(&exchange_path)).send().await?;
            let status = response.status();
            let cookie = response
                .headers()
                .get_all(reqwest::header::SET_COOKIE)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .filter_map(|value| value.split(';').next())
                .find(|pair| {
                    // Cookie name depends on APP_URL's scheme: PocketID uses the __Host-
                    // prefix only over https.
                    pair.starts_with("access_token=") || pair.starts_with("__Host-access_token=")
                })
                .map(str::to_string);

            cookie.ok_or_else(|| {
                anyhow::anyhow!(
                    "Exchanging the one-time access token returned {status} but set no \
                     session cookie"
                )
                .into()
            })
        }

        /// Completes an authorization-code + PKCE exchange as `user` using
        /// [`TEST_CLIENT_ID`] and returns the minted tokens.
        pub async fn issue_token(
            &self,
            user: &TestUser,
        ) -> Result<TokenSet, Box<dyn Error + 'static>> {
            self.issue_token_for_client(user, TEST_CLIENT_ID).await
        }

        /// As [`issue_token`](Self::issue_token), but for an arbitrary client id.
        pub async fn issue_token_for_client(
            &self,
            user: &TestUser,
            client_id: &str,
        ) -> Result<TokenSet, Box<dyn Error + 'static>> {
            let session_cookie = self.login(user).await?;

            let verifier = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
            let challenge = URL_SAFE_NO_PAD.encode(ring::digest::digest(
                &ring::digest::SHA256,
                verifier.as_bytes(),
            ));
            let nonce = uuid::Uuid::new_v4().simple().to_string();

            // The endpoint the PocketID web UI calls post-approval; a session cookie
            // substitutes for the browser.
            let authorize_body = json!({
                "clientID": client_id,
                "scope": SCOPE,
                "callbackURL": TEST_REDIRECT_URI,
                "nonce": &nonce,
                "codeChallenge": challenge,
                "codeChallengeMethod": "S256",
            });
            let response = self
                .client
                .post(self.url("/api/oidc/authorize"))
                .header(reqwest::header::COOKIE, &session_cookie)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(serde_json::to_vec(&authorize_body)?)
                .send()
                .await?;
            let authorization = Self::json_or_error("/api/oidc/authorize", response).await?;
            let code = authorization["code"].as_str().ok_or_else(|| {
                anyhow::anyhow!("Authorize returned no code, got: {authorization}")
            })?;

            let form = [
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", TEST_REDIRECT_URI),
                ("client_id", client_id),
                ("code_verifier", &verifier),
            ];
            let response = self
                .client
                .post(self.url("/api/oidc/token"))
                .form(&form)
                .send()
                .await?;
            let tokens = Self::json_or_error("/api/oidc/token", response).await?;

            Ok(serde_json::from_value(tokens)?)
        }

        /// Plays the browser for one authorization-code flow: follows `authorization_url`
        /// and returns the URL the provider would have redirected to, carrying `code` and
        /// echoing `state`.
        ///
        /// Reads everything it needs from the URL, since that is all a browser is given.
        pub async fn follow_authorization_url(
            &self,
            user: &TestUser,
            authorization_url: &str,
        ) -> Result<String, Box<dyn Error + 'static>> {
            let url = reqwest::Url::parse(authorization_url)?;
            let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
            let parameter = |name: &str| -> Result<String, Box<dyn Error + 'static>> {
                query.get(name).cloned().ok_or_else(|| {
                    anyhow::anyhow!("Authorization URL carries no {name}: {authorization_url}")
                        .into()
                })
            };

            let redirect_uri = parameter("redirect_uri")?;
            let state = parameter("state")?;
            let session_cookie = self.login(user).await?;

            let authorize_body = json!({
                "clientID": parameter("client_id")?,
                "scope": parameter("scope")?,
                "callbackURL": &redirect_uri,
                "nonce": parameter("nonce")?,
                "codeChallenge": parameter("code_challenge")?,
                "codeChallengeMethod": parameter("code_challenge_method")?,
            });
            let response = self
                .client
                .post(self.url("/api/oidc/authorize"))
                .header(reqwest::header::COOKIE, &session_cookie)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(serde_json::to_vec(&authorize_body)?)
                .send()
                .await?;
            let authorization = Self::json_or_error("/api/oidc/authorize", response).await?;
            let code = authorization["code"].as_str().ok_or_else(|| {
                anyhow::anyhow!("Authorize returned no code, got: {authorization}")
            })?;

            let mut redirect = reqwest::Url::parse(&redirect_uri)?;
            redirect
                .query_pairs_mut()
                .append_pair("code", code)
                .append_pair("state", &state);
            Ok(redirect.into())
        }

        /// Begins an RFC 8628 device authorization; no session yet, so no credentials
        /// needed.
        pub async fn start_device_authorization(
            &self,
        ) -> Result<DeviceAuthorization, Box<dyn Error + 'static>> {
            let response = self
                .client
                .post(self.url("/api/oidc/device/authorize"))
                .form(&[("client_id", TEST_CLIENT_ID), ("scope", SCOPE)])
                .send()
                .await?;
            let authorization = Self::json_or_error("/api/oidc/device/authorize", response).await?;

            Ok(serde_json::from_value(authorization)?)
        }

        /// Approves a device `user_code` as `user`, standing in for the human half of the
        /// flow via the session cookie.
        pub async fn approve_user_code(
            &self,
            user: &TestUser,
            user_code: &str,
        ) -> Result<(), Box<dyn Error + 'static>> {
            let session_cookie = self.login(user).await?;
            let response = self
                .client
                .post(self.url("/api/oidc/device/verify"))
                .query(&[("code", user_code)])
                .header(reqwest::header::COOKIE, &session_cookie)
                .send()
                .await?;

            let status = response.status();
            if !status.is_success() {
                let body = response.text().await?;
                return Err(
                    anyhow::anyhow!("Approving device code failed with {status}: {body}").into(),
                );
            }
            Ok(())
        }

        /// Redeems an approved `device_code` for tokens (a real client would poll until
        /// approval).
        pub async fn redeem_device_code(
            &self,
            device_code: &str,
        ) -> Result<TokenSet, Box<dyn Error + 'static>> {
            let response = self
                .client
                .post(self.url("/api/oidc/token"))
                .form(&[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("device_code", device_code),
                    ("client_id", TEST_CLIENT_ID),
                ])
                .send()
                .await?;
            let tokens = Self::json_or_error("/api/oidc/token", response).await?;

            Ok(serde_json::from_value(tokens)?)
        }

        /// Fetch the issuer's discovery document.
        pub async fn discovery(&self) -> Result<Value, Box<dyn Error + 'static>> {
            Ok(serde_json::from_str(
                &self
                    .client
                    .get(self.url("/.well-known/openid-configuration"))
                    .send()
                    .await?
                    .text()
                    .await?,
            )?)
        }

        /// Verifies a token's signature against the issuer's published JWKS (found via
        /// discovery) and returns its claims.
        pub async fn validate_token(
            &self,
            token: &str,
            audience: &str,
        ) -> Result<TokenData<PocketIdClaims>, Box<dyn Error + 'static>> {
            let discovery = self.discovery().await?;
            let issuer = discovery["issuer"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Discovery document has no issuer"))?;
            let jwks_uri = discovery["jwks_uri"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Discovery document has no jwks_uri"))?;

            let jwks: JwkSet =
                serde_json::from_str(&self.client.get(jwks_uri).send().await?.text().await?)?;

            let header = jsonwebtoken::decode_header(token)?;
            let kid = header
                .kid
                .ok_or_else(|| anyhow::anyhow!("Token header has no kid"))?;
            let jwk = jwks
                .find(&kid)
                .ok_or_else(|| anyhow::anyhow!("JWKS has no key for kid {kid}"))?;
            let AlgorithmParameters::RSA(rsa) = &jwk.algorithm else {
                return Err(anyhow::anyhow!("Key {kid} is not RSA: {:?}", jwk.algorithm).into());
            };
            let decoding_key = DecodingKey::from_rsa_components(&rsa.n, &rsa.e)?;

            let mut validation = Validation::new(Algorithm::RS256);
            validation.set_issuer(&[issuer]);
            validation.set_audience(&[audience]);

            Ok(jsonwebtoken::decode::<PocketIdClaims>(
                token,
                &decoding_key,
                &validation,
            )?)
        }
    }

    /// A `PocketID` container, driven only through its documented API, issues a real signed
    /// token for a user it has never logged in.
    ///
    /// Requires the compose stack (`docker compose --file lore-integration-tests/compose.yaml
    /// up --detach pocket-id`).
    #[tokio::test]
    async fn pocket_id_issues_a_verifiable_token_without_a_browser() {
        let fixture = setup().await.expect("PocketID fixture setup failed");
        let user = fixture
            .create_user("loretest")
            .await
            .expect("Could not provision a test user");

        let tokens = fixture
            .issue_token(&user)
            .await
            .expect("Could not issue a token");

        // Both tokens must verify against the JWKS that discovery points at.
        for token in [&tokens.id_token, &tokens.access_token] {
            let claims = fixture
                .validate_token(token, TEST_CLIENT_ID)
                .await
                .expect("Token did not validate against the issuer's JWKS")
                .claims;

            assert_eq!(claims.iss, fixture.issuer(), "Wrong issuer");
            assert_eq!(
                claims.aud,
                vec![TEST_CLIENT_ID.to_string()],
                "Wrong audience"
            );
            assert_eq!(claims.sub, user.id, "Token is for the wrong subject");
        }

        let id_claims = fixture
            .validate_token(&tokens.id_token, TEST_CLIENT_ID)
            .await
            .expect("id_token did not validate")
            .claims;
        assert_eq!(
            id_claims.preferred_username.as_deref(),
            Some(user.username.as_str())
        );
        assert_eq!(id_claims.email.as_deref(), Some(user.email.as_str()));
        assert_eq!(id_claims.token_type.as_deref(), Some("id-token"));
        assert!(tokens.expires_in > 0, "Token expires immediately");
        assert!(id_claims.exp > 0, "id_token carries no expiry");
        // The nonce binds the token to this exchange.
        assert!(
            id_claims.nonce.is_some(),
            "id_token did not echo the request nonce"
        );

        // The refresh grant keeps a `lore` session alive past expiry.
        assert!(
            tokens.refresh_token.is_some(),
            "No refresh token issued for a public PKCE client"
        );

        // A token minted for another client must not pass as one of ours.
        let other_client = "lore-integration-tests-other";
        fixture
            .ensure_client(other_client, &[TEST_REDIRECT_URI])
            .await
            .expect("Could not create the second client");
        let other = fixture
            .issue_token_for_client(&user, other_client)
            .await
            .expect("Could not issue a token for the second client");
        assert!(
            fixture
                .validate_token(&other.id_token, TEST_CLIENT_ID)
                .await
                .is_err(),
            "A token issued for {other_client} validated as {TEST_CLIENT_ID}"
        );
    }

    /// The device authorization grant (RFC 8628), driven end to end with no browser.
    ///
    /// Requires the compose stack (`docker compose --file lore-integration-tests/compose.yaml
    /// up --detach pocket-id`).
    #[tokio::test]
    async fn pocket_id_device_grant_completes_without_a_browser() {
        let fixture = setup().await.expect("PocketID fixture setup failed");

        // The client keys off the advertisement rather than assuming support.
        let discovery = fixture
            .discovery()
            .await
            .expect("Could not fetch the discovery document");
        assert_eq!(
            discovery["device_authorization_endpoint"].as_str(),
            Some(format!("{}/api/oidc/device/authorize", fixture.issuer()).as_str()),
            "Discovery does not advertise a device authorization endpoint"
        );
        let grant_types = discovery["grant_types_supported"]
            .as_array()
            .expect("Discovery has no grant_types_supported");
        assert!(
            grant_types
                .iter()
                .any(|grant| grant.as_str() == Some("urn:ietf:params:oauth:grant-type:device_code")),
            "Discovery does not advertise the device_code grant: {grant_types:?}"
        );

        let user = fixture
            .create_user("loredevice")
            .await
            .expect("Could not provision a test user");

        // Leg one: the headless client asks for a code, holding no credentials.
        let authorization = fixture
            .start_device_authorization()
            .await
            .expect("Could not start a device authorization");
        assert!(!authorization.user_code.is_empty(), "No user code issued");
        assert!(
            authorization.verification_uri.starts_with(fixture.issuer()),
            "Verification URI {} is not on the issuer",
            authorization.verification_uri
        );
        assert!(
            authorization.expires_in > 0,
            "Device code expires immediately"
        );
        assert!(authorization.interval > 0, "No poll interval advertised");

        // Leg two: approval, standing in for the human reading the code off a terminal.
        fixture
            .approve_user_code(&user, &authorization.user_code)
            .await
            .expect("Could not approve the device user code");

        // Leg three: the client collects real tokens for the approved code.
        let tokens = fixture
            .redeem_device_code(&authorization.device_code)
            .await
            .expect("Could not redeem the device code");

        let claims = fixture
            .validate_token(&tokens.id_token, TEST_CLIENT_ID)
            .await
            .expect("Device-flow id_token did not validate against the issuer's JWKS")
            .claims;
        assert_eq!(claims.sub, user.id, "Token is for the wrong subject");
        assert_eq!(claims.iss, fixture.issuer(), "Wrong issuer");
        assert_eq!(
            claims.aud,
            vec![TEST_CLIENT_ID.to_string()],
            "Wrong audience"
        );

        // The refresh grant has to work for a device login too.
        assert!(
            tokens.refresh_token.is_some(),
            "No refresh token issued for the device grant"
        );

        // A device code is single-use: redeeming it twice must not mint a second token.
        assert!(
            fixture
                .redeem_device_code(&authorization.device_code)
                .await
                .is_err(),
            "The same device code was redeemed twice"
        );
    }
}

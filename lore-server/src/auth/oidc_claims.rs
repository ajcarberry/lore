// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! The claim shape `[server.auth.oidc]` reads a provider-issued ID token into,
//! and its conversion to the [`AuthorizationToken`] the rest of the server uses.
use serde::Deserialize;
use serde_with::OneOrMany;
use serde_with::formats::PreferMany;
use serde_with::serde_as;

use crate::auth::jwt::AuthorizationToken;
use crate::auth::jwt::ResourcePermission;

/// The claim shape a provider-issued ID token is read into in OIDC mode.
///
/// It requires only what RFC 7519 and `OpenID` Connect Core guarantee — `iss`,
/// `sub`, `aud`, `exp`, `iat` — so a conformant ID token satisfies it.
#[serde_as]
#[derive(Debug, Deserialize)]
pub(crate) struct OidcTokenClaims {
    #[serde(rename = "sub")]
    user_id: String,
    #[serde(rename = "iss")]
    issuer: String,
    #[serde(rename = "iat")]
    issued_at: u64,
    #[serde(rename = "exp")]
    expires: u64,
    #[serde_as(as = "OneOrMany<_, PreferMany>")]
    #[serde(rename = "aud")]
    audience: Vec<String>,
    name: Option<String>,
    preferred_username: Option<String>,
}

impl From<OidcTokenClaims> for AuthorizationToken {
    /// Maps a minimal provider-issued token onto the shape the rest of the
    /// server reads, with the display fields falling back to `sub`. `resources`
    /// is always the all-repositories wildcard: this conversion is reachable
    /// only from a [`JwtVerifierMode::Oidc`] verifier, whose
    /// `authorize_all_repositories` configuration is what the wildcard records.
    ///
    /// [`JwtVerifierMode::Oidc`]: crate::auth::jwt::JwtVerifierMode::Oidc
    fn from(claims: OidcTokenClaims) -> Self {
        let display_name = claims.name.unwrap_or_else(|| claims.user_id.clone());
        let preferred_username = claims
            .preferred_username
            .unwrap_or_else(|| claims.user_id.clone());

        AuthorizationToken {
            user_id: claims.user_id,
            issuer: claims.issuer.clone(),
            issued_at: claims.issued_at,
            expires: claims.expires,
            audience: claims.audience,
            env: String::default(),
            name: display_name,
            preferred_username,
            resources: Some(vec![ResourcePermission {
                resource_id: "urc-*".to_string(),
                permission: vec![],
            }]),
            groups: None,
            is_service_account: None,
            idp: claims.issuer,
        }
    }
}

/// The third-and-final claim decode, reached only when the token carries
/// none of the Lore-specific claims.
#[cfg(test)]
mod oidc_third_decode {
    use std::ops::Add;
    use std::sync::Arc;
    use std::time::Duration;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    use async_trait::async_trait;
    use jsonwebtoken::Algorithm;
    use jsonwebtoken::DecodingKey;
    use jsonwebtoken::EncodingKey;
    use jsonwebtoken::Header;
    use jsonwebtoken::encode;
    use serde_json::json;

    use crate::auth::jwk::JWKService;
    use crate::auth::jwk::JWKServiceError;
    use crate::auth::jwt::JwtVerifier;
    use crate::auth::jwt::JwtVerifierError;

    const AGREED_UPON_ALGORITHM: Algorithm = Algorithm::HS256;
    const AGREED_UPON_SIGNING_SECRET: &str = "the-secret";

    fn agreed_upon_key() -> (DecodingKey, Algorithm) {
        (
            DecodingKey::from_secret(AGREED_UPON_SIGNING_SECRET.as_ref()),
            AGREED_UPON_ALGORITHM,
        )
    }

    /// Serves the one key these tokens are signed with, whatever key id is asked
    /// for. Nothing here turns on rotation, so a refresh offers no replacement.
    struct AgreedUponJWKService;

    #[async_trait]
    impl JWKService for AgreedUponJWKService {
        async fn get_key(&self, _kid: &str) -> Result<(DecodingKey, Algorithm), JWKServiceError> {
            Ok(agreed_upon_key())
        }

        fn get_cached_key(&self, _kid: &str) -> Option<(DecodingKey, Algorithm)> {
            Some(agreed_upon_key())
        }

        async fn refresh_key(
            &self,
            _kid: &str,
        ) -> Result<Option<(DecodingKey, Algorithm)>, JWKServiceError> {
            Ok(None)
        }
    }

    fn encode_jwt(jwt_claims: &serde_json::Value) -> String {
        let jwt_key = EncodingKey::from_secret(AGREED_UPON_SIGNING_SECRET.as_ref());
        let jwt_header = {
            let mut header = Header::new(AGREED_UPON_ALGORITHM);
            header.kid = Some("the kid".into());
            header
        };

        encode(&jwt_header, jwt_claims, &jwt_key).unwrap()
    }

    fn oidc_verifier() -> JwtVerifier {
        JwtVerifier::oidc(
            Arc::new(AgreedUponJWKService),
            Some("https://id.example.com".to_string()),
            Some(vec!["lore".to_string()]),
        )
    }

    fn minimal_claims() -> serde_json::Value {
        json!({
            "sub": "the-subject",
            "iss": "https://id.example.com",
            "aud": "lore",
            "iat": 1,
            "exp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .add(Duration::from_secs(5))
                .as_secs(),
        })
    }

    #[tokio::test]
    async fn minimal_claims_are_accepted_and_wildcarded() {
        let encoded = encode_jwt(&minimal_claims());

        let token = oidc_verifier()
            .verify_token(&encoded)
            .await
            .expect("a conformant minimal ID token is accepted");

        assert_eq!(token.user_id, "the-subject");
        assert_eq!(token.issuer, "https://id.example.com");
        assert_eq!(token.idp, "https://id.example.com");
        // No `name`/`preferred_username` in the token: both fall back to `sub`.
        assert_eq!(token.name, "the-subject");
        assert_eq!(token.preferred_username, "the-subject");
        assert_eq!(token.env, "");
        let resources = token.resources.expect("wildcard resource is populated");
        assert!(resources[0].is_wildcard_resource());
    }

    #[tokio::test]
    async fn optional_display_claims_are_used_when_present() {
        let mut claims = minimal_claims();
        claims["name"] = json!("Display Name");
        claims["preferred_username"] = json!("display_name");
        claims["email"] = json!("display@example.com");
        let encoded = encode_jwt(&claims);

        let token = oidc_verifier()
            .verify_token(&encoded)
            .await
            .expect("optional claims do not block acceptance");

        assert_eq!(token.name, "Display Name");
        assert_eq!(token.preferred_username, "display_name");
    }

    #[tokio::test]
    async fn array_audience_is_accepted() {
        let mut claims = minimal_claims();
        claims["aud"] = json!(["lore"]);
        let encoded = encode_jwt(&claims);

        let token = oidc_verifier()
            .verify_token(&encoded)
            .await
            .expect("PocketID-style array audience is accepted");

        assert_eq!(token.audience, vec!["lore".to_string()]);
    }

    #[tokio::test]
    async fn wrong_issuer_is_still_rejected() {
        let mut claims = minimal_claims();
        claims["iss"] = json!("https://not-the-configured-issuer.invalid");
        let encoded = encode_jwt(&claims);

        let error = oidc_verifier()
            .verify_token(&encoded)
            .await
            .expect_err("issuer is checked before the minimal shape ever matters");
        assert!(matches!(error, JwtVerifierError::ValidationFailed(_)));
    }

    #[tokio::test]
    async fn wrong_audience_is_still_rejected() {
        let mut claims = minimal_claims();
        claims["aud"] = json!("not-lore");
        let encoded = encode_jwt(&claims);

        oidc_verifier()
            .verify_token(&encoded)
            .await
            .expect_err("audience is checked before the minimal shape ever matters");
    }

    #[tokio::test]
    async fn expired_token_is_still_rejected() {
        let mut claims = minimal_claims();
        claims["exp"] = json!(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - 3600
        );
        let encoded = encode_jwt(&claims);

        oidc_verifier()
            .verify_token(&encoded)
            .await
            .expect_err("expiry is checked before the minimal shape ever matters");
    }

    /// A Lore-issued token matches `AuthorizationToken` or `JWTUserInfo`
    /// first, so it never reaches this decode or its wildcard.
    #[tokio::test]
    async fn a_full_lore_shaped_token_does_not_take_this_path() {
        let mut claims = minimal_claims();
        claims["env"] = json!("the env");
        claims["name"] = json!("the name");
        claims["preferred_username"] = json!("pu");
        let encoded = encode_jwt(&claims);

        let token = oidc_verifier()
            .verify_token(&encoded)
            .await
            .expect("still verifies, via JWTUserInfo");

        assert_eq!(token.name, "the name");
        assert_eq!(
            token.resources, None,
            "authn-only path grants nothing itself"
        );
    }

    /// The invariant the mode gate preserves: a `LoreClaims` verifier must
    /// refuse a token that this signature, issuer, audience, and expiry
    /// would pass, once it lacks `env`/`name`/`preferred_username`.
    #[tokio::test]
    async fn a_non_oidc_verifier_rejects_the_minimal_claim_shape() {
        let non_oidc_verifier = JwtVerifier::new(
            Arc::new(AgreedUponJWKService),
            Some("https://id.example.com".to_string()),
            Some(vec!["lore".to_string()]),
        );
        let encoded = encode_jwt(&minimal_claims());

        let error = non_oidc_verifier.verify_token(&encoded).await.expect_err(
            "a LoreClaims verifier must never accept a token missing \
                 env/name/preferred_username, however well it verifies otherwise",
        );
        assert!(matches!(error, JwtVerifierError::ValidationFailed(_)));
    }
}

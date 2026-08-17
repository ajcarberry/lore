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
    #[serde(rename = "azp")]
    authorized_party: Option<String>,
    name: Option<String>,
    preferred_username: Option<String>,
    /// Every claim the named fields do not consume, kept so the configured
    /// groups claim can be read without a second decode.
    #[serde(flatten)]
    additional: serde_json::Map<String, serde_json::Value>,
}

/// `[server.auth.oidc.permission_groups]`: which ID-token claim names the
/// user's groups, and the permissions each mapped group grants.
#[derive(Clone, Debug)]
pub(crate) struct GroupPermissions {
    pub claim: String,
    pub groups: std::collections::HashMap<String, Vec<String>>,
}

impl GroupPermissions {
    /// The union of the permissions granted to every mapped group the token's
    /// claim names, in sorted order. A missing claim, a wrong-shaped claim, or
    /// membership in no mapped group grants nothing — the token still carries
    /// the ordinary all-repositories grant, never more.
    fn granted(&self, claims: &OidcTokenClaims) -> Vec<String> {
        let named = match claims.additional.get(&self.claim) {
            // Core defines no shape for a groups claim; an array of strings is
            // what providers emit, with a bare string as the collapsed form.
            Some(serde_json::Value::Array(values)) => values
                .iter()
                .filter_map(|value| value.as_str())
                .collect::<Vec<_>>(),
            Some(serde_json::Value::String(value)) => vec![value.as_str()],
            _ => return Vec::new(),
        };

        let mut granted: Vec<String> = named
            .into_iter()
            .filter_map(|group| self.groups.get(group))
            .flatten()
            .cloned()
            .collect();
        granted.sort();
        granted.dedup();
        granted
    }
}

impl OidcTokenClaims {
    /// Core §3.1.3.7 steps 4-5: a token naming several audiences must carry an
    /// `azp`, and an `azp`, when present, must name this client. The audience
    /// check alone is membership, which would accept a token minted for
    /// another application that merely lists this client id in its audience.
    pub(crate) fn authorized_party_permitted(&self, client_ids: &[String]) -> bool {
        match &self.authorized_party {
            Some(azp) => client_ids.iter().any(|id| id == azp),
            None => self.audience.len() <= 1,
        }
    }

    /// Maps a minimal provider-issued token onto the shape the rest of the
    /// server reads, with the display fields falling back to `sub`. `resources`
    /// is always the all-repositories wildcard — this conversion is reachable
    /// only from a [`JwtVerifierMode::Oidc`] verifier, whose
    /// `authorize_all_repositories` configuration is what the wildcard records —
    /// carrying the permissions the verifier's group mapping granted, if any.
    ///
    /// [`JwtVerifierMode::Oidc`]: crate::auth::jwt::JwtVerifierMode::Oidc
    pub(crate) fn into_authorization_token(
        self,
        group_permissions: Option<&GroupPermissions>,
    ) -> AuthorizationToken {
        let permission = group_permissions
            .map(|mapping| mapping.granted(&self))
            .unwrap_or_default();
        let display_name = self.name.unwrap_or_else(|| self.user_id.clone());
        let preferred_username = self
            .preferred_username
            .unwrap_or_else(|| self.user_id.clone());

        AuthorizationToken {
            user_id: self.user_id,
            issuer: self.issuer.clone(),
            issued_at: self.issued_at,
            expires: self.expires,
            audience: self.audience,
            env: String::default(),
            name: display_name,
            preferred_username,
            resources: Some(vec![ResourcePermission {
                resource_id: "urc-*".to_string(),
                permission,
            }]),
            groups: None,
            is_service_account: None,
            idp: self.issuer,
        }
    }
}

/// The one claim decode an OIDC-mode verifier performs.
#[cfg(test)]
mod oidc_decode {
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

    /// `EdDSA` rather than an HMAC secret, because the verifier under test
    /// refuses symmetric algorithms in OIDC mode before any claim is read.
    const AGREED_UPON_ALGORITHM: Algorithm = Algorithm::EdDSA;

    fn agreed_upon_keys() -> &'static (EncodingKey, DecodingKey) {
        static KEYS: std::sync::OnceLock<(EncodingKey, DecodingKey)> = std::sync::OnceLock::new();
        KEYS.get_or_init(|| {
            let pkcs8 =
                ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                    .expect("generate test keypair");
            let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
                .expect("parse test keypair");
            use ring::signature::KeyPair;
            (
                EncodingKey::from_ed_der(pkcs8.as_ref()),
                DecodingKey::from_ed_der(pair.public_key().as_ref()),
            )
        })
    }

    /// Serves the one key these tokens are signed with, whatever key id is asked
    /// for. Nothing here turns on rotation, so a refresh offers no replacement.
    struct AgreedUponJWKService;

    #[async_trait]
    impl JWKService for AgreedUponJWKService {
        async fn get_key(&self, _kid: &str) -> Result<(DecodingKey, Algorithm), JWKServiceError> {
            Ok((agreed_upon_keys().1.clone(), AGREED_UPON_ALGORITHM))
        }

        fn get_cached_key(&self, _kid: &str) -> Option<(DecodingKey, Algorithm)> {
            Some((agreed_upon_keys().1.clone(), AGREED_UPON_ALGORITHM))
        }

        async fn refresh_key(
            &self,
            _kid: &str,
        ) -> Result<Option<(DecodingKey, Algorithm)>, JWKServiceError> {
            Ok(None)
        }
    }

    /// A provider that published a symmetric secret in its key set — the case
    /// OIDC mode must refuse however the key was obtained.
    struct SymmetricJWKService;

    #[async_trait]
    impl JWKService for SymmetricJWKService {
        async fn get_key(&self, _kid: &str) -> Result<(DecodingKey, Algorithm), JWKServiceError> {
            Ok((DecodingKey::from_secret(b"published"), Algorithm::HS256))
        }

        fn get_cached_key(&self, _kid: &str) -> Option<(DecodingKey, Algorithm)> {
            Some((DecodingKey::from_secret(b"published"), Algorithm::HS256))
        }

        async fn refresh_key(
            &self,
            _kid: &str,
        ) -> Result<Option<(DecodingKey, Algorithm)>, JWKServiceError> {
            Ok(None)
        }
    }

    fn encode_jwt(jwt_claims: &serde_json::Value) -> String {
        let jwt_header = {
            let mut header = Header::new(AGREED_UPON_ALGORITHM);
            header.kid = Some("the kid".into());
            header
        };

        encode(&jwt_header, jwt_claims, &agreed_upon_keys().0).unwrap()
    }

    fn oidc_verifier() -> JwtVerifier {
        JwtVerifier::oidc(
            Arc::new(AgreedUponJWKService),
            "https://id.example.com".to_string(),
            vec!["lore".to_string()],
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

    /// Extra claims — Lore's own among them — must not change how an OIDC-mode
    /// verifier treats a token: the claims a provider happens to emit never
    /// decide what a token authorizes.
    #[tokio::test]
    async fn lore_shaped_claims_get_the_same_oidc_treatment() {
        let mut claims = minimal_claims();
        claims["env"] = json!("the env");
        claims["name"] = json!("the name");
        claims["preferred_username"] = json!("pu");
        let encoded = encode_jwt(&claims);

        let token = oidc_verifier()
            .verify_token(&encoded)
            .await
            .expect("extra claims do not block acceptance");

        assert_eq!(token.name, "the name");
        assert_eq!(token.env, "", "`env` is not read in OIDC mode");
        let resources = token.resources.expect("wildcard resource is populated");
        assert!(resources[0].is_wildcard_resource());
    }

    /// The symmetric refusal is inside `verify_token_internal`, so it holds
    /// for any key service an OIDC verifier is built over — there is no
    /// unwrapped configuration that skips it.
    #[tokio::test]
    async fn a_key_served_under_a_symmetric_algorithm_is_refused() {
        let verifier = JwtVerifier::oidc(
            Arc::new(SymmetricJWKService),
            "https://id.example.com".to_string(),
            vec!["lore".to_string()],
        );
        let jwt_key = EncodingKey::from_secret(b"published");
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("the kid".into());
        let encoded = encode(&header, &minimal_claims(), &jwt_key).unwrap();

        let error = verifier
            .verify_token(&encoded)
            .await
            .expect_err("a published symmetric secret is a signing key for anyone who reads it");
        assert!(
            matches!(error, JwtVerifierError::SymmetricAlgorithmRefused),
            "{error:?}"
        );
    }

    /// Core §3.1.3.7 step 4: several audiences without an `azp` is refused —
    /// membership alone would admit a token minted for another application
    /// that merely lists this client id.
    #[tokio::test]
    async fn several_audiences_without_azp_are_refused() {
        let mut claims = minimal_claims();
        claims["aud"] = json!(["lore", "another-app"]);
        let encoded = encode_jwt(&claims);

        let error = oidc_verifier()
            .verify_token(&encoded)
            .await
            .expect_err("a multi-audience token must say which client it was issued to");
        assert!(
            matches!(error, JwtVerifierError::AuthorizedPartyMismatch),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn several_audiences_with_azp_naming_this_client_are_accepted() {
        let mut claims = minimal_claims();
        claims["aud"] = json!(["lore", "another-app"]);
        claims["azp"] = json!("lore");
        let encoded = encode_jwt(&claims);

        let token = oidc_verifier()
            .verify_token(&encoded)
            .await
            .expect("azp naming this client resolves the multi-audience ambiguity");
        assert_eq!(token.user_id, "the-subject");
    }

    /// A client-id rotation: the verifier accepts both the old and the new
    /// audience while logins move over, so the rotation is a configuration
    /// change rather than a flag day.
    #[tokio::test]
    async fn a_token_for_either_rotating_audience_is_accepted() {
        let verifier = JwtVerifier::oidc(
            Arc::new(AgreedUponJWKService),
            "https://id.example.com".to_string(),
            vec!["lore".to_string(), "lore-new".to_string()],
        );

        for audience in ["lore", "lore-new"] {
            let mut claims = minimal_claims();
            claims["aud"] = json!(audience);
            let encoded = encode_jwt(&claims);

            verifier
                .verify_token(&encoded)
                .await
                .unwrap_or_else(|e| panic!("audience {audience} must verify: {e:?}"));
        }
    }

    /// Core §3.1.3.7 step 5: an `azp` naming another client is refused even
    /// when the audience alone would pass.
    #[tokio::test]
    async fn an_azp_naming_another_client_is_refused() {
        let mut claims = minimal_claims();
        claims["azp"] = json!("another-app");
        let encoded = encode_jwt(&claims);

        let error = oidc_verifier()
            .verify_token(&encoded)
            .await
            .expect_err("a token issued to another client must not authenticate here");
        assert!(
            matches!(error, JwtVerifierError::AuthorizedPartyMismatch),
            "{error:?}"
        );
    }

    fn mapped_verifier() -> JwtVerifier {
        oidc_verifier().with_group_permissions(crate::auth::oidc_claims::GroupPermissions {
            claim: "groups".to_string(),
            groups: std::collections::HashMap::from([
                (
                    "lore-admins".to_string(),
                    vec!["obliterate".to_string(), "migrate".to_string()],
                ),
                ("lore-operators".to_string(), vec!["migrate".to_string()]),
            ]),
        })
    }

    /// `[server.auth.oidc.permission_groups]`: membership in mapped groups
    /// grants the union of their permission lists on the wildcard resource.
    #[tokio::test]
    async fn mapped_groups_grant_their_permissions() {
        let mut claims = minimal_claims();
        claims["groups"] = json!(["lore-operators", "unmapped-team"]);
        let encoded = encode_jwt(&claims);

        let token = mapped_verifier()
            .verify_token(&encoded)
            .await
            .expect("a mapped member verifies");

        let resources = token.resources.expect("wildcard resource is populated");
        assert_eq!(resources[0].permission, vec!["migrate".to_string()]);

        let mut claims = minimal_claims();
        claims["groups"] = json!(["lore-admins", "lore-operators"]);
        let token = mapped_verifier()
            .verify_token(&encode_jwt(&claims))
            .await
            .expect("an admin member verifies");
        assert_eq!(
            token.resources.expect("wildcard")[0].permission,
            vec!["migrate".to_string(), "obliterate".to_string()],
            "the union of both groups, deduplicated and sorted"
        );
    }

    /// Fail closed: a token with no groups claim, or membership in no mapped
    /// group, carries the ordinary grant and nothing more.
    #[tokio::test]
    async fn unmapped_or_missing_groups_grant_nothing() {
        let no_claim = mapped_verifier()
            .verify_token(&encode_jwt(&minimal_claims()))
            .await
            .expect("a token without the claim still authenticates");
        assert!(
            no_claim.resources.expect("wildcard")[0]
                .permission
                .is_empty(),
            "no claim grants nothing"
        );

        let mut claims = minimal_claims();
        claims["groups"] = json!(["some-other-team"]);
        let unmapped = mapped_verifier()
            .verify_token(&encode_jwt(&claims))
            .await
            .expect("an unmapped member still authenticates");
        assert!(
            unmapped.resources.expect("wildcard")[0]
                .permission
                .is_empty(),
            "unmapped membership grants nothing"
        );

        let mut claims = minimal_claims();
        claims["groups"] = json!({"not": "a group list"});
        let wrong_shape = mapped_verifier()
            .verify_token(&encode_jwt(&claims))
            .await
            .expect("a wrong-shaped claim still authenticates");
        assert!(
            wrong_shape.resources.expect("wildcard")[0]
                .permission
                .is_empty(),
            "a wrong-shaped claim grants nothing"
        );
    }

    /// Providers differ over collapsing a single-element array to a bare
    /// string, for a groups claim as for `aud`.
    #[tokio::test]
    async fn a_bare_string_groups_claim_is_read() {
        let mut claims = minimal_claims();
        claims["groups"] = json!("lore-admins");
        let token = mapped_verifier()
            .verify_token(&encode_jwt(&claims))
            .await
            .expect("a bare-string claim verifies");
        assert_eq!(
            token.resources.expect("wildcard")[0].permission,
            vec!["migrate".to_string(), "obliterate".to_string()]
        );
    }

    /// Without a configured mapping, a groups claim in the token changes
    /// nothing — the provider cannot steer authorization uninvited.
    #[tokio::test]
    async fn groups_grant_nothing_without_a_configured_mapping() {
        let mut claims = minimal_claims();
        claims["groups"] = json!(["lore-admins"]);
        let token = oidc_verifier()
            .verify_token(&encode_jwt(&claims))
            .await
            .expect("verifies as an ordinary token");
        assert!(
            token.resources.expect("wildcard")[0].permission.is_empty(),
            "an unconfigured server reads no groups claim"
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

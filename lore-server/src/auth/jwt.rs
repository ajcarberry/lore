// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use jsonwebtoken::DecodingKey;
use jsonwebtoken::Validation;
use jsonwebtoken::decode;
use jsonwebtoken::decode_header;
use serde::Deserialize;
use serde::Serialize;
use serde_with::OneOrMany;
use serde_with::formats::PreferMany;
use serde_with::serde_as;
use thiserror::Error;
use tracing::debug;
use tracing::warn;

use super::jwk::JWKServiceError;
use crate::auth::jwk::JWKService;

#[serde_as]
#[derive(Debug, Deserialize, Clone, Serialize, PartialEq)]
pub struct JWTUserInfo {
    #[serde(rename = "sub")]
    pub user_id: String,
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "iat")]
    pub issued_at: u64,
    #[serde_as(as = "OneOrMany<_, PreferMany>")]
    #[serde(rename = "aud")]
    pub audience: Vec<String>,
    pub env: String,
    pub name: String,
    pub preferred_username: String,
    pub is_service_account: Option<bool>,
    #[serde(rename = "exp")]
    pub expires: u64,
}

/// From Lore protos, but cannot derive deserialize on external type
#[derive(Debug, Deserialize, Clone, Serialize, PartialEq)]
pub struct ResourcePermission {
    pub resource_id: String,
    pub permission: Vec<String>,
}

impl ResourcePermission {
    pub fn is_wildcard_resource(&self) -> bool {
        self.resource_id == "urc-*"
    }

    pub fn matches_repository(&self, repository_id: &String) -> bool {
        self.resource_id == *repository_id || self.is_wildcard_resource()
    }
}

#[serde_as]
#[derive(Debug, Deserialize, Clone, Serialize, PartialEq, Default)]
pub struct AuthorizationToken {
    #[serde(rename = "sub")]
    pub user_id: String,
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "iat")]
    pub issued_at: u64,
    #[serde(rename = "exp")]
    pub expires: u64,
    #[serde_as(as = "OneOrMany<_, PreferMany>")]
    #[serde(rename = "aud")]
    pub audience: Vec<String>,
    pub env: String,
    pub name: String,
    pub preferred_username: String,
    pub resources: Option<Vec<ResourcePermission>>,
    pub groups: Option<Vec<String>>,
    pub is_service_account: Option<bool>,
    pub idp: String,
}

/// The claim shape a provider-issued token is read into, in either OIDC mode.
///
/// It demands only what RFC 7519 and OpenID Connect Core guarantee — `iss`,
/// `sub`, `aud`, `exp`, `iat` — so a conformant ID token from any standard
/// provider satisfies it, with `name`, `preferred_username`, and `email`
/// accepted when present but never required.
///
/// The same shape serves an [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068)
/// JWT access token, because its §2.2 required set is this one plus `client_id`
/// and `jti`. Neither of those is deserialized, and their absence is not a
/// rejection: §2.2 binds the *authorization server* issuing the token, while §4
/// — the resource server's own validation list — names neither, and Lore reads
/// neither. There is no replay cache for `jti` to key (this design holds no
/// per-request state at all), and the client id stopped being pinned the moment
/// `aud` began naming the resource server instead. What separates the two modes
/// is therefore not the claims but the two checks around them: the `typ` header
/// and what `aud` is pinned to.
#[serde_as]
#[derive(Debug, Deserialize, Clone, PartialEq)]
struct OidcTokenClaims {
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
    #[allow(dead_code)]
    email: Option<String>,
}

impl From<OidcTokenClaims> for AuthorizationToken {
    /// Maps a minimal provider-issued token onto the shape the rest of the
    /// server reads. `idp` is the issuer, and the display fields fall back to
    /// `sub` when the provider did not send them — the same substitution the
    /// LEP specifies for the client's `JWTUserInfo` equivalent. `resources` is
    /// always the all-repositories wildcard: this conversion is reachable only
    /// from a [`JwtVerifierMode::Oidc`] verifier, whose configuration
    /// (`authorize_all_repositories`) is what the wildcard records, and only
    /// for a token that already cleared signature, issuer, audience, and
    /// expiry checks.
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

#[derive(Debug, Error)]
pub enum JwtVerifierError {
    #[error("JWT header does not contain a kid")]
    HeaderKIDMissing,
    #[error("JWT header could not be parsed")]
    KeyNotFound(#[from] JWKServiceError),
    #[error("JWT validation failed")]
    ValidationFailed(#[from] jsonwebtoken::errors::Error),
    #[error("JWT authorization failed")]
    NotAuthorized,
    #[error("JWT is not an RFC 9068 access token")]
    NotAnAccessToken,
}

/// Which claim shapes `verify_token_internal` accepts, and whether a
/// successfully-decoded token is granted the all-repositories wildcard.
///
/// This is what makes the third, minimal OIDC claim decode additive rather
/// than a widening (LEP Security Considerations, "the third claim decode
/// accepts a token the operator did not intend"). A `[server.auth.jwk]`-only
/// deployment (`ucs-auth` and friends) always builds a `LoreClaims` verifier
/// via [`JwtVerifier::new`], so a token that is correctly signed by its
/// trusted issuer but happens to omit `env`/`name`/`preferred_username` keeps
/// being refused — it is never granted every repository on the strength of
/// an omitted claim. Only a verifier built from
/// a configured `[server.auth.oidc]` block, via [`JwtVerifier::oidc`] or
/// [`JwtVerifier::oidc_resource`], is `Oidc` mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum JwtVerifierMode {
    /// Only Lore's own claim shapes (`AuthorizationToken`, `JWTUserInfo`)
    /// verify. The mode of every verifier that does not configure
    /// `[server.auth.oidc]`, and the default.
    #[default]
    LoreClaims,
    /// `[server.auth.oidc]`'s authn-only mode. Which credential the provider
    /// is expected to have issued is the payload, because it decides both what
    /// shape verifies and what `aud` is pinned to; everything downstream of a
    /// successful verification — the all-repositories wildcard — is the same
    /// either way.
    Oidc(OidcAcceptance),
}

/// Which of the provider's two tokens a `[server.auth.oidc]` deployment accepts.
///
/// The distinction is `[server.auth.oidc].resource`, and it is the whole of the
/// opt-in: absent, the deployment accepts an ID token; present, it is strict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OidcAcceptance {
    /// No `resource` configured: a conformant OpenID Connect ID token, whose
    /// `aud` is pinned to the client id. This is an authentication assertion
    /// presented as a bearer credential, so `aud` names the client rather than
    /// the server — which is why two deployments sharing an issuer and a client
    /// id accept each other's tokens (LEP Security Considerations, residual
    /// risk #1).
    IdToken,
    /// `resource` configured: an [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068)
    /// JWT access token, whose `aud` is pinned to the resource identifier this
    /// deployment configured. ID tokens are refused outright in this mode —
    /// accepting both would leave the weaker credential as a way around the
    /// stronger one, which is the entire point of turning it on.
    AccessToken,
}

#[derive(Clone)]
pub struct JwtVerifier {
    pub jwk_service: Arc<dyn JWKService>,
    pub jwt_issuer: Option<String>,
    pub jwt_audience: Option<Vec<String>>,
    pub mode: JwtVerifierMode,
}

impl JwtVerifier {
    /// Only Lore's own claim shapes verify. What every
    /// `[server.auth.jwk]`-only deployment builds.
    pub fn new(
        jwk_service: Arc<dyn JWKService>,
        jwt_issuer: Option<String>,
        jwt_audience: Option<Vec<String>>,
    ) -> Self {
        Self {
            jwk_service,
            jwt_issuer,
            jwt_audience,
            mode: JwtVerifierMode::LoreClaims,
        }
    }

    /// `[server.auth.oidc]`'s authn-only mode, accepting an ID token. What
    /// `build_jwt_verifier` builds when the operator configured that block
    /// without a `resource`. `jwt_audience` is the client id.
    pub fn oidc(
        jwk_service: Arc<dyn JWKService>,
        jwt_issuer: Option<String>,
        jwt_audience: Option<Vec<String>>,
    ) -> Self {
        Self {
            jwk_service,
            jwt_issuer,
            jwt_audience,
            mode: JwtVerifierMode::Oidc(OidcAcceptance::IdToken),
        }
    }

    /// `[server.auth.oidc]`'s resource-bound mode: an RFC 9068 JWT access token
    /// and nothing else. What `build_jwt_verifier` builds when the operator
    /// configured a `resource`, which is also what `jwt_audience` is pinned to.
    pub fn oidc_resource(
        jwk_service: Arc<dyn JWKService>,
        jwt_issuer: Option<String>,
        jwt_audience: Option<Vec<String>>,
    ) -> Self {
        Self {
            jwk_service,
            jwt_issuer,
            jwt_audience,
            mode: JwtVerifierMode::Oidc(OidcAcceptance::AccessToken),
        }
    }
}

/// Whether a verification failure could be the signing key's fault rather than the token's.
///
/// A key rotated under an unchanged key id presents exactly this way, and it is the only
/// failure worth re-fetching keys for: a token that has expired, or that names another
/// audience or issuer, fails identically against every key that could ever be served. That
/// distinction is what keeps an invalid token from being a way to ask for network work.
fn key_may_be_stale(error: &JwtVerifierError) -> bool {
    matches!(error, JwtVerifierError::ValidationFailed(inner) if matches!(
        inner.kind(),
        jsonwebtoken::errors::ErrorKind::InvalidSignature
            | jsonwebtoken::errors::ErrorKind::InvalidAlgorithm
    ))
}

/// Whether a `typ` header declares an RFC 9068 JWT access token.
///
/// §2.1 registers the `application/at+jwt` media type and recommends omitting
/// the `application/` prefix, and §4 step 1 accepts either spelling. The
/// comparison is case-insensitive because `typ` is a media type, and media
/// types are compared case-insensitively (RFC 9110 §8.3.1); a provider that
/// spells it `AT+JWT` is conformant and refusing it would be a bug in this
/// server, not in the token.
fn is_jwt_access_token_type(typ: &str) -> bool {
    typ.eq_ignore_ascii_case("at+jwt") || typ.eq_ignore_ascii_case("application/at+jwt")
}

/// Log a claim-decode failure at the level its kind deserves, and carry it on.
///
/// An expired token is an ordinary event on any path a client can reach, so it stays at
/// `debug`; anything else is worth an operator's attention. Both terminal decode arms of
/// [`JwtVerifier::verify_token_internal`] end here, so the level a failure is reported at
/// does not depend on which claim shape was tried last.
fn decode_failure(error: jsonwebtoken::errors::Error) -> JwtVerifierError {
    if matches!(
        error.kind(),
        jsonwebtoken::errors::ErrorKind::ExpiredSignature
    ) {
        debug!(error = ?error, "Allowable error decoding JWT AuthN token");
    } else {
        warn!(error = ?error, "Unexpected error decoding JWT AuthN token");
    }
    JwtVerifierError::ValidationFailed(error)
}

impl JwtVerifier {
    /// Verify a token, re-fetching the signing key once if the cached one looks stale.
    ///
    /// The retry is what makes a key rotated under an unchanged key id recoverable. Without
    /// it the cache holds a key for the id, every lookup is satisfied by it, and every token
    /// signed with the new material fails until the process restarts.
    pub async fn verify_token(&self, token: &str) -> Result<AuthorizationToken, JwtVerifierError> {
        let header = decode_header(token).map_err(JwtVerifierError::ValidationFailed)?;
        let kid = header.kid.ok_or(JwtVerifierError::HeaderKIDMissing)?;

        let (key, alg) = self
            .jwk_service
            .get_key(&kid)
            .await
            .map_err(JwtVerifierError::KeyNotFound)?;

        let stale_failure = match self.verify_token_internal(token, &key, &alg) {
            Err(failure) if key_may_be_stale(&failure) => failure,
            result => return result,
        };

        // `None` covers both unchanged material and a declined fetch, so the original failure
        // stands rather than being re-derived from the same key.
        let Some((key, alg)) = self
            .jwk_service
            .refresh_key(&kid)
            .await
            .map_err(JwtVerifierError::KeyNotFound)?
        else {
            return Err(stale_failure);
        };

        self.verify_token_internal(token, &key, &alg)
    }

    /// Verify a token using only the JWK cache, without any `.await`. `Ok(Some(_))` on
    /// success; `Err` when the token itself is at fault; `Ok(None)` when the cache cannot
    /// answer and the caller must fall back to the async [`verify_token`].
    ///
    /// A signature that does not match the cached key is `Ok(None)`, not `Err`: the cached
    /// key may be a rotated-out one, and only the async path can replace it. Reporting it as
    /// a failure here is what left a rotated key broken until restart even though the
    /// refresh existed.
    pub fn try_verify_token_cached(
        &self,
        token: &str,
    ) -> Result<Option<AuthorizationToken>, JwtVerifierError> {
        let header = decode_header(token).map_err(JwtVerifierError::ValidationFailed)?;
        let kid = header.kid.ok_or(JwtVerifierError::HeaderKIDMissing)?;

        let Some((key, alg)) = self.jwk_service.get_cached_key(&kid) else {
            return Ok(None);
        };

        match self.verify_token_internal(token, &key, &alg) {
            Err(failure) if key_may_be_stale(&failure) => Ok(None),
            result => result.map(Some),
        }
    }

    fn verify_token_internal(
        &self,
        token: &str,
        key: &DecodingKey,
        alg: &jsonwebtoken::Algorithm,
    ) -> Result<AuthorizationToken, JwtVerifierError> {
        let mut validation = Validation::new(*alg);
        if let Some(iss) = self.jwt_issuer.as_ref() {
            validation.set_issuer(&[iss]);
        }
        if let Some(aud) = self.jwt_audience.as_ref() {
            validation.set_audience(aud);
        }

        validation.validate_exp = true;

        debug!("Decoding JWT token");

        // Resource-bound mode accepts one credential and stops. Lore's own claim
        // shapes and the ID-token shape are all refused below, at the `typ`
        // check, because leaving any of them reachable would leave a weaker
        // credential as a way around the stronger one — which is the whole
        // reason an operator configured `resource`.
        if self.mode == JwtVerifierMode::Oidc(OidcAcceptance::AccessToken) {
            return self.verify_access_token(token, key, &validation);
        }

        if let Ok(token_data) = decode::<AuthorizationToken>(token, key, &validation) {
            debug!(
                sub = %token_data.claims.user_id,
                iss = %token_data.claims.issuer,
                "Decoded user info"
            );
            return Ok(token_data.claims);
        }

        match decode::<JWTUserInfo>(token, key, &validation) {
            Ok(token_data) => {
                let token = token_data.claims;
                Ok(AuthorizationToken {
                    user_id: token.user_id,
                    issuer: token.issuer,
                    issued_at: token.issued_at,
                    expires: token.expires,
                    audience: token.audience,
                    env: token.env,
                    name: token.name,
                    preferred_username: token.preferred_username,
                    resources: None,
                    groups: None,
                    is_service_account: token.is_service_account,
                    idp: String::default(),
                })
            }
            // Reached only once both Lore-specific claim shapes above have
            // failed to deserialize, and only in OIDC mode: a
            // `[server.auth.jwk]`-only verifier stops here. In OIDC mode a
            // conformant ID token satisfies this third shape instead, carrying
            // none of `env`/`name`/`preferred_username` — see `OidcTokenClaims`.
            Err(_) if matches!(self.mode, JwtVerifierMode::Oidc(_)) => {
                decode::<OidcTokenClaims>(token, key, &validation)
                    .map_err(decode_failure)
                    .map(|token_data| token_data.claims.into())
            }
            Err(error) => Err(decode_failure(error)),
        }
    }

    /// RFC 9068 §4's validation list, which is what `[server.auth.oidc].resource`
    /// buys. Every step is here or in the `Validation` the caller assembled:
    ///
    /// 1. the `typ` header names a JWT access token — checked below, and the
    ///    only step with no equivalent in the ID-token path;
    /// 2. decryption — N/A: this design negotiates no encryption, so an
    ///    encrypted token is simply one that does not decode;
    /// 3. `iss` matches the configured issuer exactly — `validation`'s issuer;
    /// 4. `aud` contains an identifier this server expects for itself —
    ///    `validation`'s audience, which in this mode is the configured
    ///    `resource` rather than the client id. **This is the step that makes
    ///    the mode worth having**: a token minted for another deployment behind
    ///    the same provider names that deployment, and fails here;
    /// 5. the signature verifies under an algorithm that is not `none` — the
    ///    algorithm comes from the key, never from the header, and
    ///    `OidcJwkService` has already refused every symmetric one;
    /// 6. `exp` has not passed — `validation.validate_exp`.
    fn verify_access_token(
        &self,
        token: &str,
        key: &DecodingKey,
        validation: &Validation,
    ) -> Result<AuthorizationToken, JwtVerifierError> {
        // Step 1. Deliberately before the signature check: a token that is not
        // claiming to be an access token is not one this mode has any business
        // decoding, whoever signed it. It is also not a failure a key rotation
        // could ever explain, so — like an expired token or a wrong audience —
        // it never reaches `refresh_key` and cannot be used to drive outbound
        // requests (`key_may_be_stale` matches no such variant).
        let header = decode_header(token).map_err(JwtVerifierError::ValidationFailed)?;
        if !header.typ.as_deref().is_some_and(is_jwt_access_token_type) {
            debug!(
                typ = ?header.typ,
                "Refusing a token that does not declare the RFC 9068 media type"
            );
            return Err(JwtVerifierError::NotAnAccessToken);
        }

        decode::<OidcTokenClaims>(token, key, validation)
            .map_err(decode_failure)
            .map(|token_data| token_data.claims.into())
    }
}

pub fn verify_authorization(
    authorization: &AuthorizationToken,
    repository: lore_revision::lore::RepositoryId,
) -> Result<(), JwtVerifierError> {
    if let Some(resources) = authorization.resources.as_ref() {
        let checked_repository = format!("urc-{repository}");
        for authorized_resource in resources.iter() {
            if authorized_resource.matches_repository(&checked_repository) {
                return Ok(());
            }
        }
    }

    Err(JwtVerifierError::NotAuthorized)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    use lore_base::types::Context;
    use lore_revision::lore::RepositoryId;

    use super::*;

    #[test]
    fn resource_permission_matches_wildcard_resource() {
        let wildcard_resource_permission = ResourcePermission {
            permission: vec![],
            resource_id: "urc-*".to_string(),
        };
        let non_wildcard_resource_permission = ResourcePermission {
            permission: vec![],
            resource_id: "urc-123456".to_string(),
        };
        assert!(wildcard_resource_permission.is_wildcard_resource());
        assert!(!non_wildcard_resource_permission.is_wildcard_resource());
    }

    #[test]
    fn resource_permission_matches_repository() {
        let test_repository_id = "urc-0194b726b34e72b0b45550b88a967076".to_string();
        let unrelated_repository_id = "urc-0192ae48ccf17060bc1ba9d04f6acb2f".to_string();
        let wildcard_resource_permission = ResourcePermission {
            permission: vec![],
            resource_id: "urc-*".to_string(),
        };
        let regular_resource_permission = ResourcePermission {
            permission: vec![],
            resource_id: test_repository_id.clone(),
        };
        assert!(wildcard_resource_permission.matches_repository(&test_repository_id));
        assert!(wildcard_resource_permission.matches_repository(&unrelated_repository_id));
        assert!(regular_resource_permission.matches_repository(&test_repository_id));
        assert!(!regular_resource_permission.matches_repository(&unrelated_repository_id));
    }

    #[test]
    fn verify_authorization_allows_repo_from_token() {
        let allowed_repository_id = "urc-0194b726b34e72b0b45550b88a967076".to_string();
        let resource_permission = ResourcePermission {
            permission: vec![],
            resource_id: allowed_repository_id.clone(),
        };
        let authorization_token = AuthorizationToken {
            audience: vec!["test".to_string()],
            env: "test".to_string(),
            expires: 1234,
            user_id: "test".to_string(),
            idp: "test".to_string(),
            issuer: "test".to_string(),
            name: "test".to_string(),
            preferred_username: "test".to_string(),
            groups: None,
            is_service_account: Some(false),
            issued_at: 123,
            resources: Some(vec![resource_permission]),
        };
        let allowed_context: RepositoryId = Context::from_str("0194b726b34e72b0b45550b88a967076")
            .unwrap()
            .into();
        let unexpected_context: RepositoryId =
            Context::from_str("f6ca55437aa34198ba0f0fdc33154d51")
                .unwrap()
                .into();
        verify_authorization(&authorization_token, allowed_context).expect("verify auth failed");
        verify_authorization(&authorization_token, unexpected_context)
            .expect_err("verify auth should have failed");
    }

    #[test]
    fn verify_authorization_allows_all_repos_for_wildcard_token() {
        let resource_permission = ResourcePermission {
            permission: vec![],
            resource_id: "urc-*".to_string(),
        };
        let wildcard_authorization_token = AuthorizationToken {
            audience: vec!["test".to_string()],
            env: "test".to_string(),
            expires: 1234,
            user_id: "test".to_string(),
            idp: "test".to_string(),
            issuer: "test".to_string(),
            name: "test".to_string(),
            preferred_username: "test".to_string(),
            groups: None,
            is_service_account: Some(false),
            issued_at: 123,
            resources: Some(vec![resource_permission]),
        };
        let test_contexts: Vec<RepositoryId> = vec![
            Context::from_str("0194b726b34e72b0b45550b88a967076")
                .unwrap()
                .into(),
            Context::from_str("f6ca55437aa34198ba0f0fdc33154d51")
                .unwrap()
                .into(),
            Context::from_str("54006a8ca619475881f7083d625a7947")
                .unwrap()
                .into(),
        ];

        for context in test_contexts {
            verify_authorization(&wildcard_authorization_token, context)
                .expect("verify auth failed");
        }
    }

    mod jwt_verifier {

        use std::error::Error;
        use std::ops::Add;
        use std::time::Duration;

        use jsonwebtoken::Algorithm;
        use jsonwebtoken::EncodingKey;
        use jsonwebtoken::Header;
        use jsonwebtoken::encode;
        use serde_json::json;

        use super::*;

        const AGREED_UPON_ALGORITHM: Algorithm = Algorithm::HS256;
        const AGREED_UPON_SIGNING_SECRET: &str = "the-secret";

        mockall::mock! {

            #[derive(Debug)]
            pub TestJWKService {}

            #[async_trait::async_trait]
            impl JWKService for TestJWKService {
                async fn get_key(
            &self,
            kid: &str,
        ) -> Result<(DecodingKey, jsonwebtoken::Algorithm), JWKServiceError>;

                fn get_cached_key(
            &self,
            kid: &str,
        ) -> Option<(DecodingKey, jsonwebtoken::Algorithm)>;

                async fn refresh_key(
            &self,
            kid: &str,
        ) -> Result<Option<(DecodingKey, jsonwebtoken::Algorithm)>, JWKServiceError>;
            }
        }

        fn encode_jwt<T>(jwt_claims: &T) -> String
        where
            T: Serialize,
        {
            encode_jwt_signed_with(AGREED_UPON_SIGNING_SECRET, jwt_claims)
        }

        fn encode_jwt_signed_with<T>(secret: &str, jwt_claims: &T) -> String
        where
            T: Serialize,
        {
            let jwt_key = EncodingKey::from_secret(secret.as_ref());
            let jwt_header = {
                let mut header = Header::new(AGREED_UPON_ALGORITHM);
                header.kid = Some("the kid".into());
                header
            };

            encode(&jwt_header, &jwt_claims, &jwt_key).unwrap()
        }

        /// A key service whose material changes under an unchanged key id, which is the
        /// rotation a cache keyed on the id alone cannot see. Refreshes are counted so a
        /// test can assert that a failure no key could explain never asks for one.
        struct RotatingJWKService {
            served: std::sync::Mutex<String>,
            rotates_to: Option<String>,
            refreshes: std::sync::atomic::AtomicUsize,
        }

        impl RotatingJWKService {
            fn new(served: &str, rotates_to: Option<&str>) -> Self {
                RotatingJWKService {
                    served: std::sync::Mutex::new(served.to_string()),
                    rotates_to: rotates_to.map(str::to_string),
                    refreshes: std::sync::atomic::AtomicUsize::new(0),
                }
            }

            fn refreshes(&self) -> usize {
                self.refreshes.load(std::sync::atomic::Ordering::Relaxed)
            }

            fn current(&self) -> (DecodingKey, Algorithm) {
                let served = self.served.lock().expect("served key");
                (
                    DecodingKey::from_secret(served.as_bytes()),
                    AGREED_UPON_ALGORITHM,
                )
            }
        }

        #[async_trait::async_trait]
        impl JWKService for RotatingJWKService {
            async fn get_key(
                &self,
                _kid: &str,
            ) -> Result<(DecodingKey, Algorithm), JWKServiceError> {
                Ok(self.current())
            }

            fn get_cached_key(&self, _kid: &str) -> Option<(DecodingKey, Algorithm)> {
                Some(self.current())
            }

            async fn refresh_key(
                &self,
                _kid: &str,
            ) -> Result<Option<(DecodingKey, Algorithm)>, JWKServiceError> {
                self.refreshes
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some(rotated) = self.rotates_to.as_ref() else {
                    return Ok(None);
                };
                let mut served = self.served.lock().expect("served key");
                if *served == *rotated {
                    return Ok(None);
                }
                served.clone_from(rotated);
                Ok(Some((
                    DecodingKey::from_secret(served.as_bytes()),
                    AGREED_UPON_ALGORITHM,
                )))
            }
        }

        fn verifier_for(service: Arc<RotatingJWKService>) -> JwtVerifier {
            JwtVerifier::new(service, None, Some(vec!["Lore".to_string()]))
        }

        /// Well past `Validation`'s default 60-second leeway, so the expiry is what fails.
        fn expired_authz_token() -> AuthorizationToken {
            let mut claims = mock_authz_token(vec!["Lore".to_string()]);
            claims.expires = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - 3600;
            claims
        }

        /// The finding: the identity provider replaces the material behind a key id without
        /// changing the id. Every lookup is satisfied by the cached key, so every token
        /// signed with the new one fails until the process restarts.
        #[tokio::test]
        async fn a_key_rotated_under_the_same_kid_is_picked_up() {
            let service = Arc::new(RotatingJWKService::new(
                "rotated-out-secret",
                Some(AGREED_UPON_SIGNING_SECRET),
            ));
            let verifier = verifier_for(service.clone());
            let (expected, encoded) = make_authz_token_with_audience(vec!["Lore".to_string()]);

            let verified = verifier
                .verify_token(&encoded)
                .await
                .expect("a rotated key is refetched");

            assert_eq!(verified, expected);
            assert_eq!(service.refreshes(), 1);
        }

        /// The interceptor's synchronous path has to defer rather than deny, or the retry
        /// above is never reached for gRPC traffic.
        #[test]
        fn the_cached_path_defers_a_signature_failure_to_the_async_path() {
            let service = Arc::new(RotatingJWKService::new("rotated-out-secret", None));
            let verifier = verifier_for(service.clone());
            let (_, encoded) = make_authz_token_with_audience(vec!["Lore".to_string()]);

            let verdict = verifier
                .try_verify_token_cached(&encoded)
                .expect("a signature failure is not the token's fault");

            assert!(verdict.is_none(), "must fall through to the async path");
        }

        /// A key that has not in fact rotated must cost exactly one refresh, not one per
        /// verification attempt and not a retry loop.
        #[tokio::test]
        async fn a_key_that_did_not_rotate_is_refreshed_once_and_then_fails() {
            let service = Arc::new(RotatingJWKService::new("wrong-secret", None));
            let verifier = verifier_for(service.clone());
            let (_, encoded) = make_authz_token_with_audience(vec!["Lore".to_string()]);

            let error = verifier
                .verify_token(&encoded)
                .await
                .expect_err("no key can verify this token");

            assert!(matches!(error, JwtVerifierError::ValidationFailed(_)));
            assert_eq!(service.refreshes(), 1);
        }

        /// An expired token is the token's fault. Refreshing keys cannot change the verdict,
        /// and anyone can present one — so it must not reach the refresh at all, on either
        /// path. This is the bound on using invalid tokens to drive outbound requests.
        #[tokio::test]
        async fn a_token_that_no_key_could_rescue_never_asks_for_a_refresh() {
            let service = Arc::new(RotatingJWKService::new(
                AGREED_UPON_SIGNING_SECRET,
                Some(AGREED_UPON_SIGNING_SECRET),
            ));
            let verifier = verifier_for(service.clone());
            let encoded = encode_jwt(&expired_authz_token());

            verifier
                .verify_token(&encoded)
                .await
                .expect_err("an expired token stays rejected");
            verifier
                .try_verify_token_cached(&encoded)
                .expect_err("and is rejected outright, not deferred");

            assert_eq!(service.refreshes(), 0);
        }

        /// The same for a token whose audience is wrong, which is the other failure an
        /// unauthenticated caller can produce at will against a perfectly good key.
        #[tokio::test]
        async fn a_wrong_audience_never_asks_for_a_refresh() {
            let service = Arc::new(RotatingJWKService::new(
                AGREED_UPON_SIGNING_SECRET,
                Some(AGREED_UPON_SIGNING_SECRET),
            ));
            let verifier = verifier_for(service.clone());
            let (_, encoded) = make_authz_token_with_audience(vec!["not-lore".to_string()]);

            verifier
                .verify_token(&encoded)
                .await
                .expect_err("wrong audience stays rejected");

            assert_eq!(service.refreshes(), 0);
        }

        /// Modulus and exponent of the RSA example key from RFC 7515 Appendix A.2. Public
        /// values — which is the whole point of the test below.
        const RSA_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4\
                             cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiF\
                             V4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6C\
                             f0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9\
                             c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTW\
                             hAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1\
                             jF44-csFCur-kEgU8awapJzKnqDKgw";
        const RSA_E: &str = "AQAB";

        /// A key service serving one RSA public key under `the kid`, as a real provider would.
        fn rsa_verifier() -> JwtVerifier {
            let mut service = MockTestJWKService::new();
            service.expect_get_key().returning(|_| {
                Ok((
                    DecodingKey::from_rsa_components(RSA_N, RSA_E).expect("rsa decoding key"),
                    Algorithm::RS256,
                ))
            });
            // A rejected signature looks like a possible rotation, so the retry is reached.
            // Serving no replacement keeps these tests about the first verdict.
            service.expect_refresh_key().returning(|_| Ok(None));

            JwtVerifier::new(Arc::new(service), None, Some(vec!["Lore".to_string()]))
        }

        /// Assemble a token with an arbitrary header, since `encode` will not produce the
        /// mismatches these tests are about.
        fn token_with_header(
            header_json: &str,
            claims: &impl Serialize,
            signature: &str,
        ) -> String {
            use base64::Engine;
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;

            let header = URL_SAFE_NO_PAD.encode(header_json);
            let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("claims"));
            format!("{header}.{claims}.{signature}")
        }

        /// The algorithm-confusion forgery, and the reason the algorithm comes from the JWK
        /// rather than the token.
        ///
        /// An RSA public key is published to the world in the JWKS. If the header could choose
        /// the algorithm, an attacker would sign with HS256 using that public modulus as the
        /// shared secret, and the server — holding the same public value — would agree. Nobody
        /// needs the private key for this. The signature here is genuinely valid for the
        /// algorithm the token claims; it is refused because the token does not get a say.
        #[tokio::test]
        async fn a_public_rsa_key_is_never_accepted_as_an_hmac_secret() {
            let verifier = rsa_verifier();
            let claims = mock_authz_token(vec!["Lore".to_string()]);

            let forged = {
                let jwt_key = EncodingKey::from_secret(RSA_N.as_bytes());
                let mut header = Header::new(Algorithm::HS256);
                header.kid = Some("the kid".into());
                encode(&header, &claims, &jwt_key).expect("attacker signs with the public modulus")
            };

            let error = verifier
                .verify_token(&forged)
                .await
                .expect_err("an RSA key must never verify an HMAC signature");

            // Specifically the algorithm, not some incidental claim failure — otherwise this
            // would still pass with the pin removed.
            let JwtVerifierError::ValidationFailed(inner) = &error else {
                panic!("expected a validation failure, got {error:?}");
            };
            assert!(
                matches!(
                    inner.kind(),
                    jsonwebtoken::errors::ErrorKind::InvalidAlgorithm
                ),
                "the header's algorithm is refused, not merely the signature: {inner:?}"
            );
        }

        /// The same refusal on the synchronous interceptor path, which must not be a way
        /// around the async one.
        #[test]
        fn the_cached_path_also_refuses_an_hmac_signature_against_an_rsa_key() {
            let mut service = MockTestJWKService::new();
            // `times(1)` matters: `Ok(None)` is also what a cache miss produces, so without
            // proving the key was served this would pass against a mock that returned nothing.
            service.expect_get_cached_key().times(1).returning(|_| {
                Some((
                    DecodingKey::from_rsa_components(RSA_N, RSA_E).expect("rsa decoding key"),
                    Algorithm::RS256,
                ))
            });
            let verifier =
                JwtVerifier::new(Arc::new(service), None, Some(vec!["Lore".to_string()]));

            let forged = {
                let jwt_key = EncodingKey::from_secret(RSA_N.as_bytes());
                let mut header = Header::new(Algorithm::HS256);
                header.kid = Some("the kid".into());
                encode(&header, &jwt_claims_for_forgery(), &jwt_key).expect("forge")
            };

            // Deferred rather than denied outright, because a rejected signature is how a
            // rotated key presents — but never accepted.
            let verdict = verifier
                .try_verify_token_cached(&forged)
                .expect("not the token's own fault");
            assert!(verdict.is_none(), "must never verify, on any path");
        }

        fn jwt_claims_for_forgery() -> AuthorizationToken {
            mock_authz_token(vec!["Lore".to_string()])
        }

        /// A token naming a different RSA algorithm than the key does is refused too. The
        /// signature is nonsense, but the algorithm check fires before it is ever examined,
        /// which is what makes it a pin rather than a preference.
        #[tokio::test]
        async fn a_token_naming_another_algorithm_for_the_same_key_is_refused() {
            let verifier = rsa_verifier();
            let claims = mock_authz_token(vec!["Lore".to_string()]);
            let token = token_with_header(
                r#"{"alg":"RS512","typ":"JWT","kid":"the kid"}"#,
                &claims,
                "bm90LWEtc2lnbmF0dXJl",
            );

            let error = verifier
                .verify_token(&token)
                .await
                .expect_err("the key is pinned to RS256");
            let JwtVerifierError::ValidationFailed(inner) = &error else {
                panic!("expected a validation failure, got {error:?}");
            };
            assert!(
                matches!(
                    inner.kind(),
                    jsonwebtoken::errors::ErrorKind::InvalidAlgorithm
                ),
                "the algorithm is refused before the signature is looked at: {inner:?}"
            );
        }

        /// `alg: none` is the other half of the classic pair. It has no `Algorithm` at all, so
        /// it cannot match the pinned one and the token is thrown out at the header.
        #[tokio::test]
        async fn a_token_claiming_no_algorithm_is_refused() {
            let verifier = rsa_verifier();
            let claims = mock_authz_token(vec!["Lore".to_string()]);
            let token =
                token_with_header(r#"{"alg":"none","typ":"JWT","kid":"the kid"}"#, &claims, "");

            verifier
                .verify_token(&token)
                .await
                .expect_err("an unsigned token is never acceptable");
        }

        /// A token signed by a key that was never served must still be refused after the
        /// refresh, or the retry would be a way around verification rather than a way to
        /// pick up a rotation.
        #[tokio::test]
        async fn a_token_signed_by_an_unknown_key_is_still_refused_after_a_refresh() {
            let service = Arc::new(RotatingJWKService::new(
                "rotated-out-secret",
                Some(AGREED_UPON_SIGNING_SECRET),
            ));
            let verifier = verifier_for(service.clone());
            let encoded = encode_jwt_signed_with(
                "an-attackers-secret",
                &mock_authz_token(vec!["Lore".to_string()]),
            );

            verifier
                .verify_token(&encoded)
                .await
                .expect_err("a forged token is refused even though the key rotated");
            assert_eq!(service.refreshes(), 1);
        }

        fn mock_authz_token(audience: Vec<String>) -> AuthorizationToken {
            AuthorizationToken {
                user_id: "the u".to_string(),
                issuer: "the issuer".to_string(),
                issued_at: 1,
                audience,
                env: "the env".to_string(),
                name: "the name".to_string(),
                preferred_username: "pu".to_string(),
                resources: None,
                groups: None,
                is_service_account: Some(false),
                expires: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .add(Duration::from_secs(5))
                    .as_secs(),
                idp: "the idp".to_string(),
            }
        }

        fn mock_authn_token(audience: Vec<String>) -> JWTUserInfo {
            JWTUserInfo {
                user_id: "the u".to_string(),
                issuer: "the issuer".to_string(),
                issued_at: 1,
                audience,
                env: "the env".to_string(),
                name: "the name".to_string(),
                preferred_username: "pu".to_string(),
                is_service_account: Some(false),
                expires: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .add(Duration::from_secs(5))
                    .as_secs(),
            }
        }

        fn make_authz_token_with_audience(audience: Vec<String>) -> (AuthorizationToken, String) {
            let jwt_claims = mock_authz_token(audience);
            let encoded = encode_jwt(&jwt_claims);
            (jwt_claims, encoded)
        }

        fn make_authn_token_with_audience(audience: Vec<String>) -> (JWTUserInfo, String) {
            let jwt_claims = mock_authn_token(audience);
            let encoded = encode_jwt(&jwt_claims);
            (jwt_claims, encoded)
        }

        // a legacy token verified against an updated server with multiple audiences allowed
        #[tokio::test]
        async fn verify_string_audience_in_authn_token_against_multiple_allowed()
        -> Result<(), Box<dyn Error>> {
            let mut service = MockTestJWKService::new();
            service.expect_get_key().returning(|_| {
                Ok((
                    DecodingKey::from_secret(AGREED_UPON_SIGNING_SECRET.as_ref()),
                    AGREED_UPON_ALGORITHM,
                ))
            });

            let verifier = JwtVerifier::new(
                Arc::new(service),
                None,
                Some(vec!["urc.example.com".to_string(), "URC_test".to_string()]),
            );

            let authn_string_audience = json!({
                "sub": "the u".to_string(),
                "iss": "the issuer".to_string(),
                "iat": 1,
                "aud": "URC_test", // crucial bit
                "env": "the env".to_string(),
                "name": "the name".to_string(),
                "preferred_username": "pu".to_string(),
                "is_service_account": false,
                "exp": SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .add(Duration::from_secs(5))
                    .as_secs(),
            });
            let encoded = encode_jwt(&authn_string_audience);
            let verified_authn_token = verifier.verify_token(&encoded).await?;
            assert_eq!(verified_authn_token.audience, vec!["URC_test".to_string()]);

            Ok(())
        }

        #[tokio::test]
        async fn verify_string_audience_in_authz_token_against_multiple_allowed()
        -> Result<(), Box<dyn Error>> {
            let mut service = MockTestJWKService::new();
            service.expect_get_key().returning(|_| {
                Ok((
                    DecodingKey::from_secret(AGREED_UPON_SIGNING_SECRET.as_ref()),
                    AGREED_UPON_ALGORITHM,
                ))
            });

            let verifier = JwtVerifier::new(
                Arc::new(service),
                None,
                Some(vec!["urc.example.com".to_string(), "URC_test".to_string()]),
            );

            let base_authz_token = mock_authz_token(vec!["URC_test".to_string()]);
            let authz_string_audience = json!({
                "idp": base_authz_token.idp,
                "sub": base_authz_token.user_id,
                "iss": base_authz_token.issuer,
                "iat":base_authz_token.issued_at,
                "aud": "URC_test", // crucial bit
                "env": base_authz_token.env,
                "name": base_authz_token.name,
                "preferred_username": base_authz_token.preferred_username,
                "is_service_account": false,
                "exp": base_authz_token.expires
            });
            let encoded = encode_jwt(&authz_string_audience);
            let verified_authz_token = verifier.verify_token(&encoded).await?;
            assert_eq!(verified_authz_token, base_authz_token);

            Ok(())
        }

        #[tokio::test]
        async fn verify_single_audience_against_multiple_allowed() -> Result<(), Box<dyn Error>> {
            let mut service = MockTestJWKService::new();
            service.expect_get_key().returning(|_| {
                Ok((
                    DecodingKey::from_secret(AGREED_UPON_SIGNING_SECRET.as_ref()),
                    AGREED_UPON_ALGORITHM,
                ))
            });

            let verifier = JwtVerifier::new(
                Arc::new(service),
                None,
                Some(vec!["urc.example.com".to_string(), "Lore".to_string()]),
            );
            let (original_authz_token, encoded_authz_token) =
                make_authz_token_with_audience(vec!["Lore".to_string()]);
            let (original_authn_token, encoded_authn_token) =
                make_authn_token_with_audience(vec!["Lore".to_string()]);

            let verified_authz_token = verifier.verify_token(&encoded_authz_token).await?;
            let verified_authn_token = verifier.verify_token(&encoded_authn_token).await?;
            assert_eq!(original_authz_token, verified_authz_token);
            assert_eq!(
                original_authn_token.audience,
                verified_authn_token.audience.clone()
            );

            Ok(())
        }

        // an updated token verified against an updated server with multiple audiences allowed
        #[tokio::test]
        async fn verify_multiple_audience_against_multiple_allowed() -> Result<(), Box<dyn Error>> {
            let mut service = MockTestJWKService::new();
            service.expect_get_key().return_once(|_| {
                Ok((
                    DecodingKey::from_secret(AGREED_UPON_SIGNING_SECRET.as_ref()),
                    AGREED_UPON_ALGORITHM,
                ))
            });

            let common_audience = vec!["urc.example.com".to_string(), "Lore".to_string()];

            let verifier = JwtVerifier::new(Arc::new(service), None, Some(common_audience.clone()));

            let (original_token, encoded_token) = make_authz_token_with_audience(common_audience);

            let verified_token = verifier.verify_token(&encoded_token).await?;
            assert_eq!(original_token, verified_token);

            Ok(())
        }

        // an updated token verified against a old server config with a single audience allowed
        #[tokio::test]
        async fn verify_multiple_audience_against_single_allowed() -> Result<(), Box<dyn Error>> {
            let mut service = MockTestJWKService::new();
            service.expect_get_key().return_once(|_| {
                Ok((
                    DecodingKey::from_secret(AGREED_UPON_SIGNING_SECRET.as_ref()),
                    AGREED_UPON_ALGORITHM,
                ))
            });

            let verifier =
                JwtVerifier::new(Arc::new(service), None, Some(vec!["Lore".to_string()]));

            let (original_token, encoded_token) = make_authz_token_with_audience(vec![
                "urc.example.com".to_string(),
                "Lore".to_string(),
            ]);

            let verified_token = verifier.verify_token(&encoded_token).await?;
            assert_eq!(original_token, verified_token);

            Ok(())
        }

        /// The third-and-final claim decode: reached only when the token carries
        /// none of the Lore-specific claims, as a conformant OpenID Connect ID
        /// token does. It must accept the RFC 7519 / OIDC-guaranteed minimum,
        /// accept the optional display claims when present, and still enforce
        /// every check `Validation` applies regardless of target shape.
        mod oidc_third_decode {
            use super::*;

            fn oidc_verifier() -> JwtVerifier {
                let mut service = MockTestJWKService::new();
                service.expect_get_key().returning(|_| {
                    Ok((
                        DecodingKey::from_secret(AGREED_UPON_SIGNING_SECRET.as_ref()),
                        AGREED_UPON_ALGORITHM,
                    ))
                });

                JwtVerifier::oidc(
                    Arc::new(service),
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

            /// A Lore-issued token (carrying `env`/`name`/`preferred_username`) always
            /// matches `AuthorizationToken` or `JWTUserInfo` first, so it never reaches
            /// this decode — and therefore never gets the wildcard from it.
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

            /// The invariant the third decode exists to preserve: a
            /// `[server.auth.jwk]`-only verifier — `LoreClaims` mode, what every
            /// `ucs-auth` deployment builds via `JwtVerifier::new` — must refuse a
            /// token this same signature, issuer, audience, and expiry would pass,
            /// once it lacks `env`/`name`/`preferred_username`. Without this gate,
            /// such a deployment would accept a trusted-issuer-signed token that
            /// must otherwise be refused, and grant it every repository on the
            /// strength of the omitted claims — the exact widening
            /// `[server.auth.oidc]` is supposed to require an explicit opt-in for.
            #[tokio::test]
            async fn a_non_oidc_verifier_rejects_the_minimal_claim_shape() {
                let mut service = MockTestJWKService::new();
                service.expect_get_key().returning(|_| {
                    Ok((
                        DecodingKey::from_secret(AGREED_UPON_SIGNING_SECRET.as_ref()),
                        AGREED_UPON_ALGORITHM,
                    ))
                });
                let non_oidc_verifier = JwtVerifier::new(
                    Arc::new(service),
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

        /// `[server.auth.oidc].resource`: the deployment names itself, the
        /// provider audience-restricts an RFC 9068 access token to that name
        /// (RFC 8707 §2), and the server accepts nothing else. What this buys
        /// is stated precisely in the LEP: two deployments sharing an issuer
        /// and a client id stop accepting each other's tokens, because `aud`
        /// now identifies the resource server rather than the client.
        mod resource_mode {
            use super::*;

            const RESOURCE: &str = "https://lore.example.com";
            const OTHER_RESOURCE: &str = "https://lore.other.example.com";
            const CLIENT_ID: &str = "lore";

            fn resource_verifier() -> JwtVerifier {
                let mut service = MockTestJWKService::new();
                service.expect_get_key().returning(|_| {
                    Ok((
                        DecodingKey::from_secret(AGREED_UPON_SIGNING_SECRET.as_ref()),
                        AGREED_UPON_ALGORITHM,
                    ))
                });
                service.expect_refresh_key().returning(|_| Ok(None));

                JwtVerifier::oidc_resource(
                    Arc::new(service),
                    Some("https://id.example.com".to_string()),
                    Some(vec![RESOURCE.to_string()]),
                )
            }

            /// RFC 9068 §2.2's required claim set, audience-restricted to this
            /// deployment's resource identifier.
            fn access_token_claims() -> serde_json::Value {
                json!({
                    "sub": "the-subject",
                    "iss": "https://id.example.com",
                    "aud": RESOURCE,
                    "client_id": CLIENT_ID,
                    "iat": 1,
                    "jti": "the-token-id",
                    "exp": SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .add(Duration::from_secs(5))
                        .as_secs(),
                })
            }

            /// `encode` writes `typ: "JWT"`, so the RFC 9068 media type has to
            /// be set deliberately — which is the point of the header check.
            fn encode_access_token(claims: &serde_json::Value, typ: Option<&str>) -> String {
                let jwt_key = EncodingKey::from_secret(AGREED_UPON_SIGNING_SECRET.as_ref());
                let mut header = Header::new(AGREED_UPON_ALGORITHM);
                header.kid = Some("the kid".into());
                header.typ = typ.map(str::to_string);
                encode(&header, claims, &jwt_key).unwrap()
            }

            /// An ID token — or any token — whose `aud` is the *client id*
            /// must be refused by a resource-mode server, even though it is
            /// signed by the pinned issuer and unexpired. This is what kills
            /// cross-deployment token interchange: a token minted for a
            /// sibling Lore deployment behind the same provider carries that
            /// deployment's `aud`, not this one's.
            #[tokio::test]
            async fn a_client_id_audience_token_is_rejected() {
                let mut claims = access_token_claims();
                claims["aud"] = json!(CLIENT_ID);
                let encoded = encode_access_token(&claims, Some("at+jwt"));

                resource_verifier().verify_token(&encoded).await.expect_err(
                    "a token audienced to the client id authorizes every deployment \
                     sharing that client — which is the risk resource mode removes",
                );
            }

            /// The sibling-deployment case stated directly: correct `typ`,
            /// correct issuer, valid signature, and an `aud` naming *another*
            /// Lore server's resource identifier.
            #[tokio::test]
            async fn another_deployments_resource_audience_is_rejected() {
                let mut claims = access_token_claims();
                claims["aud"] = json!(OTHER_RESOURCE);
                let encoded = encode_access_token(&claims, Some("at+jwt"));

                resource_verifier()
                    .verify_token(&encoded)
                    .await
                    .expect_err("a token minted for the deployment next door is not ours");
            }

            #[tokio::test]
            async fn a_conformant_access_token_is_accepted_and_wildcarded() {
                let encoded = encode_access_token(&access_token_claims(), Some("at+jwt"));

                let token = resource_verifier()
                    .verify_token(&encoded)
                    .await
                    .expect("an RFC 9068 access token for this resource is accepted");

                assert_eq!(token.user_id, "the-subject");
                assert_eq!(token.issuer, "https://id.example.com");
                assert_eq!(token.idp, "https://id.example.com");
                assert_eq!(token.audience, vec![RESOURCE.to_string()]);
                let resources = token.resources.expect("wildcard resource is populated");
                assert!(resources[0].is_wildcard_resource());
            }

            /// RFC 9068 §2.1 recommends omitting the `application/` prefix but
            /// §4 step 1 accepts both spellings, and a media type is compared
            /// case-insensitively.
            #[tokio::test]
            async fn both_spellings_of_the_media_type_are_accepted() {
                for typ in [
                    "at+jwt",
                    "application/at+jwt",
                    "AT+JWT",
                    "Application/AT+JWT",
                ] {
                    let encoded = encode_access_token(&access_token_claims(), Some(typ));
                    resource_verifier()
                        .verify_token(&encoded)
                        .await
                        .unwrap_or_else(|e| panic!("typ '{typ}' must be accepted: {e}"));
                }
            }

            /// RFC 9068 §4 step 1: "reject tokens carrying any other value".
            /// `typ: "JWT"` is what every ordinary JWT — every ID token
            /// included — carries, so this check is what makes ID-token
            /// acceptance actually off rather than merely unadvertised.
            #[tokio::test]
            async fn a_plain_jwt_media_type_is_rejected() {
                for typ in [Some("JWT"), Some("oauth-access-token"), Some(""), None] {
                    let encoded = encode_access_token(&access_token_claims(), typ);
                    if let Ok(accepted) = resource_verifier().verify_token(&encoded).await {
                        panic!("typ {typ:?} was accepted, yielding {}", accepted.user_id);
                    }
                }
            }

            /// The other half of "ID-token acceptance is OFF": a conformant ID
            /// token, correctly audienced to the client id and correctly
            /// signed, is exactly what an attacker harvests by standing up a
            /// look-alike deployment. In resource mode it verifies nothing.
            #[tokio::test]
            async fn an_id_token_is_rejected_in_resource_mode() {
                let encoded = encode_jwt(&json!({
                    "sub": "the-subject",
                    "iss": "https://id.example.com",
                    "aud": CLIENT_ID,
                    "iat": 1,
                    "exp": SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .add(Duration::from_secs(5))
                        .as_secs(),
                }));

                resource_verifier()
                    .verify_token(&encoded)
                    .await
                    .expect_err("the weaker credential is not a way around the stronger one");
            }

            /// Lore's own claim shapes are refused too, and for the same
            /// reason: a `ucs-auth`-issued token carries `typ: "JWT"`, so it
            /// never reaches a claim decode here however well it verifies
            /// otherwise. Resource mode has exactly one door.
            #[tokio::test]
            async fn a_lore_shaped_token_is_rejected_in_resource_mode() {
                let mut claims = access_token_claims();
                claims["env"] = json!("the env");
                claims["name"] = json!("the name");
                claims["preferred_username"] = json!("pu");
                let encoded = encode_jwt(&claims);

                resource_verifier()
                    .verify_token(&encoded)
                    .await
                    .expect_err("resource mode accepts the RFC 9068 shape and nothing else");
            }

            /// `sub` and `iat` are RFC 9068 §2.2 REQUIRED claims that Lore
            /// actually consumes — `sub` is the identity every authenticated
            /// path records — so their absence is a rejection rather than a
            /// substitution.
            #[tokio::test]
            async fn a_token_missing_sub_or_iat_is_rejected() {
                for claim in ["sub", "iat"] {
                    let mut claims = access_token_claims();
                    claims.as_object_mut().expect("claims object").remove(claim);
                    let encoded = encode_access_token(&claims, Some("at+jwt"));

                    if resource_verifier().verify_token(&encoded).await.is_ok() {
                        panic!("a token without '{claim}' must be refused");
                    }
                }
            }

            /// `jti` and `client_id` are REQUIRED of the *authorization server*
            /// by RFC 9068 §2.2, but §4 — the resource server's own validation
            /// list — names neither, and Lore reads neither: it keeps no replay
            /// cache for `jti` to key (LEP Non-Functional Considerations,
            /// "Statelessness"), and it no longer pins the client id, because
            /// `aud` names the resource server instead. Refusing a token whose
            /// security properties are complete, over claims the server would
            /// then discard, buys nothing and costs interoperability.
            #[tokio::test]
            async fn a_token_without_jti_or_client_id_is_still_accepted() {
                let mut claims = access_token_claims();
                let object = claims.as_object_mut().expect("claims object");
                object.remove("jti");
                object.remove("client_id");
                let encoded = encode_access_token(&claims, Some("at+jwt"));

                resource_verifier()
                    .verify_token(&encoded)
                    .await
                    .expect("leniency on claims the resource server does not read");
            }

            #[tokio::test]
            async fn wrong_issuer_and_expiry_are_still_rejected() {
                let mut wrong_issuer = access_token_claims();
                wrong_issuer["iss"] = json!("https://not-the-configured-issuer.invalid");
                resource_verifier()
                    .verify_token(&encode_access_token(&wrong_issuer, Some("at+jwt")))
                    .await
                    .expect_err("the issuer pin holds in resource mode too");

                let mut expired = access_token_claims();
                expired["exp"] = json!(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        - 3600
                );
                resource_verifier()
                    .verify_token(&encode_access_token(&expired, Some("at+jwt")))
                    .await
                    .expect_err("the expiry check holds in resource mode too");
            }

            /// A `typ` this server does not accept is the token's own fault and
            /// no key could ever rescue it, so — like an expired token or a
            /// wrong audience — it must not be a way to drive outbound key
            /// fetches.
            #[tokio::test]
            async fn a_wrong_media_type_never_asks_for_a_refresh() {
                let service = Arc::new(RotatingJWKService::new(
                    AGREED_UPON_SIGNING_SECRET,
                    Some(AGREED_UPON_SIGNING_SECRET),
                ));
                let verifier = JwtVerifier::oidc_resource(
                    service.clone(),
                    Some("https://id.example.com".to_string()),
                    Some(vec![RESOURCE.to_string()]),
                );
                let encoded = encode_access_token(&access_token_claims(), Some("JWT"));

                verifier
                    .verify_token(&encoded)
                    .await
                    .expect_err("the wrong media type stays rejected");
                verifier
                    .try_verify_token_cached(&encoded)
                    .expect_err("and is rejected outright, not deferred");

                assert_eq!(service.refreshes(), 0);
            }

            /// The regression guard in the other direction: turning resource
            /// mode off leaves the ID-token mode unaffected, so the opt-in
            /// really is one.
            #[tokio::test]
            async fn an_access_token_shape_still_verifies_in_id_token_mode() {
                let mut service = MockTestJWKService::new();
                service.expect_get_key().returning(|_| {
                    Ok((
                        DecodingKey::from_secret(AGREED_UPON_SIGNING_SECRET.as_ref()),
                        AGREED_UPON_ALGORITHM,
                    ))
                });
                let id_token_verifier = JwtVerifier::oidc(
                    Arc::new(service),
                    Some("https://id.example.com".to_string()),
                    Some(vec![CLIENT_ID.to_string()]),
                );
                let mut claims = access_token_claims();
                claims["aud"] = json!(CLIENT_ID);

                id_token_verifier
                    .verify_token(&encode_access_token(&claims, Some("at+jwt")))
                    .await
                    .expect("ID-token mode is unchanged: it never looked at typ");
            }
        }

        #[tokio::test]
        async fn rejects_unrecognised_audience() -> Result<(), Box<dyn Error>> {
            let mut service = MockTestJWKService::new();
            service.expect_get_key().return_once(|_| {
                Ok((
                    DecodingKey::from_secret(AGREED_UPON_SIGNING_SECRET.as_ref()),
                    AGREED_UPON_ALGORITHM,
                ))
            });

            let verifier =
                JwtVerifier::new(Arc::new(service), None, Some(vec!["skein".to_string()]));

            let (_, encoded_token) = make_authz_token_with_audience(vec!["Lore".to_string()]);

            let verify_error = verifier.verify_token(&encoded_token).await.unwrap_err();
            assert!(matches!(
                verify_error,
                JwtVerifierError::ValidationFailed(_)
            ));

            Ok(())
        }
    }
}

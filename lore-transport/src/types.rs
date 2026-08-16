// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use bytes::Bytes;
use lore_base::types::*;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Environment types
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(bound(deserialize = "'de: 'static"))]
pub struct EnvironmentConfig {
    pub endpoint: Option<Endpoint>,
    pub config: Option<EnvironmentServerConfig>,
}

impl EnvironmentConfig {
    pub fn max_query_batch(&self) -> Option<usize> {
        self.config.as_ref().and_then(|c| c.max_query_batch)
    }

    /// Per-service endpoint URL. If the environment's `endpoint.storage_url`
    /// is set and non-empty, it overrides `fallback`; otherwise `fallback` is
    /// returned unchanged. Same contract for the other `*_url` methods below.
    pub fn storage_url<'a>(&'a self, fallback: &'a str) -> &'a str {
        service_url_or(
            self.endpoint
                .as_ref()
                .and_then(|e| e.storage_url.as_deref()),
            fallback,
        )
    }

    pub fn revision_url<'a>(&'a self, fallback: &'a str) -> &'a str {
        service_url_or(
            self.endpoint
                .as_ref()
                .and_then(|e| e.revision_url.as_deref()),
            fallback,
        )
    }

    pub fn lock_url<'a>(&'a self, fallback: &'a str) -> &'a str {
        service_url_or(
            self.endpoint.as_ref().and_then(|e| e.lock_url.as_deref()),
            fallback,
        )
    }

    pub fn repository_url<'a>(&'a self, fallback: &'a str) -> &'a str {
        service_url_or(
            self.endpoint
                .as_ref()
                .and_then(|e| e.repository_url.as_deref()),
            fallback,
        )
    }

    pub fn notification_url<'a>(&'a self, fallback: &'a str) -> &'a str {
        service_url_or(
            self.endpoint
                .as_ref()
                .and_then(|e| e.notification_url.as_deref()),
            fallback,
        )
    }
}

fn service_url_or<'a>(override_url: Option<&'a str>, fallback: &'a str) -> &'a str {
    match override_url {
        Some(url) if !url.is_empty() => url,
        _ => fallback,
    }
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(bound(deserialize = "'de: 'static"))]
pub struct Endpoint {
    pub auth_url: Option<String>,
    pub repository_url: Option<String>,
    pub storage_url: Option<String>,
    pub revision_url: Option<String>,
    pub lock_url: Option<String>,
    pub notification_url: Option<String>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(bound(deserialize = "'de: 'static"))]
pub struct CompressionMode(u32);

impl CompressionMode {
    pub fn from_u32(value: u32) -> Self {
        CompressionMode(value)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(bound(deserialize = "'de: 'static"))]
pub struct EnvironmentServerConfig {
    pub max_query_batch: Option<usize>,
    pub compression_mode: Option<CompressionMode>,
}

// ---------------------------------------------------------------------------
// Protocol response types
// ---------------------------------------------------------------------------

pub struct BranchPushResponse {
    /// True if the server performed a fast-forward merge
    pub fast_forward_merged: bool,
    /// New branch latest revision identifier
    pub revision: Hash,
    /// Revision number of new branch latest revision
    pub revision_number: u64,
    /// Optional message from the server
    pub message: Option<String>,
}

pub struct BranchQueryResponse {
    /// Branch ID
    pub id: BranchId,
    /// Latest revision
    pub latest: Hash,
    /// Metadata hash
    pub metadata: Hash,
    /// Whether the branch has been deleted (name->id mapping removed)
    pub deleted: bool,
}

pub struct BranchListResponse {
    /// Branch list
    pub list: Vec<BranchMetadata>,
}

pub struct RevisionListResponse {
    pub items: Vec<RevisionItem>,
    pub next_revision: Hash,
    pub previous_revision: Hash,
}

#[derive(Debug)]
pub struct RevisionItem {
    pub number: u64,
    pub signature: Hash,
    pub metadata: Hash,
    pub state: Bytes,
}

#[derive(Clone)]
pub enum RevisionListStart {
    Identifier(RevisionListIdentifier),
    Signature(Hash),
}

#[derive(Clone)]
pub struct RevisionListIdentifier {
    pub branch: BranchId,
    pub number: u64,
}

impl From<RevisionListIdentifier> for RevisionListStart {
    fn from(value: RevisionListIdentifier) -> Self {
        RevisionListStart::Identifier(value)
    }
}

impl From<Hash> for RevisionListStart {
    fn from(value: Hash) -> Self {
        RevisionListStart::Signature(value)
    }
}

#[derive(Default, Debug, Clone)]
pub struct RepositoryData {
    pub id: RepositoryId,
    pub name: String,
    pub metadata: Hash,
}

/// Result of a repository metadata compare-and-swap operation
#[derive(Default, Debug, Clone)]
pub struct MetadataSetResult {
    pub success: bool,
    pub current_hash: Hash,
}

// ---------------------------------------------------------------------------
// Authentication types
// ---------------------------------------------------------------------------

/// Result of an interactive login session initiation.
#[derive(Clone, Debug)]
pub struct AuthSession {
    /// Opaque session identifier for polling.
    pub session_code: String,
    /// URL the user should visit to authenticate.
    pub login_url: String,
}

/// How the domains a token may be sent to are determined.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenRecipients {
    /// The token's own claims name where it may go; the recipient is verified
    /// against them and rejected if absent.
    SelfDescribing,
    /// These domains are authoritative; the recipient is added if absent.
    Explicit(Vec<String>),
}

impl TokenRecipients {
    /// The domains `token` may be sent to, always admitting `recipient_domain`.
    ///
    /// `SelfDescribing` derives the set from the token's own claims (read without
    /// signature verification -- something else has verified or will verify the
    /// token), refusing a recipient the claims do not name; the returned set is
    /// the claims' own and need not list the recipient verbatim. `Explicit` is
    /// authoritative; the recipient is added if absent. Enforcement happens where
    /// a stored token is loaded, by filtering on the set this returns.
    pub fn domains_for(
        &self,
        token: &str,
        recipient_domain: &str,
    ) -> Result<Vec<String>, lore_credential::JwtUsageError> {
        use lore_credential::JwtUsageError;
        match self {
            Self::SelfDescribing => {
                let decoded = lore_credential::insecure_decode_token(token).map_err(|err| {
                    JwtUsageError::internal(format!("Could not decode token: {err}"))
                })?;
                lore_credential::verify_jwt_usage_for_remote(&decoded.claims, recipient_domain)?;
                Ok(decoded.claims.acceptable_root_domains())
            }
            Self::Explicit(domains) => {
                let mut domains = domains.clone();
                if !domains.iter().any(|domain| domain == recipient_domain) {
                    domains.push(recipient_domain.to_string());
                }
                Ok(domains)
            }
        }
    }
}

/// Authentication token with user identity metadata.
///
/// Returned from login flows (interactive, token exchange, refresh).
/// This is the protocol-layer type -- transient, in-memory. The orchestration
/// layer converts it to `SerializedToken` (the token store's on-disk format)
/// when persisting to `tokens.toml`.
#[derive(Clone, Debug)]
pub struct AuthenticationToken {
    /// The bearer token string (typically a JWT, but opaque to the interface).
    pub token: String,
    /// Opaque user identity ID.
    pub user_id: String,
    /// Human-readable display name.
    pub user_name: String,
    /// Expiry as milliseconds since UNIX epoch.
    pub expires_ms: u64,
    /// How the domains this token may be sent to are determined.
    pub recipients: TokenRecipients,
    /// One-time-use refresh token for obtaining a new authentication token
    /// without re-authenticating. `None` if the auth backend does not support
    /// refresh. Consumed on use -- the next refresh returns a new one.
    pub refresh_token: Option<String>,
}

/// Authorization token scoped to a specific resource.
///
/// Returned from `exchange_for_repository` or `exchange_for_custom_resource`.
/// Shorter-lived than the authentication token and re-obtained via exchange
/// when expired.
#[derive(Clone, Debug)]
pub struct AuthorizationToken {
    /// The bearer token string.
    pub token: String,
    /// Expiry as milliseconds since UNIX epoch.
    pub expires_ms: u64,
    /// How the domains this token may be sent to are determined.
    pub recipients: TokenRecipients,
}

/// Resolved user identity information.
#[derive(Clone, Debug)]
pub struct ResolvedUser {
    /// Opaque user identity ID.
    pub user_id: String,
    /// Human-readable display name.
    pub user_name: String,
}

/// A JWT with the given claims and a signature nothing checks.
#[cfg(test)]
pub(crate) fn unsigned_jwt(claims: &str) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(claims),
        URL_SAFE_NO_PAD.encode("not-a-signature"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const FALLBACK: &str = "grpc://fallback.example:1234";

    fn env_with(endpoint: Endpoint) -> EnvironmentConfig {
        EnvironmentConfig {
            endpoint: Some(endpoint),
            config: None,
        }
    }

    #[test]
    fn service_url_returns_override_when_set() {
        let env = env_with(Endpoint {
            storage_url: Some("quic://storage.example:7000".into()),
            ..Default::default()
        });
        assert_eq!(env.storage_url(FALLBACK), "quic://storage.example:7000");
    }

    #[test]
    fn service_url_falls_back_when_field_is_none() {
        let env = env_with(Endpoint::default());
        assert_eq!(env.storage_url(FALLBACK), FALLBACK);
        assert_eq!(env.revision_url(FALLBACK), FALLBACK);
        assert_eq!(env.lock_url(FALLBACK), FALLBACK);
        assert_eq!(env.repository_url(FALLBACK), FALLBACK);
        assert_eq!(env.notification_url(FALLBACK), FALLBACK);
    }

    #[test]
    fn service_url_falls_back_when_field_is_empty_string() {
        // An empty Option<String> from proto decoding must behave identically
        // to None — the field is "unset."
        let env = env_with(Endpoint {
            storage_url: Some(String::new()),
            revision_url: Some(String::new()),
            ..Default::default()
        });
        assert_eq!(env.storage_url(FALLBACK), FALLBACK);
        assert_eq!(env.revision_url(FALLBACK), FALLBACK);
    }

    #[test]
    fn service_url_falls_back_when_endpoint_section_missing() {
        let env = EnvironmentConfig {
            endpoint: None,
            config: None,
        };
        assert_eq!(env.storage_url(FALLBACK), FALLBACK);
        assert_eq!(env.repository_url(FALLBACK), FALLBACK);
    }

    #[test]
    fn per_service_overrides_are_independent() {
        // Only some services have overrides; the others must fall back.
        let env = env_with(Endpoint {
            storage_url: Some("quic://storage.example:7000".into()),
            lock_url: Some("grpc://lock.example:8000".into()),
            ..Default::default()
        });
        assert_eq!(env.storage_url(FALLBACK), "quic://storage.example:7000");
        assert_eq!(env.lock_url(FALLBACK), "grpc://lock.example:8000");
        assert_eq!(env.revision_url(FALLBACK), FALLBACK);
        assert_eq!(env.repository_url(FALLBACK), FALLBACK);
        assert_eq!(env.notification_url(FALLBACK), FALLBACK);
    }

    #[test]
    fn self_describing_recipients_keep_jwt_derived_domains() {
        let jwt = crate::types::unsigned_jwt(
            r#"{"iss":"auth.example.com","sub":"user-1","exp":9999999999,"aud":["repo.example.com"]}"#,
        );

        let domains = TokenRecipients::SelfDescribing
            .domains_for(&jwt, "repo.example.com")
            .unwrap();

        assert_eq!(
            domains,
            vec![
                "auth.example.com".to_string(),
                "repo.example.com".to_string(),
            ]
        );
    }

    #[test]
    fn explicit_recipients_beat_the_jwt_derived_set() {
        // An OIDC token's `aud` is a client id and `iss` a URL; only the backend's
        // explicit set can admit the remote.
        let jwt = crate::types::unsigned_jwt(
            r#"{"iss":"https://id.example.com","sub":"user-1","exp":9999999999,"aud":["lore-cli"]}"#,
        );
        let recipients = TokenRecipients::Explicit(vec!["id.example.com".to_string()]);

        let domains = recipients.domains_for(&jwt, "repo.example.com").unwrap();

        assert!(domains.contains(&"id.example.com".to_string()));
        assert!(domains.contains(&"repo.example.com".to_string()));
    }

    #[test]
    fn explicit_recipients_already_naming_the_remote_are_not_duplicated() {
        let jwt = crate::types::unsigned_jwt(
            r#"{"iss":"https://id.example.com","sub":"user-1","exp":9999999999,"aud":["lore-cli"]}"#,
        );
        let recipients = TokenRecipients::Explicit(vec![
            "id.example.com".to_string(),
            "repo.example.com".to_string(),
        ]);

        let domains = recipients.domains_for(&jwt, "repo.example.com").unwrap();

        assert_eq!(
            domains,
            vec!["id.example.com".to_string(), "repo.example.com".to_string()]
        );
    }
}

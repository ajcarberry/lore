// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::collections::HashMap;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use lore_base::error::Disconnected;
use lore_base::error::Maintenance;
use lore_base::error::NoRemote;
use lore_base::error::NotAuthenticated;
use lore_base::error::NotAuthorized;
use lore_base::error::NotFound;
use lore_base::error::NotSupported;
use lore_base::error::Oversized;
use lore_base::error::SlowDown;
use lore_base::lore_debug;
use lore_base::lore_trace;
use lore_base::lore_warn;
use lore_base::types::RepositoryId;
use lore_credential::get_domain_or_empty;
use lore_credential::insecure_decode_token;
use lore_credential::token_store;
use lore_credential::token_store::tokens_only_for_recipient_domain;
use lore_credential::verify_jwt_usage_for_remote;
use lore_error_set::prelude::*;
use tokio::sync::Mutex;

use crate::auth::authentication;
use crate::types::AuthorizationToken;

#[error_set]
pub enum ExchangeError {
    NotAuthenticated,
    NotAuthorized,
    Disconnected,
    SlowDown,
    Maintenance,
    NotFound,
    NoRemote,
    NotSupported,
    Oversized,
}

type AuthUrl = String;
type Identity = String;
type CacheResourceId = String;
type RecipientDomain = String;
type AuthzCache = Mutex<HashMap<(AuthUrl, Identity, CacheResourceId, RecipientDomain), String>>;

static AUTHZ_CACHE: std::sync::OnceLock<AuthzCache> = std::sync::OnceLock::new();

fn cache() -> &'static AuthzCache {
    AUTHZ_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn is_expired(expires: u64) -> bool {
    let expires = expires as u128;
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    current_time >= expires
}

/// The domains an authz token obtained via exchange may be sent to, recorded alongside it
/// in the token store and later enforced by [`verify_jwt_usage_for_remote`].
///
/// An OIDC ID token's `aud` is a client id and `iss` an issuer URL, neither of which is
/// the repository's domain, so a set derived only from the token's own claims can never
/// include it. `AuthorizationToken::acceptable_root_domains` is authoritative whenever the
/// `Authentication` implementation filled it in, since only the implementation knows its
/// own tokens' audience semantics; an empty set falls back to the JWT-derived domains.
fn acceptable_root_domains(
    authz: &AuthorizationToken,
    recipient_domain: &str,
) -> Result<Vec<String>, ExchangeError> {
    if authz.acceptable_root_domains.is_empty() {
        let decoded_token = insecure_decode_token(&authz.token)
            .internal("Could not decode token")
            .map_err(ExchangeError::from)?;
        verify_jwt_usage_for_remote(&decoded_token.claims, recipient_domain).map_err(|err| {
            lore_warn!("{err}");
            ExchangeError::internal_with_context(
                err,
                "The token is not suitable for what you intend to do",
            )
        })?;
        return Ok(decoded_token.claims.acceptable_root_domains());
    }

    // The remote is added rather than checked for: what says whether this credential may
    // reach it is the *authentication* token's stored set, which
    // `tokens_for_auth_service_and_recipient` has already required the recipient to be in.
    // A backend's set describes its own token's audience and can never name the remote.
    let mut domains = authz.acceptable_root_domains.clone();
    if !domains.iter().any(|domain| domain == recipient_domain) {
        domains.push(recipient_domain.to_string());
    }
    Ok(domains)
}

/// Loads only a stored authentication token that is acceptable both for the auth service
/// it will be presented to and for the remote the authorization token is destined for.
///
/// The recipient half is the token-recipient guard on this path. `exchange` is reachable
/// with an explicit identity and a caller-supplied recipient, and where the authorization
/// token *is* the authentication token -- an OpenID Connect passthrough -- any remote that
/// advertises the auth URL a user logged in against would otherwise be handed that user's
/// credential. Only the stored acceptable-domain set records where a token may go, since an
/// ID token's own claims name a client id and an issuer but never a remote, so the check
/// belongs on the way out of the store.
fn tokens_for_auth_service_and_recipient(
    auth_domain: String,
    recipient_domain: String,
) -> impl FnMut(&&token_store::IdentityToken) -> bool {
    let mut for_auth_service = tokens_only_for_recipient_domain(auth_domain);
    let mut for_recipient = tokens_only_for_recipient_domain(recipient_domain);
    move |item| for_auth_service(item) && for_recipient(item)
}

/// Exchanges an authentication token for a repository-scoped authorization
/// token via the registered `Authentication` implementation.
///
/// Checks the in-memory cache and on-disk token store first. On miss,
/// loads the authn token and delegates to the implementation's
/// `exchange_for_repository`. The returned authz token is cached in memory
/// and persisted to the token store.
///
/// Token store keys use `"{auth_url}/{repository_id}"` (no implementation-
/// specific prefix). The `Authentication` implementation handles resource ID
/// formatting internally.
pub async fn exchange(
    auth_url: &str,
    identity: &str,
    repository: RepositoryId,
    recipient_domain: String,
) -> Result<String, ExchangeError> {
    if auth_url.is_empty() {
        lore_debug!("No auth url, unable to perform authz exchange");
        return Err(NotSupported {
            operation: "No authentication configured on server".to_string(),
        }
        .into());
    }
    if identity.is_empty() {
        lore_debug!("No identity, unable to perform authz exchange");
        return Err(NotAuthenticated.into());
    }

    let auth_domain = get_domain_or_empty(auth_url);
    let auth_url = auth_url.to_string();
    let repo_id_str = repository.to_string();
    let cache_key = (
        auth_url.clone(),
        identity.to_string(),
        repo_id_str.clone(),
        recipient_domain.clone(),
    );
    let mut cache = cache().lock().await;

    lore_trace!(
        "Check for cached authz token for {cache_key:?} in cache with {} tokens",
        cache.len()
    );

    let mut token = cache.get(&cache_key).cloned().unwrap_or_default();

    // Token store key: "{auth_url}/{repository_id}" (no urc- prefix)
    let token_store_key = format!("{auth_url}/{repo_id_str}");

    if !token.is_empty() {
        lore_trace!("Found cached authz token for {cache_key:?}");
    } else {
        lore_trace!("Check for token store authz token for {token_store_key:?}");
        token = token_store::load_user_token(
            &token_store_key,
            identity,
            tokens_only_for_recipient_domain(recipient_domain.clone()),
        )
        .await
        .unwrap_or_default();
    }

    if !token.is_empty() {
        lore_trace!("Validating token expiry");
        if let Some(user_info) = lore_credential::user_info_from_token(token.clone()) {
            if !is_expired(user_info.expires) {
                lore_trace!("Using authz token for {cache_key:?}");
                cache.insert(cache_key, token.clone());
                return Ok(token.clone());
            } else {
                lore_debug!("Authz token for {cache_key:?} has expired");
            }
        } else {
            lore_warn!("Invalid authz token found for {cache_key:?}");
        }
    } else {
        lore_trace!("No stored authz token found for {cache_key:?}");
    }

    // Load authn token for the auth service domain, and only if it may reach the recipient
    lore_trace!("Authorizing using authn identity: {identity}");
    let Some(auth_service_only_token) = lore_credential::user_info(
        auth_url.as_str(),
        identity,
        tokens_for_auth_service_and_recipient(auth_domain, recipient_domain.clone()),
    )
    .await
    else {
        lore_debug!(
            "No authentication token usable at {recipient_domain}, unable to perform authz exchange"
        );
        return Err(NotAuthenticated.into());
    };
    lore_trace!("Authorizing using endpoint: {auth_url}");

    let time_start = Instant::now();

    // Delegate to the Authentication implementation
    let auth_impl = authentication::find(&auth_url)
        .forward::<ExchangeError>("Unable to connect to auth exchange endpoint")?;
    // The correlation_id is no longer available from ExecutionContext in lore-transport.
    // Pass an empty string -- the gRPC interceptor may inject it from ambient state.
    let correlation_id = String::new();

    lore_trace!("Send auth exchange request");
    let authz = auth_impl
        .exchange_for_repository(
            &auth_url,
            &auth_service_only_token.token,
            repository,
            &correlation_id,
        )
        .await
        .map_err(|err| {
            if err.is_not_authorized() {
                ExchangeError::from(NotAuthorized)
            } else {
                ExchangeError::internal_with_context(err, "Failed to exchange token")
            }
        })?;

    if authz.token.is_empty() {
        return Err(ExchangeError::internal("Empty token response"));
    }
    let domains = acceptable_root_domains(&authz, &recipient_domain)?;
    let token = authz.token;

    lore_trace!(
        "Authorization with user token successful in {} ms",
        time_start.elapsed().as_millis()
    );

    lore_trace!("Cached authz token for {cache_key:?}");

    cache.insert(cache_key, token.clone());

    let _ = token_store::store_user_token(&token_store_key, identity, &token, domains)
        .await
        .map_err(|err| {
            lore_warn!("Failed to store token: {err}");
        });

    Ok(token)
}

/// Exchanges an authentication token for an authorization token scoped to an
/// arbitrary resource identifier (non-repository). Mirrors `exchange` but
/// delegates to the implementation's `exchange_for_custom_resource`, letting
/// callers authorize against resources the `RepositoryId` model cannot express.
///
/// The `resource_id` is used verbatim as the cache/token-store key and is
/// passed unmodified to the auth backend.
pub async fn exchange_custom_resource(
    auth_url: &str,
    identity: &str,
    resource_id: &str,
    recipient_domain: String,
) -> Result<String, ExchangeError> {
    if auth_url.is_empty() {
        lore_debug!("No auth url, unable to perform authz exchange");
        return Err(NotSupported {
            operation: "No authentication configured on server".to_string(),
        }
        .into());
    }
    if identity.is_empty() {
        lore_debug!("No identity, unable to perform authz exchange");
        return Err(NotAuthenticated.into());
    }
    if resource_id.is_empty() {
        lore_debug!("No resource_id, unable to perform authz exchange");
        return Err(ExchangeError::internal(
            "Failed to exchange token: empty resource_id",
        ));
    }

    let auth_domain = get_domain_or_empty(auth_url);
    let auth_url = auth_url.to_string();
    let cache_key = (
        auth_url.clone(),
        identity.to_string(),
        resource_id.to_string(),
        recipient_domain.clone(),
    );
    let mut cache = cache().lock().await;

    lore_trace!(
        "Check for cached authz token for {cache_key:?} in cache with {} tokens",
        cache.len()
    );

    let mut token = cache.get(&cache_key).cloned().unwrap_or_default();

    // Token store key: "{auth_url}/{resource_id}" -- same shape as the
    // repository variant, with the resource ID taking the repository slot.
    let token_store_key = format!("{auth_url}/{resource_id}");

    if !token.is_empty() {
        lore_trace!("Found cached authz token for {cache_key:?}");
    } else {
        lore_trace!("Check for token store authz token for {token_store_key:?}");
        token = token_store::load_user_token(
            &token_store_key,
            identity,
            tokens_only_for_recipient_domain(recipient_domain.clone()),
        )
        .await
        .unwrap_or_default();
    }

    if !token.is_empty() {
        lore_trace!("Validating token expiry");
        if let Some(user_info) = lore_credential::user_info_from_token(token.clone()) {
            if !is_expired(user_info.expires) {
                lore_trace!("Using authz token for {cache_key:?}");
                cache.insert(cache_key, token.clone());
                return Ok(token.clone());
            } else {
                lore_debug!("Authz token for {cache_key:?} has expired");
            }
        } else {
            lore_warn!("Invalid authz token found for {cache_key:?}");
        }
    } else {
        lore_trace!("No stored authz token found for {cache_key:?}");
    }

    lore_trace!("Authorizing using authn identity: {identity}");
    let Some(auth_service_only_token) = lore_credential::user_info(
        auth_url.as_str(),
        identity,
        tokens_for_auth_service_and_recipient(auth_domain, recipient_domain.clone()),
    )
    .await
    else {
        lore_debug!(
            "No authentication token usable at {recipient_domain}, unable to perform authz exchange"
        );
        return Err(NotAuthenticated.into());
    };
    lore_trace!("Authorizing using endpoint: {auth_url}");

    let time_start = Instant::now();

    let auth_impl = authentication::find(&auth_url)
        .forward::<ExchangeError>("Unable to connect to auth exchange endpoint")?;
    // The correlation_id is no longer available from ExecutionContext in lore-transport.
    // Pass an empty string -- the gRPC interceptor may inject it from ambient state.
    let correlation_id = String::new();

    lore_trace!("Send auth exchange request");
    let authz = auth_impl
        .exchange_for_custom_resource(
            &auth_url,
            &auth_service_only_token.token,
            resource_id,
            &correlation_id,
        )
        .await
        .map_err(|err| {
            if err.is_not_authorized() {
                ExchangeError::from(NotAuthorized)
            } else {
                ExchangeError::internal_with_context(err, "Failed to exchange token")
            }
        })?;

    if authz.token.is_empty() {
        return Err(ExchangeError::internal("Empty token response"));
    }
    let domains = acceptable_root_domains(&authz, &recipient_domain)?;
    let token = authz.token;

    lore_trace!(
        "Authorization with user token successful in {} ms",
        time_start.elapsed().as_millis()
    );

    lore_trace!("Cached authz token for {cache_key:?}");

    cache.insert(cache_key, token.clone());

    let _ = token_store::store_user_token(&token_store_key, identity, &token, domains)
        .await
        .map_err(|err| {
            lore_warn!("Failed to store token: {err}");
        });

    Ok(token)
}

/// Resolves an identity and obtains authentication/authorization tokens.
///
/// Returned tuple: (`authentication_token`, `authorization_token`, `resolved_identity`)
///
/// If `identity` is empty, iterates over available identities for the given
/// `auth_url` and tries to find one that can authenticate (and optionally
/// authorize for the given repository).
pub async fn auth_exchange(
    auth_url: &str,
    remote_domain: &str,
    identity: &str,
    repository: RepositoryId,
) -> (String, String, String) {
    if !identity.is_empty() {
        return auth_exchange_for_identity(auth_url, remote_domain, identity, repository).await;
    }

    // No identity given, resolve one from available identities
    let Ok(identities) = token_store::load_identities(auth_url).await else {
        lore_debug!("No identities found for {auth_url}");
        return (String::new(), String::new(), String::new());
    };

    if repository.is_zero() {
        // No resource, pick first identity with a valid authn token
        for entry in &identities {
            let result =
                auth_exchange_for_identity(auth_url, remote_domain, entry, repository).await;
            if !result.0.is_empty() {
                return result;
            }
        }
        return (String::new(), String::new(), String::new());
    }

    // Try each identity: first check for cached/stored authz token, then try exchange
    for entry in &identities {
        let result = auth_exchange_for_identity(auth_url, remote_domain, entry, repository).await;
        if !result.1.is_empty() {
            return result;
        }
    }

    lore_debug!("No identity could be authorized for repository {repository}");
    (String::new(), String::new(), String::new())
}

async fn auth_exchange_for_identity(
    auth_url: &str,
    remote_domain: &str,
    identity: &str,
    repository: RepositoryId,
) -> (String, String, String) {
    let Ok(authentication_token) = token_store::load_user_token(
        auth_url,
        identity,
        tokens_only_for_recipient_domain(remote_domain.to_string()),
    )
    .await
    else {
        lore_debug!("Auth exchange failed, no user authentication token found for {identity}");
        return (String::new(), String::new(), String::new());
    };

    // Reject expired authn tokens
    if let Some(info) = lore_credential::user_info_from_token(authentication_token.clone())
        && is_expired(info.expires)
    {
        lore_debug!("Skipping identity {identity}, authn token is expired");
        return (String::new(), String::new(), String::new());
    }

    // This will return the cached authz token if it is still valid,
    // or perform an authz exchange if needed
    let authorization_token = if !repository.is_zero() {
        exchange(auth_url, identity, repository, remote_domain.to_string())
            .await
            .inspect_err(|err| {
                lore_debug!("Auth exchange failed for repository {repository}: {err}");
            })
            .unwrap_or_default()
    } else {
        String::new()
    };

    // Dedupe these debug lines: the same identity getting reselected for the
    // same repository/domain pair on every authz refresh is the steady-state
    // and just spams the log. Re-emit only when the inputs change. The lock
    // is dropped before we log so the dispatch (file write, event channel)
    // cannot block other callers.
    if !authorization_token.is_empty() {
        static LAST_AUTHORIZED: parking_lot::Mutex<Option<(String, RepositoryId, String)>> =
            parking_lot::Mutex::new(None);
        let key = (identity.to_string(), repository, remote_domain.to_string());
        let changed = {
            let mut last = LAST_AUTHORIZED.lock();
            if last.as_ref() != Some(&key) {
                *last = Some(key);
                true
            } else {
                false
            }
        };
        if changed {
            lore_debug!(
                "Selected identity {identity}, authorized for repository {repository} on {remote_domain}"
            );
        }
    } else if repository.is_zero() {
        static LAST_AUTHENTICATED: parking_lot::Mutex<Option<(String, String)>> =
            parking_lot::Mutex::new(None);
        let key = (identity.to_string(), remote_domain.to_string());
        let changed = {
            let mut last = LAST_AUTHENTICATED.lock();
            if last.as_ref() != Some(&key) {
                *last = Some(key);
                true
            } else {
                false
            }
        };
        if changed {
            lore_debug!("Selected identity {identity}, authenticated for {remote_domain}");
        }
    }

    (
        authentication_token,
        authorization_token,
        identity.to_string(),
    )
}

/// Resolves an identity and obtains authentication/authorization tokens for an
/// arbitrary resource identifier.
///
/// Returned tuple: (`authentication_token`, `authorization_token`, `resolved_identity`)
///
/// Mirrors `auth_exchange`, but authorizes against a caller-supplied resource
/// identifier rather than a repository.
pub async fn auth_exchange_custom_resource(
    auth_url: &str,
    remote_domain: &str,
    identity: &str,
    resource_id: &str,
) -> (String, String, String) {
    if !identity.is_empty() {
        return auth_exchange_custom_resource_for_identity(
            auth_url,
            remote_domain,
            identity,
            resource_id,
        )
        .await;
    }

    let Ok(identities) = token_store::load_identities(auth_url).await else {
        lore_debug!("No identities found for {auth_url}");
        return (String::new(), String::new(), String::new());
    };

    for entry in &identities {
        let result =
            auth_exchange_custom_resource_for_identity(auth_url, remote_domain, entry, resource_id)
                .await;
        if !result.1.is_empty() {
            return result;
        }
    }

    lore_debug!("No identity could be authorized for resource {resource_id}");
    (String::new(), String::new(), String::new())
}

async fn auth_exchange_custom_resource_for_identity(
    auth_url: &str,
    remote_domain: &str,
    identity: &str,
    resource_id: &str,
) -> (String, String, String) {
    let Ok(authentication_token) = token_store::load_user_token(
        auth_url,
        identity,
        tokens_only_for_recipient_domain(remote_domain.to_string()),
    )
    .await
    else {
        lore_debug!("Auth exchange failed, no user authentication token found for {identity}");
        return (String::new(), String::new(), String::new());
    };

    if let Some(info) = lore_credential::user_info_from_token(authentication_token.clone())
        && is_expired(info.expires)
    {
        lore_debug!("Skipping identity {identity}, authn token is expired");
        return (String::new(), String::new(), String::new());
    }

    let authorization_token =
        exchange_custom_resource(auth_url, identity, resource_id, remote_domain.to_string())
            .await
            .inspect_err(|err| {
                lore_debug!("Auth exchange failed for resource {resource_id}: {err}");
            })
            .unwrap_or_default();

    // Dedupe: same identity reselected for the same resource/domain on every
    // refresh is the steady-state — re-emit only when the inputs change.
    // Drop the lock before logging so dispatch can't block other callers.
    if !authorization_token.is_empty() {
        static LAST_RESOURCE_AUTHORIZED: parking_lot::Mutex<Option<(String, String, String)>> =
            parking_lot::Mutex::new(None);
        let key = (
            identity.to_string(),
            resource_id.to_string(),
            remote_domain.to_string(),
        );
        let changed = {
            let mut last = LAST_RESOURCE_AUTHORIZED.lock();
            if last.as_ref() != Some(&key) {
                *last = Some(key);
                true
            } else {
                false
            }
        };
        if changed {
            lore_debug!(
                "Selected identity {identity}, authorized for resource {resource_id} on {remote_domain}"
            );
        }
    }

    (
        authentication_token,
        authorization_token,
        identity.to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A JWT with the given claims and a signature nothing checks -- the shape the client
    /// reads, since the server owns verification.
    fn unsigned_jwt(claims: &str) -> String {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#),
            URL_SAFE_NO_PAD.encode(claims),
            URL_SAFE_NO_PAD.encode("not-a-signature"),
        )
    }

    fn authz_token(acceptable_root_domains: Vec<String>, jwt: &str) -> AuthorizationToken {
        AuthorizationToken {
            token: jwt.to_string(),
            expires_ms: 0,
            acceptable_root_domains,
        }
    }

    /// A response supplying no domains of its own (`acceptable_root_domains` empty) falls
    /// back to the JWT-derived set.
    #[test]
    fn ucs_auth_shaped_token_keeps_jwt_derived_domains() {
        let jwt = unsigned_jwt(
            r#"{"iss":"auth.example.com","sub":"user-1","exp":9999999999,"aud":["repo.example.com"]}"#,
        );
        let authz = authz_token(vec![], &jwt);

        let domains = acceptable_root_domains(&authz, "repo.example.com").unwrap();

        assert_eq!(
            domains,
            vec![
                "auth.example.com".to_string(),
                "repo.example.com".to_string(),
            ]
        );
    }

    /// An OIDC ID token's own claims (`aud` = client id, `iss` = issuer URL) can never
    /// name the repository's domain, so a non-empty
    /// `AuthorizationToken::acceptable_root_domains` from the backend must be authoritative
    /// instead of the JWT-derived fallback.
    #[test]
    fn oidc_shaped_token_survives_the_exchange_path() {
        let jwt = unsigned_jwt(
            r#"{"iss":"https://id.example.com","sub":"user-1","exp":9999999999,"aud":["lore-cli"]}"#,
        );
        let authz = authz_token(vec!["id.example.com".to_string()], &jwt);

        let domains = acceptable_root_domains(&authz, "repo.example.com").unwrap();

        assert!(domains.contains(&"id.example.com".to_string()));
        assert!(domains.contains(&"repo.example.com".to_string()));
    }

    /// The remote is added rather than checked for, so an authoritative set that already
    /// names the remote is not duplicated.
    #[test]
    fn authoritative_domains_already_containing_the_remote_are_not_duplicated() {
        let jwt = unsigned_jwt(
            r#"{"iss":"https://id.example.com","sub":"user-1","exp":9999999999,"aud":["lore-cli"]}"#,
        );
        let authz = authz_token(
            vec!["id.example.com".to_string(), "repo.example.com".to_string()],
            &jwt,
        );

        let domains = acceptable_root_domains(&authz, "repo.example.com").unwrap();

        assert_eq!(
            domains,
            vec!["id.example.com".to_string(), "repo.example.com".to_string(),]
        );
    }
}

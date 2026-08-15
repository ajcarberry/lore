// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Keeps stored authentication tokens usable across expiry: a selection guard
//! for loading them and a single-flight refresh grant.

use std::collections::HashMap;
use std::sync::Arc;

use lore_base::lore_debug;
use lore_base::lore_warn;
use lore_credential::UserInfo;
use lore_credential::token_store;
use lore_credential::token_store::tokens_only_for_recipient_domain;
use tokio::sync::Mutex;

use super::authentication;
use super::exchange::is_expired;

/// Accepts a stored token only when its acceptable-domain set names both the
/// auth service and the recipient.
pub(super) fn tokens_for_auth_service_and_recipient(
    auth_domain: String,
    recipient_domain: String,
) -> impl FnMut(&&token_store::IdentityToken) -> bool {
    let mut for_auth_service = tokens_only_for_recipient_domain(auth_domain);
    let mut for_recipient = tokens_only_for_recipient_domain(recipient_domain);
    move |item| for_auth_service(item) && for_recipient(item)
}

type RefreshKey = (String, String);

struct RefreshedToken {
    token: String,
    expires_ms: u64,
}

/// One in-flight refresh per `(auth_url, identity)`, plus the last result so a
/// refresh whose store write failed is not repeated with an already-spent
/// refresh token. Serialization is per process; another process may still race.
struct RefreshState {
    in_flight: HashMap<RefreshKey, Arc<Mutex<()>>>,
    last_result: HashMap<RefreshKey, RefreshedToken>,
}

static REFRESH_STATE: std::sync::OnceLock<Mutex<RefreshState>> = std::sync::OnceLock::new();

fn refresh_state() -> &'static Mutex<RefreshState> {
    REFRESH_STATE.get_or_init(|| {
        Mutex::new(RefreshState {
            in_flight: HashMap::new(),
            last_result: HashMap::new(),
        })
    })
}

/// The stored token, or its refreshed replacement when it has expired.
///
/// A refresh that cannot happen leaves the expired token in place.
pub(super) async fn unexpired_authn_token(
    stored: UserInfo,
    auth_url: &str,
    auth_domain: &str,
    identity: &str,
    recipient_domain: &str,
) -> String {
    if !is_expired(stored.expires) {
        return stored.token;
    }
    lore_debug!("Authentication token for {identity} has expired, trying the refresh grant");
    refreshed_authn_token(auth_url, auth_domain, identity, recipient_domain)
        .await
        .unwrap_or(stored.token)
}

/// Trades the stored refresh token for a new authentication token.
///
/// Best-effort: `None` when no refresh token is stored or the provider
/// refuses, leaving the caller with the token it already had. One attempt,
/// no retry loop.
pub(super) async fn refreshed_authn_token(
    auth_url: &str,
    auth_domain: &str,
    identity: &str,
    recipient_domain: &str,
) -> Option<String> {
    let key = (auth_url.to_string(), identity.to_string());

    // One refresh per key at a time: the grant spends a single-use token, so
    // two callers racing on the same expiry would spend it twice. Unrelated
    // identities and providers are unaffected.
    let entry_lock = {
        let mut state = refresh_state().lock().await;
        state.in_flight.entry(key.clone()).or_default().clone()
    };
    let _single_flight = entry_lock.lock().await;

    // The refresh may have happened while waiting: check the recorded result,
    // then the store another caller may have written.
    {
        let state = refresh_state().lock().await;
        if let Some(last) = state.last_result.get(&key)
            && !is_expired(last.expires_ms)
        {
            lore_debug!("Authentication token for {identity} was already refreshed");
            return Some(last.token.clone());
        }
    }
    if let Some(info) = lore_credential::user_info(
        auth_url,
        identity,
        tokens_for_auth_service_and_recipient(
            auth_domain.to_string(),
            recipient_domain.to_string(),
        ),
    )
    .await
        && !is_expired(info.expires)
    {
        lore_debug!("Authentication token for {identity} was refreshed while waiting");
        return Some(info.token);
    }

    let refresh_token = token_store::load_refresh_token(auth_url, identity)
        .await
        .inspect_err(|err| lore_debug!("No refresh token stored for {identity}: {err}"))
        .ok()?;

    let refreshed = authentication::find(auth_url)
        .inspect_err(|err| lore_debug!("No authentication implementation to refresh with: {err}"))
        .ok()?
        .refresh_authentication(auth_url, &refresh_token, "")
        .await
        .inspect_err(|err| {
            lore_debug!("Could not refresh the authentication token for {identity}: {err}");
        })
        .ok()?;

    if refreshed.token.is_empty() {
        lore_debug!("The refresh grant returned an empty token for {identity}");
        return None;
    }

    // Record before storing: if the store write fails, the next caller reuses
    // this result instead of spending a refresh token that is already gone.
    {
        let mut state = refresh_state().lock().await;
        state.last_result.insert(
            key.clone(),
            RefreshedToken {
                token: refreshed.token.clone(),
                expires_ms: refreshed.expires_ms,
            },
        );
    }

    match token_store::store_refreshed_user_token(
        auth_url,
        identity,
        &refreshed.token,
        refreshed.refresh_token.as_deref(),
    )
    .await
    {
        // Stored, so the record — a bearer token — need not outlive this call.
        Ok(()) => {
            refresh_state().lock().await.last_result.remove(&key);
        }
        Err(err) => lore_warn!("Failed to store the refreshed authentication token: {err}"),
    }

    Some(refreshed.token)
}

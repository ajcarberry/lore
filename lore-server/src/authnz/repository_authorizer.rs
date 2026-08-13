// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use async_trait::async_trait;
use lore_base::types::RepositoryId;
use lore_proto::auth::CheckUserPermissionRequest;
use tonic::Code;
use tonic::Status;
use tracing::warn;

use super::auth::grpc_get_auth_client;
use super::common::create_request_with_authorization;
use crate::grpc::ServerResultExt;

#[async_trait]
pub trait RepositoryAuthorizer: Send + Sync {
    async fn check_repository_access(
        &self,
        authorization: Option<String>,
        repository_id: RepositoryId,
    ) -> Result<(), Status>;
}

/// Always allows access. Used when no auth URL is configured.
pub struct AllowAllRepositoryAuthorizer;

#[async_trait]
impl RepositoryAuthorizer for AllowAllRepositoryAuthorizer {
    async fn check_repository_access(
        &self,
        _authorization: Option<String>,
        _repository_id: RepositoryId,
    ) -> Result<(), Status> {
        Ok(())
    }
}

/// Checks repository access against the Lore auth service.
pub struct AuthClientAuthorizer {
    auth_url: String,
}

impl AuthClientAuthorizer {
    pub fn new(auth_url: String) -> Self {
        Self { auth_url }
    }
}

#[async_trait]
impl RepositoryAuthorizer for AuthClientAuthorizer {
    async fn check_repository_access(
        &self,
        authorization: Option<String>,
        repository_id: RepositoryId,
    ) -> Result<(), Status> {
        let mut client = grpc_get_auth_client(self.auth_url.clone()).await?;
        let resource_id = format!("urc-{repository_id}");
        let request = create_request_with_authorization(
            CheckUserPermissionRequest {
                resource_id: vec![resource_id.clone()],
                target_user: None,
            },
            authorization,
        )?;

        let permissions = client
            .check_user_permission(request)
            .await
            .warn_map_err(|err| {
                if err.code() == Code::PermissionDenied {
                    return Status::permission_denied("Query resource denied");
                } else if err.code() == Code::Unauthenticated {
                    return Status::unauthenticated("Query resource failed - unauthenticated");
                }
                Status::internal(format!("Failed to call auth check_user_permission: {err}"))
            })?;

        if permissions
            .into_inner()
            .allowed_resource_permission
            .first()
            .ok_or(Status::internal("No permissions for resource"))?
            .resource_id
            == resource_id
        {
            Ok(())
        } else {
            Err(Status::internal("Unexpected resource_id"))
        }
    }
}

/// Whether `auth_url` names an OpenID Connect provider, which is the one thing this
/// server must not point its relationship-based authorization client at: the URL names an
/// identity provider, and dialing it as if it were the authorization service would fail
/// every repository operation that checks a permission.
fn is_oidc_scheme(auth_url: &str) -> bool {
    auth_url
        .split_once("://")
        .is_some_and(|(scheme, _)| scheme.starts_with("oidc+"))
}

/// Whether `auth_url` names a scheme this server checks repository access against.
///
/// Everything that is not an `oidc+` URL does. The rule is written that way round on
/// purpose: an allowlist of known authorization schemes silently drops the check for any
/// deployment spelling its auth URL differently — plain `http` to a service behind a mesh,
/// say — and dropping the check is the failure that cannot be noticed from the outside,
/// because every operation still succeeds. Only OIDC, where the check genuinely moves into
/// the server's own token verification, gives it up.
pub(crate) fn is_auth_client_scheme(auth_url: &str) -> bool {
    !is_oidc_scheme(auth_url)
}

/// Creates the appropriate authorizer from an optional auth URL.
///
/// Returns `AllowAllRepositoryAuthorizer` when no URL is configured — the correct answer
/// under `authorize_all_repositories` — and for an `oidc+` URL, where the server verifies
/// the provider's token itself and has no per-repository authority to consult. Every other
/// URL keeps its authorization check (see [`is_auth_client_scheme`]).
pub fn repository_authorizer(auth_url: Option<String>) -> Arc<dyn RepositoryAuthorizer> {
    match auth_url {
        Some(url) if is_oidc_scheme(&url) => {
            warn!(
                "Auth URL '{url}' names an OpenID Connect provider, so repository access is \
                 not checked against an authorization service: every verified token is \
                 allowed every repository"
            );
            Arc::new(AllowAllRepositoryAuthorizer)
        }
        Some(url) => Arc::new(AuthClientAuthorizer::new(url)),
        None => Arc::new(AllowAllRepositoryAuthorizer),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ucs_auth_scheme_selects_the_auth_client() {
        assert!(is_auth_client_scheme("ucs-auth://auth.example.com"));
    }

    #[test]
    fn https_scheme_selects_the_auth_client() {
        assert!(is_auth_client_scheme("https://auth.example.com"));
    }

    /// The risk the LEP names by name: an OIDC-advertised `auth_url` must never
    /// be handed to the gRPC client meant for the relationship-based
    /// authorization service, or repository create/delete/query/metadata
    /// operations would all fail against a live provider.
    #[test]
    fn oidc_https_scheme_does_not_select_the_auth_client() {
        assert!(!is_auth_client_scheme("oidc+https://id.example.com"));
    }

    #[test]
    fn oidc_http_scheme_does_not_select_the_auth_client() {
        assert!(!is_auth_client_scheme("oidc+http://127.0.0.1:1411"));
    }

    /// The rule is fail-closed for everything this change did not come to serve: only an
    /// `oidc+` scheme gives up the authorization check. A deployment that reaches its
    /// authorization service over plain `http` -- behind a mesh, or in a test harness --
    /// kept its check before OIDC existed and keeps it now.
    #[test]
    fn plain_http_scheme_selects_the_auth_client() {
        assert!(is_auth_client_scheme("http://auth.example.com"));
    }

    /// An unrecognized scheme is not a licence to stop checking either.
    #[test]
    fn an_unknown_scheme_selects_the_auth_client() {
        assert!(is_auth_client_scheme("grpc://auth.example.com"));
    }

    #[tokio::test]
    async fn no_auth_url_falls_back_to_allow_all() {
        // Exercised through the public constructor: `AllowAllRepositoryAuthorizer`
        // carries no state to introspect, so behavior is the observable proof.
        let authorizer = repository_authorizer(None);
        let repository_id = lore_base::types::RepositoryId::from([0u8; 16]);
        assert!(
            authorizer
                .check_repository_access(None, repository_id)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn an_oidc_auth_url_falls_back_to_allow_all() {
        let authorizer = repository_authorizer(Some("oidc+https://id.example.com".to_string()));
        let repository_id = lore_base::types::RepositoryId::from([0u8; 16]);
        assert!(
            authorizer
                .check_repository_access(None, repository_id)
                .await
                .is_ok()
        );
    }
}

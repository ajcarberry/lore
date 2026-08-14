// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_proto::EnvironmentGetResponse;
use lore_storage::CompressionMode;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::instrument;

use crate::legacy::rpc::environment_service_server::EnvironmentService;

fn proto_from_endpoint(
    endpoint: &Option<lore_transport::Endpoint>,
) -> Option<lore_proto::EnvironmentEndpoint> {
    endpoint
        .as_ref()
        .map(|endpoint| lore_proto::EnvironmentEndpoint {
            auth_url: endpoint.auth_url.clone().unwrap_or_default(),
            repository_url: endpoint.repository_url.clone().unwrap_or_default(),
            storage_url: endpoint.storage_url.clone().unwrap_or_default(),
            revision_url: endpoint.revision_url.clone().unwrap_or_default(),
            lock_url: endpoint.lock_url.clone().unwrap_or_default(),
            notification_url: endpoint.notification_url.clone().unwrap_or_default(),
        })
}

fn proto_from_config(
    config: &Option<lore_revision::environment::Config>,
) -> Option<lore_proto::EnvironmentConfig> {
    config.as_ref().map(|config| lore_proto::EnvironmentConfig {
        max_query_batch: config.max_query_batch.unwrap_or_default() as u32,
        compression_mode: config.compression_mode.as_ref().map(|mode| match mode {
            CompressionMode::NotSpecified => lore_proto::CompressionMode::NotSpecified as i32,
            CompressionMode::NoCompression => lore_proto::CompressionMode::NoCompression as i32,
            CompressionMode::Lz4 => lore_proto::CompressionMode::Lz4 as i32,
            CompressionMode::Oodle => lore_proto::CompressionMode::Oodle as i32,
            CompressionMode::Zstd => lore_proto::CompressionMode::Zstd as i32,
        }),
    })
}

fn proto_from_environment_config(
    environment: &lore_revision::environment::EnvironmentConfig,
) -> lore_proto::model::Environment {
    lore_proto::model::Environment {
        endpoint: proto_from_endpoint(&environment.endpoint),
        config: proto_from_config(&environment.config),
    }
}

#[derive(Clone)]
pub struct LoreEnvironmentService {
    environment: lore_proto::Environment,
    /// OIDC login URL to advertise when the environment carries no `auth_url` of its
    /// own. Derived from `[server.auth.oidc]` and applied only in the `Get` response, so
    /// the `oidc+https://…` string never reaches an internal consumer.
    advertised_auth_url: Option<String>,
    maintenance: bool,
}

impl LoreEnvironmentService {
    pub fn new(
        environment: lore_revision::environment::EnvironmentConfig,
        advertised_auth_url: Option<String>,
    ) -> Self {
        Self {
            environment: proto_from_environment_config(&environment),
            advertised_auth_url,
            maintenance: false,
        }
    }

    pub fn maintenance(environment: lore_revision::environment::EnvironmentConfig) -> Self {
        Self {
            environment: proto_from_environment_config(&environment),
            advertised_auth_url: None,
            maintenance: true,
        }
    }
}

#[tonic::async_trait]
impl EnvironmentService for LoreEnvironmentService {
    #[instrument(name = "EnvironmentService::Get", skip_all)]
    async fn get(
        &self,
        _request: Request<lore_proto::EnvironmentGetRequest>,
    ) -> Result<Response<EnvironmentGetResponse>, Status> {
        if self.maintenance {
            return Err(Status::unavailable("Server is in maintenance"));
        }
        let mut environment = self.environment.clone();
        if let Some(auth_url) = &self.advertised_auth_url {
            let endpoint = environment.endpoint.get_or_insert_with(Default::default);
            if endpoint.auth_url.is_empty() {
                endpoint.auth_url = auth_url.clone();
            }
        }
        Ok(Response::new(EnvironmentGetResponse {
            environment: Some(environment),
        }))
    }
}

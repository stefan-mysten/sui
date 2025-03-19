// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{AppState, FaucetConfig, FaucetError, FaucetRequest};
use axum::{
    error_handling::HandleErrorLayer, http::StatusCode, response::IntoResponse, routing::post,
    BoxError, Extension, Json, Router,
};
use http::Method;
use mysten_metrics::spawn_monitored_task;
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use sui_config::SUI_CLIENT_CONFIG;
use sui_sdk::wallet_context::WalletContext;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn};

/// basic handler that responds with a static string
async fn health() -> &'static str {
    "OK"
}

#[derive(Serialize, Deserialize, Debug)]
pub enum RequestStatus {
    GasSent,
    Success,
    Failure(FaucetError),
}

#[derive(Serialize, Deserialize, Debug)]
struct FaucetResponse {
    pub status: RequestStatus,
}

impl From<FaucetError> for FaucetResponse {
    fn from(value: FaucetError) -> Self {
        FaucetResponse {
            status: RequestStatus::Failure(value),
        }
    }
}

impl From<reqwest::Error> for FaucetResponse {
    fn from(value: reqwest::Error) -> Self {
        FaucetResponse {
            status: RequestStatus::Failure(FaucetError::internal(value)),
        }
    }
}

async fn request_local_gas(
    Extension(state): Extension<Arc<AppState>>,
    Json(payload): Json<FaucetRequest>,
    // ) -> &'static str {
) -> impl IntoResponse {
    let FaucetRequest::FixedAmountRequest(request) = payload;
    info!("Local request to add to queue for faucet");
    state
        .faucet
        .local_request_add_to_queue(request.recipient)
        .await;

    (
        StatusCode::CREATED,
        Json(FaucetResponse {
            status: RequestStatus::Success,
        }),
    )
}

async fn process_local_gas_requests(
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    let resp = state.faucet.local_request_execute_tx().await;
    match resp {
        Ok(_) => (
            StatusCode::OK,
            Json(FaucetResponse {
                status: RequestStatus::GasSent,
            }),
        ),
        Err(error) => {
            warn!("Failed to request gas: {:?}", error);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(FaucetResponse {
                    status: RequestStatus::Failure(error),
                }),
            )
        }
    }
}

pub fn create_wallet_context(
    timeout_secs: u64,
    config_dir: PathBuf,
) -> Result<WalletContext, anyhow::Error> {
    let wallet_conf = config_dir.join(SUI_CLIENT_CONFIG);
    info!("Initialize wallet from config path: {:?}", wallet_conf);
    WalletContext::new(
        &wallet_conf,
        Some(Duration::from_secs(timeout_secs)),
        Some(1000),
    )
}

async fn handle_error(error: BoxError) -> impl IntoResponse {
    if error.is::<tower::load_shed::error::Overloaded>() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Cow::from("service is overloaded, please try again later"),
        );
    }

    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Cow::from(format!("Unhandled internal error: {}", error)),
    )
}

/// Start a faucet that is run locally. This should only be used for starting a local network, and
/// not for devnet/testnet deployments!
pub async fn start_faucet(
    app_state: Arc<AppState>,
) -> Result<(), anyhow::Error> {
    let cors = CorsLayer::new()
        .allow_methods(vec![Method::GET, Method::POST])
        .allow_headers(Any)
        .allow_origin(Any);
    let FaucetConfig { port, host_ip, .. } = app_state.config;

    println!("Starting in local mode");
    let app = Router::new()
        .route("/v1/gas", post(request_local_gas))
        .route("/gas", post(request_local_gas))
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(handle_error))
                .load_shed()
                .layer(Extension(app_state.clone()))
                .layer(cors)
                .into_inner(),
        );

    spawn_monitored_task!(async move {
        info!("Starting task to process requests");
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            process_local_gas_requests(Extension(app_state.clone())).await;
        }
    });
    let addr = SocketAddr::new(IpAddr::V4(host_ip), port);
    info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

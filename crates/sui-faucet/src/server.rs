// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{AppState, FaucetConfig, FaucetError, FaucetRequest};
use axum::{
    error_handling::HandleErrorLayer,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    BoxError, Extension, Json, Router,
};
use http::Method;
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
use tracing::info;

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
    info!("Local request for address: {}", request.recipient);
    let request = state
        .faucet
        .local_request_execute_tx(request.recipient)
        .await;

    if let Err(e) = request {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(FaucetResponse {
                status: RequestStatus::Failure(e),
            }),
        );
    }

    (
        StatusCode::CREATED,
        Json(FaucetResponse {
            status: RequestStatus::Success,
        }),
    )
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
pub async fn start_faucet(app_state: Arc<AppState>) -> Result<(), anyhow::Error> {
    let cors = CorsLayer::new()
        .allow_methods(vec![Method::GET, Method::POST])
        .allow_headers(Any)
        .allow_origin(Any);
    let FaucetConfig { port, host_ip, .. } = app_state.config;

    println!("Starting in local mode");
    let app = Router::new()
        .route("/", get(health))
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

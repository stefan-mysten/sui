// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    app_state, requests_manager::RequestsManager, AppState, FaucetConfig, FaucetError,
    FaucetRequest, RequestMetricsLayer,
};
use axum::{
    error_handling::HandleErrorLayer,
    extract::{ConnectInfo, Host},
    http::{header::HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    BoxError, Extension, Json, Router,
};
use fastcrypto::encoding::{Base64, Encoding};
use http::{header::CONTENT_TYPE, Method};
use mysten_metrics::spawn_monitored_task;
use prometheus::Registry;
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use sui_config::{sui_config_dir, SUI_CLIENT_CONFIG, SUI_KEYSTORE_FILENAME};
use sui_sdk::{
    rpc_types::{SuiObjectRef, SuiTransactionBlockEffects, SuiTransactionBlockEffectsAPI},
    types::{
        base_types::{ObjectID, SuiAddress},
        transaction::TransactionData,
    },
    wallet_context::WalletContext,
};
use tower::ServiceBuilder;
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::GlobalKeyExtractor, GovernorLayer,
};
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, warn};

use anyhow::ensure;
use once_cell::sync::Lazy;
use serde_json::json;
use shared_crypto::intent::Intent;
use sui_keys::keystore::{AccountKeystore, FileBasedKeystore};

const DEFAULT_FAUCET_WEB_APP_URL: &str = "https://faucet.sui.io";

static GAS_AUTH_TOKEN: Lazy<String> = Lazy::new(|| {
    std::env::var("GAS_AUTH_TOKEN")
        .ok()
        .unwrap_or_else(|| ("".to_string()))
});

static FAUCET_WEB_APP_URL: Lazy<String> = Lazy::new(|| {
    std::env::var("FAUCET_WEB_APP_URL")
        .ok()
        .unwrap_or_else(|| DEFAULT_FAUCET_WEB_APP_URL.to_string())
});

static CLOUDFLARE_TURNSTILE_URL: Lazy<Option<String>> =
    Lazy::new(|| std::env::var("CLOUDFLARE_TURNSTILE_URL").ok());

static TURNSTILE_SECRET_KEY: Lazy<Option<String>> =
    Lazy::new(|| std::env::var("TURNSTILE_SECRET_KEY").ok());

static DISCORD_BOT_PWD: Lazy<String> =
    Lazy::new(|| std::env::var("DISCORD_BOT_PWD").unwrap_or_else(|_| "".to_string()));

pub async fn start_faucet(
    app_state: Arc<AppState>,
    concurrency_limit: usize,
    prometheus_registry: &Registry,
) -> Result<(), anyhow::Error> {
    println!("Starting faucet");

    // TODO: restrict access if needed
    let cors = CorsLayer::new()
        .allow_methods(vec![Method::GET, Method::POST])
        .allow_headers(Any)
        .allow_origin(Any);

    if app_state.config.local {
        // Local faucet
        start_local_server(app_state, concurrency_limit, prometheus_registry).await
    } else {
        // Deployed faucet (devnet/testnet)
        start_non_local_server(app_state, concurrency_limit, prometheus_registry, cors).await
    }
}

/// basic handler that responds with a static string
async fn health() -> &'static str {
    "OK"
}

/// Redirect to faucet.sui.io/?network if it's testnet/devnet network. For local network, keep the
/// previous behavior to return health status.
async fn redirect(Host(host): Host) -> Response {
    let url = FAUCET_WEB_APP_URL.to_string();
    if host.contains("testnet") {
        let redirect = Redirect::to(&format!("{url}/?network=testnet"));
        redirect.into_response()
    } else if host.contains("devnet") {
        let redirect = Redirect::to(&format!("{url}/?network=devnet"));
        redirect.into_response()
    } else {
        health().await.into_response()
    }
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

/// A route for requests coming from the discord bot.
async fn request_faucet_discord(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    Json(payload): Json<FaucetRequest>,
) -> impl IntoResponse {
    if state.config.authenticated {
        let Some(agent_value) = headers
            .get(reqwest::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
        else {
            return (
                StatusCode::BAD_REQUEST,
                Json(FaucetResponse::from(FaucetError::InvalidUserAgent(
                    "Invalid user agent for this route".to_string(),
                ))),
            );
        };

        if agent_value != *DISCORD_BOT_PWD {
            return (
                StatusCode::BAD_REQUEST,
                Json(FaucetResponse::from(FaucetError::InvalidUserAgent(
                    "Invalid user agent for this route".to_string(),
                ))),
            );
        }
    }

    let FaucetRequest::FixedAmountRequest(request) = payload else {
        return (
            StatusCode::BAD_REQUEST,
            Json(FaucetResponse::from(FaucetError::Internal(
                "Input Error.".to_string(),
            ))),
        );
    };

    (
        StatusCode::BAD_REQUEST,
        Json(FaucetResponse::from(FaucetError::Internal(
            "Input Error.".to_string(),
        ))),
    )
    // batch_request_spawn_task(request, state).await
}

/// Handler for requests coming from the frontend faucet web app.
async fn request_faucet_web_gas(
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(token_manager): Extension<Arc<RequestsManager>>,
    Extension(state): Extension<Arc<AppState>>,
    Json(payload): Json<FaucetRequest>,
) -> impl IntoResponse {
    if state.config.authenticated {
        let Some(token) = headers
            .get("X-Turnstile-Token")
            .and_then(|v| v.to_str().ok())
        else {
            return (
                StatusCode::BAD_REQUEST,
                Json(FaucetResponse::from(
                    FaucetError::MissingTurnstileTokenHeader,
                )),
            );
        };

        let validation = token_manager.validate_turnstile_token(addr, token).await;

        if let Err((status_code, faucet_error)) = validation {
            return (status_code, Json(FaucetResponse::from(faucet_error)));
        }
    }

    let FaucetRequest::FixedAmountRequest(request) = payload else {
        return (
            StatusCode::BAD_REQUEST,
            Json(FaucetResponse::from(FaucetError::Internal(
                "Input Error.".to_string(),
            ))),
        );
    };
    (
        StatusCode::BAD_REQUEST,
        Json(FaucetResponse::from(FaucetError::Internal(
            "Input Error.".to_string(),
        ))),
    )

    // batch_request_spawn_task(request, state).await
}

#[derive(Debug, Serialize, Deserialize)]
struct GasPoolRequest {
    gas_budget: u64,
    reserve_duration_secs: u64,
}
pub type ReservationID = u64;
pub type ExpirationTimeMs = u64;
pub type GasGroupKey = ObjectID;

#[derive(Debug, Serialize, Deserialize)]
pub struct ReserveGasResponse {
    pub result: Option<ReserveGasResult>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReserveGasResult {
    pub sponsor_address: SuiAddress,
    pub reservation_id: ReservationID,
    pub gas_coins: Vec<SuiObjectRef>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExecuteTxRequest {
    /// This must be the same reservation ID returned in ReserveGasResponse.
    pub reservation_id: ReservationID,
    /// BCS serialized transaction data bytes without its type tag, as base-64 encoded string.
    pub tx_bytes: Base64,
    /// User signature (`flag || signature || pubkey` bytes, as base-64 encoded string). Signature is committed to the intent message of the transaction data, as base-64 encoded string.
    pub user_sig: Base64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExecuteTxResponse {
    pub effects: Option<SuiTransactionBlockEffects>,
    pub error: Option<String>,
}

/// handler for all the request_gas requests
async fn request_gas_from_pool(
    Extension(state): Extension<Arc<AppState>>,
    Json(payload): Json<FaucetRequest>,
) -> impl IntoResponse {
    // ID for traceability
    // let id = Uuid::new_v4();
    // info!(uuid = ?id, "Got new gas request.");

    let FaucetRequest::FixedAmountRequest(request) = payload else {
        return (
            StatusCode::BAD_REQUEST,
            Json(FaucetResponse::from(FaucetError::Internal(
                "Input Error.".to_string(),
            ))),
        );
    };

    let gas_pool_request = GasPoolRequest {
        gas_budget: 1000000,
        reserve_duration_secs: state.config.ttl_expiration,
    };

    let client = reqwest::Client::new();
    let url = "GAS_POOL_URL";
    let response = client
        .post(url)
        .header("Content-Type", "application/json")
        .bearer_auth(GAS_AUTH_TOKEN.to_string())
        .json(&json!(gas_pool_request))
        .send()
        .await;

    if let Err(error) = response {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(FaucetResponse::from(error)),
        );
    }

    let response: Result<ReserveGasResponse, _> = response.unwrap().json().await;

    if let Err(error) = response {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(FaucetResponse::from(error)),
        );
    }

    let response = response.unwrap();

    if let Some(error) = response.error {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(FaucetResponse {
                status: RequestStatus::Failure(FaucetError::internal(error)),
            }),
        );
    }

    if let Some(data) = response.result {
        let reservation_id = data.reservation_id;
        let gas_payment = data.gas_coins.iter().map(|x| x.to_object_ref()).collect();
        let mut tx_builder =
            sui_sdk::types::programmable_transaction_builder::ProgrammableTransactionBuilder::new();

        tx_builder
            .pay_sui(vec![request.recipient], vec![1_000_000_000])
            .unwrap();
        let tx = tx_builder.finish();
        let sender = data.sponsor_address;
        let tx_data = TransactionData::new_programmable(sender, gas_payment, tx, 50000000, 1000);
        let tx_bytes = Base64::from_bytes(&bcs::to_bytes(&tx_data).unwrap());
        let keystore =
            FileBasedKeystore::new(&sui_config_dir().unwrap().join(SUI_KEYSTORE_FILENAME)).unwrap();
        let sig = keystore
            .sign_secure(&sender, &tx_data, Intent::sui_transaction())
            .unwrap();
        let user_sig = Base64::from_bytes(sig.as_ref());

        let gas_pool_request = ExecuteTxRequest {
            reservation_id,
            tx_bytes,
            user_sig,
        };

        let gas_pool_request = client
            .post(url)
            .header(CONTENT_TYPE, "application/json")
            .bearer_auth(GAS_AUTH_TOKEN.to_string())
            .json(&json!(gas_pool_request))
            .send()
            .await;

        let Ok(gas_pool_response) = gas_pool_request else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(FaucetResponse {
                    status: RequestStatus::Failure(FaucetError::Internal(format!(
                        "Gas pool request failed: {}",
                        gas_pool_request.unwrap_err()
                    ))),
                }),
            );
        };

        let Ok(ExecuteTxResponse { effects, error }) = gas_pool_response.json().await else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(FaucetResponse {
                    status: RequestStatus::Failure(FaucetError::Internal(format!(
                        "Could not decode gas pool response json"
                    ))),
                }),
            );
        };

        if let Some(effects) = effects {
            let status = effects.status();
            if status.is_ok() {
                return (
                    StatusCode::OK,
                    Json(FaucetResponse {
                        status: RequestStatus::GasSent,
                    }),
                );
            } else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(FaucetResponse::from(FaucetError::Internal(
                        "Could not ".to_string(),
                    ))),
                );
            }
        } else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(FaucetResponse::from(FaucetError::Internal(
                    "Could not ".to_string(),
                ))),
            );
        }
    }

    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(FaucetResponse::from(FaucetError::Internal(
            "Could not ".to_string(),
        ))),
    )
}

// async fn request_spawn_task(
//     request: GasPoolRequest
//     state: Arc<AppState>,
// ) -> (StatusCode, Json<BatchFaucetResponse>) {
//     let result = spawn_monitored_task!(async move {
//         state
//             .faucet
//             .batch_send(
//                 Uuid::new_v4(),
//                 request.recipient,
//                 &vec![state.config.amount; state.config.num_coins],
//             )
//             .await
//     })
//     .await
//     .unwrap();
//     match result {
//         Ok(v) => (StatusCode::ACCEPTED, Json(BatchFaucetResponse::from(v))),
//         Err(v) => (
//             StatusCode::INTERNAL_SERVER_ERROR,
//             Json(BatchFaucetResponse::from(v)),
//         ),
//     }
// }

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

async fn start_non_local_server(
    app_state: Arc<AppState>,
    concurrency_limit: usize,
    prometheus_registry: &Registry,
    cors: CorsLayer,
) -> Result<(), anyhow::Error> {
    let FaucetConfig {
        port,
        host_ip,
        request_buffer_size,
        max_request_per_second,
        replenish_quota_interval_ms,
        reset_time_interval_secs,
        rate_limiter_cleanup_interval_secs,
        max_requests_per_ip,
        local,
        ..
    } = app_state.config;
    let (cloudflare_turnstile_url, turnstile_secret_key) = if app_state.config.authenticated {
        ensure!(TURNSTILE_SECRET_KEY.is_some() && CLOUDFLARE_TURNSTILE_URL.is_some(),
                "Both CLOUDFLARE_TURNSTILE_URL and TURNSTILE_SECRET_KEY env vars must be set for testnet deployment (--authenticated flag was set)");

        (
            CLOUDFLARE_TURNSTILE_URL.as_ref().unwrap().to_string(),
            TURNSTILE_SECRET_KEY.as_ref().unwrap().to_string(),
        )
    } else {
        ("".to_string(), "".to_string())
    };

    let token_manager = Arc::new(RequestsManager::new(
        max_requests_per_ip,
        Duration::from_secs(reset_time_interval_secs),
        cloudflare_turnstile_url,
        turnstile_secret_key,
    ));
    let governor_cfg = Arc::new(
        GovernorConfigBuilder::default()
            .const_per_millisecond(replenish_quota_interval_ms)
            .burst_size(max_request_per_second as u32)
            .key_extractor(GlobalKeyExtractor)
            .finish()
            .unwrap(),
    );
    // these routes have a more aggressive rate limit to reduce the number of reqs per second as
    // per the governor config above.
    let global_limited_routes = Router::new()
        .route("/v1/gas", post(request_gas_from_pool))
        .layer(GovernorLayer {
            config: governor_cfg.clone(),
        });

    // This has its own rate limiter via the RequestManager
    let faucet_web_routes = Router::new().route("/v1/faucet_web_gas", post(request_faucet_web_gas));
    // Routes with no rate limit
    let unrestricted_routes = Router::new()
        .route("/", get(redirect))
        .route("/health", get(health))
        .route("/v1/faucet_discord", post(request_faucet_discord));

    // Combine all routes
    let app = Router::new()
        .merge(global_limited_routes)
        .merge(unrestricted_routes)
        .merge(faucet_web_routes)
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(handle_error))
                .layer(RequestMetricsLayer::new(prometheus_registry))
                .load_shed()
                .buffer(request_buffer_size)
                .concurrency_limit(concurrency_limit)
                .layer(Extension(app_state.clone()))
                .layer(Extension(token_manager.clone()))
                .layer(cors)
                .into_inner(),
        );

    spawn_monitored_task!(async move {
        info!("Starting task to clear banned ip addresses.");
        loop {
            tokio::time::sleep(Duration::from_secs(rate_limiter_cleanup_interval_secs)).await;
            token_manager.cleanup_expired_tokens();
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

/// Start a faucet that is run locally. This should only be used for starting a local network, and
/// not for devnet/testnet deployments!
async fn start_local_server(
    app_state: Arc<AppState>,
    prometheus_registry: &Registry,
    cors: CorsLayer,
) -> Result<(), anyhow::Error> {
    let FaucetConfig { port, host_ip, .. } = app_state.config;

    println!("Starting in local mode");
    let app = Router::new()
        .route("/v1/gas", post(request_local_gas))
        .route("/gas", post(request_local_gas))
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(handle_error))
                .layer(RequestMetricsLayer::new(prometheus_registry))
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

// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{AppState, FaucetConfig, FaucetError, FaucetRequest, RequestMetricsLayer};
use axum::{
    error_handling::HandleErrorLayer,
    extract::Host,
    http::{header::HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    BoxError, Extension, Json, Router,
};
use dashmap::{mapref::entry::Entry, DashMap};
use http::Method;
use mysten_metrics::spawn_monitored_task;
use prometheus::Registry;
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use sui_config::SUI_CLIENT_CONFIG;
use sui_sdk::wallet_context::WalletContext;
use tower::ServiceBuilder;
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::GlobalKeyExtractor, GovernorLayer,
};
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, warn};

use anyhow::ensure;
use once_cell::sync::Lazy;

const DEFAULT_FAUCET_WEB_APP_URL: &str = "https://faucet.sui.io";

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

/// Keep track of every IP address' requests.
#[derive(Debug)]
struct RequestsManager {
    data: Arc<DashMap<IpAddr, RequestInfo>>,
    reset_time_interval: Duration,
    max_requests_per_ip: u64,
    cloudflare_turnstile_url: String,
    turnstile_secret_key: String,
}

/// Request's metadata
#[derive(Debug, Clone)]
struct RequestInfo {
    /// When the first request from this IP address was made. In case of resetting the IP addresses
    /// metadata, this field will be updated with the new current time.
    timestamp: Instant,
    requests_used: u64,
}

/// Struct to deserialize token verification response from Cloudflare
#[derive(Deserialize, Debug)]
struct TurnstileValidationResponse {
    success: bool,
    #[serde(rename = "error-codes")]
    error_codes: Vec<String>,
}

impl RequestsManager {
    /// Initialize a new RequestsManager
    fn new(
        max_requests_per_ip: u64,
        reset_time_interval_secs: Duration,
        cloudflare_turnstile_url: String,
        turnstile_secret_key: String,
    ) -> Self {
        Self {
            data: Arc::new(DashMap::new()),
            reset_time_interval: reset_time_interval_secs,
            max_requests_per_ip,
            cloudflare_turnstile_url,
            turnstile_secret_key,
        }
    }

    /// Validates a turnstile token
    /// - against Cloudflare turnstile's server to ensure token was issued by turnstile
    /// - against the IP address' request count
    async fn validate_turnstile_token(
        &self,
        addr: SocketAddr,
        token: &str,
    ) -> Result<(), (StatusCode, FaucetError)> {
        let ip = addr.ip();
        let req = reqwest::Client::new();
        let params = [
            ("secret", self.turnstile_secret_key.as_str()),
            ("response", token),
            ("remoteip", &ip.to_string()),
        ];

        // Make the POST request
        let resp = match req
            .post(&self.cloudflare_turnstile_url)
            .form(&params)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                error!("Cloudflare turnstile request failed: {:?}", e);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    FaucetError::Internal(e.to_string()),
                ));
            }
        };

        // Check if the request was successful.
        if !resp.status().is_success() {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                FaucetError::Internal("Verification failed".to_string()),
            ));
        }

        let body = match resp.json::<TurnstileValidationResponse>().await {
            Ok(body) => body,
            Err(e) => {
                error!("Failed to parse token validation response: {:?}", e);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    FaucetError::Internal(e.to_string()),
                ));
            }
        };

        if !body.success {
            return Err((
                StatusCode::BAD_REQUEST,
                FaucetError::Internal(format!("Token verification failed: {:?}", body.error_codes)),
            ));
        }

        match self.data.entry(ip) {
            Entry::Vacant(entry) => {
                entry.insert(RequestInfo {
                    timestamp: Instant::now(),
                    requests_used: 1,
                });
            }

            Entry::Occupied(mut entry) => {
                let token = entry.get_mut();
                let elapsed = token.timestamp.elapsed();

                if elapsed >= self.reset_time_interval {
                    token.timestamp = Instant::now();
                    token.requests_used = 1;
                } else if token.requests_used >= self.max_requests_per_ip {
                    return Err((
                        StatusCode::TOO_MANY_REQUESTS,
                        FaucetError::TooManyRequests(format!(
                            "You can request a new token in {}",
                            secs_to_human_readable((self.reset_time_interval - elapsed).as_secs())
                        )),
                    ));
                } else {
                    token.requests_used += 1;
                }
            }
        }

        Ok(())
    }

    /// This function iterates through the stored IPs and removes those IP addresses which are now
    /// eligible to make new requests.
    fn cleanup_expired_tokens(&self) {
        // keep only those IP addresses that are still under time limit.
        self.data
            .retain(|_, info| info.timestamp.elapsed() < self.reset_time_interval);
    }
}

pub async fn start_faucet(
    app_state: Arc<AppState>,
    concurrency_limit: usize,
    prometheus_registry: &Registry,
) -> Result<(), anyhow::Error> {
    println!("Starting faucet");
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

    // TODO: restrict access if needed
    let cors = CorsLayer::new()
        .allow_methods(vec![Method::GET, Method::POST])
        .allow_headers(Any)
        .allow_origin(Any);

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

    let token_manager = Arc::new(RequestsManager::new(
        max_requests_per_ip,
        Duration::from_secs(reset_time_interval_secs),
        cloudflare_turnstile_url,
        turnstile_secret_key,
    ));

    if local {
        println!("Starting in local mode");
        let app = Router::new()
            .route("/v1/gas", post(request_local_gas))
            .route("/gas", post(request_local_gas))
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
                tokio::time::sleep(Duration::from_secs(1)).await;
                app_state.faucet.local_request_execute_tx().await;
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
    } else {
        let governor_cfg = Arc::new(
            GovernorConfigBuilder::default()
                .const_per_millisecond(replenish_quota_interval_ms)
                .burst_size(max_request_per_second as u32)
                .key_extractor(GlobalKeyExtractor)
                .finish()
                .unwrap(),
        );
        // // these routes have a more aggressive rate limit to reduce the number of reqs per second as
        // // per the governor config above.
        // let global_limited_routes = Router::new()
        //     .route("/v1/gas", post(batch_request_gas))
        //     .layer(GovernorLayer {
        //         config: governor_cfg.clone(),
        //     });
        //
        // // This has its own rate limiter via the RequestManager
        // let faucet_web_routes = Router::new().route("/v1/faucet_web_gas", post(request_faucet_web_gas));
        // // Routes with no rate limit
        // let unrestricted_routes = Router::new()
        //     .route("/", get(redirect))
        //     .route("/health", get(health))
        //     .route("/v1/faucet_discord", post(request_faucet_discord));
        //
        // // Combine all routes
        // let app = Router::new()
        //     .merge(global_limited_routes)
        //     .merge(unrestricted_routes)
        //     .merge(faucet_web_routes)
        //     .layer(
        //         ServiceBuilder::new()
        //             .layer(HandleErrorLayer::new(handle_error))
        //             .layer(RequestMetricsLayer::new(prometheus_registry))
        //             .load_shed()
        //             .buffer(request_buffer_size)
        //             .concurrency_limit(concurrency_limit)
        //             .layer(Extension(app_state.clone()))
        //             .layer(Extension(token_manager.clone()))
        //             .layer(cors)
        //             .into_inner(),
        //     );
        //
        // spawn_monitored_task!(async move {
        //     info!("Starting task to clear banned ip addresses.");
        //     loop {
        //         tokio::time::sleep(Duration::from_secs(rate_limiter_cleanup_interval_secs)).await;
        //         token_manager.cleanup_expired_tokens();
        //     }
        // });
        //
        // let addr = SocketAddr::new(IpAddr::V4(host_ip), port);
        // info!("listening on {}", addr);
        // let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        // axum::serve(
        //     listener,
        //     app.into_make_service_with_connect_info::<SocketAddr>(),
        // )
        // .await?;
        // Ok(())

        Ok(())
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
    Success,
    Failure,
}

#[derive(Serialize, Deserialize, Debug)]
struct FaucetResponse {
    pub status: RequestStatus,
}

async fn request_local_gas(
    Extension(state): Extension<Arc<AppState>>,
    Json(payload): Json<FaucetRequest>,
    // ) -> &'static str {
) -> impl IntoResponse {
    let FaucetRequest::FixedAmountRequest(request) = payload;
    state
        .faucet
        .local_request_add_to_queue(request.recipient)
        .await;
    // info!("Local request to add to queue for faucet");
}

async fn process_local_gas_requests(
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    let resp = state.faucet.local_request_execute_tx().await;
    match resp {
        Ok(v) => {
            // info!("Local request is successfully served");
            (
                StatusCode::CREATED,
                Json(FaucetResponse {
                    status: RequestStatus::Success,
                }),
            )
        }
        Err(v) => {
            // warn!("Failed to request gas: {:?}", v);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(FaucetResponse {
                    status: RequestStatus::Failure,
                }),
            )
        }
    }
}

// /// A route for requests coming from the discord bot.
// async fn request_faucet_discord(
//     headers: HeaderMap,
//     Extension(state): Extension<Arc<AppState>>,
//     Json(payload): Json<FaucetRequest>,
// ) -> impl IntoResponse {
//     if state.config.authenticated {
//         let Some(agent_value) = headers
//             .get(reqwest::header::USER_AGENT)
//             .and_then(|v| v.to_str().ok())
//         else {
//             return (
//                 StatusCode::BAD_REQUEST,
//                 Json(BatchFaucetResponse::from(FaucetError::InvalidUserAgent(
//                     "Invalid user agent for this route".to_string(),
//                 ))),
//             );
//         };
//
//         if agent_value != *DISCORD_BOT_PWD {
//             return (
//                 StatusCode::BAD_REQUEST,
//                 Json(BatchFaucetResponse::from(FaucetError::InvalidUserAgent(
//                     "Invalid user agent for this route".to_string(),
//                 ))),
//             );
//         }
//     }
//
//     let FaucetRequest::FixedAmountRequest(request) = payload else {
//         return (
//             StatusCode::BAD_REQUEST,
//             Json(BatchFaucetResponse::from(FaucetError::Internal(
//                 "Input Error.".to_string(),
//             ))),
//         );
//     };
//
//     batch_request_spawn_task(request, state).await
// }
//
// /// Handler for requests coming from the frontend faucet web app.
// async fn request_faucet_web_gas(
//     headers: HeaderMap,
//     ConnectInfo(addr): ConnectInfo<SocketAddr>,
//     Extension(token_manager): Extension<Arc<RequestsManager>>,
//     Extension(state): Extension<Arc<AppState>>,
//     Json(payload): Json<FaucetRequest>,
// ) -> impl IntoResponse {
//     if state.config.authenticated {
//         let Some(token) = headers
//             .get("X-Turnstile-Token")
//             .and_then(|v| v.to_str().ok())
//         else {
//             return (
//                 StatusCode::BAD_REQUEST,
//                 Json(BatchFaucetResponse::from(
//                     FaucetError::MissingTurnstileTokenHeader,
//                 )),
//             );
//         };
//
//         let validation = token_manager.validate_turnstile_token(addr, token).await;
//
//         if let Err((status_code, faucet_error)) = validation {
//             return (status_code, Json(BatchFaucetResponse::from(faucet_error)));
//         }
//     }
//
//     let FaucetRequest::FixedAmountRequest(request) = payload else {
//         return (
//             StatusCode::BAD_REQUEST,
//             Json(BatchFaucetResponse::from(FaucetError::Internal(
//                 "Input Error.".to_string(),
//             ))),
//         );
//     };
//
//     batch_request_spawn_task(request, state).await
// }
//
// /// handler for all the request_gas requests
// async fn request_gas_from_pool(
//     Extension(state): Extension<Arc<AppState>>,
//     Json(payload): Json<FaucetRequest>,
// ) -> impl IntoResponse {
//     // ID for traceability
//     let id = Uuid::new_v4();
//     info!(uuid = ?id, "Got new gas request.");
//
//     let result = match payload {
//         FaucetRequest::FixedAmountRequest(requests) => {
//             // We spawn a tokio task for this such that connection drop will not interrupt
//             // it and impact the recycling of coins
//         }
//         _ => {
//             return (
//                 StatusCode::BAD_REQUEST,
//                 Json(FaucetResponse::from(FaucetError::Internal(
//                     "Input Error.".to_string(),
//                 ))),
//             )
//         }
//     };
//     match result {
//         Ok(v) => {
//             info!(uuid =?id, "Request is successfully served");
//             (StatusCode::CREATED, Json(FaucetResponse::from(v)))
//         }
//         Err(v) => {
//             warn!(uuid =?id, "Failed to request gas: {:?}", v);
//             (
//                 StatusCode::INTERNAL_SERVER_ERROR,
//                 Json(FaucetResponse::from(v)),
//             )
//         }
//     }
// }
//
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
//
/// Format seconds to human readable format.
fn secs_to_human_readable(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let seconds = seconds % 60;

    if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

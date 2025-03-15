// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::FaucetError;
use dashmap::{mapref::entry::Entry, DashMap};
use http::StatusCode;
use serde::Deserialize;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::error;

/// Keep track of every IP address' requests.
#[derive(Debug)]
pub(crate) struct RequestsManager {
    data: Arc<DashMap<IpAddr, RequestInfo>>,
    reset_time_interval: Duration,
    max_requests_per_ip: u64,
    cloudflare_turnstile_url: String,
    turnstile_secret_key: String,
}

/// Request's metadata
#[derive(Debug, Clone)]
pub(crate) struct RequestInfo {
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
    pub(crate) fn new(
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
    pub(crate) async fn validate_turnstile_token(
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
    pub(crate) fn cleanup_expired_tokens(&self) {
        // keep only those IP addresses that are still under time limit.
        self.data
            .retain(|_, info| info.timestamp.elapsed() < self.reset_time_interval);
    }
}

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

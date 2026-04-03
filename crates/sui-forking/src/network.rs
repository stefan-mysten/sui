// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Network selection parsing for `sui-forking`.
//!
//! This module only validates and normalizes user-provided network input. Endpoint resolution and
//! startup wiring are added in later slices.

use std::str::FromStr;

use anyhow::anyhow;
use anyhow::bail;
use url::Url;

/// Parsed source-network selection for the forking tool.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ForkNetwork {
    /// Sui mainnet.
    Mainnet,
    /// Sui testnet.
    Testnet,
    /// Sui devnet.
    Devnet,
    /// Custom GraphQL endpoint URL.
    Custom(String),
}

impl ForkNetwork {
    /// Parse a network value from CLI or config input.
    ///
    /// Accepted values are `mainnet`, `testnet`, `devnet`, or a full `http(s)` URL.
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        let value = value.trim();
        if value.is_empty() {
            bail!("network cannot be empty");
        }

        match value.to_ascii_lowercase().as_str() {
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            "devnet" => Ok(Self::Devnet),
            _ => {
                validate_custom_url(value)
                    .map_err(|error| anyhow!("invalid network value '{value}': {error}"))?;
                Ok(Self::Custom(value.to_owned()))
            }
        }
    }
}

impl FromStr for ForkNetwork {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Validate a custom GraphQL endpoint URL.
fn validate_custom_url(value: &str) -> anyhow::Result<()> {
    let parsed = Url::parse(value).map_err(|error| {
        anyhow!("expected mainnet, testnet, devnet, or a full http(s) URL ({error})")
    })?;

    match parsed.scheme() {
        "http" | "https" => {}
        scheme => bail!("unsupported URL scheme '{scheme}'; expected http or https"),
    }

    if parsed.host_str().is_none() {
        bail!("expected a URL with a host");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_network_keywords() {
        assert_eq!(ForkNetwork::parse("mainnet").unwrap(), ForkNetwork::Mainnet);
        assert_eq!(ForkNetwork::parse("testnet").unwrap(), ForkNetwork::Testnet);
        assert_eq!(ForkNetwork::parse("devnet").unwrap(), ForkNetwork::Devnet);
        assert_eq!(
            ForkNetwork::parse("  MainNet ").unwrap(),
            ForkNetwork::Mainnet
        );
    }

    #[test]
    fn parses_custom_graphql_url_without_rewriting() {
        let url = "https://example.com/custom/graphql";

        assert_eq!(
            ForkNetwork::parse(url).unwrap(),
            ForkNetwork::Custom(url.to_owned())
        );
    }

    #[test]
    fn rejects_invalid_non_url_custom_values() {
        let error = ForkNetwork::parse("not-a-network").unwrap_err().to_string();

        assert!(error.contains("expected mainnet, testnet, devnet"));
    }

    #[test]
    fn rejects_non_http_scheme_custom_values() {
        let error = ForkNetwork::parse("ws://example.com/graphql")
            .unwrap_err()
            .to_string();

        assert!(error.contains("unsupported URL scheme 'ws'"));
    }
}

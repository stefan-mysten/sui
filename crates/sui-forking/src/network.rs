// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Network selection parsing for `sui-forking`.
//!
//! This module only validates and normalizes user-provided network input. Endpoint resolution and
//! startup wiring are added in later slices.

use std::str::FromStr;

use anyhow::Context as _;
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
    Custom(Url),
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
                let url = parse_custom_url(value)
                    .with_context(|| format!("invalid network value '{value}'"))?;
                Ok(Self::Custom(url))
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

/// Parse and validate a custom GraphQL endpoint URL.
fn parse_custom_url(value: &str) -> anyhow::Result<Url> {
    let parsed =
        Url::parse(value).context("expected mainnet, testnet, devnet, or a full http(s) URL")?;

    match parsed.scheme() {
        "http" | "https" => {}
        scheme => bail!("unsupported URL scheme '{scheme}'; expected http or https"),
    }

    if parsed.host_str().is_none() {
        bail!("expected a URL with a host");
    }

    Ok(parsed)
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
    fn parses_custom_graphql_url() {
        let url = "https://example.com/custom/graphql";

        assert_eq!(
            ForkNetwork::parse(url).unwrap(),
            ForkNetwork::Custom(Url::parse(url).unwrap())
        );
    }

    #[test]
    fn rejects_invalid_non_url_custom_values() {
        let error = ForkNetwork::parse("not-a-network").unwrap_err();

        assert!(error.to_string().contains("invalid network value"));
        assert!(format!("{error:?}").contains("expected mainnet, testnet, devnet"));
    }

    #[test]
    fn rejects_non_http_scheme_custom_values() {
        let error = ForkNetwork::parse("ws://example.com/graphql").unwrap_err();

        assert!(error.to_string().contains("invalid network value"));
        assert!(format!("{error:?}").contains("unsupported URL scheme 'ws'"));
    }
}

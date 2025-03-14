// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Error;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};
use sui_protocol_config::Chain;
use sui_sdk::apis::ReadApi;
use sui_types::digests::ChainIdentifier;

#[derive(Debug, Serialize)]
pub struct MvrResolver {
    pub names: BTreeSet<String>,
    pub token_to_name: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResolvedMvrAddresses {
    pub resolution: BTreeMap<String, PackageId>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PackageId {
    pub package_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TypeTagContainer {
    pub type_tag: String,
}

impl MvrResolver {
    pub fn from_tokens<'a>(tokens: impl Iterator<Item = &'a str>) -> Self {
        let mut mvr_tokens: BTreeSet<_> = BTreeSet::new();
        let mut token_to_name: BTreeMap<String, String> = BTreeMap::new();
        for t in tokens {
            let token = if t.starts_with("<") && t.ends_with(">") {
                &t[1..t.len() - 1]
            } else {
                t
            };

            let versioned_name = mvr_types::name::VersionedName::from_str(token);
            let parsed_type = mvr_types::named_type::NamedType::parse_names(token);

            if let Ok(versioned_name) = versioned_name {
                mvr_tokens.insert(versioned_name.to_string());
                token_to_name.insert(t.to_string(), versioned_name.to_string());
            }
            if let Ok(parsed_type) = parsed_type {
                if !parsed_type.is_empty() {
                    token_to_name.insert(t.to_string(), parsed_type.first().unwrap().to_string());
                    mvr_tokens.extend(parsed_type);
                }
            }
        }
        Self {
            names: mvr_tokens,
            token_to_name,
        }
    }

    pub async fn resolve_into_addresses(
        &self,
        read_api: &ReadApi,
    ) -> Result<ResolvedMvrAddresses, Error> {
        if self.names.is_empty() {
            return Ok(ResolvedMvrAddresses {
                resolution: BTreeMap::new(),
            });
        }

        let request = reqwest::Client::new();
        let url = mvr_req_url(read_api).await?;
        let body = serde_json::to_string(&self).expect("Failed to serialize request body");
        let response = request
            .post(url)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await?;

        let resolved_addresses: ResolvedMvrAddresses = response.json().await?;

        anyhow::ensure!(
            resolved_addresses.resolution.len() == self.names.len(),
            "expected {} addresses but got {}. Could not find package id for {}",
            self.names.len(),
            resolved_addresses.resolution.len(),
            self.names
                .difference(
                    &resolved_addresses
                        .resolution
                        .keys()
                        .cloned()
                        .collect::<BTreeSet<_>>()
                )
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        );

        Ok(resolved_addresses)
    }
}

/// Based on the chain id of the current set environment, return the correct MVR URL to use for
/// resolution.
async fn mvr_req_url(read_api: &ReadApi) -> Result<&'static str, Error> {
    let chain_id = read_api.get_chain_identifier().await?;
    let chain = ChainIdentifier::from_chain_short_id(&chain_id);

    if let Some(chain) = chain {
        let chain = chain.chain();
        match chain {
            Chain::Mainnet => Ok("https://qa.mainnet.mvr.mystenlabs.com/v1/resolution/bulk"),
            Chain::Testnet => Ok("https://qa.testnet.mvr.mystenlabs.com/v1/resolution/bulk"),
            Chain::Unknown => {
                anyhow::bail!("Unsupported chain identifier: {:?}", chain);
            }
        }
    } else {
        anyhow::bail!("Unsupported chain identifier: {:?}", chain)
    }
}

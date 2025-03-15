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

const MVR_RESOLVER_MAINNET_URL: &str = "https://qa.mainnet.mvr.mystenlabs.com";
const MVR_RESOLVER_TESTNET_URL: &str = "https://qa.testnet.mvr.mystenlabs.com";

#[derive(Debug, Serialize)]
pub struct MvrResolver {
    pub names: BTreeSet<String>,
    pub types: BTreeSet<String>,
    pub token_to_name: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResolvedNames {
    pub resolution: BTreeMap<String, PackageId>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResolvedTypes {
    pub resolution: BTreeMap<String, TypeTagContainer>,
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
        let mut names: BTreeSet<_> = BTreeSet::new();
        let mut types: BTreeSet<_> = BTreeSet::new();
        let mut token_to_name: BTreeMap<String, Vec<String>> = BTreeMap::new();

        for t in tokens {
            if t.contains("@") || t.contains(".") {
                if t.starts_with("<") {
                    // we have a type tag
                    let token = t[1..t.len() - 1].to_string();
                    let type_tag = mvr_types::named_type::NamedType::parse_names(&token);
                    if let Ok(parsed_type) = type_tag {
                        if !parsed_type.is_empty() {
                            types.insert(token.clone());
                            token_to_name.insert(t.to_string(), parsed_type);
                        }
                    }
                } else if t.contains("<") {
                    // we have a type tag

                    let type_tag = mvr_types::named_type::NamedType::parse_names(t);
                    if let Ok(parsed_type) = type_tag {
                        if !parsed_type.is_empty() {
                            types.insert(t.to_string());
                            token_to_name.insert(t.to_string(), parsed_type);
                        }
                    }
                } else {
                    let versioned_name = mvr_types::name::VersionedName::from_str(t);
                    if let Ok(versioned_name) = versioned_name {
                        names.insert(versioned_name.to_string());
                        token_to_name.insert(t.to_string(), vec![versioned_name.to_string()]);
                    }

                    let parsed_type = mvr_types::named_type::NamedType::parse_names(t);
                    if let Ok(parsed_type) = parsed_type {
                        if !parsed_type.is_empty() {
                            for parsed_type in &parsed_type {
                                names.insert(parsed_type.to_string());
                            }
                            token_to_name.insert(t.to_string(), parsed_type);
                        }
                    }
                }
            }
        }
        println!("Names: {:?}", names);
        println!("Types: {:?}", types);
        // for t in tokens {
        //     let token = if t.starts_with("<") && t.ends_with(">") {
        //         &t[1..t.len() - 1]
        //     } else {
        //         t
        //     };
        //
        //     println!("Token: {token}");
        //     let versioned_name = mvr_types::name::VersionedName::from_str(token);
        //     let parsed_type = mvr_types::named_type::NamedType::parse_names(token);
        //
        //     println!("VersionedName: {versioned_name:?}");
        //     println!("ParsedType: {parsed_type:?}");
        //
        //     if let Ok(versioned_name) = versioned_name {
        //         names.insert(versioned_name.to_string());
        //         token_to_name.insert(t.to_string(), vec![versioned_name.to_string()]);
        //     }
        //     if let Ok(parsed_type) = parsed_type {
        //         if !parsed_type.is_empty() {
        //             types.extend(t);
        //             token_to_name.insert(t.to_string(), parsed_type);
        //         }
        //     }
        // }
        Self {
            names,
            types,
            token_to_name,
        }
    }

    pub async fn resolve_names(&self, read_api: &ReadApi) -> Result<ResolvedNames, Error> {
        if self.names.is_empty() {
            return Ok(ResolvedNames {
                resolution: BTreeMap::new(),
            });
        }

        let request = reqwest::Client::new();
        let (url, chain) = mvr_req_url(read_api).await?;
        let body = serde_json::to_string(&self).expect("Failed to serialize request body");
        let response = request
            .post(format!("{url}/v1/resolution/bulk"))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await?;

        let resolved_addresses: ResolvedNames = response.json().await?;

        anyhow::ensure!(
            resolved_addresses.resolution.len() == self.names.len(),
            "expected {} addresses but got {}. Could not find package id for {} for {chain} enviroment",
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

    pub async fn resolve_types(&self, read_api: &ReadApi) -> Result<ResolvedTypes, Error> {
        if self.types.is_empty() {
            return Ok(ResolvedTypes {
                resolution: BTreeMap::new(),
            });
        }
        let request = reqwest::Client::new();
        let (url, chain) = mvr_req_url(read_api).await?;
        let body = serde_json::to_string(&self).expect("Failed to serialize request body");
        let response = request
            .post(format!("{url}/v1/type_resolution/bulk"))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await?;

        let resolved_types: ResolvedTypes = response.json().await?;

        anyhow::ensure!(
            resolved_types.resolution.len() == self.types.len(),
            "expected {} addresses but got {}. Could not find package id for {} for {chain} enviroment",
            self.types.len(),
            resolved_types.resolution.len(),
            self.types
                .difference(
                    &resolved_types
                        .resolution
                        .keys()
                        .cloned()
                        .collect::<BTreeSet<_>>()
                )
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        );

        Ok(resolved_types)
    }
}

/// Based on the chain id of the current set environment, return the correct MVR URL to use for
/// resolution.
async fn mvr_req_url(read_api: &ReadApi) -> Result<(&'static str, &'static str), Error> {
    let chain_id = read_api.get_chain_identifier().await?;
    let chain = ChainIdentifier::from_chain_short_id(&chain_id);

    if let Some(chain) = chain {
        let chain = chain.chain();
        match chain {
            Chain::Mainnet => Ok((MVR_RESOLVER_MAINNET_URL, "mainnet")),
            Chain::Testnet => Ok((MVR_RESOLVER_TESTNET_URL, "testnet")),
            Chain::Unknown => {
                anyhow::bail!("Unsupported chain identifier: {:?}", chain);
            }
        }
    } else {
        anyhow::bail!("Unsupported chain identifier: {:?}", chain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_from_tokens() {
        let tokens = [
            "0x1::option::is_some",                            // ignored
            "0x1::option::is_none<u8>",                        // ignored
            "0x1::coin::Coin<0x2::sui::SUI>",                  // ignored
            "<0x1::coin::Coin<0x2::sui::SUI>>",                // type tag
            "<0x1::coin::Coin<@mvr/pkg::module::type>>",       // type tag with @mvr/pkg
            "<0x1::coin::Coin<sui.test/pkg/1::module::type>>", // type tag with sui.test/pkg/1
            // version
            "test.sui/pkg::module::function", // package name
            "<pkg::module::type<@mvr/pkg::module::type, test.sui/pkg::module::type>>", // type tag with two types
        ];

        let resolver = MvrResolver::from_tokens(tokens.iter().cloned());
        assert_eq!(resolver.names.len(), 1);
        assert_eq!(resolver.names.first().unwrap(), "test.sui/pkg");
        assert_eq!(resolver.types.len(), 2);
        assert_eq!(
            resolver.types,
            BTreeSet::from([
                "0x1::coin::Coin<@mvr/pkg::module::type>".to_string(),
                "0x1::coin::Coin<sui.test/pkg/1::module::type>".to_string(),
                "pkg::module::type<@mvr/pkg::module::type, test.sui/pkg::module::type>".to_string()
            ])
        );
    }
}

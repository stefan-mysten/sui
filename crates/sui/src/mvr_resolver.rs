// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Error;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use sui_protocol_config::Chain;
use sui_sdk::apis::ReadApi;
use sui_types::digests::ChainIdentifier;

use once_cell::sync::Lazy;

const MVR_RESOLVER_MAINNET_URL: &str = "https://qa.mainnet.mvr.mystenlabs.com";
const MVR_RESOLVER_TESTNET_URL: &str = "https://qa.testnet.mvr.mystenlabs.com";

pub(crate) static MVR_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(@[^\s,<>]+|[^\s,<>]+\.sui[^\s,<>]*)").unwrap());

#[derive(Debug, Serialize)]
pub struct MvrResolver {
    pub names: BTreeSet<String>,
    pub types: BTreeSet<String>,
    pub token_to_names: BTreeMap<String, Vec<String>>,
    pub token_to_types: BTreeMap<String, Vec<String>>,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct TypesRequest {
    pub types: BTreeSet<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NamesRequest {
    pub names: BTreeSet<String>,
}

impl MvrResolver {
    pub fn should_resolve(&self) -> bool {
        !self.names.is_empty() || !self.types.is_empty()
    }

    pub fn from_tokens<'a>(tokens: impl Iterator<Item = &'a str>) -> Result<Self, anyhow::Error> {
        let mut names: BTreeSet<_> = BTreeSet::new();
        let mut types: BTreeSet<_> = BTreeSet::new();
        // let mut token_to_name: BTreeMap<String, Vec<String>> = BTreeMap::new();

        let mut token_to_names: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut token_to_types: BTreeMap<String, Vec<String>> = BTreeMap::new();

        for t in tokens {
            if t.contains("@") || t.contains(".sui") {
                if t.starts_with("<") {
                    // we have a type tag
                    let token = if t.starts_with("<") {
                        t[1..t.len() - 1].to_string()
                    } else {
                        t.to_string()
                    };
                    // these are the type tags that we found which we need to pass to the MVR
                    // forward lookup service
                    let collect_type_tags = extract_types_for_resolver(&token);

                    types.extend(collect_type_tags.clone());
                    token_to_types.insert(t.to_string(), collect_type_tags.into_iter().collect());
                }
                if t.contains("<") {
                    // if we have something like pkg::module::function<type, type, type>, we want
                    // to split it as the initial pkg::module::function is not a type arg.
                    let split = t.split_once("<");

                    if let Some((first, rest)) = split {
                        // the first part is the package name so we need only that pkg
                        if let Some(name) = extract_name_for_resolver(first) {
                            names.insert(name.clone());
                            token_to_names.insert(t.to_string(), vec![name]);
                        }

                        // the rest is type tag
                        let token = rest[0..rest.len() - 1].to_string();

                        // these are the type tags that we found which we need to pass to the MVR
                        // forward lookup service
                        let collect_type_tags = extract_types_for_resolver(&token);
                        types.extend(collect_type_tags.clone());
                        token_to_types
                            .insert(t.to_string(), collect_type_tags.into_iter().collect());
                    }
                } else {
                    if let Some(name) = extract_name_for_resolver(t) {
                        names.insert(name.clone());
                        token_to_names.insert(t.to_string(), vec![name]);
                    }
                }
            }
        }

        Ok(Self {
            names,
            types,
            token_to_names,
            token_to_types,
        })
    }

    pub async fn resolve_names(&self, read_api: &ReadApi) -> Result<ResolvedNames, Error> {
        if self.names.is_empty() {
            return Ok(ResolvedNames {
                resolution: BTreeMap::new(),
            });
        }

        let request = reqwest::Client::new();
        let (url, chain) = mvr_req_url(read_api).await?;
        let json_body = json!(NamesRequest {
            names: self.names.clone()
        });
        let response = request
            .post(format!("{url}/v1/resolution/bulk"))
            .header("Content-Type", "application/json")
            .json(&json_body)
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
        let json_body = json!(TypesRequest {
            types: self.types.clone().into_iter().collect(),
        });

        let response = request
            .post(format!("{url}/v1/type-resolution/bulk"))
            .header("Content-Type", "application/json")
            .json(&json_body)
            .send()
            .await?;

        let resolved_types: ResolvedTypes = response.json().await?;

        anyhow::ensure!(
            resolved_types.resolution.len() == self.types.len(),
            "expected {} resolved types but got {}. Could not find id for {} for {chain} enviroment",
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
        anyhow::bail!(
            "Unsupported chain: {chain_id}. Only mainnet/testnet are supported for \
            MVR resolution",
        )
    }
}

pub async fn resolve_mvr_name(name: &str, read_api: &ReadApi) -> Result<PackageId, Error> {
    let request = reqwest::Client::new();
    let (url, chain) = mvr_req_url(read_api).await?;
    let json_body = json!(NamesRequest {
        names: BTreeSet::from([name.to_string()])
    });
    let response = request
        .post(format!("{url}/v1/resolution/bulk"))
        .header("Content-Type", "application/json")
        .json(&json_body)
        .send()
        .await?;

    let resolved_addresses: ResolvedNames = response.json().await?;

    resolved_addresses
        .resolution
        .into_values()
        .next()
        .ok_or_else(|| {
            anyhow::anyhow!("Could not find package id for {name} for {chain} environment")
        })
}

pub async fn resolve_mvr_type(name: &str, read_api: &ReadApi) -> Result<TypeTagContainer, Error> {
    let request = reqwest::Client::new();
    let (url, chain) = mvr_req_url(read_api).await?;
    let json_body = json!(TypesRequest {
        types: BTreeSet::from([name.to_string()])
    });
    let response = request
        .post(format!("{url}/v1/type-resolution/bulk"))
        .header("Content-Type", "application/json")
        .json(&json_body)
        .send()
        .await?;

    let resolved_types: ResolvedTypes = response.json().await?;

    resolved_types
        .resolution
        .into_values()
        .next()
        .ok_or_else(|| anyhow::anyhow!("Could not find type id for {name} for {chain} environment"))
}

fn extract_name_for_resolver(input: &str) -> Option<String> {
    // Regex::new(r"((?:.*\.sui.*|@.*)?)(?=:)")
    //     .unwrap()
    //     .find(input)
    //     .map(|x| x.as_str().to_string())
    None
}

fn extract_types_for_resolver(input: &str) -> BTreeSet<String> {
    // Collect all matches into a set
    let matches: BTreeSet<String> = MVR_REGEX
        .find_iter(input)
        .map(|m| m.as_str().to_string())
        .collect();

    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_from_tokens() {
        let tokens = [
            "0x1::option::is_some",                      // ignored
            "0x1::option::is_none<u8>",                  // ignored
            "0x1::coin::Coin<0x2::sui::SUI>",            // ignored
            "<0x1::coin::Coin<@mvr/pkg::module::type>>", // type tag with @mvr/pkg
            // type tag, same as previous one but without the starting < tag
            "0x1::coin::Coin<@mvr/pkg::module::type>",
            "<0x1::coin::Coin<0x2::sui::SUI>>", // ignored type tag
            "<0x1::coin::Coin<test.sui/pkg/1::module::type>>", // type tag with sui.test/pkg/1
            // version
            // @test === test.sui/pkg/1
            "test.sui/pkg::module::function",     // package name
            "test.sui/pkg::module::function<u8>", // package name
            "test.sui/pkg::module::function<u8, @mvr/pkg::module::TYPE>", // package name
        ];

        let resolver = MvrResolver::from_tokens(tokens.into_iter()).unwrap();
        println!("Resolver {:?}", resolver);

        assert_eq!(resolver.names.len(), 1);
        assert_eq!(resolver.names.first().unwrap(), "test.sui/pkg");
        assert_eq!(resolver.types.len(), 3);
        assert_eq!(
            resolver.types,
            BTreeSet::from([
                "@mvr/pkg::module::type".to_string(),
                "test.sui/pkg/1::module::type".to_string(),
                "@mvr/pkg::module::TYPE".to_string(),
            ])
        );
    }

    #[test]
    fn test_extract_types_for_resolver() {
        let tokens = [
            "0x1::option::is_none<u8>",
            "pkg::module::func<u8, @mvr/core::module::Type, test.sui::module::Type>>",
            "pkg::module::func<u8, @mvr/core::module::Type<u8, test.sui::module::Type>, test.sui::module::Type1>>",
            "<u8, @mvr/core::module::Type, test.sui::module::Type>>",
            "<@mvr/core::module::Type, test.sui::module::Type>>",
            "<@mvr/core::module::Type>",
        ];

        assert_eq!(extract_types_for_resolver(tokens[0]), BTreeSet::new());
        assert_eq!(
            extract_types_for_resolver(tokens[1]),
            BTreeSet::from([
                "@mvr/core::module::Type".to_string(),
                "test.sui::module::Type".to_string()
            ])
        );
        assert_eq!(
            extract_types_for_resolver(tokens[2]),
            BTreeSet::from([
                "@mvr/core::module::Type".to_string(),
                "test.sui::module::Type".to_string(),
                "test.sui::module::Type1".to_string()
            ])
        );
        assert_eq!(
            extract_types_for_resolver(tokens[3]),
            BTreeSet::from([
                "@mvr/core::module::Type".to_string(),
                "test.sui::module::Type".to_string()
            ])
        );
        assert_eq!(
            extract_types_for_resolver(tokens[4]),
            BTreeSet::from([
                "@mvr/core::module::Type".to_string(),
                "test.sui::module::Type".to_string()
            ])
        );
        assert_eq!(
            extract_types_for_resolver(tokens[5]),
            BTreeSet::from(["@mvr/core::module::Type".to_string(),])
        );
    }
}

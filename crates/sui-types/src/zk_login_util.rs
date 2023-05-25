// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::error::SuiError;
use once_cell::sync::Lazy;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt, hash::Hash};

/// A whitelist of client_ids (i.e. the value of "aud" in cliams) for each provider
pub static DEFAULT_WHITELIST: Lazy<HashMap<&str, Vec<&str>>> = Lazy::new(|| {
    let mut map = HashMap::new();
    map.insert(
        OAuthProvider::Google.get_config().0,
        vec!["575519204237-msop9ep45u2uo98hapqmngv8d84qdc8k.apps.googleusercontent.com"],
    );
    map.insert(
        OAuthProvider::Twitch.get_config().0,
        vec!["d31icql6l8xzpa7ef31ztxyss46ock"],
    );
    map
});

/// A default Google JWK raw response bytes from https://www.googleapis.com/oauth2/v2/certs
/// retrieved on 05/23/2023.
pub static DEFAULT_GOOGLE_JWK_BYTES: Lazy<Vec<u8>> = Lazy::new(|| {
    r#"{
        "keys": [
          {
            "e": "AQAB",
            "kty": "RSA",
            "kid": "822838c1c8bf9edcf1f5050662e54bcb1adb5b5f",
            "alg": "RS256",
            "n": "vwoDsDX87o_8xf6IOtIK92rkKfBLlcYhSbtNP5CgTTEmPVy5g-_1Jv4iItLc4jq3rGgDM6kvniczOUrzBVxTftW6womYaDq2_AQathzLUrSPTs9RsxPUWUUBOeFbBtE-KaAtP97nYkqFD0em2EiRhnLYa3SyClCtWCUx60Aw_0NkiGZFuYXG7jkcYQ_8TZMZdBUC08_rtHpsOfzUetA3DvJ8lkfRSwbCf8GkT5ksFzCyXrYDmWJEGVNTPNYZVuVlfHuT6-abeTcSuPvUYYOL0qWbfq8B-imQ7mF4afBAQkWiKyRSM4iE2CC4MOHOjkKFIDeX5ahpeTSXdVGpYTnPiw==",
            "use": "sig"
          },
          {
            "use": "sig",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2d9a5ef5b12623c91671a7093cb323333cd07d09",
            "n": "0NDRXWtH6_HnmuSuTAisgYVZ3Z67PQjHbRFz4XNYuD95BKx0wQr0GWOi_UCGLfI0col3i6J3_AF-b1YrTFTMEr_bL8CYDdK2CYLcGUzc5bLRDAySsqnKdlhWkneqfFdr3J66mHu11KUaIIRWiLsCkR9QFF-8o2PtZzv3F-3Uh7L4q7i_Evs1s7SJlO0OAnI4ew4rP2HbRaO0Q2zK0DL_d1eoAC72apQuEzz-2aXfQ-QYSTlVK74McBhP1MRtgD6zGF2lwg4uhgb55fDDQQh0VHWQSxwbvAL0Oox69zzpkFgpjJAJUqaxegzETU1jf3iKs1vyFIB0C4N-Jr__zwLQZw==",
            "kty": "RSA"
          }
        ]
      }"#.as_bytes().to_vec()
});

/// Supported OAuth providers. Must contain "openid" in "scopes_supported"
/// and "public" for "subject_types_supported" instead of "pairwise".
#[derive(Clone)]
pub enum OAuthProvider {
    Google, // https://accounts.google.com/.well-known/openid-configuration
    Twitch, // https://id.twitch.tv/oauth2/.well-known/openid-configuration
}

impl OAuthProvider {
    /// Returns a tuple of iss string and JWK endpoint string for the given provider.
    pub fn get_config(&self) -> (&str, &str) {
        match self {
            OAuthProvider::Google => (
                "https://accounts.google.com",
                "https://www.googleapis.com/oauth2/v2/certs",
            ),
            OAuthProvider::Twitch => (
                "https://id.twitch.tv/oauth2",
                "https://id.twitch.tv/oauth2/keys",
            ),
        }
    }

    pub fn from_iss(iss: &str) -> Result<Self, SuiError> {
        match iss {
            "https://accounts.google.com" => Ok(Self::Google),
            "https://id.twitch.tv/oauth2" => Ok(Self::Twitch),
            _ => Err(SuiError::UnsupportedFeatureError {
                error: "Provider not supported".to_string(),
            }),
        }
    }
}

/// The claims in the body signed by OAuth provider that must
/// be locally unique to the provider and cannot be reassigned.
pub enum SupportedKeyClaim {
    Sub,
    Email,
}

impl fmt::Display for SupportedKeyClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SupportedKeyClaim::Email => write!(f, "email"),
            SupportedKeyClaim::Sub => write!(f, "sub"),
        }
    }
}

pub fn get_supported_claims() -> Vec<String> {
    let supported_claims: Vec<SupportedKeyClaim> =
        vec![SupportedKeyClaim::Sub, SupportedKeyClaim::Email];

    supported_claims
        .iter()
        .map(|claim| claim.to_string())
        .collect()
}

/// Parameters for generating an address.
#[derive(Serialize, Deserialize)]
pub struct AddressParams {
    iss: String,
    key_claim_name: String,
}

impl AddressParams {
    pub fn new(iss: String, key_claim_name: String) -> Self {
        Self {
            iss,
            key_claim_name,
        }
    }
}

/// Struct that contains all the OAuth provider information. A list of them can
/// be retrieved from the JWK endpoint (e.g. https://www.googleapis.com/oauth2/v3/certs)
/// and published on the bulletin along with a trusted party's signature.
#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct OAuthProviderContent {
    kty: String,
    kid: String,
    pub e: String,
    pub n: String,
    alg: String,
}

#[derive(Debug, Clone, PartialEq, Eq, JsonSchema, Hash, Serialize, Deserialize)]
pub struct OAuthProviderContentReader {
    e: String,
    n: String,
    #[serde(rename = "use")]
    my_use: String,
    kid: String,
    kty: String,
    alg: String,
}

impl OAuthProviderContent {
    pub fn from_reader(reader: OAuthProviderContentReader) -> Self {
        Self {
            kty: reader.kty,
            kid: reader.kid,
            e: trim(reader.e),
            n: trim(reader.n),
            alg: reader.alg,
        }
    }
}

/// Trim trailing '=' so that it is considered a valid base64 url encoding string by base64ct library.
fn trim(str: String) -> String {
    str.trim_end_matches(|c: char| c == '=').to_owned()
}

/// Parse the bytes as JSON and find the keys that has the expected kid.
/// Return the OAuthProviderContentReader if valid.
pub fn find_jwk_by_kid(kid: &str, json_bytes: &[u8]) -> Result<OAuthProviderContent, SuiError> {
    let json_str = String::from_utf8_lossy(json_bytes);
    let parsed_list: Result<serde_json::Value, serde_json::Error> = serde_json::from_str(&json_str);
    if let Ok(parsed_list) = parsed_list {
        if let Some(keys) = parsed_list["keys"].as_array() {
            for k in keys {
                let parsed: OAuthProviderContentReader =
                    serde_json::from_value(k.clone()).map_err(|_| SuiError::JWKRetrievalError)?;
                if parsed.kid == kid
                    && parsed.alg == "RS256"
                    && parsed.my_use == "sig"
                    && parsed.kty == "RSA"
                {
                    return Ok(OAuthProviderContent::from_reader(parsed));
                }
            }
        }
    }
    Err(SuiError::JWKRetrievalError)
}

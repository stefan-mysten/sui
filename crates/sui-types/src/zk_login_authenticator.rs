// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    base_types::SuiAddress,
    crypto::{Signature, SignatureScheme, SuiSignature},
    error::SuiError,
    signature::{AuthenticatorTrait, AuxVerifyData},
    zk_login_util::{find_jwk_by_kid, get_supported_claims, AddressParams, DEFAULT_WHITELIST},
};
use fastcrypto::rsa::Base64UrlUnpadded;
use fastcrypto::rsa::Encoding as OtherEncoding;
use fastcrypto::rsa::RSAPublicKey;
use fastcrypto::rsa::RSASignature;
use fastcrypto_zkp::bn254::zk_login::{
    verify_groth16_with_fixed_vk, AuxInputs, ProofPoints, PublicInputs,
};
use once_cell::sync::OnceCell;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use shared_crypto::intent::IntentMessage;
use std::hash::Hash;
use std::hash::Hasher;

#[cfg(test)]
#[cfg(feature = "test-utils")]
#[path = "unit_tests/zk_login_authenticator_test.rs"]
mod zk_login_authenticator_test;

/// An zk login authenticator with all the necessary fields.
#[derive(Debug, Clone, JsonSchema, Serialize, Deserialize)]
pub struct ZkLoginAuthenticator {
    proof_points: ProofPoints,
    public_inputs: PublicInputs,
    aux_inputs: AuxInputs,
    user_signature: Signature,
    #[serde(skip)]
    pub bytes: OnceCell<Vec<u8>>,
}

impl ZkLoginAuthenticator {
    /// Create a new [struct ZkLoginAuthenticator] with necessary fields.
    pub fn new(
        proof_points: ProofPoints,
        public_inputs: PublicInputs,
        aux_inputs: AuxInputs,
        user_signature: Signature,
    ) -> Self {
        Self {
            proof_points,
            public_inputs,
            aux_inputs,
            user_signature,
            bytes: OnceCell::new(),
        }
    }

    pub fn get_address_seed(&self) -> &str {
        self.aux_inputs.get_address_seed()
    }

    pub fn get_address_params(&self) -> AddressParams {
        AddressParams::new(
            self.aux_inputs.get_iss().to_string(),
            self.aux_inputs.get_claim_name().to_string(),
        )
    }
}

/// Necessary trait for [struct SenderSignedData].
impl PartialEq for ZkLoginAuthenticator {
    fn eq(&self, other: &Self) -> bool {
        self.proof_points == other.proof_points
            && self.aux_inputs == other.aux_inputs
            && self.user_signature == other.user_signature
            && self.public_inputs == other.public_inputs
    }
}

/// Necessary trait for [struct SenderSignedData].
impl Eq for ZkLoginAuthenticator {}

/// Necessary trait for [struct SenderSignedData].
impl Hash for ZkLoginAuthenticator {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl AuthenticatorTrait for ZkLoginAuthenticator {
    /// Verify an intent message of a transaction with an zk login authenticator.
    fn verify_secure_generic<T>(
        &self,
        intent_msg: &IntentMessage<T>,
        author: SuiAddress,
        aux_verify_data: AuxVerifyData,
    ) -> Result<(), SuiError>
    where
        T: Serialize,
    {
        // Verify the author of the transaction is indeed computed from address seed,
        // iss and key claim name.
        if author != self.into() {
            return Err(SuiError::InvalidAddress);
        }

        let aux_inputs = &self.aux_inputs;

        // Verify the max epoch in aux inputs is <= the current epoch of authority.
        if aux_inputs.get_max_epoch() <= aux_verify_data.epoch.unwrap_or(0) {
            return Err(SuiError::InvalidSignature {
                error: "Invalid max epoch".to_string(),
            });
        }

        if !get_supported_claims().contains(&aux_inputs.get_claim_name().to_owned()) {
            return Err(SuiError::InvalidSignature {
                error: "Unsupported claim".to_string(),
            });
        }
        // println!("aux_inputs: {:?}", aux_inputs);
        // println!("cal hash== {:?}", &aux_inputs.calculate_all_inputs_hash());
        // println!("public== {:?}", self.public_inputs.get_all_inputs_hash());

        // Calculates the hash of all inputs equals to the one in public inputs.
        if aux_inputs.calculate_all_inputs_hash() != self.public_inputs.get_all_inputs_hash() {
            return Err(SuiError::InvalidSignature {
                error: "Invalid all inputs hash".to_string(),
            });
        }

        // Parse JWT signature from aux inputs.
        let sig = RSASignature::from_bytes(aux_inputs.get_jwt_signature()).map_err(|_| {
            SuiError::InvalidSignature {
                error: "Invalid JWT signature".to_string(),
            }
        })?;
        // println!("parsed jwt sig");

        // Parse the JWK content for the given provider from the bytes.
        let selected = find_jwk_by_kid(
            aux_inputs.get_kid(),
            &aux_verify_data.google_jwk_as_bytes.unwrap_or_default(),
        )?;
        // println!("selected {:?}", selected);

        // Verify the JWT signature against one of OAuth provider public keys in the bulletin.
        // Since more than one JWKs are available in the bulletin, iterate and find the one with
        // matching kid, iss and verify the signature against it.
        if !DEFAULT_WHITELIST
            .get(aux_inputs.get_iss())
            .unwrap()
            .contains(&aux_inputs.get_client_id())
        {
            return Err(SuiError::InvalidSignature {
                error: "Client id not in whitelist".to_string(),
            });
        }

        let pk = RSAPublicKey::from_raw_components(
            &Base64UrlUnpadded::decode_vec(&selected.n).map_err(|_| {
                SuiError::InvalidSignature {
                    error: "Invalid OAuth provider pubkey n".to_string(),
                }
            })?,
            &Base64UrlUnpadded::decode_vec(&selected.e).map_err(|_| {
                SuiError::InvalidSignature {
                    error: "Invalid OAuth provider pubkey e".to_string(),
                }
            })?,
        )
        .map_err(|_| SuiError::InvalidSignature {
            error: "Invalid RSA raw components".to_string(),
        })?;
        // println!(
        //     "&self.aux_inputs.get_jwt_hash()=={:?}",
        //     &self.aux_inputs.get_jwt_hash()
        // );
        // println!("&sig=={:?}", &sig.0);
        // println!("&pk=={:?}", &pk.0);

        pk.verify_prehash(&self.aux_inputs.get_jwt_hash(), &sig)
            .map_err(|_| SuiError::InvalidSignature {
                error: "JWT signature verify failed".to_string(),
            })?;

        // Ensure the ephemeral public key in the aux inputs matches the one in the
        // user signature.
        if self.aux_inputs.get_eph_pub_key() != self.user_signature.public_key_bytes() {
            return Err(SuiError::InvalidSignature {
                error: "Invalid ephemeral public_key".to_string(),
            });
        }
        // println!("verify get_eph_pub_key ok");

        // Verify the user signature over the intent message of the transaction data.
        if self
            .user_signature
            .verify_secure(intent_msg, author)
            .is_err()
        {
            return Err(SuiError::InvalidSignature {
                error: "User signature verify failed".to_string(),
            });
        }
        // println!("verify user sig ok");

        // Finally, verify the Groth16 proof against public inputs and proof points.
        // Verifying key is pinned in fastcrypto.
        match verify_groth16_with_fixed_vk(
            self.public_inputs.get_serialized_hash(),
            self.proof_points.get_bytes(),
        ) {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => Err(SuiError::InvalidSignature {
                error: "Groth16 proof verify failed".to_string(),
            }),
        }
    }
}

impl AsRef<[u8]> for ZkLoginAuthenticator {
    fn as_ref(&self) -> &[u8] {
        self.bytes
            .get_or_try_init::<_, eyre::Report>(|| {
                let as_bytes = bcs::to_bytes(self).expect("BCS serialization should not fail");
                let mut bytes = Vec::with_capacity(1 + as_bytes.len());
                bytes.push(SignatureScheme::ZkLoginAuthenticator.flag());
                bytes.extend_from_slice(as_bytes.as_slice());
                Ok(bytes)
            })
            .expect("OnceCell invariant violated")
    }
}

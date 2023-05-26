// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::utils::make_transaction;
use crate::zk_login_util::DEFAULT_GOOGLE_JWK_BYTES;
use crate::{
    base_types::SuiAddress,
    crypto::{get_key_pair_from_rng, DefaultHash, SignatureScheme, SuiKeyPair},
    signature::{AuthenticatorTrait, AuxVerifyData, GenericSignature},
    zk_login_authenticator::{AddressParams, ProofPoints, PublicInputs, ZkLoginAuthenticator},
};
use fastcrypto::hash::HashFunction;
use fastcrypto_zkp::bn254::zk_login::{
    big_int_str_to_bytes, AuxInputs, OAuthProvider, SupportedKeyClaim,
};
use rand::{rngs::StdRng, SeedableRng};
use shared_crypto::intent::{Intent, IntentMessage};

#[test]
fn zklogin_authenticator_scenarios() {
    let user_key: SuiKeyPair =
        SuiKeyPair::Ed25519(get_key_pair_from_rng(&mut StdRng::from_seed([0; 32])).1);

    let public_inputs = PublicInputs::from_fp("./src/unit_tests/google/public.json");
    let proof_points = ProofPoints::from_fp("./src/unit_tests/google/zkp.json");
    let aux_inputs = AuxInputs::from_fp("./src/unit_tests/google/aux.json").unwrap();

    // Derive user address manually: Blake2b_256 hash of [zklogin_flag || address seed in bytes || bcs bytes of AddressParams])
    let mut hasher = DefaultHash::default();
    hasher.update([SignatureScheme::ZkLoginAuthenticator.flag()]);
    let address_params = AddressParams::new(
        OAuthProvider::Google.get_config().0.to_owned(),
        SupportedKeyClaim::Sub.to_string(),
    );
    hasher.update(bcs::to_bytes(&address_params).unwrap());
    hasher.update(big_int_str_to_bytes(aux_inputs.get_address_seed()));
    let user_address = SuiAddress::from_bytes(hasher.finalize().digest).unwrap();

    // Sign the user transaction with the user's ephemeral key.
    let tx = make_transaction(user_address, &user_key, Intent::sui_transaction());
    let s = match tx.inner().tx_signatures.first().unwrap() {
        GenericSignature::Signature(s) => s,
        _ => panic!("Expected a signature"),
    };

    let intent_msg = IntentMessage::new(
        Intent::sui_transaction(),
        tx.clone().into_data().transaction_data().clone(),
    );

    // Construct the authenticator with all user submitted components.
    let authenticator =
        ZkLoginAuthenticator::new(proof_points, public_inputs, aux_inputs, s.clone());

    // Construct the required info required to verify a zk login authenticator
    // in authority server (i.e. epoch and default JWK).
    let aux_verify_data =
        AuxVerifyData::new(Some(0), Some((*DEFAULT_GOOGLE_JWK_BYTES.clone()).to_vec()));

    // Verify passes.
    assert!(authenticator
        .verify_secure_generic(&intent_msg, user_address, aux_verify_data)
        .is_ok());

    // Malformed JWK in aux verify data.
    let aux_verify_data = AuxVerifyData::new(Some(9999), Some(vec![0, 0, 0]));

    // Verify fails.
    assert!(authenticator
        .verify_secure_generic(&intent_msg, user_address, aux_verify_data)
        .is_err());
}

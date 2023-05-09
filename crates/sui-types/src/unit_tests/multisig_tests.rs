// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use super::{MultiSigPublicKey, ThresholdUnit, WeightUnit};
use crate::{
    base_types::SuiAddress,
    crypto::{
        get_key_pair, get_key_pair_from_rng, Ed25519SuiSignature, PublicKey, Signature, SuiKeyPair,
        SuiSignatureInner,
    },
    multisig::{MultiSig, MAX_SIGNER_IN_MULTISIG},
    signature::{AuthenticatorTrait, GenericSignature},
};
use fastcrypto::{
    ed25519::{Ed25519KeyPair, Ed25519PrivateKey, Ed25519PublicKey},
    encoding::{Base64, Encoding},
    secp256k1::{Secp256k1KeyPair, Secp256k1PrivateKey},
    traits::ToFromBytes,
};
use once_cell::sync::OnceCell;
use rand::{rngs::StdRng, SeedableRng};
use roaring::RoaringBitmap;
use shared_crypto::intent::{Intent, IntentMessage, PersonalMessage};

pub fn keys() -> Vec<SuiKeyPair> {
    let mut seed = StdRng::from_seed([0; 32]);
    let kp1: SuiKeyPair = SuiKeyPair::Ed25519(get_key_pair_from_rng(&mut seed).1);
    let kp2: SuiKeyPair = SuiKeyPair::Secp256k1(get_key_pair_from_rng(&mut seed).1);
    let kp3: SuiKeyPair = SuiKeyPair::Secp256r1(get_key_pair_from_rng(&mut seed).1);
    vec![kp1, kp2, kp3]
}

#[test]
fn multisig_scenarios() {
    let keys = keys();
    let pk1 = keys[0].public();
    let pk2 = keys[1].public();
    let pk3 = keys[2].public();

    let multisig_pk = MultiSigPublicKey::new(
        vec![pk1.clone(), pk2.clone(), pk3.clone()],
        vec![1, 1, 1],
        2,
    )
    .unwrap();
    let addr = SuiAddress::from(&multisig_pk);
    let msg = IntentMessage::new(
        Intent::sui_transaction(),
        PersonalMessage {
            message: "Hello".as_bytes().to_vec(),
        },
    );
    let sig1 = Signature::new_secure(&msg, &keys[0]);
    let sig2 = Signature::new_secure(&msg, &keys[1]);
    let sig3 = Signature::new_secure(&msg, &keys[2]);

    // Any 2 of 3 signatures verifies ok.
    let multi_sig1 =
        MultiSig::combine(vec![sig1.clone(), sig2.clone()], multisig_pk.clone()).unwrap();
    assert!(multi_sig1.verify_secure_generic(&msg, addr).is_ok());

    let multi_sig2 =
        MultiSig::combine(vec![sig1.clone(), sig3.clone()], multisig_pk.clone()).unwrap();
    assert!(multi_sig2.verify_secure_generic(&msg, addr).is_ok());

    let multi_sig3 =
        MultiSig::combine(vec![sig2.clone(), sig3.clone()], multisig_pk.clone()).unwrap();
    assert!(multi_sig3.verify_secure_generic(&msg, addr).is_ok());

    // 1 of 3 signature verify fails.
    let multi_sig4 = MultiSig::combine(vec![sig2.clone()], multisig_pk).unwrap();
    assert!(multi_sig4.verify_secure_generic(&msg, addr).is_err());

    // Incorrect address fails.
    let kp4: SuiKeyPair = SuiKeyPair::Secp256r1(get_key_pair().1);
    let pk4 = kp4.public();
    let multisig_pk_1 = MultiSigPublicKey::new(
        vec![pk1.clone(), pk2.clone(), pk3.clone(), pk4],
        vec![1, 1, 1, 1],
        1,
    )
    .unwrap();
    let multisig5 = MultiSig::combine(vec![sig1.clone(), sig2.clone()], multisig_pk_1).unwrap();
    assert!(multisig5.verify_secure_generic(&msg, addr).is_err());

    // Create a MultiSig pubkey of pk1 (weight = 1), pk2 (weight = 2), pk3 (weight = 3), threshold 3.
    let multisig_pk_2 = MultiSigPublicKey::new(
        vec![pk1.clone(), pk2.clone(), pk3.clone()],
        vec![1, 2, 3],
        3,
    )
    .unwrap();
    let addr_2 = SuiAddress::from(&multisig_pk_2);

    // sig1 and sig2 (3 of 6) verifies ok.
    let multi_sig_6 =
        MultiSig::combine(vec![sig1.clone(), sig2.clone()], multisig_pk_2.clone()).unwrap();
    assert!(multi_sig_6.verify_secure_generic(&msg, addr_2).is_ok());

    // providing the same sig twice fails.
    assert!(MultiSig::combine(vec![sig1.clone(), sig1.clone()], multisig_pk_2.clone()).is_err());

    // Change position for sig2 and sig1 fails.
    let multi_sig_7 =
        MultiSig::combine(vec![sig2.clone(), sig1.clone()], multisig_pk_2.clone()).unwrap();
    assert!(multi_sig_7.verify_secure_generic(&msg, addr_2).is_err());

    // sig3 itself (3 of 6) verifies ok.
    let multi_sig_8 = MultiSig::combine(vec![sig3.clone()], multisig_pk_2.clone()).unwrap();
    assert!(multi_sig_8.verify_secure_generic(&msg, addr_2).is_ok());

    // sig2 itself (2 of 6) verifies fail.
    let multi_sig_9 = MultiSig::combine(vec![sig2.clone()], multisig_pk_2.clone()).unwrap();
    assert!(multi_sig_9.verify_secure_generic(&msg, addr_2).is_err());

    // A bad sig in the multisig fails, even though sig2 and sig3 verifies and weights meets threshold.
    let bad_sig = Signature::new_secure(
        &IntentMessage::new(
            Intent::sui_transaction(),
            PersonalMessage {
                message: "Bad message".as_bytes().to_vec(),
            },
        ),
        &keys[0],
    );
    let multi_sig_9 = MultiSig::combine(vec![bad_sig, sig2, sig3], multisig_pk_2).unwrap();
    assert!(multi_sig_9.verify_secure_generic(&msg, addr_2).is_err());

    // Wrong bitmap verifies fail.
    let mut bitmap = RoaringBitmap::new();
    bitmap.insert(1);
    let multi_sig_10 = MultiSig {
        sigs: vec![sig1.to_compressed().unwrap()], // sig1 has index 0
        bitmap,
        multisig_pk: MultiSigPublicKey::new(vec![pk1, pk2, pk3], vec![1, 2, 3], 3).unwrap(),
        bytes: OnceCell::new(),
    };
    assert!(multi_sig_10.verify_secure_generic(&msg, addr_2).is_err());
}

#[test]
fn test_combine_sigs() {
    let kp1: SuiKeyPair = SuiKeyPair::Ed25519(get_key_pair().1);
    let kp2: SuiKeyPair = SuiKeyPair::Secp256k1(get_key_pair().1);
    let kp3: SuiKeyPair = SuiKeyPair::Secp256r1(get_key_pair().1);

    let pk1 = kp1.public();
    let pk2 = kp2.public();

    let multisig_pk = MultiSigPublicKey::new(vec![pk1, pk2], vec![1, 1], 2).unwrap();

    let msg = IntentMessage::new(
        Intent::sui_transaction(),
        PersonalMessage {
            message: "Hello".as_bytes().to_vec(),
        },
    );
    let sig1 = Signature::new_secure(&msg, &kp1);
    let sig2 = Signature::new_secure(&msg, &kp2);
    let sig3 = Signature::new_secure(&msg, &kp3);

    // MultiSigPublicKey contains only 2 public key but 3 signatures are passed, fails to combine.
    assert!(MultiSig::combine(vec![sig1, sig2, sig3], multisig_pk.clone()).is_err());

    // Cannot create malformed MultiSig.
    assert!(MultiSig::combine(vec![], multisig_pk).is_err());
}
#[test]
fn test_serde_roundtrip() {
    let msg = IntentMessage::new(
        Intent::sui_transaction(),
        PersonalMessage {
            message: "Hello".as_bytes().to_vec(),
        },
    );

    for kp in keys() {
        let pk = kp.public();
        let multisig_pk = MultiSigPublicKey::new(vec![pk], vec![1], 1).unwrap();
        let sig = Signature::new_secure(&msg, &kp);
        let multisig = MultiSig::combine(vec![sig], multisig_pk).unwrap();
        let plain_bytes = bcs::to_bytes(&multisig).unwrap();

        let generic_sig = GenericSignature::MultiSig(multisig);
        let generic_sig_bytes = generic_sig.as_bytes();
        let generic_sig_roundtrip = GenericSignature::from_bytes(generic_sig_bytes).unwrap();
        assert_eq!(generic_sig, generic_sig_roundtrip);

        // A MultiSig flag 0x03 is appended before the bcs serialized bytes.
        assert_eq!(plain_bytes.len() + 1, generic_sig_bytes.len());
        assert_eq!(generic_sig_bytes.first().unwrap(), &0x03);
    }

    // Malformed multisig cannot be deserialized
    let multisig_pk = MultiSigPublicKey {
        pk_map: vec![(keys()[0].public(), 1)],
        threshold: 1,
    };
    let multisig = MultiSig {
        sigs: vec![], // No sigs
        bitmap: RoaringBitmap::new(),
        multisig_pk,
        bytes: OnceCell::new(),
    };

    let generic_sig = GenericSignature::MultiSig(multisig);
    let generic_sig_bytes = generic_sig.as_bytes();
    assert!(GenericSignature::from_bytes(generic_sig_bytes).is_err());

    // Malformed multisig_pk cannot be deserialized
    let multisig_pk_1 = MultiSigPublicKey {
        pk_map: vec![],
        threshold: 0,
    };

    let multisig_1 = MultiSig {
        sigs: vec![],
        bitmap: RoaringBitmap::new(),
        multisig_pk: multisig_pk_1,
        bytes: OnceCell::new(),
    };

    let generic_sig_1 = GenericSignature::MultiSig(multisig_1);
    let generic_sig_bytes = generic_sig_1.as_bytes();
    assert!(GenericSignature::from_bytes(generic_sig_bytes).is_err());

    // Single sig serialization unchanged.
    let sig = Ed25519SuiSignature::default();
    let single_sig = GenericSignature::Signature(sig.clone().into());
    let single_sig_bytes = single_sig.as_bytes();
    let single_sig_roundtrip = GenericSignature::from_bytes(single_sig_bytes).unwrap();
    assert_eq!(single_sig, single_sig_roundtrip);
    assert_eq!(single_sig_bytes.len(), Ed25519SuiSignature::LENGTH);
    assert_eq!(
        single_sig_bytes.first().unwrap(),
        &Ed25519SuiSignature::SCHEME.flag()
    );
    assert_eq!(sig.as_bytes().len(), single_sig_bytes.len());
}

#[test]
fn single_sig_port_works() {
    let kp: SuiKeyPair = SuiKeyPair::Ed25519(get_key_pair().1);
    let addr = SuiAddress::from(&kp.public());
    let msg = IntentMessage::new(
        Intent::sui_transaction(),
        PersonalMessage {
            message: "Hello".as_bytes().to_vec(),
        },
    );
    let sig = Signature::new_secure(&msg, &kp);
    assert!(sig.verify_secure_generic(&msg, addr).is_ok());
}

#[test]
fn test_multisig_pk_failure() {
    let keys = keys();
    let pk1 = keys[0].public();
    let pk2 = keys[1].public();
    let pk3 = keys[2].public();

    // Fails on weight 0.
    assert!(MultiSigPublicKey::new(
        vec![pk1.clone(), pk2.clone(), pk3.clone()],
        vec![0, 1, 1],
        2
    )
    .is_err());

    // Fails on threshold 0.
    assert!(MultiSigPublicKey::new(
        vec![pk1.clone(), pk2.clone(), pk3.clone()],
        vec![0, 1, 1],
        0
    )
    .is_err());

    // Fails on incorrect array length.
    assert!(
        MultiSigPublicKey::new(vec![pk1.clone(), pk2.clone(), pk3.clone()], vec![1], 2).is_err()
    );

    // Fails on empty array length.
    assert!(MultiSigPublicKey::new(vec![pk1, pk2, pk3], vec![], 2).is_err());
}

#[test]
fn test_multisig_address() {
    // Pin an hardcoded multisig address generation here. If this fails, the address
    // generation logic may have changed. If this is intended, update the hardcoded value below.
    let keys = keys();
    let pk1 = keys[0].public();
    let pk2 = keys[1].public();
    let pk3 = keys[2].public();

    let threshold: ThresholdUnit = 2;
    let w1: WeightUnit = 1;
    let w2: WeightUnit = 2;
    let w3: WeightUnit = 3;

    let multisig_pk =
        MultiSigPublicKey::new(vec![pk1, pk2, pk3], vec![w1, w2, w3], threshold).unwrap();
    let address: SuiAddress = (&multisig_pk).into();
    assert_eq!(
        SuiAddress::from_str("0xe35c69eb504de34afdbd9f307fb3ca152646c92d549fea00065d26fc422109ea")
            .unwrap(),
        address
    );
}

#[test]
fn test_max_sig() {
    let msg = IntentMessage::new(
        Intent::sui_transaction(),
        PersonalMessage {
            message: "Hello".as_bytes().to_vec(),
        },
    );
    let mut seed = StdRng::from_seed([0; 32]);
    let mut keys = Vec::new();
    let mut sigs = Vec::new();
    let mut pks = Vec::new();

    for _ in 0..10 {
        let k = SuiKeyPair::Ed25519(get_key_pair_from_rng(&mut seed).1);
        sigs.push(Signature::new_secure(&msg, &k));
        pks.push(k.public());
        keys.push(k);
    }

    // multisig_pk with larger that max number of pks fails.
    assert!(MultiSigPublicKey::new(
        vec![keys[0].public(); MAX_SIGNER_IN_MULTISIG + 1],
        vec![WeightUnit::MAX; MAX_SIGNER_IN_MULTISIG + 1],
        ThresholdUnit::MAX
    )
    .is_err());

    // multisig_pk with unreachable threshold fails.
    assert!(MultiSigPublicKey::new(
        vec![keys[0].public(); 5],
        vec![3; MAX_SIGNER_IN_MULTISIG],
        16
    )
    .is_err());

    // multisig_pk with max weights for each pk and max reachable threshold is ok.
    let high_threshold_pk = MultiSigPublicKey::new(
        pks,
        vec![WeightUnit::MAX; MAX_SIGNER_IN_MULTISIG],
        (WeightUnit::MAX as ThresholdUnit) * (MAX_SIGNER_IN_MULTISIG as ThresholdUnit),
    )
    .unwrap();
    let address: SuiAddress = (&high_threshold_pk).into();

    // But max threshold cannot be met, fails to verify.
    sigs.remove(0);
    let multisig = MultiSig::combine(sigs, high_threshold_pk).unwrap();
    assert!(multisig.verify_secure_generic(&msg, address).is_err());

    // multisig_pk with max weights for each pk with threshold is 1x max weight verifies ok.
    let low_threshold_pk = MultiSigPublicKey::new(
        vec![keys[0].public(); MAX_SIGNER_IN_MULTISIG],
        vec![WeightUnit::MAX; 10],
        WeightUnit::MAX.into(),
    )
    .unwrap();
    let address: SuiAddress = (&low_threshold_pk).into();
    let sig = Signature::new_secure(&msg, &keys[0]);
    let multisig = MultiSig::combine(vec![sig; 1], low_threshold_pk).unwrap();
    assert!(multisig.verify_secure_generic(&msg, address).is_ok());
}

#[test]
fn multisig_address_consistency_test() {
    let keys = keys();
    let pk1 = keys[0].public();
    let pk2 = keys[1].public();

    let multisig_pk =
        MultiSigPublicKey::new(vec![pk1, pk2.clone()], vec![2, 3], 4).unwrap();
    let addr = SuiAddress::from(&multisig_pk);
    assert_eq!(
        addr,
        SuiAddress::from_str("0x877aa5c525c5662060e9f01c6f8a931cdc4917ac926666ac9b61562ead3e3238")
            .unwrap()
    );
}

#[test]
fn multisig_serde_test() {
    let k1 = SuiKeyPair::Ed25519(Ed25519KeyPair::from(
        Ed25519PrivateKey::from_bytes(&[
            59, 148, 11, 85, 134, 130, 61, 253, 2, 174, 59, 70, 27, 180, 51, 107, 94, 203, 174,
            253, 102, 39, 170, 146, 46, 252, 4, 143, 236, 12, 136, 28,
        ])
        .unwrap(),
    ));
    let pk1 = k1.public();
    println!("pk1: {:?}", pk1.as_ref());

    let k2 = SuiKeyPair::Secp256k1(Secp256k1KeyPair::from(
        Secp256k1PrivateKey::from_bytes(&[
            59, 148, 11, 85, 134, 130, 61, 253, 2, 174, 59, 70, 27, 180, 51, 107, 94, 203, 174,
            253, 102, 39, 170, 146, 46, 252, 4, 143, 236, 12, 136, 28,
        ])
        .unwrap(),
    ));
    let pk2 = k2.public();
    println!("pk2: {:?}", pk2.as_ref());

    let k3 = SuiKeyPair::Ed25519(Ed25519KeyPair::from(
        Ed25519PrivateKey::from_bytes(&[0; 32]).unwrap(),
    ));
    let pk3 = k3.public();
    println!("pk3: {:?}", pk3.as_ref());

    // let pk2 = keys[1].public();
    // let kp3: SuiKeyPair = SuiKeyPair::Secp256k1(get_key_pair_from_rng(&mut StdRng::from_seed([1; 32])).1);
    // let pk3 = kp3.public();

    let multisig_pk = MultiSigPublicKey::new(
        vec![pk1.clone(), pk2.clone(), pk3.clone()],
        vec![1, 2, 3],
        3,
    )
    .unwrap();
    let addr = SuiAddress::from(&multisig_pk);
    println!("multisig_pk: {:?}", multisig_pk);
    println!(
        "multi_sig pk: {:?}",
        Base64::encode(bcs::to_bytes(&multisig_pk).unwrap())
    );

    let msg = IntentMessage::new(
        Intent::sui_transaction(),
        PersonalMessage {
            message: "Hello".as_bytes().to_vec(),
        },
    );
    println!("msg: {:?}", bcs::to_bytes(&msg).unwrap());
    let sig1 = Signature::new_secure(&msg, &k1);
    let sig2 = Signature::new_secure(&msg, &k2);

    let _p = PublicKey::Ed25519(
        (&Ed25519PublicKey::from_bytes(&[
            90, 226, 32, 180, 178, 246, 94, 151, 124, 18, 237, 230, 21, 121, 255, 81, 112, 182,
            194, 44, 0, 97, 104, 195, 123, 94, 124, 97, 175, 1, 128, 131,
        ])
        .unwrap())
            .into(),
    );

    let multi_sig =
        MultiSig::combine(vec![sig1.clone(), sig2.clone()], multisig_pk.clone()).unwrap();
    println!("multi_sig: {:?}", multi_sig);
    println!("multi_sig: {:?}", Base64::encode(multi_sig.as_bytes()));

    assert!(multi_sig.verify_secure_generic(&msg, addr).is_ok());

    assert_eq!(
        addr,
        SuiAddress::from_str("0x37b048598ca569756146f4e8ea41666c657406db154a31f11bb5c1cbaf0b98d7")
            .unwrap()
    );
}

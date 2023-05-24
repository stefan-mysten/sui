// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module crypto::ec_ops {

    //////////////////////////////
    ////// ECIES decryption //////

    // useful for fraud proofs
    // there is known pk=g^x, and enc (g^r, hkdf(pk^r) xor m
    // given pk, and r, output m

    // TODO: knowledge of DL

    // TODO: BLS signature verification

    /////////////////
    ////// IBE //////

    // useful for timed locked encryptions
    // there is known pk=g2^x, and enc g2^r, e(H(m)^r, pk) xor m, and key H(m)^x
    // compute e(H(m)^x, g2^r) c

    // TODO: groth16 proof verification

    // TODO: KZG commitment verification

}
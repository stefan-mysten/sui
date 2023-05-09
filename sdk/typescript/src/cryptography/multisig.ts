// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { toB64 } from '@mysten/bcs';
import { SIGNATURE_SCHEME_TO_FLAG, SerializedSignature, SignaturePubkeyPair, fromSerializedSignature } from './signature';
import { PublicKey } from './publickey';
import { blake2b } from '@noble/hashes/blake2b';
import { bytesToHex } from '@noble/hashes/utils';
import RoaringBitmap32 from 'roaring/RoaringBitmap32';

import { normalizeSuiAddress, SUI_ADDRESS_LENGTH } from '../types';
import { Ed25519PublicKey, Secp256k1PublicKey, builder, fromB64 } from '..';

export type PubkeyWeightPair = {
  pubKey: PublicKey;
  weight: number;
};

export type CompressedSignature = { Ed25519: number[]} | { Secp256k1: number[]} | { Secp256r1: number[]};
export type PublicKeyEnum = { Ed25519: number[]} | { Secp256k1: number[]} | { Secp256r1: number[]};

export type PkWeightPair = {
  pubKey: PublicKeyEnum,
  weight: number,
};

export type MultiSigPublicKey = {
  pk_map: PkWeightPair[],
  threshold: number,
}

export type MultiSig = {
  sigs: CompressedSignature[],
  bitmap: number[],
  multisig_pk: MultiSigPublicKey,
}
export function toMultiSigAddress(
  pks: PubkeyWeightPair[],
  threshold: Uint8Array,
  ): string {
    let maxLength = 1 + 64 * 10 + 1 * 10 + 2;
    let tmp = new Uint8Array(maxLength);
    tmp.set([SIGNATURE_SCHEME_TO_FLAG['MultiSig']]);
    tmp.set(threshold, 1);
    let i = 3;
    for (const pk of pks) {
      tmp.set(pk.pubKey.flag(), i);
      tmp.set(pk.pubKey.toBytes(), i + 1);
      tmp.set([pk.weight], i + 1 + pk.pubKey.toBytes().length);
      i += pk.pubKey.toBytes().length + 2;
    }
    return normalizeSuiAddress(
      bytesToHex(blake2b(tmp.slice(0, i), { dkLen: 32 })).slice(0, SUI_ADDRESS_LENGTH * 2),
    );
}

export function combinePartialSigs(
  pairs: SerializedSignature[],
  pks: PubkeyWeightPair[],
  threshold: Uint16Array
): SerializedSignature {
  let multisig_pk: MultiSigPublicKey = {
    pk_map: pks.map((x) => toPkWeightPair(x)),
    threshold: threshold[0],
  };

  const bitmap3 = new RoaringBitmap32();
  let compressed_sigs: CompressedSignature[] = new Array(pairs.length);
  for (let i = 0; i < pairs.length; i++) {
    let parsed = fromSerializedSignature(pairs[i]);
    let v = Array.from(parsed.signature.map((x) => Number(x)));
    if (parsed.signatureScheme == 'Ed25519') {
      compressed_sigs[i] = { Ed25519: v};
    } else if (parsed.signatureScheme == 'Secp256k1') {
      compressed_sigs[i] = { Secp256k1: v};
    } else if (parsed.signatureScheme == 'Secp256r1') {
      compressed_sigs[i] = { Secp256r1: v};
    }
    for (let j = 0; j < pks.length; j++) {
      if (parsed.pubKey.equals(pks[j].pubKey)) {
        bitmap3.add(j);
        break;
      }
    }
  }
  let multisig: MultiSig = {
    sigs: compressed_sigs,
    bitmap: Array.from(bitmap3.serialize(true).map((x) => Number(x))),
    multisig_pk: multisig_pk,
  }; 

  const bytes = builder.ser('MultiSig', multisig).toBytes();
  let tmp = new Uint8Array(bytes.length + 1);
  tmp.set([SIGNATURE_SCHEME_TO_FLAG['MultiSig']]);
  tmp.set(bytes, 1);
  return toB64(tmp);
}

export function decodeMultiSig(signature: string): SignaturePubkeyPair[] {
    const parsed = fromB64(signature);
    if (parsed.length < 1 || parsed[0] !== SIGNATURE_SCHEME_TO_FLAG['MultiSig']) {
      throw new Error('Invalid MultiSig flag');
    };
    const multisig: MultiSig = builder.de('MultiSig', parsed.slice(1));
    let res: SignaturePubkeyPair[] = new Array(multisig.sigs.length);
    for (let i = 0; i < multisig.sigs.length; i++) {
      let s: CompressedSignature = multisig.sigs[i];
      let deserialized = RoaringBitmap32.deserialize(new Uint8Array(multisig.bitmap), true).toArray();
      let pk_index = deserialized.at(i);
      let pk_bytes = Object.values(multisig.multisig_pk.pk_map[pk_index as number].pubKey)[0];
      const PublicKey = ("Ed25519" in s) ? Ed25519PublicKey : Secp256k1PublicKey;
      const scheme = ("Ed25519" in s) ? "Ed25519" : "Secp256k1";

      res[i] = {
          signatureScheme: scheme,
          signature: Uint8Array.from(Object.values(s)[0]),
          pubKey: new PublicKey(pk_bytes),
        };
    }
    return res;
  }

  export function toPkWeightPair(pair: PubkeyWeightPair): PkWeightPair {
    let pk: PublicKeyEnum = {
      Ed25519: Array.from(pair.pubKey.toBytes().map((x) => Number(x))),
    };
    if (pair.pubKey.flag()[0] === SIGNATURE_SCHEME_TO_FLAG['Secp256k1']) {
      pk = {
        Secp256k1: Array.from(pair.pubKey.toBytes().map((x) => Number(x))),
      };
    }

    return {
      pubKey: pk,
      weight: pair.weight,
    };
  }
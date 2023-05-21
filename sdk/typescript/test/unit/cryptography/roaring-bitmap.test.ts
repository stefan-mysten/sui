// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest';
import { RoaringBitmap32 } from '../../../src/cryptography/roaring-bitmap';

describe('roaring bitmap', () => {
    it('equals to rust impl', () => {
        const bitmap = new RoaringBitmap32();
        bitmap.add(0);
        bitmap.add(1);
        console.log(bitmap);
        const serialized = bitmap.serialize();
        const expectedSerialized = new Uint8Array([
          58, 48, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 16, 0, 0, 0, 0, 0, 1, 0,
        ]);
        
        expect(serialized).toEqual(expectedSerialized);
        });
  });





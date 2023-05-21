// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

export class RoaringBitmap32 {
    private blocks: Map<number, number>;

    constructor() {
      this.blocks = new Map<number, number>();
    }
  
    add(value: number): void {
      const blockIndex = Math.floor(value / 32);
      const bitIndex = value % 32;
      if (!this.blocks.has(blockIndex)) {
        this.blocks.set(blockIndex, 0);
      }
      const block = this.blocks.get(blockIndex)!;
      this.blocks.set(blockIndex, block | (1 << bitIndex));
    }
  
    contains(value: number): boolean {
      const blockIndex = Math.floor(value / 32);
      const bitIndex = value % 32;
      if (!this.blocks.has(blockIndex)) {
        return false;
      }
      const block = this.blocks.get(blockIndex)!;
      return (block & (1 << bitIndex)) !== 0;
    }
  
    serialize(): Uint8Array {
        const blockIndices = Array.from(this.blocks.keys()).sort((a, b) => a - b);
        const byteArray: number[] = [];
    
        for (const blockIndex of blockIndices) {
          const block = this.blocks.get(blockIndex)!;
          byteArray.push((blockIndex >> 24) & 0xff);
          byteArray.push((blockIndex >> 16) & 0xff);
          byteArray.push((blockIndex >> 8) & 0xff);
          byteArray.push(blockIndex & 0xff);
          byteArray.push((block >> 24) & 0xff);
          byteArray.push((block >> 16) & 0xff);
          byteArray.push((block >> 8) & 0xff);
          byteArray.push(block & 0xff);
        }
    
        return new Uint8Array(byteArray);
      }
    static deserialize(byteArray: Uint8Array): RoaringBitmap32 {
      const bitmap = new RoaringBitmap32();
      let i = 0;
      while (i < byteArray.length) {
        const blockIndex =
          (byteArray[i] << 24) |
          (byteArray[i + 1] << 16) |
          (byteArray[i + 2] << 8) |
          byteArray[i + 3];
        const block =
          (byteArray[i + 4] << 24) |
          (byteArray[i + 5] << 16) |
          (byteArray[i + 6] << 8) |
          byteArray[i + 7];
        bitmap.blocks.set(blockIndex, block);
        i += 8;
      }
      return bitmap;
    }
  }
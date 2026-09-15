/**
 * LombokFuzzer — Hash Utilities
 *
 * Zero-dependency hash functions for corpus deduplication and coverage bitmaps.
 * FNV-1a for simplicity, xxHash64 for performance.
 *
 * @license Apache-2.0
 */
/** FNV-1a 64-bit hash. Simple, good distribution, zero-dependency. */
export declare function fnv1a64(data: Uint8Array): bigint;
/** xxHash64 — faster on large inputs. */
export declare function xxhash64(data: Uint8Array, seed?: bigint): bigint;
/** Hash a stack trace for crash deduplication. Uses top N frames. */
export declare function stackHash(frames: Array<{
    functionName: string;
    file?: string;
    line?: number;
}>, maxFrames?: number): string;
/** Hash a (prev_pc, cur_pc) pair to a bitmap index. */
export declare function edgeHash(prevPc: number, curPc: number, bitmapSize: number): number;
/** Count number of non-zero bytes in a bitmap (hit edges). */
export declare function countNonZero(bitmap: Uint8Array): number;
/** Classify hit count into AFL-style bucket. */
export declare function classifyCount(count: number): number;
//# sourceMappingURL=hash.d.ts.map
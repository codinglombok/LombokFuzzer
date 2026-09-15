/**
 * LombokFuzzer — Hash Utilities
 *
 * Zero-dependency hash functions for corpus deduplication and coverage bitmaps.
 * FNV-1a for simplicity, xxHash64 for performance.
 *
 * @license Apache-2.0
 */
const MASK64 = (1n << 64n) - 1n;
// ─── FNV-1a 64-bit ─────────────────────────────────────────────────────────
const FNV_OFFSET_64 = 0xcbf29ce484222325n;
const FNV_PRIME_64 = 0x100000001b3n;
/** FNV-1a 64-bit hash. Simple, good distribution, zero-dependency. */
export function fnv1a64(data) {
    let hash = FNV_OFFSET_64;
    for (let i = 0; i < data.length; i++) {
        hash ^= BigInt(data[i]);
        hash = (hash * FNV_PRIME_64) & MASK64;
    }
    return hash;
}
// ─── xxHash64 ───────────────────────────────────────────────────────────────
const XXHASH_PRIME1 = 0x9e3779b185ebca87n;
const XXHASH_PRIME2 = 0xc2b2ae3d27d4eb4fn;
const XXHASH_PRIME3 = 0x165667b19e3779f9n;
const XXHASH_PRIME4 = 0x85ebca77c2b2ae63n;
const XXHASH_PRIME5 = 0x27d4eb2f165667c5n;
/** xxHash64 — faster on large inputs. */
export function xxhash64(data, seed = 0n) {
    const len = data.length;
    let h;
    if (len >= 32) {
        let v1 = (seed + XXHASH_PRIME1 + XXHASH_PRIME2) & MASK64;
        let v2 = (seed + XXHASH_PRIME2) & MASK64;
        let v3 = seed;
        let v4 = (seed - XXHASH_PRIME1) & MASK64;
        let i = 0;
        const limit = len - 32;
        while (i <= limit) {
            v1 = xxRound(v1, readU64LE(data, i));
            i += 8;
            v2 = xxRound(v2, readU64LE(data, i));
            i += 8;
            v3 = xxRound(v3, readU64LE(data, i));
            i += 8;
            v4 = xxRound(v4, readU64LE(data, i));
            i += 8;
        }
        h = (rotl64(v1, 1n) + rotl64(v2, 7n) + rotl64(v3, 12n) + rotl64(v4, 18n)) & MASK64;
        h = xxMergeRound(h, v1);
        h = xxMergeRound(h, v2);
        h = xxMergeRound(h, v3);
        h = xxMergeRound(h, v4);
    }
    else {
        h = (seed + XXHASH_PRIME5) & MASK64;
    }
    h = (h + BigInt(len)) & MASK64;
    // Process remaining bytes
    let pos = len & ~31; // start of remaining bytes
    while (pos + 8 <= len) {
        const k1 = xxRound(0n, readU64LE(data, pos));
        h = (((h ^ k1) & MASK64) * XXHASH_PRIME1 + XXHASH_PRIME4) & MASK64;
        h = (rotl64(h, 27n) * XXHASH_PRIME1 + XXHASH_PRIME4) & MASK64;
        pos += 8;
    }
    while (pos + 4 <= len) {
        const k = BigInt(readU32LE(data, pos));
        h = ((h ^ ((k * XXHASH_PRIME1) & MASK64)) & MASK64);
        h = (rotl64(h, 23n) * XXHASH_PRIME2 + XXHASH_PRIME3) & MASK64;
        pos += 4;
    }
    while (pos < len) {
        h = ((h ^ (BigInt(data[pos]) * XXHASH_PRIME5)) & MASK64);
        h = (rotl64(h, 11n) * XXHASH_PRIME1) & MASK64;
        pos++;
    }
    return xxAvalanche(h);
}
// ─── Stack Hash (for crash dedup) ───────────────────────────────────────────
/** Hash a stack trace for crash deduplication. Uses top N frames. */
export function stackHash(frames, maxFrames = 5) {
    const normalized = frames
        .slice(0, maxFrames)
        .map(f => `${f.functionName}@${f.file ?? '?'}:${f.line ?? 0}`)
        .join('|');
    const bytes = new TextEncoder().encode(normalized);
    const hash = fnv1a64(bytes);
    return hash.toString(16).padStart(16, '0');
}
// ─── Bitmap operations ──────────────────────────────────────────────────────
/** Hash a (prev_pc, cur_pc) pair to a bitmap index. */
export function edgeHash(prevPc, curPc, bitmapSize) {
    return ((prevPc >> 1) ^ curPc) & (bitmapSize - 1);
}
/** Count number of non-zero bytes in a bitmap (hit edges). */
export function countNonZero(bitmap) {
    let count = 0;
    for (let i = 0; i < bitmap.length; i++) {
        if (bitmap[i] !== 0)
            count++;
    }
    return count;
}
/** Classify hit count into AFL-style bucket. */
export function classifyCount(count) {
    if (count === 0)
        return 0;
    if (count === 1)
        return 1;
    if (count === 2)
        return 2;
    if (count === 3)
        return 4;
    if (count <= 7)
        return 8;
    if (count <= 15)
        return 16;
    if (count <= 31)
        return 32;
    if (count <= 127)
        return 64;
    return 128;
}
// ─── Internal ───────────────────────────────────────────────────────────────
function rotl64(x, k) {
    return ((x << k) | (x >> (64n - k))) & MASK64;
}
function xxRound(acc, input) {
    acc = (acc + input * XXHASH_PRIME2) & MASK64;
    acc = rotl64(acc, 31n);
    return (acc * XXHASH_PRIME1) & MASK64;
}
function xxMergeRound(acc, val) {
    val = xxRound(0n, val);
    acc = ((acc ^ val) * XXHASH_PRIME1 + XXHASH_PRIME4) & MASK64;
    return acc;
}
function xxAvalanche(h) {
    h = ((h ^ (h >> 33n)) * XXHASH_PRIME2) & MASK64;
    h = ((h ^ (h >> 29n)) * XXHASH_PRIME3) & MASK64;
    return (h ^ (h >> 32n)) & MASK64;
}
function readU64LE(buf, offset) {
    let val = 0n;
    for (let i = 7; i >= 0; i--) {
        val = (val << 8n) | BigInt(buf[offset + i]);
    }
    return val;
}
function readU32LE(buf, offset) {
    return ((buf[offset]) |
        (buf[offset + 1] << 8) |
        (buf[offset + 2] << 16) |
        (buf[offset + 3] << 24)) >>> 0;
}
//# sourceMappingURL=hash.js.map
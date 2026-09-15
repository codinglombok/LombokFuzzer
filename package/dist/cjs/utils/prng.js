"use strict";
/**
 * LombokFuzzer — PRNG (xoshiro256++)
 *
 * Deterministic, high-quality PRNG with 256-bit state. Passes BigCrush.
 * Seeded for reproducible fuzz campaigns.
 *
 * Implementation note: the 256-bit state is held as four 64-bit words, each
 * split into a low/high pair of unsigned 32-bit JavaScript numbers. All core
 * arithmetic is done on 32-bit halves so the hot path allocates nothing — a
 * BigInt-based generator allocates ~10 objects per draw, which dominates a
 * fuzzing loop's CPU time and GC pressure. `nextU64()` composes a BigInt only
 * when explicitly requested; the fuzzer's hot path uses nextU32/nextRange/
 * fillBytes, none of which touch BigInt.
 *
 * @license Apache-2.0
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.PRNG = void 0;
const POW32 = 4294967296; // 2^32
const POW21 = 2097152; // 2^21
const POW53 = 9007199254740992; // 2^53
class PRNG {
    // 256-bit state as four 64-bit words, each a (lo, hi) pair of uint32.
    s0lo = 0;
    s0hi = 0;
    s1lo = 0;
    s1hi = 0;
    s2lo = 0;
    s2hi = 0;
    s3lo = 0;
    s3hi = 0;
    // Last generated 64-bit result, as (lo, hi). Written by _next().
    _rlo = 0;
    _rhi = 0;
    constructor(seed = 0n) {
        // SplitMix64 seed expansion to fill 256-bit state (4 BigInt draws total —
        // negligible, runs once at construction).
        const sm = new SplitMix64(seed);
        const w0 = sm.next();
        const w1 = sm.next();
        const w2 = sm.next();
        const w3 = sm.next();
        this.s0lo = Number(w0 & 0xffffffffn) >>> 0;
        this.s0hi = Number(w0 >> 32n) >>> 0;
        this.s1lo = Number(w1 & 0xffffffffn) >>> 0;
        this.s1hi = Number(w1 >> 32n) >>> 0;
        this.s2lo = Number(w2 & 0xffffffffn) >>> 0;
        this.s2hi = Number(w2 >> 32n) >>> 0;
        this.s3lo = Number(w3 & 0xffffffffn) >>> 0;
        this.s3hi = Number(w3 >> 32n) >>> 0;
    }
    /**
     * Advance the state one step (xoshiro256++), storing the 64-bit output in
     * (_rlo, _rhi). Pure 32-bit arithmetic — no allocation.
     */
    _next() {
        const s0lo = this.s0lo, s0hi = this.s0hi;
        const s1lo = this.s1lo, s1hi = this.s1hi;
        const s2lo = this.s2lo, s2hi = this.s2hi;
        const s3lo = this.s3lo, s3hi = this.s3hi;
        // result = rotl(s0 + s3, 23) + s0
        let sum = s0lo + s3lo;
        const alo = sum >>> 0;
        let carry = sum >= POW32 ? 1 : 0;
        const ahi = (s0hi + s3hi + carry) >>> 0;
        // rotl(a, 23): 23 < 32
        const rlo = ((alo << 23) | (ahi >>> 9)) >>> 0;
        const rhi = ((ahi << 23) | (alo >>> 9)) >>> 0;
        // + s0
        sum = rlo + s0lo;
        this._rlo = sum >>> 0;
        carry = sum >= POW32 ? 1 : 0;
        this._rhi = (rhi + s0hi + carry) >>> 0;
        // t = s1 << 17
        const tlo = (s1lo << 17) >>> 0;
        const thi = ((s1hi << 17) | (s1lo >>> 15)) >>> 0;
        // s2 ^= s0 ; s3 ^= s1 ; s1 ^= s2 ; s0 ^= s3 ; s2 ^= t ; s3 = rotl(s3, 45)
        const n2lo = s2lo ^ s0lo, n2hi = s2hi ^ s0hi; // s2 ^= s0
        const n3lo = s3lo ^ s1lo, n3hi = s3hi ^ s1hi; // s3 ^= s1
        const n1lo = s1lo ^ n2lo, n1hi = s1hi ^ n2hi; // s1 ^= (new s2)
        const n0lo = s0lo ^ n3lo, n0hi = s0hi ^ n3hi; // s0 ^= (new s3)
        const f2lo = (n2lo ^ tlo) >>> 0, f2hi = (n2hi ^ thi) >>> 0; // s2 ^= t
        // s3 = rotl(new s3, 45): 45 > 32 -> shift by 13 across swapped halves
        const f3lo = ((n3hi << 13) | (n3lo >>> 19)) >>> 0;
        const f3hi = ((n3lo << 13) | (n3hi >>> 19)) >>> 0;
        this.s0lo = n0lo >>> 0;
        this.s0hi = n0hi >>> 0;
        this.s1lo = n1lo >>> 0;
        this.s1hi = n1hi >>> 0;
        this.s2lo = f2lo;
        this.s2hi = f2hi;
        this.s3lo = f3lo;
        this.s3hi = f3hi;
    }
    /** Return a 64-bit unsigned pseudorandom integer. */
    nextU64() {
        this._next();
        return (BigInt(this._rhi) << 32n) | BigInt(this._rlo >>> 0);
    }
    /** Return a 32-bit unsigned integer. */
    nextU32() {
        this._next();
        return this._rhi;
    }
    /** Return a random integer in [0, bound). */
    nextRange(bound) {
        if (bound <= 0)
            return 0;
        if (bound <= 0xFFFFFFFF) {
            this._next();
            return this._rhi % bound;
        }
        return Number(this.nextU64() % BigInt(bound));
    }
    /** Return a random float in [0, 1). */
    nextFloat() {
        this._next();
        // 53-bit mantissa: 32 high bits + 21 bits from the low word.
        return (this._rhi * POW21 + (this._rlo >>> 11)) / POW53;
    }
    /** Return a random boolean with given probability [0, 1]. */
    nextBool(probability = 0.5) {
        return this.nextFloat() < probability;
    }
    /** Fill a Uint8Array with random bytes. */
    fillBytes(buf) {
        let i = 0;
        const n = buf.length;
        while (i < n) {
            this._next();
            const lo = this._rlo, hi = this._rhi;
            buf[i++] = lo & 0xFF;
            if (i >= n)
                break;
            buf[i++] = (lo >>> 8) & 0xFF;
            if (i >= n)
                break;
            buf[i++] = (lo >>> 16) & 0xFF;
            if (i >= n)
                break;
            buf[i++] = (lo >>> 24) & 0xFF;
            if (i >= n)
                break;
            buf[i++] = hi & 0xFF;
            if (i >= n)
                break;
            buf[i++] = (hi >>> 8) & 0xFF;
            if (i >= n)
                break;
            buf[i++] = (hi >>> 16) & 0xFF;
            if (i >= n)
                break;
            buf[i++] = (hi >>> 24) & 0xFF;
        }
    }
    /** Return a random Uint8Array of given length. */
    randomBytes(length) {
        const buf = new Uint8Array(length);
        this.fillBytes(buf);
        return buf;
    }
    /** Pick a random element from an array. */
    pick(array) {
        if (array.length === 0)
            throw new Error('Cannot pick from empty array');
        return array[this.nextRange(array.length)];
    }
    /** Shuffle array in-place (Fisher-Yates). */
    shuffle(array) {
        for (let i = array.length - 1; i > 0; i--) {
            const j = this.nextRange(i + 1);
            [array[i], array[j]] = [array[j], array[i]];
        }
        return array;
    }
    /** Clone with current state (for branching). */
    clone() {
        const p = new PRNG(0n);
        p.s0lo = this.s0lo;
        p.s0hi = this.s0hi;
        p.s1lo = this.s1lo;
        p.s1hi = this.s1hi;
        p.s2lo = this.s2lo;
        p.s2hi = this.s2hi;
        p.s3lo = this.s3lo;
        p.s3hi = this.s3hi;
        return p;
    }
    /** Serialize state for checkpoint/restore. */
    saveState() {
        return [
            (BigInt(this.s0hi) << 32n) | BigInt(this.s0lo >>> 0),
            (BigInt(this.s1hi) << 32n) | BigInt(this.s1lo >>> 0),
            (BigInt(this.s2hi) << 32n) | BigInt(this.s2lo >>> 0),
            (BigInt(this.s3hi) << 32n) | BigInt(this.s3lo >>> 0),
        ];
    }
    /** Restore from serialized state. */
    restoreState(state) {
        if (state.length !== 4)
            throw new Error('PRNG state must have 4 elements');
        const [w0, w1, w2, w3] = state;
        this.s0lo = Number(w0 & 0xffffffffn) >>> 0;
        this.s0hi = Number(w0 >> 32n) >>> 0;
        this.s1lo = Number(w1 & 0xffffffffn) >>> 0;
        this.s1hi = Number(w1 >> 32n) >>> 0;
        this.s2lo = Number(w2 & 0xffffffffn) >>> 0;
        this.s2hi = Number(w2 >> 32n) >>> 0;
        this.s3lo = Number(w3 & 0xffffffffn) >>> 0;
        this.s3hi = Number(w3 >> 32n) >>> 0;
    }
}
exports.PRNG = PRNG;
// --- Internal ---------------------------------------------------------------
const MASK64 = (1n << 64n) - 1n;
/** SplitMix64 - used for seed expansion only (4 draws per PRNG construction). */
class SplitMix64 {
    state;
    constructor(seed) {
        this.state = seed & MASK64;
    }
    next() {
        this.state = (this.state + 0x9e3779b97f4a7c15n) & MASK64;
        let z = this.state;
        z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & MASK64;
        z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & MASK64;
        return (z ^ (z >> 31n)) & MASK64;
    }
}
//# sourceMappingURL=prng.js.map
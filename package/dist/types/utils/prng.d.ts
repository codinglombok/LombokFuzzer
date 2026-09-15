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
export declare class PRNG {
    private s0lo;
    private s0hi;
    private s1lo;
    private s1hi;
    private s2lo;
    private s2hi;
    private s3lo;
    private s3hi;
    private _rlo;
    private _rhi;
    constructor(seed?: bigint);
    /**
     * Advance the state one step (xoshiro256++), storing the 64-bit output in
     * (_rlo, _rhi). Pure 32-bit arithmetic — no allocation.
     */
    private _next;
    /** Return a 64-bit unsigned pseudorandom integer. */
    nextU64(): bigint;
    /** Return a 32-bit unsigned integer. */
    nextU32(): number;
    /** Return a random integer in [0, bound). */
    nextRange(bound: number): number;
    /** Return a random float in [0, 1). */
    nextFloat(): number;
    /** Return a random boolean with given probability [0, 1]. */
    nextBool(probability?: number): boolean;
    /** Fill a Uint8Array with random bytes. */
    fillBytes(buf: Uint8Array): void;
    /** Return a random Uint8Array of given length. */
    randomBytes(length: number): Uint8Array;
    /** Pick a random element from an array. */
    pick<T>(array: readonly T[]): T;
    /** Shuffle array in-place (Fisher-Yates). */
    shuffle<T>(array: T[]): T[];
    /** Clone with current state (for branching). */
    clone(): PRNG;
    /** Serialize state for checkpoint/restore. */
    saveState(): bigint[];
    /** Restore from serialized state. */
    restoreState(state: bigint[]): void;
}
//# sourceMappingURL=prng.d.ts.map
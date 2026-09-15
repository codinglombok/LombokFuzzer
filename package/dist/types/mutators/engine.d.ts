/**
 * LombokFuzzer — Mutation Engine
 *
 * Implements 15 mutation strategies from classical (AFL bit-flip) to modern
 * (structure-aware, grammar-guided, token-level). Each strategy is a pure
 * function: (input, prng, context) → mutated output.
 *
 * @license Apache-2.0
 */
import type { MutatorConfig, FuzzInput } from '../core/types.js';
import { MutatorStrategy } from '../core/types.js';
import type { PRNG } from '../utils/prng.js';
/** Result of a single mutation pass. */
export interface MutationResult {
    data: Uint8Array;
    strategies: MutatorStrategy[];
}
export declare class MutationEngine {
    private readonly config;
    private readonly prng;
    private readonly dictionary;
    private readonly strategyFns;
    constructor(config: MutatorConfig, prng: PRNG);
    /** Mutate an input using configured strategies. */
    mutate(input: Uint8Array, maxSize: number, corpus: ReadonlyArray<FuzzInput>): MutationResult;
    /** Havoc: stack multiple random mutations. */
    private havoc;
    /** Flip 1/2/4 random bits. */
    private bitFlip;
    /** Flip 1/2/4 random bytes. */
    private byteFlip;
    /** Add small random value to a byte/word/dword. */
    private arithInc;
    /** Subtract small random value from a byte/word/dword. */
    private arithDec;
    /** Replace byte/word/dword with "interesting" boundary value. */
    private interestingValues;
    /** Insert a dictionary token at a random position. */
    private dictInsert;
    /** Overwrite at a random position with a dictionary token. */
    private dictOverwrite;
    /** Splice: crossover two corpus entries. */
    private splice;
    /** Trim: delete a random chunk. */
    private trim;
    /** Extend: insert random bytes at a random position. */
    private extend;
    /** Structure-aware: parse as chunks (length-prefixed) and mutate one chunk. */
    private structureAware;
    /** Grammar-guided: placeholder for grammar engine integration. */
    private grammarGuided;
    /** Token-level: identify and mutate text tokens. */
    private tokenLevel;
    private mutateToken;
    /** Add a dictionary entry. */
    addDictionary(value: Uint8Array, level?: number): void;
    /** Add dictionary entries from a file (one token per line). */
    addDictionaryTokens(tokens: string[]): void;
    /** Number of dictionary entries. */
    get dictionarySize(): number;
}
//# sourceMappingURL=engine.d.ts.map
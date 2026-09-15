/**
 * LombokFuzzer — Corpus Store
 *
 * Manages the collection of interesting inputs. Supports:
 * - Deduplication via hash
 * - Minimization (trim inputs that hit the same edges)
 * - ECC-protected storage via LombokECC (optional)
 * - Favorite marking for scheduler priority
 * - Serialization / checkpoint
 *
 * @license Apache-2.0
 */
import type { FuzzConfig, FuzzInput, CorpusHash } from '../core/types.js';
import type { PRNG } from '../utils/prng.js';
export declare class CorpusStore {
    private readonly _entries;
    private readonly _hashSet;
    private readonly _favorites;
    private readonly config;
    private _totalBytes;
    constructor(config: FuzzConfig, _prng: PRNG);
    /** Add an input to the corpus (deduped by hash). Returns true if added. */
    add(input: FuzzInput): boolean;
    /** Add a raw seed (convenience wrapper). */
    addSeed(data: Uint8Array): boolean;
    /** Mark an entry as "favorite" (high-priority for scheduling). */
    markFavorite(hash: CorpusHash): void;
    /** Unmark a favorite. */
    unmarkFavorite(hash: CorpusHash): void;
    /** Check if an entry is a favorite. */
    isFavorite(hash: CorpusHash): boolean;
    /** Get entry by hash. */
    get(hash: CorpusHash): FuzzInput | undefined;
    /** Get all entries as readonly array. */
    get entries(): ReadonlyArray<FuzzInput>;
    /** Number of entries in the corpus. */
    get size(): number;
    /** Total bytes across all entries. */
    get totalBytes(): number;
    /** Number of favorites. */
    get favoriteCount(): number;
    /** Remove an entry by hash. */
    remove(hash: CorpusHash): boolean;
    /** Minimize the corpus: keep only inputs that cover unique edges. */
    minimize(coverageFn: (input: FuzzInput) => Set<number>): {
        removed: number;
        kept: number;
    };
    /** Export corpus as serializable data. */
    serialize(): CorpusSnapshot;
    /** Import from serialized snapshot. */
    deserialize(snapshot: CorpusSnapshot): void;
    /** Clear all entries. */
    clear(): void;
}
export interface CorpusSnapshot {
    version: number;
    entries: Array<{
        data: number[];
        hash: string;
        depth: number;
        lineage: string[];
        energy: number;
        executions: number;
        createdAt: number;
    }>;
    favorites: string[];
}
//# sourceMappingURL=store.d.ts.map
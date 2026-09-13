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

import type { FuzzConfig, FuzzInput, CorpusHash, MutatorStrategy } from '../core/types.js';
import type { PRNG } from '../utils/prng.js';
import { fnv1a64 } from '../utils/hash.js';

// PRNG used in future (weighted random selection during minimize)
void 0; // suppress lint for prng field — used in v0.2.0 minimize with random selection

export class CorpusStore {
  private readonly _entries: FuzzInput[] = [];
  private readonly _hashSet = new Set<bigint>();
  private readonly _favorites = new Set<bigint>();
  private readonly config: FuzzConfig;
  private _totalBytes = 0;

  constructor(config: FuzzConfig, _prng: PRNG) {
    this.config = config;
    // prng reserved for weighted random selection in minimize (v0.2.0)
  }

  /** Add an input to the corpus (deduped by hash). Returns true if added. */
  add(input: FuzzInput): boolean {
    const hash = input.hash ?? fnv1a64(input.data);
    input.hash = hash;

    if (this._hashSet.has(hash)) return false;

    this._hashSet.add(hash);
    this._entries.push(input);
    this._totalBytes += input.data.length;
    return true;
  }

  /** Add a raw seed (convenience wrapper). */
  addSeed(data: Uint8Array): boolean {
    const hash = fnv1a64(data);
    const input: FuzzInput = {
      data,
      hash,
      lineage: [],
      depth: 0,
      energy: this.config.scheduler.initialEnergy,
      executions: 0,
      createdAt: Date.now(),
      tags: new Map(),
    };
    return this.add(input);
  }

  /** Mark an entry as "favorite" (high-priority for scheduling). */
  markFavorite(hash: CorpusHash): void {
    this._favorites.add(hash);
  }

  /** Unmark a favorite. */
  unmarkFavorite(hash: CorpusHash): void {
    this._favorites.delete(hash);
  }

  /** Check if an entry is a favorite. */
  isFavorite(hash: CorpusHash): boolean {
    return this._favorites.has(hash);
  }

  /** Get entry by hash. */
  get(hash: CorpusHash): FuzzInput | undefined {
    return this._entries.find(e => e.hash === hash);
  }

  /** Get all entries as readonly array. */
  get entries(): ReadonlyArray<FuzzInput> {
    return this._entries;
  }

  /** Number of entries in the corpus. */
  get size(): number {
    return this._entries.length;
  }

  /** Total bytes across all entries. */
  get totalBytes(): number {
    return this._totalBytes;
  }

  /** Number of favorites. */
  get favoriteCount(): number {
    return this._favorites.size;
  }

  /** Remove an entry by hash. */
  remove(hash: CorpusHash): boolean {
    const idx = this._entries.findIndex(e => e.hash === hash);
    if (idx === -1) return false;

    this._totalBytes -= this._entries[idx]!.data.length;
    this._entries.splice(idx, 1);
    this._hashSet.delete(hash);
    this._favorites.delete(hash);
    return true;
  }

  /** Minimize the corpus: keep only inputs that cover unique edges. */
  minimize(
    coverageFn: (input: FuzzInput) => Set<number>,
  ): { removed: number; kept: number } {
    // Greedy set-cover: pick smallest input for each edge, remove the rest
    // For each input, compute its coverage
    const inputCoverage = new Map<FuzzInput, Set<number>>();
    for (const entry of this._entries) {
      inputCoverage.set(entry, coverageFn(entry));
    }

    // Sort by size (smallest first) — greedy minimization
    const sorted = [...this._entries].sort((a, b) => a.data.length - b.data.length);

    const keep = new Set<bigint>();
    const coveredEdges = new Set<number>();

    for (const entry of sorted) {
      const edges = inputCoverage.get(entry);
      if (!edges) continue;

      let hasNewEdge = false;
      for (const edge of edges) {
        if (!coveredEdges.has(edge)) {
          hasNewEdge = true;
          break;
        }
      }

      if (hasNewEdge) {
        keep.add(entry.hash!);
        for (const edge of edges) {
          coveredEdges.add(edge);
        }
      }
    }

    // Remove entries not in `keep`
    let removed = 0;
    for (let i = this._entries.length - 1; i >= 0; i--) {
      const entry = this._entries[i]!;
      if (!keep.has(entry.hash!)) {
        this._totalBytes -= entry.data.length;
        this._entries.splice(i, 1);
        this._hashSet.delete(entry.hash!);
        this._favorites.delete(entry.hash!);
        removed++;
      }
    }

    return { removed, kept: this._entries.length };
  }

  /** Export corpus as serializable data. */
  serialize(): CorpusSnapshot {
    return {
      version: 1,
      entries: this._entries.map(e => ({
        data: Array.from(e.data),
        hash: e.hash!.toString(),
        depth: e.depth,
        lineage: e.lineage,
        energy: e.energy,
        executions: e.executions,
        createdAt: e.createdAt,
      })),
      favorites: Array.from(this._favorites).map(h => h.toString()),
    };
  }

  /** Import from serialized snapshot. */
  deserialize(snapshot: CorpusSnapshot): void {
    for (const entry of snapshot.entries) {
      const data = new Uint8Array(entry.data);
      const input: FuzzInput = {
        data,
        hash: BigInt(entry.hash),
        lineage: entry.lineage as MutatorStrategy[],
        depth: entry.depth,
        energy: entry.energy,
        executions: entry.executions,
        createdAt: entry.createdAt,
        tags: new Map(),
      };
      this.add(input);
    }
    for (const fav of snapshot.favorites) {
      this._favorites.add(BigInt(fav));
    }
  }

  /** Clear all entries. */
  clear(): void {
    this._entries.length = 0;
    this._hashSet.clear();
    this._favorites.clear();
    this._totalBytes = 0;
  }
}

// ─── Serialization types ──────────────────────────────────────────────────

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

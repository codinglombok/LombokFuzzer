"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.CorpusStore = void 0;
const hash_js_1 = require("../utils/hash.js");
// PRNG used in future (weighted random selection during minimize)
void 0; // suppress lint for prng field — used in v0.2.0 minimize with random selection
class CorpusStore {
    _entries = [];
    _hashSet = new Set();
    _favorites = new Set();
    config;
    _totalBytes = 0;
    constructor(config, _prng) {
        this.config = config;
        // prng reserved for weighted random selection in minimize (v0.2.0)
    }
    /** Add an input to the corpus (deduped by hash). Returns true if added. */
    add(input) {
        const hash = input.hash ?? (0, hash_js_1.fnv1a64)(input.data);
        input.hash = hash;
        if (this._hashSet.has(hash))
            return false;
        this._hashSet.add(hash);
        this._entries.push(input);
        this._totalBytes += input.data.length;
        return true;
    }
    /** Add a raw seed (convenience wrapper). */
    addSeed(data) {
        const hash = (0, hash_js_1.fnv1a64)(data);
        const input = {
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
    markFavorite(hash) {
        this._favorites.add(hash);
    }
    /** Unmark a favorite. */
    unmarkFavorite(hash) {
        this._favorites.delete(hash);
    }
    /** Check if an entry is a favorite. */
    isFavorite(hash) {
        return this._favorites.has(hash);
    }
    /** Get entry by hash. */
    get(hash) {
        return this._entries.find(e => e.hash === hash);
    }
    /** Get all entries as readonly array. */
    get entries() {
        return this._entries;
    }
    /** Number of entries in the corpus. */
    get size() {
        return this._entries.length;
    }
    /** Total bytes across all entries. */
    get totalBytes() {
        return this._totalBytes;
    }
    /** Number of favorites. */
    get favoriteCount() {
        return this._favorites.size;
    }
    /** Remove an entry by hash. */
    remove(hash) {
        const idx = this._entries.findIndex(e => e.hash === hash);
        if (idx === -1)
            return false;
        this._totalBytes -= this._entries[idx].data.length;
        this._entries.splice(idx, 1);
        this._hashSet.delete(hash);
        this._favorites.delete(hash);
        return true;
    }
    /** Minimize the corpus: keep only inputs that cover unique edges. */
    minimize(coverageFn) {
        // Greedy set-cover: pick smallest input for each edge, remove the rest
        // For each input, compute its coverage
        const inputCoverage = new Map();
        for (const entry of this._entries) {
            inputCoverage.set(entry, coverageFn(entry));
        }
        // Sort by size (smallest first) — greedy minimization
        const sorted = [...this._entries].sort((a, b) => a.data.length - b.data.length);
        const keep = new Set();
        const coveredEdges = new Set();
        for (const entry of sorted) {
            const edges = inputCoverage.get(entry);
            if (!edges)
                continue;
            let hasNewEdge = false;
            for (const edge of edges) {
                if (!coveredEdges.has(edge)) {
                    hasNewEdge = true;
                    break;
                }
            }
            if (hasNewEdge) {
                keep.add(entry.hash);
                for (const edge of edges) {
                    coveredEdges.add(edge);
                }
            }
        }
        // Remove entries not in `keep`
        let removed = 0;
        for (let i = this._entries.length - 1; i >= 0; i--) {
            const entry = this._entries[i];
            if (!keep.has(entry.hash)) {
                this._totalBytes -= entry.data.length;
                this._entries.splice(i, 1);
                this._hashSet.delete(entry.hash);
                this._favorites.delete(entry.hash);
                removed++;
            }
        }
        return { removed, kept: this._entries.length };
    }
    /** Export corpus as serializable data. */
    serialize() {
        return {
            version: 1,
            entries: this._entries.map(e => ({
                data: Array.from(e.data),
                hash: e.hash.toString(),
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
    deserialize(snapshot) {
        for (const entry of snapshot.entries) {
            const data = new Uint8Array(entry.data);
            const input = {
                data,
                hash: BigInt(entry.hash),
                lineage: entry.lineage,
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
    clear() {
        this._entries.length = 0;
        this._hashSet.clear();
        this._favorites.clear();
        this._totalBytes = 0;
    }
}
exports.CorpusStore = CorpusStore;
//# sourceMappingURL=store.js.map
/**
 * LombokFuzzer — Coverage Tracker
 *
 * Tracks code coverage using shared-memory-style bitmaps. Supports edge,
 * branch, comparison (CmpLog), and data-flow coverage metrics.
 *
 * The bitmap format is compatible with AFL/libFuzzer instrumentation.
 *
 * @license Apache-2.0
 */
import type { CoverageConfig, CoverageSnapshot, EdgeId } from '../core/types.js';
export declare class CoverageTracker {
    /** The global accumulated coverage bitmap. */
    private readonly globalBitmap;
    /** Virgin bits: which bitmap positions have never been hit. */
    private readonly virginBits;
    /** Per-edge hit count (for stability calculation). */
    private readonly edgeHits;
    /**
     * Number of distinct bitmap positions that are non-zero in globalBitmap.
     * Maintained incrementally by recordEdge so snapshot/findNewEdges/mergeBitmap
     * can short-circuit in O(1) when no edge has ever been recorded — the common
     * case for in-process fuzzing without instrumentation. Without this guard,
     * every execution would allocate and scan the full bitmap, making a campaign
     * O(executions × bitmapSize).
     */
    private _globalHitCount;
    /** Shared zero-length bitmap reused by the empty-trace fast path. */
    private readonly _emptyBitmap;
    /** Total possible edges (set by instrumentation callback). */
    private _edgesTotal;
    /** When the last new edge was found. */
    private _lastNewEdgeAt;
    /** Stability: fraction of deterministic executions. */
    private _stability;
    /** Execution counter for stability tracking. */
    private _stableExecs;
    private _totalExecsForStability;
    private readonly config;
    constructor(config: CoverageConfig);
    /** Record a single edge hit (call from instrumentation callback). */
    recordEdge(edgeId: EdgeId): void;
    /** Take a snapshot of current execution's coverage. */
    snapshot(): CoverageSnapshot;
    /** Find edges in the snapshot that are new (not in global accumulation). */
    findNewEdges(snap: CoverageSnapshot): EdgeId[];
    /** Merge a snapshot's coverage into the global bitmap. */
    mergeBitmap(snap: CoverageSnapshot): number;
    /** Reset the trace bitmap for a new execution. */
    resetTrace(): void;
    /** Set total edges count (from instrumentation). */
    setEdgesTotal(total: number): void;
    /** Number of unique edges found so far. */
    get edgesFound(): number;
    /** Total possible edges. */
    get edgesTotal(): number;
    /** Coverage percentage. */
    get percentage(): number;
    /** When the last new edge was found. */
    get lastNewEdgeAt(): number;
    /** Stability percentage. */
    get stability(): number;
    /** Update stability metric after a deterministic test. */
    updateStability(isDeterministic: boolean): void;
    /** Get the raw global bitmap (for serialization). */
    getBitmap(): Readonly<Uint8Array>;
    /** Get hit count map for all edges. */
    getEdgeHitCounts(): ReadonlyMap<EdgeId, number>;
    /** Reset all coverage data. */
    reset(): void;
}
//# sourceMappingURL=tracker.d.ts.map
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
import { CoverageMetric } from '../core/types.js';
import { classifyCount, countNonZero } from '../utils/hash.js';

export class CoverageTracker {
  /** The global accumulated coverage bitmap. */
  private readonly globalBitmap: Uint8Array;

  /** Virgin bits: which bitmap positions have never been hit. */
  private readonly virginBits: Uint8Array;

  /** Per-edge hit count (for stability calculation). */
  private readonly edgeHits: Map<EdgeId, number> = new Map();

  /**
   * Number of distinct bitmap positions that are non-zero in globalBitmap.
   * Maintained incrementally by recordEdge so snapshot/findNewEdges/mergeBitmap
   * can short-circuit in O(1) when no edge has ever been recorded — the common
   * case for in-process fuzzing without instrumentation. Without this guard,
   * every execution would allocate and scan the full bitmap, making a campaign
   * O(executions × bitmapSize).
   */
  private _globalHitCount = 0;

  /** Shared zero-length bitmap reused by the empty-trace fast path. */
  private readonly _emptyBitmap = new Uint8Array(0);

  /** Total possible edges (set by instrumentation callback). */
  private _edgesTotal = 0;

  /** When the last new edge was found. */
  private _lastNewEdgeAt = 0;

  /** Stability: fraction of deterministic executions. */
  private _stability = 100;

  /** Execution counter for stability tracking. */
  private _stableExecs = 0;
  private _totalExecsForStability = 0;

  private readonly config: CoverageConfig;

  constructor(config: CoverageConfig) {
    this.config = config;
    this.globalBitmap = new Uint8Array(config.bitmapSize);
    this.virginBits = new Uint8Array(config.bitmapSize);
    this.virginBits.fill(0xFF); // All bits virgin initially
  }

  /** Record a single edge hit (call from instrumentation callback). */
  recordEdge(edgeId: EdgeId): void {
    const idx = edgeId & (this.config.bitmapSize - 1);
    const prev = this.globalBitmap[idx] ?? 0;
    if (prev === 0) this._globalHitCount++;
    this.globalBitmap[idx] = Math.min(255, prev + 1);
  }

  /** Take a snapshot of current execution's coverage. */
  snapshot(): CoverageSnapshot {
    // Fast path: nothing has ever been recorded (in-process without
    // instrumentation). Skip the 64KB allocation and full scan entirely.
    if (this._globalHitCount === 0) {
      return {
        edgeBitmap: this._emptyBitmap,
        totalEdgesHit: 0,
        totalEdges: this._edgesTotal || this.config.bitmapSize,
        percentage: 0,
        metric: this.config.metrics[0] ?? CoverageMetric.Edge,
      };
    }

    // In real instrumentation, this reads the shared-memory bitmap.
    // For in-process fuzzing, we use the globalBitmap as the trace bitmap.
    const edgeBitmap = new Uint8Array(this.globalBitmap);
    const totalHit = countNonZero(edgeBitmap);

    return {
      edgeBitmap,
      totalEdgesHit: totalHit,
      totalEdges: this._edgesTotal || this.config.bitmapSize,
      percentage: this._edgesTotal > 0
        ? (totalHit / this._edgesTotal) * 100
        : (totalHit / this.config.bitmapSize) * 100,
      metric: this.config.metrics[0] ?? CoverageMetric.Edge,
    };
  }

  /** Find edges in the snapshot that are new (not in global accumulation). */
  findNewEdges(snap: CoverageSnapshot): EdgeId[] {
    if (snap.totalEdgesHit === 0) return [];

    const newEdges: EdgeId[] = [];

    for (let i = 0; i < snap.edgeBitmap.length; i++) {
      const traceVal = snap.edgeBitmap[i] ?? 0;
      if (traceVal === 0) continue;

      const classified = classifyCount(traceVal);
      const virginVal = this.virginBits[i] ?? 0;

      // Check if this bucketed count is new
      if ((virginVal & classified) !== 0) {
        newEdges.push(i);
      }
    }

    return newEdges;
  }

  /** Merge a snapshot's coverage into the global bitmap. */
  mergeBitmap(snap: CoverageSnapshot): number {
    if (snap.totalEdgesHit === 0) return 0;

    let newCount = 0;

    for (let i = 0; i < snap.edgeBitmap.length; i++) {
      const traceVal = snap.edgeBitmap[i] ?? 0;
      if (traceVal === 0) continue;

      const classified = classifyCount(traceVal);
      const virginVal = this.virginBits[i] ?? 0;

      if ((virginVal & classified) !== 0) {
        this.virginBits[i] = (virginVal & ~classified) & 0xFF;
        newCount++;
        this._lastNewEdgeAt = Date.now();
      }

      // Update global max
      if (traceVal > (this.globalBitmap[i] ?? 0)) {
        this.globalBitmap[i] = traceVal;
      }

      // Track per-edge hits for stability
      const prevHits = this.edgeHits.get(i) ?? 0;
      this.edgeHits.set(i, prevHits + 1);
    }

    return newCount;
  }

  /** Reset the trace bitmap for a new execution. */
  resetTrace(): void {
    // In fork-server mode, this clears shared memory.
    // For in-process, the trace is implicitly reset each call.
  }

  /** Set total edges count (from instrumentation). */
  setEdgesTotal(total: number): void {
    this._edgesTotal = total;
  }

  /** Number of unique edges found so far. */
  get edgesFound(): number {
    let count = 0;
    for (let i = 0; i < this.virginBits.length; i++) {
      if (this.virginBits[i] !== 0xFF) count++;
    }
    return count;
  }

  /** Total possible edges. */
  get edgesTotal(): number {
    return this._edgesTotal || this.config.bitmapSize;
  }

  /** Coverage percentage. */
  get percentage(): number {
    const found = this.edgesFound;
    const total = this.edgesTotal;
    return total > 0 ? (found / total) * 100 : 0;
  }

  /** When the last new edge was found. */
  get lastNewEdgeAt(): number {
    return this._lastNewEdgeAt;
  }

  /** Stability percentage. */
  get stability(): number {
    return this._stability;
  }

  /** Update stability metric after a deterministic test. */
  updateStability(isDeterministic: boolean): void {
    this._totalExecsForStability++;
    if (isDeterministic) this._stableExecs++;
    this._stability = this._totalExecsForStability > 0
      ? (this._stableExecs / this._totalExecsForStability) * 100
      : 100;
  }

  /** Get the raw global bitmap (for serialization). */
  getBitmap(): Readonly<Uint8Array> {
    return this.globalBitmap;
  }

  /** Get hit count map for all edges. */
  getEdgeHitCounts(): ReadonlyMap<EdgeId, number> {
    return this.edgeHits;
  }

  /** Reset all coverage data. */
  reset(): void {
    this.globalBitmap.fill(0);
    this.virginBits.fill(0xFF);
    this.edgeHits.clear();
    this._globalHitCount = 0;
    this._lastNewEdgeAt = 0;
    this._stableExecs = 0;
    this._totalExecsForStability = 0;
    this._stability = 100;
  }
}

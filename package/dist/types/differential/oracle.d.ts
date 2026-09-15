/**
 * LombokFuzzer — Differential Oracle
 *
 * Compares N implementations of the same interface with the same input.
 * Any divergence (output mismatch, crash-vs-success, timing anomaly)
 * is flagged as a potential bug.
 *
 * Use cases:
 *   - Cross-language parity (TS vs Go vs Rust parser)
 *   - Regression testing (v1 vs v2)
 *   - Semantic equivalence (optimised vs reference)
 *
 * @license Apache-2.0
 */
import type { FuzzInput } from '../core/types.js';
import { Severity } from '../core/types.js';
/**
 * A test oracle: a function that takes input bytes and returns output bytes,
 * or throws on error. Each oracle has a name for reporting.
 */
export interface Oracle {
    /** Human-readable name (e.g. 'typescript', 'go', 'v2.1'). */
    name: string;
    /** Execute the input and return the output. Throw on crash. */
    execute: (input: Uint8Array) => OracleOutput | Promise<OracleOutput>;
}
/** Output from one oracle execution. */
export interface OracleOutput {
    /** Raw output bytes (or serialised result). */
    data: Uint8Array;
    /** Execution time in microseconds. */
    durationUs: number;
    /** Whether the execution crashed/errored. */
    crashed: boolean;
    /** Error message if crashed. */
    error?: string;
    /** Optional metadata (e.g. memory usage). */
    metadata?: Record<string, unknown>;
}
/** Result of comparing all oracles on one input. */
export interface DiffResult {
    /** The input that was tested. */
    input: FuzzInput;
    /** Per-oracle outputs (same order as registered oracles). */
    outputs: OracleOutput[];
    /** Whether all oracles agreed. */
    unanimous: boolean;
    /** Divergences found (empty if unanimous). */
    divergences: Divergence[];
    /** Wall-clock time for the entire comparison (μs). */
    totalDurationUs: number;
}
/** A single divergence between oracles. */
export interface Divergence {
    /** Type of divergence. */
    kind: DivergenceKind;
    /** Which oracles diverged (by name). */
    oracles: [string, string];
    /** Severity assessment. */
    severity: Severity;
    /** Human-readable description. */
    description: string;
    /** Byte offset of first difference (for output divergence). */
    firstDiffOffset?: number;
}
/** Classification of divergence types. */
export declare enum DivergenceKind {
    /** Output bytes differ. */
    OutputMismatch = "output_mismatch",
    /** One crashed, the other didn't. */
    CrashDivergence = "crash_divergence",
    /** Both crashed but with different errors. */
    ErrorDivergence = "error_divergence",
    /** Execution time ratio exceeds threshold. */
    TimingAnomaly = "timing_anomaly",
    /** Output lengths differ. */
    LengthMismatch = "length_mismatch"
}
/** Configuration for the differential oracle engine. */
export interface DiffOracleConfig {
    /** Timing ratio threshold: report if slowest/fastest > this. */
    timingRatioThreshold: number;
    /** Max output bytes to compare (0 = unlimited). */
    maxCompareBytes: number;
    /** Whether to compare output lengths as a separate check. */
    checkLengths: boolean;
    /** Whether to check timing anomalies. */
    checkTiming: boolean;
}
export declare class DiffOracle {
    private readonly oracles;
    private readonly config;
    private readonly results;
    constructor(config?: Partial<DiffOracleConfig>);
    /** Register an oracle. At least 2 are required for differential testing. */
    addOracle(oracle: Oracle): this;
    /** Get registered oracle count. */
    get oracleCount(): number;
    /** Run all oracles on one input and compare results. */
    compare(input: FuzzInput): Promise<DiffResult>;
    /** Get all results so far. */
    getResults(): readonly DiffResult[];
    /** Get divergence statistics. */
    getStats(): DiffStats;
    private findDivergences;
}
/** Aggregate statistics from differential testing. */
export interface DiffStats {
    totalComparisons: number;
    totalDivergences: number;
    crashDivergences: number;
    outputMismatches: number;
    timingAnomalies: number;
    /** Percentage of comparisons where all oracles agreed. */
    unanimousRate: number;
}
//# sourceMappingURL=oracle.d.ts.map
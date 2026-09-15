/**
 * LombokFuzzer — Crash Analyzer
 *
 * Detects, classifies, deduplicates, and triages crashes. Each crash is
 * assigned a CWE category and severity based on signal, sanitizer output,
 * and stack analysis.
 *
 * @license Apache-2.0
 */
import type { FuzzConfig, ExecutionResult, CrashInfo, StackFrame } from '../core/types.js';
import { CrashCategory, Severity } from '../core/types.js';
export declare class CrashAnalyzer {
    private readonly config;
    private readonly _crashes;
    private readonly _stackHashes;
    constructor(config: FuzzConfig);
    /** Analyze an execution result and return crash info (or null if no crash). */
    analyze(result: ExecutionResult): CrashInfo | null;
    /** Parse a stack trace string into frames. */
    parseStackTrace(stderr: string): StackFrame[];
    /** Try to parse a single stack frame line. */
    private parseFrame;
    /** Classify crash into a CWE category. */
    private classifyCrash;
    /** Assess severity based on crash category. */
    private assessSeverity;
    /** Convert signal number to name. */
    private signalName;
    /** Number of unique crashes. */
    get uniqueCount(): number;
    /** All unique crashes. */
    get all(): ReadonlyMap<string, CrashInfo>;
    /** Get crashes by severity. */
    getBySeverity(severity: Severity): CrashInfo[];
    /** Get crashes by category (CWE). */
    getByCategory(category: CrashCategory): CrashInfo[];
    /** Clear all crash data. */
    clear(): void;
}
//# sourceMappingURL=analyzer.d.ts.map
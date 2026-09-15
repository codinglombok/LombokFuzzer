/**
 * LombokFuzzer — Sanitizer Bridge
 *
 * Parses output from native sanitizers (ASan, MSan, UBSan, TSan) and
 * provides equivalent JavaScript-level checks:
 *   - BoundsCheck   — typed-array OOB
 *   - TypeCheck     — unexpected typeof / NaN propagation
 *   - LeakCheck     — closure / timer / event-listener leak detection
 *   - RaceCheck     — SharedArrayBuffer data-race detection
 *   - UndefinedCheck — reading uninitialised buffer positions
 *
 * @license Apache-2.0
 */
import type { StackFrame } from '../core/types.js';
import { CrashCategory, Severity } from '../core/types.js';
/** A sanitizer finding (from native or JS checks). */
export interface SanitizerFinding {
    /** Which sanitizer. */
    sanitizer: SanitizerKind;
    /** Short description. */
    summary: string;
    /** Full detail / report text. */
    detail: string;
    /** Mapped CWE category. */
    category: CrashCategory;
    /** Severity. */
    severity: Severity;
    /** Parsed stack frames (if available). */
    stackTrace: StackFrame[];
    /** Faulting address (native sanitizers). */
    address?: bigint;
    /** Access size in bytes. */
    accessSize?: number;
    /** Whether the access was a read or write. */
    accessType?: 'read' | 'write';
}
/** Supported sanitizer identifiers. */
export declare enum SanitizerKind {
    ASan = "asan",
    MSan = "msan",
    UBSan = "ubsan",
    TSan = "tsan",
    LSan = "lsan",
    JsBounds = "js_bounds",
    JsType = "js_type",
    JsLeak = "js_leak",
    JsRace = "js_race",
    JsUndef = "js_undef"
}
/**
 * Parses sanitizer output (stderr) from ASan, MSan, UBSan, TSan, LSan
 * and returns structured findings.
 */
export declare class SanitizerParser {
    /** Parse raw sanitizer output into findings. */
    parse(output: string): SanitizerFinding[];
    private parseASan;
    private parseMSan;
    private parseUBSan;
    private parseTSan;
    private parseLSan;
}
/**
 * JS-level bounds checking. Wraps a Uint8Array and throws on OOB access.
 * Used to simulate ASan for in-process JS targets.
 */
export declare class JsBoundsChecker {
    /**
     * Wrap a buffer so that OOB reads/writes throw instead of returning
     * `undefined` or silently clamping.
     */
    static wrap(buf: Uint8Array): Uint8Array;
}
/**
 * Tracks leaked resources (timers, listeners, closures over large data).
 * Call `snapshot()` before the target, `check()` after — any new timers
 * or listeners that weren't cleaned up are reported.
 */
export declare class JsLeakChecker {
    private timersBefore;
    /** Take a "before" snapshot. */
    snapshot(): void;
    /** Compare to the snapshot and return findings. */
    check(): SanitizerFinding[];
}
/**
 * Detects NaN propagation and unexpected type coercion.
 */
export declare class JsTypeChecker {
    /** Check a value for NaN, undefined, or suspicious coercion. */
    static check(value: unknown, label: string): SanitizerFinding | null;
}
//# sourceMappingURL=bridge.d.ts.map
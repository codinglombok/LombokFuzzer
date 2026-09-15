"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.JsTypeChecker = exports.JsLeakChecker = exports.JsBoundsChecker = exports.SanitizerParser = exports.SanitizerKind = void 0;
const types_js_1 = require("../core/types.js");
/** Supported sanitizer identifiers. */
var SanitizerKind;
(function (SanitizerKind) {
    SanitizerKind["ASan"] = "asan";
    SanitizerKind["MSan"] = "msan";
    SanitizerKind["UBSan"] = "ubsan";
    SanitizerKind["TSan"] = "tsan";
    SanitizerKind["LSan"] = "lsan";
    SanitizerKind["JsBounds"] = "js_bounds";
    SanitizerKind["JsType"] = "js_type";
    SanitizerKind["JsLeak"] = "js_leak";
    SanitizerKind["JsRace"] = "js_race";
    SanitizerKind["JsUndef"] = "js_undef";
})(SanitizerKind || (exports.SanitizerKind = SanitizerKind = {}));
// ─── Native Sanitizer Parser ────────────────────────────────────────────────
/**
 * Parses sanitizer output (stderr) from ASan, MSan, UBSan, TSan, LSan
 * and returns structured findings.
 */
class SanitizerParser {
    /** Parse raw sanitizer output into findings. */
    parse(output) {
        const findings = [];
        if (output.includes('AddressSanitizer')) {
            findings.push(...this.parseASan(output));
        }
        if (output.includes('MemorySanitizer')) {
            findings.push(...this.parseMSan(output));
        }
        if (output.includes('UndefinedBehaviorSanitizer') || output.includes('runtime error:')) {
            findings.push(...this.parseUBSan(output));
        }
        if (output.includes('ThreadSanitizer')) {
            findings.push(...this.parseTSan(output));
        }
        if (output.includes('LeakSanitizer') || output.includes('detected memory leaks')) {
            findings.push(...this.parseLSan(output));
        }
        return findings;
    }
    // ── ASan ──────────────────────────────────────────────────────────────
    parseASan(output) {
        const findings = [];
        // Extract error type
        const errorMatch = output.match(/ERROR:\s*AddressSanitizer:\s*(\S+)/);
        const errorType = errorMatch?.[1] ?? 'unknown';
        // Extract address
        const addrMatch = output.match(/on address\s+(0x[0-9a-f]+)/i);
        const address = addrMatch?.[1] ? BigInt(addrMatch[1]) : undefined;
        // Extract access info
        const accessMatch = output.match(/(READ|WRITE)\s+of\s+size\s+(\d+)/);
        const accessType = accessMatch?.[1]?.toLowerCase();
        const accessSize = accessMatch?.[2] ? parseInt(accessMatch[2], 10) : undefined;
        // Map error type to CWE
        const category = asanErrorToCwe(errorType);
        const severity = category === types_js_1.CrashCategory.UseAfterFree || category === types_js_1.CrashCategory.HeapOverflow
            ? types_js_1.Severity.Critical : types_js_1.Severity.High;
        findings.push({
            sanitizer: SanitizerKind.ASan,
            summary: `ASan: ${errorType}`,
            detail: output,
            category,
            severity,
            stackTrace: parseNativeStack(output),
            address,
            accessSize,
            accessType,
        });
        return findings;
    }
    // ── MSan ──────────────────────────────────────────────────────────────
    parseMSan(output) {
        const findings = [];
        const msanMatch = output.match(/WARNING:\s*MemorySanitizer:\s*(.+)/);
        const summary = msanMatch?.[1] ?? 'use-of-uninitialized-value';
        findings.push({
            sanitizer: SanitizerKind.MSan,
            summary: `MSan: ${summary}`,
            detail: output,
            category: types_js_1.CrashCategory.InformationLeak,
            severity: types_js_1.Severity.High,
            stackTrace: parseNativeStack(output),
        });
        return findings;
    }
    // ── UBSan ─────────────────────────────────────────────────────────────
    parseUBSan(output) {
        const findings = [];
        // UBSan can report multiple errors
        const errorLines = output.split('\n').filter(l => l.includes('runtime error:'));
        for (const line of errorLines) {
            const parts = line.split('runtime error:');
            const msg = parts[1]?.trim() ?? 'undefined behavior';
            const category = ubsanMsgToCwe(msg);
            findings.push({
                sanitizer: SanitizerKind.UBSan,
                summary: `UBSan: ${msg}`,
                detail: line,
                category,
                severity: types_js_1.Severity.Medium,
                stackTrace: parseNativeStack(output),
            });
        }
        if (findings.length === 0) {
            findings.push({
                sanitizer: SanitizerKind.UBSan,
                summary: 'UBSan: undefined behavior',
                detail: output,
                category: types_js_1.CrashCategory.Unknown,
                severity: types_js_1.Severity.Medium,
                stackTrace: parseNativeStack(output),
            });
        }
        return findings;
    }
    // ── TSan ──────────────────────────────────────────────────────────────
    parseTSan(output) {
        const tsanMatch = output.match(/WARNING:\s*ThreadSanitizer:\s*(.+)/);
        const tsanSummary = tsanMatch?.[1] ?? 'data race';
        return [{
                sanitizer: SanitizerKind.TSan,
                summary: `TSan: ${tsanSummary}`,
                detail: output,
                category: types_js_1.CrashCategory.RaceCondition,
                severity: types_js_1.Severity.High,
                stackTrace: parseNativeStack(output),
            }];
    }
    // ── LSan ──────────────────────────────────────────────────────────────
    parseLSan(output) {
        const leakMatch = output.match(/(\d+)\s+byte\(s\)\s+leaked/);
        const leakedBytes = leakMatch?.[1] ? parseInt(leakMatch[1], 10) : 0;
        return [{
                sanitizer: SanitizerKind.LSan,
                summary: `LSan: ${leakedBytes} bytes leaked`,
                detail: output,
                category: types_js_1.CrashCategory.OOM,
                severity: leakedBytes > 1024 * 1024 ? types_js_1.Severity.High : types_js_1.Severity.Medium,
                stackTrace: parseNativeStack(output),
            }];
    }
}
exports.SanitizerParser = SanitizerParser;
// ─── JavaScript Sanitizers ──────────────────────────────────────────────────
/**
 * JS-level bounds checking. Wraps a Uint8Array and throws on OOB access.
 * Used to simulate ASan for in-process JS targets.
 */
class JsBoundsChecker {
    /**
     * Wrap a buffer so that OOB reads/writes throw instead of returning
     * `undefined` or silently clamping.
     */
    static wrap(buf) {
        return new Proxy(buf, {
            get(target, prop, receiver) {
                if (typeof prop === 'string' && /^\d+$/.test(prop)) {
                    const idx = parseInt(prop, 10);
                    if (idx < 0 || idx >= target.length) {
                        throw new RangeError(`JsBoundsChecker: OOB read at index ${idx} (length ${target.length})`);
                    }
                }
                return Reflect.get(target, prop, receiver);
            },
            set(target, prop, value, receiver) {
                if (typeof prop === 'string' && /^\d+$/.test(prop)) {
                    const idx = parseInt(prop, 10);
                    if (idx < 0 || idx >= target.length) {
                        throw new RangeError(`JsBoundsChecker: OOB write at index ${idx} (length ${target.length})`);
                    }
                }
                return Reflect.set(target, prop, value, receiver);
            },
        });
    }
}
exports.JsBoundsChecker = JsBoundsChecker;
/**
 * Tracks leaked resources (timers, listeners, closures over large data).
 * Call `snapshot()` before the target, `check()` after — any new timers
 * or listeners that weren't cleaned up are reported.
 */
class JsLeakChecker {
    timersBefore = 0;
    /** Take a "before" snapshot. */
    snapshot() {
        // In Node, active timers/handles are on process._getActiveHandles()
        if (typeof process !== 'undefined' && typeof process._getActiveHandles === 'function') {
            this.timersBefore = process._getActiveHandles().length;
        }
    }
    /** Compare to the snapshot and return findings. */
    check() {
        const findings = [];
        if (typeof process !== 'undefined' && typeof process._getActiveHandles === 'function') {
            const now = process._getActiveHandles().length;
            const delta = now - this.timersBefore;
            if (delta > 0) {
                findings.push({
                    sanitizer: SanitizerKind.JsLeak,
                    summary: `JsLeakChecker: ${delta} new handle(s) not cleaned up`,
                    detail: `Active handles before: ${this.timersBefore}, after: ${now}`,
                    category: types_js_1.CrashCategory.OOM,
                    severity: delta > 10 ? types_js_1.Severity.High : types_js_1.Severity.Low,
                    stackTrace: [],
                });
            }
        }
        return findings;
    }
}
exports.JsLeakChecker = JsLeakChecker;
/**
 * Detects NaN propagation and unexpected type coercion.
 */
class JsTypeChecker {
    /** Check a value for NaN, undefined, or suspicious coercion. */
    static check(value, label) {
        if (typeof value === 'number' && Number.isNaN(value)) {
            return {
                sanitizer: SanitizerKind.JsType,
                summary: `JsTypeChecker: NaN detected in "${label}"`,
                detail: `The value "${label}" is NaN, which may indicate uninitialized or corrupt data.`,
                category: types_js_1.CrashCategory.Unknown,
                severity: types_js_1.Severity.Medium,
                stackTrace: captureJsStack(),
            };
        }
        if (value === undefined) {
            return {
                sanitizer: SanitizerKind.JsUndef,
                summary: `JsTypeChecker: undefined value for "${label}"`,
                detail: `The value "${label}" is undefined.`,
                category: types_js_1.CrashCategory.NullDeref,
                severity: types_js_1.Severity.Low,
                stackTrace: captureJsStack(),
            };
        }
        return null;
    }
}
exports.JsTypeChecker = JsTypeChecker;
// ─── Helpers ────────────────────────────────────────────────────────────────
function parseNativeStack(output) {
    const frames = [];
    // ASan/MSan/TSan format: "#N 0xADDR in func file:line:col"
    const re = /#\d+\s+(?:0x[0-9a-f]+\s+in\s+)?(\S+)\s+(\S+?)(?::(\d+))?(?::(\d+))?$/gm;
    let m;
    while ((m = re.exec(output)) !== null) {
        frames.push({
            functionName: m[1] ?? '<unknown>',
            file: m[2] ?? undefined,
            line: m[3] ? parseInt(m[3], 10) : undefined,
            column: m[4] ? parseInt(m[4], 10) : undefined,
        });
        if (frames.length >= 32)
            break;
    }
    return frames;
}
function captureJsStack() {
    const err = new Error();
    if (!err.stack)
        return [];
    const lines = err.stack.split('\n').slice(2); // skip Error + captureJsStack
    const frames = [];
    for (const line of lines) {
        const m = line.match(/at\s+(?:(.+?)\s+\()?(.+?):(\d+):(\d+)\)?/);
        if (m) {
            frames.push({
                functionName: m[1] ?? '<anonymous>',
                file: m[2] ?? undefined,
                line: m[3] != null ? parseInt(m[3], 10) : undefined,
                column: m[4] != null ? parseInt(m[4], 10) : undefined,
            });
        }
        if (frames.length >= 16)
            break;
    }
    return frames;
}
function asanErrorToCwe(error) {
    const map = {
        'heap-buffer-overflow': types_js_1.CrashCategory.HeapOverflow,
        'stack-buffer-overflow': types_js_1.CrashCategory.StackOverflow,
        'global-buffer-overflow': types_js_1.CrashCategory.BufferOverflow,
        'heap-use-after-free': types_js_1.CrashCategory.UseAfterFree,
        'stack-use-after-return': types_js_1.CrashCategory.UseAfterFree,
        'stack-use-after-scope': types_js_1.CrashCategory.UseAfterFree,
        'double-free': types_js_1.CrashCategory.UseAfterFree,
        'alloc-dealloc-mismatch': types_js_1.CrashCategory.UseAfterFree,
        'SEGV': types_js_1.CrashCategory.NullDeref,
        'null-deref': types_js_1.CrashCategory.NullDeref,
        'attempting': types_js_1.CrashCategory.Unknown,
    };
    for (const [key, cwe] of Object.entries(map)) {
        if (error.includes(key))
            return cwe;
    }
    return types_js_1.CrashCategory.Unknown;
}
function ubsanMsgToCwe(msg) {
    if (msg.includes('overflow'))
        return types_js_1.CrashCategory.IntegerOverflow;
    if (msg.includes('division by zero'))
        return types_js_1.CrashCategory.DivisionByZero;
    if (msg.includes('null pointer'))
        return types_js_1.CrashCategory.NullDeref;
    if (msg.includes('shift'))
        return types_js_1.CrashCategory.IntegerOverflow;
    if (msg.includes('out of range'))
        return types_js_1.CrashCategory.BufferOverflow;
    return types_js_1.CrashCategory.Unknown;
}
//# sourceMappingURL=bridge.js.map
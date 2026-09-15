/**
 * LombokFuzzer — Crash Analyzer
 *
 * Detects, classifies, deduplicates, and triages crashes. Each crash is
 * assigned a CWE category and severity based on signal, sanitizer output,
 * and stack analysis.
 *
 * @license Apache-2.0
 */
import { CrashCategory, Severity } from '../core/types.js';
import { stackHash as computeStackHash } from '../utils/hash.js';
export class CrashAnalyzer {
    config;
    _crashes = new Map();
    _stackHashes = new Set();
    constructor(config) {
        this.config = config;
    }
    /** Analyze an execution result and return crash info (or null if no crash). */
    analyze(result) {
        if (!result.crashed)
            return null;
        const frames = this.parseStackTrace(result.stderr ?? '');
        const hash = computeStackHash(frames, 5);
        const isDuplicate = this.config.deduplicateCrashes && this._stackHashes.has(hash);
        const category = this.classifyCrash(result, frames);
        const severity = this.assessSeverity(category, result);
        const crash = {
            id: hash,
            input: result.input,
            stackTrace: frames,
            category,
            severity,
            isDuplicate,
            duplicateOf: isDuplicate ? hash : undefined,
            signal: this.signalName(result.signal),
            sanitizerReport: result.sanitizerOutput,
            discoveredAt: Date.now(),
            reproCount: 1,
        };
        if (isDuplicate) {
            const existing = this._crashes.get(hash);
            if (existing)
                existing.reproCount++;
        }
        else {
            this._stackHashes.add(hash);
            this._crashes.set(hash, crash);
        }
        return crash;
    }
    /** Parse a stack trace string into frames. */
    parseStackTrace(stderr) {
        const frames = [];
        const lines = stderr.split('\n');
        for (const line of lines) {
            const frame = this.parseFrame(line);
            if (frame)
                frames.push(frame);
        }
        return frames;
    }
    /** Try to parse a single stack frame line. */
    parseFrame(line) {
        // Node.js style: "    at functionName (file:line:column)"
        const nodeMatch = line.match(/^\s+at\s+(.+?)\s+\((.+?):(\d+):(\d+)\)/);
        if (nodeMatch) {
            return {
                functionName: nodeMatch[1],
                file: nodeMatch[2],
                line: parseInt(nodeMatch[3], 10),
                column: parseInt(nodeMatch[4], 10),
            };
        }
        // Node.js anonymous: "    at file:line:column"
        const nodeAnon = line.match(/^\s+at\s+(.+?):(\d+):(\d+)/);
        if (nodeAnon) {
            return {
                functionName: '<anonymous>',
                file: nodeAnon[1],
                line: parseInt(nodeAnon[2], 10),
                column: parseInt(nodeAnon[3], 10),
            };
        }
        // ASan/native style: "#0 0xaddr in function file:line"
        const asanMatch = line.match(/#\d+\s+(0x[0-9a-fA-F]+)\s+in\s+(\S+)\s+(.+?):(\d+)/);
        if (asanMatch) {
            return {
                functionName: asanMatch[2],
                file: asanMatch[3],
                line: parseInt(asanMatch[4], 10),
                address: BigInt(asanMatch[1]),
            };
        }
        // GDB style: "#0  function (args) at file:line"
        const gdbMatch = line.match(/#\d+\s+(.+?)\s+\(.*\)\s+at\s+(.+?):(\d+)/);
        if (gdbMatch) {
            return {
                functionName: gdbMatch[1],
                file: gdbMatch[2],
                line: parseInt(gdbMatch[3], 10),
            };
        }
        return null;
    }
    /** Classify crash into a CWE category. */
    classifyCrash(result, _frames) {
        // Sanitizer (ASan/MSan/etc.) output is multi-line and the key token may
        // appear anywhere, so match it in full. For JS errors and injection
        // heuristics we match only the error *message* (first line) — matching the
        // full stack trace produces false positives, because file paths and
        // framework frame names contain substrings like "exec", ".." and "script".
        const sanitizer = (result.sanitizerOutput ?? '').toLowerCase();
        const stderr = result.stderr ?? '';
        const message = firstLine(stderr).toLowerCase();
        // ── Sanitizer reports (match full output) ──
        if (sanitizer.includes('heap-buffer-overflow'))
            return CrashCategory.HeapOverflow;
        if (sanitizer.includes('stack-buffer-overflow'))
            return CrashCategory.StackOverflow;
        if (sanitizer.includes('heap-use-after-free'))
            return CrashCategory.UseAfterFree;
        if (sanitizer.includes('null') && sanitizer.includes('dereference'))
            return CrashCategory.NullDeref;
        if (sanitizer.includes('integer-overflow'))
            return CrashCategory.IntegerOverflow;
        if (sanitizer.includes('data race'))
            return CrashCategory.RaceCondition;
        if (sanitizer.includes('out-of-bounds') || sanitizer.includes('out of bounds'))
            return CrashCategory.BufferOverflow;
        // ── Message-based classification (match first line only) ──
        if (message.includes('out of memory') || message.includes('heap out of memory'))
            return CrashCategory.OOM;
        if (message.includes('integer overflow'))
            return CrashCategory.IntegerOverflow;
        if (message.includes('division by zero') || message.includes('divide by zero'))
            return CrashCategory.DivisionByZero;
        if (message.includes('format string'))
            return CrashCategory.FormatString;
        if (message.includes('assertion'))
            return CrashCategory.Assertion;
        if (message.includes('data race') || message.includes('race condition'))
            return CrashCategory.RaceCondition;
        // Signal-based (native harnesses)
        if (result.signal === 11)
            return CrashCategory.BufferOverflow; // SIGSEGV
        if (result.signal === 6)
            return CrashCategory.Assertion; // SIGABRT
        if (result.signal === 8)
            return CrashCategory.DivisionByZero; // SIGFPE
        // ── JavaScript error types (match message line) ──
        if (message.includes('rangeerror')) {
            if (message.includes('call stack') || message.includes('recursion'))
                return CrashCategory.StackOverflow;
            if (message.includes('buffer') || message.includes('over-read') || message.includes('overread') ||
                message.includes('out of bounds') || message.includes('out-of-bounds') ||
                message.includes('offset') || message.includes('index')) {
                return CrashCategory.BufferOverflow;
            }
            if (message.includes('invalid array length') || message.includes('invalid string length')) {
                return CrashCategory.IntegerOverflow;
            }
            return CrashCategory.BufferOverflow; // generic bounds violation
        }
        if (message.includes('typeerror') &&
            (message.includes('null') || message.includes('undefined') ||
                message.includes('reading') || message.includes('properties of'))) {
            return CrashCategory.NullDeref;
        }
        // ── Injection / web categories — require specific, unambiguous phrases ──
        if (message.includes('sql') && (message.includes('injection') || message.includes('syntax error'))) {
            return CrashCategory.SQLInjection;
        }
        if (message.includes('command injection') || message.includes('child_process') ||
            message.includes('spawn ') || message.includes('exec(')) {
            return CrashCategory.CommandInjection;
        }
        if (message.includes('path traversal') || message.includes('directory traversal')) {
            return CrashCategory.PathTraversal;
        }
        if (message.includes('cross-site scripting') || message.includes('xss'))
            return CrashCategory.XSS;
        if (message.includes('ssrf') || message.includes('server-side request forgery'))
            return CrashCategory.SSRF;
        if (message.includes('deserializ'))
            return CrashCategory.Deserialization;
        return CrashCategory.Unknown;
    }
    /** Assess severity based on crash category. */
    assessSeverity(category, _result) {
        // Critical: exploitable memory corruption, injection
        const critical = new Set([
            CrashCategory.HeapOverflow,
            CrashCategory.StackOverflow,
            CrashCategory.UseAfterFree,
            CrashCategory.CommandInjection,
            CrashCategory.SQLInjection,
            CrashCategory.Deserialization,
            CrashCategory.SSRF,
        ]);
        // High: other memory safety issues
        const high = new Set([
            CrashCategory.BufferOverflow,
            CrashCategory.FormatString,
            CrashCategory.XSS,
            CrashCategory.PathTraversal,
            CrashCategory.RaceCondition,
        ]);
        // Medium: logic/overflow issues
        const medium = new Set([
            CrashCategory.IntegerOverflow,
            CrashCategory.NullDeref,
            CrashCategory.CryptoWeakness,
            CrashCategory.InformationLeak,
        ]);
        if (critical.has(category))
            return Severity.Critical;
        if (high.has(category))
            return Severity.High;
        if (medium.has(category))
            return Severity.Medium;
        if (category === CrashCategory.Assertion || category === CrashCategory.DivisionByZero) {
            return Severity.Low;
        }
        if (category === CrashCategory.OOM || category === CrashCategory.Timeout) {
            return Severity.Info;
        }
        return Severity.Medium;
    }
    /** Convert signal number to name. */
    signalName(signal) {
        const names = {
            0: 'none', 1: 'SIGHUP', 2: 'SIGINT', 3: 'SIGQUIT',
            4: 'SIGILL', 6: 'SIGABRT', 7: 'SIGBUS', 8: 'SIGFPE',
            9: 'SIGKILL', 11: 'SIGSEGV', 13: 'SIGPIPE', 14: 'SIGALRM',
            15: 'SIGTERM',
        };
        return names[signal] ?? `SIG${signal}`;
    }
    /** Number of unique crashes. */
    get uniqueCount() {
        return this._crashes.size;
    }
    /** All unique crashes. */
    get all() {
        return this._crashes;
    }
    /** Get crashes by severity. */
    getBySeverity(severity) {
        return [...this._crashes.values()].filter(c => c.severity === severity);
    }
    /** Get crashes by category (CWE). */
    getByCategory(category) {
        return [...this._crashes.values()].filter(c => c.category === category);
    }
    /** Clear all crash data. */
    clear() {
        this._crashes.clear();
        this._stackHashes.clear();
    }
}
// ─── Helpers ──────────────────────────────────────────────────────────────
/**
 * Return the first non-empty line of a multi-line string (the "ErrorName:
 * message" line of a stack trace), trimmed. Used to classify on the error
 * message rather than the full stack, whose file paths and framework frame
 * names would otherwise trigger false substring matches.
 */
function firstLine(text) {
    const lines = text.split('\n');
    for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.length > 0)
            return trimmed;
    }
    return '';
}
//# sourceMappingURL=analyzer.js.map
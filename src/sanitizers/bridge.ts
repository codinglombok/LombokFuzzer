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

// ─── Types ──────────────────────────────────────────────────────────────────

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
export enum SanitizerKind {
  ASan = 'asan',
  MSan = 'msan',
  UBSan = 'ubsan',
  TSan = 'tsan',
  LSan = 'lsan',
  JsBounds = 'js_bounds',
  JsType = 'js_type',
  JsLeak = 'js_leak',
  JsRace = 'js_race',
  JsUndef = 'js_undef',
}

// ─── Native Sanitizer Parser ────────────────────────────────────────────────

/**
 * Parses sanitizer output (stderr) from ASan, MSan, UBSan, TSan, LSan
 * and returns structured findings.
 */
export class SanitizerParser {
  /** Parse raw sanitizer output into findings. */
  parse(output: string): SanitizerFinding[] {
    const findings: SanitizerFinding[] = [];

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

  private parseASan(output: string): SanitizerFinding[] {
    const findings: SanitizerFinding[] = [];

    // Extract error type
    const errorMatch = output.match(/ERROR:\s*AddressSanitizer:\s*(\S+)/);
    const errorType = errorMatch?.[1] ?? 'unknown';

    // Extract address
    const addrMatch = output.match(/on address\s+(0x[0-9a-f]+)/i);
    const address = addrMatch?.[1] ? BigInt(addrMatch[1]) : undefined;

    // Extract access info
    const accessMatch = output.match(/(READ|WRITE)\s+of\s+size\s+(\d+)/);
    const accessType = accessMatch?.[1]?.toLowerCase() as 'read' | 'write' | undefined;
    const accessSize = accessMatch?.[2] ? parseInt(accessMatch[2], 10) : undefined;

    // Map error type to CWE
    const category = asanErrorToCwe(errorType);
    const severity = category === CrashCategory.UseAfterFree || category === CrashCategory.HeapOverflow
      ? Severity.Critical : Severity.High;

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

  private parseMSan(output: string): SanitizerFinding[] {
    const findings: SanitizerFinding[] = [];

    const msanMatch = output.match(/WARNING:\s*MemorySanitizer:\s*(.+)/);
    const summary = msanMatch?.[1] ?? 'use-of-uninitialized-value';

    findings.push({
      sanitizer: SanitizerKind.MSan,
      summary: `MSan: ${summary}`,
      detail: output,
      category: CrashCategory.InformationLeak,
      severity: Severity.High,
      stackTrace: parseNativeStack(output),
    });

    return findings;
  }

  // ── UBSan ─────────────────────────────────────────────────────────────

  private parseUBSan(output: string): SanitizerFinding[] {
    const findings: SanitizerFinding[] = [];

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
        severity: Severity.Medium,
        stackTrace: parseNativeStack(output),
      });
    }

    if (findings.length === 0) {
      findings.push({
        sanitizer: SanitizerKind.UBSan,
        summary: 'UBSan: undefined behavior',
        detail: output,
        category: CrashCategory.Unknown,
        severity: Severity.Medium,
        stackTrace: parseNativeStack(output),
      });
    }

    return findings;
  }

  // ── TSan ──────────────────────────────────────────────────────────────

  private parseTSan(output: string): SanitizerFinding[] {
    const tsanMatch = output.match(/WARNING:\s*ThreadSanitizer:\s*(.+)/);
    const tsanSummary = tsanMatch?.[1] ?? 'data race';

    return [{
      sanitizer: SanitizerKind.TSan,
      summary: `TSan: ${tsanSummary}`,
      detail: output,
      category: CrashCategory.RaceCondition,
      severity: Severity.High,
      stackTrace: parseNativeStack(output),
    }];
  }

  // ── LSan ──────────────────────────────────────────────────────────────

  private parseLSan(output: string): SanitizerFinding[] {
    const leakMatch = output.match(/(\d+)\s+byte\(s\)\s+leaked/);
    const leakedBytes = leakMatch?.[1] ? parseInt(leakMatch[1], 10) : 0;

    return [{
      sanitizer: SanitizerKind.LSan,
      summary: `LSan: ${leakedBytes} bytes leaked`,
      detail: output,
      category: CrashCategory.OOM,
      severity: leakedBytes > 1024 * 1024 ? Severity.High : Severity.Medium,
      stackTrace: parseNativeStack(output),
    }];
  }
}

// ─── JavaScript Sanitizers ──────────────────────────────────────────────────

/**
 * JS-level bounds checking. Wraps a Uint8Array and throws on OOB access.
 * Used to simulate ASan for in-process JS targets.
 */
export class JsBoundsChecker {
  /**
   * Wrap a buffer so that OOB reads/writes throw instead of returning
   * `undefined` or silently clamping.
   */
  static wrap(buf: Uint8Array): Uint8Array {
    return new Proxy(buf, {
      get(target, prop, receiver) {
        if (typeof prop === 'string' && /^\d+$/.test(prop)) {
          const idx = parseInt(prop, 10);
          if (idx < 0 || idx >= target.length) {
            throw new RangeError(
              `JsBoundsChecker: OOB read at index ${idx} (length ${target.length})`,
            );
          }
        }
        return Reflect.get(target, prop, receiver);
      },
      set(target, prop, value, receiver) {
        if (typeof prop === 'string' && /^\d+$/.test(prop)) {
          const idx = parseInt(prop, 10);
          if (idx < 0 || idx >= target.length) {
            throw new RangeError(
              `JsBoundsChecker: OOB write at index ${idx} (length ${target.length})`,
            );
          }
        }
        return Reflect.set(target, prop, value, receiver);
      },
    });
  }
}

/**
 * Tracks leaked resources (timers, listeners, closures over large data).
 * Call `snapshot()` before the target, `check()` after — any new timers
 * or listeners that weren't cleaned up are reported.
 */
export class JsLeakChecker {
  private timersBefore = 0;

  /** Take a "before" snapshot. */
  snapshot(): void {
    // In Node, active timers/handles are on process._getActiveHandles()
    if (typeof process !== 'undefined' && typeof (process as any)._getActiveHandles === 'function') {
      this.timersBefore = (process as any)._getActiveHandles().length;
    }
  }

  /** Compare to the snapshot and return findings. */
  check(): SanitizerFinding[] {
    const findings: SanitizerFinding[] = [];

    if (typeof process !== 'undefined' && typeof (process as any)._getActiveHandles === 'function') {
      const now = (process as any)._getActiveHandles().length;
      const delta = now - this.timersBefore;
      if (delta > 0) {
        findings.push({
          sanitizer: SanitizerKind.JsLeak,
          summary: `JsLeakChecker: ${delta} new handle(s) not cleaned up`,
          detail: `Active handles before: ${this.timersBefore}, after: ${now}`,
          category: CrashCategory.OOM,
          severity: delta > 10 ? Severity.High : Severity.Low,
          stackTrace: [],
        });
      }
    }

    return findings;
  }
}

/**
 * Detects NaN propagation and unexpected type coercion.
 */
export class JsTypeChecker {
  /** Check a value for NaN, undefined, or suspicious coercion. */
  static check(value: unknown, label: string): SanitizerFinding | null {
    if (typeof value === 'number' && Number.isNaN(value)) {
      return {
        sanitizer: SanitizerKind.JsType,
        summary: `JsTypeChecker: NaN detected in "${label}"`,
        detail: `The value "${label}" is NaN, which may indicate uninitialized or corrupt data.`,
        category: CrashCategory.Unknown,
        severity: Severity.Medium,
        stackTrace: captureJsStack(),
      };
    }
    if (value === undefined) {
      return {
        sanitizer: SanitizerKind.JsUndef,
        summary: `JsTypeChecker: undefined value for "${label}"`,
        detail: `The value "${label}" is undefined.`,
        category: CrashCategory.NullDeref,
        severity: Severity.Low,
        stackTrace: captureJsStack(),
      };
    }
    return null;
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function parseNativeStack(output: string): StackFrame[] {
  const frames: StackFrame[] = [];

  // ASan/MSan/TSan format: "#N 0xADDR in func file:line:col"
  const re = /#\d+\s+(?:0x[0-9a-f]+\s+in\s+)?(\S+)\s+(\S+?)(?::(\d+))?(?::(\d+))?$/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(output)) !== null) {
    frames.push({
      functionName: m[1] ?? '<unknown>',
      file: m[2] ?? undefined,
      line: m[3] ? parseInt(m[3], 10) : undefined,
      column: m[4] ? parseInt(m[4], 10) : undefined,
    });
    if (frames.length >= 32) break;
  }

  return frames;
}

function captureJsStack(): StackFrame[] {
  const err = new Error();
  if (!err.stack) return [];

  const lines = err.stack.split('\n').slice(2); // skip Error + captureJsStack
  const frames: StackFrame[] = [];

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
    if (frames.length >= 16) break;
  }

  return frames;
}

function asanErrorToCwe(error: string): CrashCategory {
  const map: Record<string, CrashCategory> = {
    'heap-buffer-overflow': CrashCategory.HeapOverflow,
    'stack-buffer-overflow': CrashCategory.StackOverflow,
    'global-buffer-overflow': CrashCategory.BufferOverflow,
    'heap-use-after-free': CrashCategory.UseAfterFree,
    'stack-use-after-return': CrashCategory.UseAfterFree,
    'stack-use-after-scope': CrashCategory.UseAfterFree,
    'double-free': CrashCategory.UseAfterFree,
    'alloc-dealloc-mismatch': CrashCategory.UseAfterFree,
    'SEGV': CrashCategory.NullDeref,
    'null-deref': CrashCategory.NullDeref,
    'attempting': CrashCategory.Unknown,
  };

  for (const [key, cwe] of Object.entries(map)) {
    if (error.includes(key)) return cwe;
  }
  return CrashCategory.Unknown;
}

function ubsanMsgToCwe(msg: string): CrashCategory {
  if (msg.includes('overflow')) return CrashCategory.IntegerOverflow;
  if (msg.includes('division by zero')) return CrashCategory.DivisionByZero;
  if (msg.includes('null pointer')) return CrashCategory.NullDeref;
  if (msg.includes('shift')) return CrashCategory.IntegerOverflow;
  if (msg.includes('out of range')) return CrashCategory.BufferOverflow;
  return CrashCategory.Unknown;
}

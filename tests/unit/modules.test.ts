/**
 * LombokFuzzer — Tests for v0.2.0 modules
 *
 * generators, harness, reporters, sanitizers, differential, ecc
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import { PRNG } from '../../src/utils/prng.js';
import { fnv1a64 } from '../../src/utils/hash.js';
import type { FuzzInput, FuzzStats, CrashInfo, StackFrame } from '../../src/core/types.js';
import { Severity, CrashCategory, FuzzEvent } from '../../src/core/types.js';
import { GrammarEngine } from '../../src/grammar/engine.js';

// ─── Generators ─────────────────────────────────────────────────────────────

import {
  GeneratorEngine,
  GeneratorKind,
} from '../../src/generators/engine.js';

describe('GeneratorEngine', () => {
  let prng: PRNG;

  beforeEach(() => {
    prng = new PRNG(42n);
  });

  it('should generate random inputs by default', () => {
    const gen = new GeneratorEngine({}, prng);
    const result = gen.generate();
    expect(result.kind).toBe(GeneratorKind.Random);
    expect(result.data.length).toBeGreaterThan(0);
  });

  it('should respect min/max size constraints', () => {
    const gen = new GeneratorEngine({ minSize: 10, maxSize: 20 }, prng);
    for (let i = 0; i < 100; i++) {
      const result = gen.generate();
      expect(result.data.length).toBeGreaterThanOrEqual(10);
      expect(result.data.length).toBeLessThanOrEqual(20);
    }
  });

  it('should generate grammar-based inputs', () => {
    const grammarEngine = new GrammarEngine(prng);
    const jsonGrammar = GrammarEngine.jsonGrammar();

    const gen = new GeneratorEngine({
      kinds: [GeneratorKind.Grammar],
      grammars: new Map([['json', jsonGrammar]]),
    }, prng);

    const result = gen.generate();
    expect(result.kind).toBe(GeneratorKind.Grammar);
    expect(result.grammarName).toBe('json');
    expect(result.data.length).toBeGreaterThan(0);
  });

  it('should generate dictionary-based inputs', () => {
    const tokens = [
      new TextEncoder().encode('SELECT'),
      new TextEncoder().encode('INSERT'),
      new TextEncoder().encode('DELETE'),
    ];

    const gen = new GeneratorEngine({
      kinds: [GeneratorKind.Dictionary],
      dictionaryTokens: tokens,
    }, prng);

    const result = gen.generate();
    expect(result.kind).toBe(GeneratorKind.Dictionary);
    expect(result.data.length).toBeGreaterThan(0);
  });

  it('should generate protocol-template inputs', () => {
    const httpTemplate = new TextEncoder().encode('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n');

    const gen = new GeneratorEngine({
      kinds: [GeneratorKind.ProtocolTemplate],
      protocolTemplates: new Map([['HTTP', [httpTemplate]]]),
    }, prng);

    const result = gen.generate();
    expect(result.kind).toBe(GeneratorKind.ProtocolTemplate);
    expect(result.protocolName).toBe('HTTP');
    expect(result.data.length).toBe(httpTemplate.length);
  });

  it('should convert result to FuzzInput', () => {
    const gen = new GeneratorEngine({}, prng);
    const result = gen.generate();
    const input = gen.toFuzzInput(result);
    expect(input.data).toEqual(result.data);
    expect(input.hash).toBeDefined();
    expect(input.depth).toBe(0);
    expect(input.tags.get('generator')).toBe(result.kind);
  });

  it('should track generation history', () => {
    const gen = new GeneratorEngine({}, prng);
    expect(gen.stats.totalGenerated).toBe(0);

    gen.generate();
    gen.generate();
    gen.generate();

    expect(gen.stats.totalGenerated).toBe(3);
    expect(gen.stats.recentInputs.length).toBe(3);
  });

  it('should record coverage and crash hits', () => {
    const gen = new GeneratorEngine({}, prng);
    gen.recordCoverageHit();
    gen.recordCoverageHit();
    gen.recordCrashHit();
    expect(gen.stats.coverageHits).toBe(2);
    expect(gen.stats.crashHits).toBe(1);
  });

  it('should support custom generators', () => {
    const gen = new GeneratorEngine({
      kinds: [GeneratorKind.Custom],
      customGenerator: (rng) => rng.randomBytes(5),
    }, prng);

    const result = gen.generate();
    expect(result.kind).toBe(GeneratorKind.Custom);
    expect(result.data.length).toBe(5);
  });

  it('should fallback to random when no grammars registered', () => {
    const gen = new GeneratorEngine({
      kinds: [GeneratorKind.Grammar],
      grammars: new Map(),
    }, prng);

    const result = gen.generate();
    expect(result.kind).toBe(GeneratorKind.Random);
  });

  it('should support addGrammar and addProtocolTemplate', () => {
    const gen = new GeneratorEngine({}, prng);
    const grammar = GrammarEngine.jsonGrammar();
    gen.addGrammar('json', grammar);
    gen.addProtocolTemplate('HTTP', [new Uint8Array([0x47, 0x45, 0x54])]);

    expect(gen.config.grammars.has('json')).toBe(true);
    expect(gen.config.protocolTemplates.has('HTTP')).toBe(true);
  });
});

// ─── Harness ────────────────────────────────────────────────────────────────

import {
  InProcessHarness,
  HarnessManager,
} from '../../src/harness/manager.js';

function makeFuzzInput(data: Uint8Array): FuzzInput {
  return {
    data,
    hash: fnv1a64(data),
    lineage: [],
    depth: 0,
    energy: 1,
    executions: 0,
    createdAt: Date.now(),
    tags: new Map(),
  };
}

describe('InProcessHarness', () => {
  it('should execute a target function successfully', async () => {
    const harness = new InProcessHarness((data) => {
      // no-op target
    });
    await harness.init();

    const input = makeFuzzInput(new Uint8Array([1, 2, 3]));
    const result = await harness.execute(input);

    expect(result.crashed).toBe(false);
    expect(result.exitCode).toBe(0);
    expect(result.durationUs).toBeGreaterThanOrEqual(0);
    expect(input.executions).toBe(1);

    await harness.destroy();
  });

  it('should detect crashes', async () => {
    const harness = new InProcessHarness(() => {
      throw new Error('segfault simulation');
    });
    await harness.init();

    const input = makeFuzzInput(new Uint8Array([0xFF]));
    const result = await harness.execute(input);

    expect(result.crashed).toBe(true);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('segfault simulation');

    await harness.destroy();
  });

  it('should handle non-Error throws', async () => {
    const harness = new InProcessHarness(() => {
      throw 'string error';
    });
    await harness.init();

    const input = makeFuzzInput(new Uint8Array([0]));
    const result = await harness.execute(input);

    expect(result.crashed).toBe(true);
    expect(result.stderr).toBe('string error');

    await harness.destroy();
  });
});

describe('HarnessManager', () => {
  it('should create InProcess harness from config', async () => {
    const mgr = new HarnessManager();
    const harness = await mgr.init({
      mode: 'in_process' as any,
      targetFunction: () => {},
    });

    expect(harness.kind).toBe('in_process');

    const input = makeFuzzInput(new Uint8Array([1]));
    const result = await mgr.execute(input);

    expect(result.crashed).toBe(false);
    expect(mgr.getStats().totalExecutions).toBe(1);

    await mgr.destroy();
  });

  it('should track crash stats', async () => {
    const mgr = new HarnessManager();
    await mgr.init({
      mode: 'in_process' as any,
      targetFunction: () => { throw new Error('boom'); },
    });

    const input = makeFuzzInput(new Uint8Array([1]));
    await mgr.execute(input);

    expect(mgr.getStats().totalCrashes).toBe(1);
    await mgr.destroy();
  });

  it('should throw on missing targetFunction for InProcess', async () => {
    const mgr = new HarnessManager();
    await expect(mgr.init({ mode: 'in_process' as any }))
      .rejects.toThrow('requires targetFunction');
  });

  it('should throw on missing targetBinary for ForkServer', async () => {
    const mgr = new HarnessManager();
    await expect(mgr.init({ mode: 'fork_server' as any }))
      .rejects.toThrow('requires targetBinary');
  });

  it('should throw on missing networkTarget for Network', async () => {
    const mgr = new HarnessManager();
    await expect(mgr.init({ mode: 'network' as any }))
      .rejects.toThrow('requires networkTarget');
  });

  it('should throw on missing wasmModule for WASM', async () => {
    const mgr = new HarnessManager();
    await expect(mgr.init({ mode: 'wasm' as any }))
      .rejects.toThrow('requires wasmModule');
  });

  it('should throw on execute before init', async () => {
    const mgr = new HarnessManager();
    const input = makeFuzzInput(new Uint8Array([1]));
    await expect(mgr.execute(input)).rejects.toThrow('not initialised');
  });
});

// ─── Reporters ──────────────────────────────────────────────────────────────

import {
  ConsoleReporter,
  JsonReporter,
  HtmlReporter,
  CiReporter,
  ReporterRegistry,
} from '../../src/reporters/reporter.js';

function makeStats(overrides: Partial<FuzzStats> = {}): FuzzStats {
  return {
    executionId: 'test-001',
    campaignName: 'test-campaign',
    startedAt: Date.now(),
    elapsedMs: 5000,
    totalExecutions: 1000,
    execsPerSecond: 200,
    peakExecsPerSecond: 250,
    corpusSize: 50,
    corpusTotalBytes: 25000,
    uniqueCrashes: 2,
    uniqueTimeouts: 0,
    coveragePercent: 45.5,
    edgesFound: 100,
    edgesTotal: 220,
    lastNewEdgeAt: Date.now(),
    dictionarySize: 10,
    mutatorHits: new Map(),
    mutatorFinds: new Map(),
    stability: 98.5,
    pendingFavorites: 3,
    currentPhase: 'havoc',
    crashesBySeverity: new Map(),
    ...overrides,
  };
}

function makeCrash(): CrashInfo {
  return {
    id: 'crash-abc123',
    input: makeFuzzInput(new Uint8Array([0xFF, 0xFE])),
    stackTrace: [{
      functionName: 'parseJson',
      file: 'parser.ts',
      line: 42,
      column: 10,
    }],
    category: CrashCategory.NullDeref,
    severity: Severity.High,
    isDuplicate: false,
    signal: 'SIGSEGV',
    discoveredAt: Date.now(),
    reproCount: 1,
  };
}

describe('ConsoleReporter', () => {
  it('should emit start/stats/crash/stop without throwing', () => {
    const reporter = new ConsoleReporter();
    const stats = makeStats();
    const crash = makeCrash();

    // These should not throw
    reporter.onStart(stats);
    reporter.onStats(stats);
    reporter.onCrash(crash);
    reporter.onStop(stats);
    reporter.flush();
  });
});

describe('JsonReporter', () => {
  it('should accumulate NDJSON lines', () => {
    const reporter = new JsonReporter();
    const stats = makeStats();
    const crash = makeCrash();

    reporter.onStart(stats);
    reporter.onStats(stats);
    reporter.onCrash(crash);
    reporter.onStop(stats);

    const lines = reporter.getLines();
    expect(lines.length).toBe(4);

    // Each line should be valid JSON
    for (const line of lines) {
      expect(() => JSON.parse(line)).not.toThrow();
    }

    // First line should be a start event
    const first = JSON.parse(lines[0]!);
    expect(first.event).toBe('start');
    expect(first.stats.campaignName).toBe('test-campaign');

    // Crash event
    const crashLine = JSON.parse(lines[2]!);
    expect(crashLine.event).toBe('crash');
    expect(crashLine.crash.id).toBe('crash-abc123');
  });
});

describe('HtmlReporter', () => {
  it('should render a valid HTML report', () => {
    const reporter = new HtmlReporter();
    const stats = makeStats();
    const crash = makeCrash();

    reporter.onStart(stats);
    reporter.onStats(stats);
    reporter.onCrash(crash);
    reporter.onStop(stats);

    const html = reporter.renderHtml();
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('test-campaign');
    expect(html).toContain('LombokFuzzer');
    expect(html).toContain('crash-abc123');
    expect(html).toContain('lombokcss');
    expect(html).toContain('lombokcharts');
  });
});

describe('CiReporter', () => {
  it('should generate GitHub Actions annotations', () => {
    const reporter = new CiReporter('github');
    const crash = makeCrash();

    reporter.onCrash(crash);

    const annotations = reporter.getAnnotations();
    expect(annotations.length).toBe(1);
    expect(annotations[0]).toContain('::error');
    expect(annotations[0]).toContain('CWE-476');
  });

  it('should generate GitLab CI annotations', () => {
    const reporter = new CiReporter('gitlab');
    const crash = makeCrash();

    reporter.onCrash(crash);

    const annotations = reporter.getAnnotations();
    const parsed = JSON.parse(annotations[0]!);
    expect(parsed.type).toBe('sast');
    expect(parsed.severity).toBe('high');
  });

  it('should generate generic annotations', () => {
    const reporter = new CiReporter('generic');
    const crash = makeCrash();

    reporter.onCrash(crash);

    const annotations = reporter.getAnnotations();
    expect(annotations[0]).toContain('CRASH');
    expect(annotations[0]).toContain('high');
  });
});

describe('ReporterRegistry', () => {
  it('should create reporters from config array', () => {
    const registry = ReporterRegistry.fromConfigs([
      { type: 'console', intervalSeconds: 1 },
      { type: 'json', intervalSeconds: 5 },
    ]);

    // Should have created both reporters
    expect(registry.get('console')).toBeDefined();
    expect(registry.get('json')).toBeDefined();
  });

  it('should broadcast events to all reporters', () => {
    const registry = new ReporterRegistry();
    const json = new JsonReporter();
    registry.add(json);

    const stats = makeStats();
    registry.onStart(stats);
    registry.onStats(stats);
    registry.onStop(stats);

    expect(json.getLines().length).toBe(3);
  });
});

// ─── Sanitizers ─────────────────────────────────────────────────────────────

import {
  SanitizerParser,
  SanitizerKind,
  JsBoundsChecker,
  JsTypeChecker,
} from '../../src/sanitizers/bridge.js';

describe('SanitizerParser', () => {
  const parser = new SanitizerParser();

  it('should parse ASan heap-buffer-overflow', () => {
    const output = `
=================================================================
==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010
READ of size 4 at 0x602000000010
    #0 0x55a1 in main /src/main.c:10:5
    #1 0x7f01 in __libc_start_main /libc.c:100
=================================================================`;

    const findings = parser.parse(output);
    expect(findings.length).toBe(1);
    expect(findings[0]!.sanitizer).toBe(SanitizerKind.ASan);
    expect(findings[0]!.summary).toContain('heap-buffer-overflow');
    expect(findings[0]!.category).toBe(CrashCategory.HeapOverflow);
    expect(findings[0]!.severity).toBe(Severity.Critical);
    expect(findings[0]!.accessType).toBe('read');
    expect(findings[0]!.accessSize).toBe(4);
  });

  it('should parse UBSan runtime errors', () => {
    const output = `src/math.c:15:10: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented`;

    const findings = parser.parse(output);
    expect(findings.length).toBe(1);
    expect(findings[0]!.sanitizer).toBe(SanitizerKind.UBSan);
    expect(findings[0]!.category).toBe(CrashCategory.IntegerOverflow);
  });

  it('should parse TSan data race', () => {
    const output = `WARNING: ThreadSanitizer: data race (pid=1234)`;

    const findings = parser.parse(output);
    expect(findings.length).toBe(1);
    expect(findings[0]!.sanitizer).toBe(SanitizerKind.TSan);
    expect(findings[0]!.category).toBe(CrashCategory.RaceCondition);
  });

  it('should parse MSan uninitialized value', () => {
    const output = `WARNING: MemorySanitizer: use-of-uninitialized-value`;

    const findings = parser.parse(output);
    expect(findings.length).toBe(1);
    expect(findings[0]!.sanitizer).toBe(SanitizerKind.MSan);
  });

  it('should parse LSan leak report', () => {
    const output = `
==1234==ERROR: LeakSanitizer: detected memory leaks
1024 byte(s) leaked in 2 allocation(s)`;

    const findings = parser.parse(output);
    expect(findings.length).toBe(1);
    expect(findings[0]!.sanitizer).toBe(SanitizerKind.LSan);
    expect(findings[0]!.summary).toContain('1024');
  });

  it('should return empty for clean output', () => {
    const findings = parser.parse('All tests passed.');
    expect(findings.length).toBe(0);
  });
});

describe('JsBoundsChecker', () => {
  it('should throw on OOB read', () => {
    const buf = JsBoundsChecker.wrap(new Uint8Array(4));
    // Positive OOB (negative indices are regular property lookups in JS)
    expect(() => (buf as any)[4]).toThrow(RangeError);
    expect(() => (buf as any)[100]).toThrow(RangeError);
  });

  it('should throw on OOB write', () => {
    const buf = JsBoundsChecker.wrap(new Uint8Array(4));
    expect(() => { (buf as any)[4] = 0xFF; }).toThrow(RangeError);
  });

  it('should allow valid access', () => {
    const buf = JsBoundsChecker.wrap(new Uint8Array([10, 20, 30]));
    expect(buf[0]).toBe(10);
    expect(buf[2]).toBe(30);
  });
});

describe('JsTypeChecker', () => {
  it('should detect NaN', () => {
    const finding = JsTypeChecker.check(NaN, 'result');
    expect(finding).not.toBeNull();
    expect(finding!.sanitizer).toBe(SanitizerKind.JsType);
    expect(finding!.summary).toContain('NaN');
  });

  it('should detect undefined', () => {
    const finding = JsTypeChecker.check(undefined, 'value');
    expect(finding).not.toBeNull();
    expect(finding!.sanitizer).toBe(SanitizerKind.JsUndef);
  });

  it('should return null for valid values', () => {
    expect(JsTypeChecker.check(42, 'num')).toBeNull();
    expect(JsTypeChecker.check('hello', 'str')).toBeNull();
    expect(JsTypeChecker.check(null, 'nul')).toBeNull();
  });
});

// ─── Differential ───────────────────────────────────────────────────────────

import {
  DiffOracle,
  DivergenceKind,
} from '../../src/differential/oracle.js';
import type { Oracle, OracleOutput } from '../../src/differential/oracle.js';

describe('DiffOracle', () => {
  it('should detect unanimous results', async () => {
    const oracle = new DiffOracle();
    oracle.addOracle({
      name: 'impl-a',
      execute: (data) => ({
        data: new Uint8Array(data),
        durationUs: 100,
        crashed: false,
      }),
    });
    oracle.addOracle({
      name: 'impl-b',
      execute: (data) => ({
        data: new Uint8Array(data),
        durationUs: 150,
        crashed: false,
      }),
    });

    const input = makeFuzzInput(new Uint8Array([1, 2, 3]));
    const result = await oracle.compare(input);

    expect(result.unanimous).toBe(true);
    expect(result.divergences.length).toBe(0);
    expect(result.outputs.length).toBe(2);
  });

  it('should detect output mismatches', async () => {
    const oracle = new DiffOracle();
    oracle.addOracle({
      name: 'correct',
      execute: () => ({
        data: new Uint8Array([1, 2, 3]),
        durationUs: 100,
        crashed: false,
      }),
    });
    oracle.addOracle({
      name: 'buggy',
      execute: () => ({
        data: new Uint8Array([1, 2, 99]),
        durationUs: 100,
        crashed: false,
      }),
    });

    const input = makeFuzzInput(new Uint8Array([0]));
    const result = await oracle.compare(input);

    expect(result.unanimous).toBe(false);
    expect(result.divergences.length).toBeGreaterThan(0);

    const outputDiv = result.divergences.find(d => d.kind === DivergenceKind.OutputMismatch);
    expect(outputDiv).toBeDefined();
    expect(outputDiv!.firstDiffOffset).toBe(2);
  });

  it('should detect crash divergence', async () => {
    const oracle = new DiffOracle();
    oracle.addOracle({
      name: 'stable',
      execute: () => ({
        data: new Uint8Array([0]),
        durationUs: 100,
        crashed: false,
      }),
    });
    oracle.addOracle({
      name: 'crashy',
      execute: () => { throw new Error('segfault'); },
    });

    const input = makeFuzzInput(new Uint8Array([0xFF]));
    const result = await oracle.compare(input);

    expect(result.unanimous).toBe(false);
    const crashDiv = result.divergences.find(d => d.kind === DivergenceKind.CrashDivergence);
    expect(crashDiv).toBeDefined();
    expect(crashDiv!.severity).toBe(Severity.High);
  });

  it('should detect timing anomalies', async () => {
    const oracle = new DiffOracle({ timingRatioThreshold: 2 });
    oracle.addOracle({
      name: 'fast',
      execute: () => ({
        data: new Uint8Array([0]),
        durationUs: 10,
        crashed: false,
      }),
    });
    oracle.addOracle({
      name: 'slow',
      execute: () => ({
        data: new Uint8Array([0]),
        durationUs: 1000,
        crashed: false,
      }),
    });

    const input = makeFuzzInput(new Uint8Array([0]));
    const result = await oracle.compare(input);

    const timingDiv = result.divergences.find(d => d.kind === DivergenceKind.TimingAnomaly);
    expect(timingDiv).toBeDefined();
  });

  it('should require at least 2 oracles', async () => {
    const oracle = new DiffOracle();
    oracle.addOracle({ name: 'only-one', execute: () => ({ data: new Uint8Array(0), durationUs: 0, crashed: false }) });

    const input = makeFuzzInput(new Uint8Array([0]));
    await expect(oracle.compare(input)).rejects.toThrow('at least 2');
  });

  it('should track stats', async () => {
    const oracle = new DiffOracle();
    oracle.addOracle({ name: 'a', execute: () => ({ data: new Uint8Array([1]), durationUs: 10, crashed: false }) });
    oracle.addOracle({ name: 'b', execute: () => ({ data: new Uint8Array([2]), durationUs: 10, crashed: false }) });

    const input = makeFuzzInput(new Uint8Array([0]));
    await oracle.compare(input);
    await oracle.compare(input);

    const stats = oracle.getStats();
    expect(stats.totalComparisons).toBe(2);
    expect(stats.outputMismatches).toBe(2);
    expect(stats.unanimousRate).toBe(0);
  });

  it('should detect length mismatches', async () => {
    const oracle = new DiffOracle({ checkLengths: true });
    oracle.addOracle({ name: 'short', execute: () => ({ data: new Uint8Array([1]), durationUs: 10, crashed: false }) });
    oracle.addOracle({ name: 'long', execute: () => ({ data: new Uint8Array([1, 2, 3]), durationUs: 10, crashed: false }) });

    const input = makeFuzzInput(new Uint8Array([0]));
    const result = await oracle.compare(input);

    const lenDiv = result.divergences.find(d => d.kind === DivergenceKind.LengthMismatch);
    expect(lenDiv).toBeDefined();
  });
});

// ─── ECC Integrity ──────────────────────────────────────────────────────────

import {
  EccIntegrity,
  IntegrityStatus,
} from '../../src/ecc/integrity.js';

describe('EccIntegrity', () => {
  it('should operate in pass-through when disabled', () => {
    const ecc = new EccIntegrity({ enabled: false });
    const data = new Uint8Array([1, 2, 3, 4, 5]);

    const encoded = ecc.encode(data);
    expect(encoded.status).toBe(IntegrityStatus.Unprotected);
    expect(encoded.data).toEqual(data);
  });

  it('should operate in pass-through when LombokECC not installed', async () => {
    const ecc = new EccIntegrity({ enabled: true });
    const available = await ecc.init();

    // LombokECC is not installed in test env
    expect(available).toBe(false);
    expect(ecc.isActive).toBe(false);

    const data = new Uint8Array([10, 20, 30]);
    const encoded = ecc.encode(data);
    expect(encoded.status).toBe(IntegrityStatus.Unprotected);
  });

  it('should identify ECC blobs by magic header', () => {
    const ecc = new EccIntegrity();
    const eccBlob = new Uint8Array([0x4C, 0x4B, 0x45, 0x43, 0, 0, 0, 5, ...new Array(255).fill(0)]);
    const plainBlob = new Uint8Array([0, 1, 2, 3, 4]);

    expect(ecc.isEccBlob(eccBlob)).toBe(true);
    expect(ecc.isEccBlob(plainBlob)).toBe(false);
    expect(ecc.isEccBlob(new Uint8Array(3))).toBe(false);
  });

  it('should decode unprotected blobs as pass-through', () => {
    const ecc = new EccIntegrity();
    const data = new Uint8Array([1, 2, 3]);

    const result = ecc.decode(data);
    expect(result.status).toBe(IntegrityStatus.Unprotected);
    expect(result.data).toEqual(data);
  });

  it('should verify unprotected blobs', () => {
    const ecc = new EccIntegrity();
    const data = new Uint8Array([1, 2, 3]);
    expect(ecc.verify(data)).toBe(IntegrityStatus.Unprotected);
  });
});

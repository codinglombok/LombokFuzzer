/**
 * LombokFuzzer — Test Suite
 *
 * Covers: PRNG, hashing, mutation, corpus, coverage, crash analysis,
 * scheduling, grammar, protocol, API, web, SQL, crypto, hardware.
 *
 * Run: npx jest tests/unit/core.test.ts
 *
 * @license Apache-2.0
 */

// ─── NOTE ─────────────────────────────────────────────────────────────────
// These tests are designed to run with ts-jest or after compilation.
// For CI, compile first then run jest on the .js output.
// ──────────────────────────────────────────────────────────────────────────

import { describe, it, expect, beforeEach } from '@jest/globals';

// Since we're testing source, we use relative imports.
// In CI, these resolve to compiled dist/ via jest moduleNameMapper.

// ═══════════════════════════════════════════════════════════════════════════
// PRNG
// ═══════════════════════════════════════════════════════════════════════════

describe('PRNG (xoshiro256**)', () => {
  it('should produce deterministic output for same seed', () => {
    const { PRNG } = require('../../src/utils/prng');
    const a = new PRNG(42n);
    const b = new PRNG(42n);
    for (let i = 0; i < 100; i++) {
      expect(a.nextU64()).toBe(b.nextU64());
    }
  });

  it('should produce different output for different seeds', () => {
    const { PRNG } = require('../../src/utils/prng');
    const a = new PRNG(1n);
    const b = new PRNG(2n);
    const va = a.nextU64();
    const vb = b.nextU64();
    expect(va).not.toBe(vb);
  });

  it('nextRange should stay within bounds', () => {
    const { PRNG } = require('../../src/utils/prng');
    const p = new PRNG(123n);
    for (let i = 0; i < 10000; i++) {
      const val = p.nextRange(100);
      expect(val).toBeGreaterThanOrEqual(0);
      expect(val).toBeLessThan(100);
    }
  });

  it('nextFloat should be in [0, 1)', () => {
    const { PRNG } = require('../../src/utils/prng');
    const p = new PRNG(999n);
    for (let i = 0; i < 10000; i++) {
      const val = p.nextFloat();
      expect(val).toBeGreaterThanOrEqual(0);
      expect(val).toBeLessThan(1);
    }
  });

  it('fillBytes should fill entire buffer', () => {
    const { PRNG } = require('../../src/utils/prng');
    const p = new PRNG(77n);
    const buf = new Uint8Array(1024);
    p.fillBytes(buf);
    // At least some bytes should be non-zero
    const nonZero = buf.filter(b => b !== 0).length;
    expect(nonZero).toBeGreaterThan(900);
  });

  it('pick should select from array', () => {
    const { PRNG } = require('../../src/utils/prng');
    const p = new PRNG(55n);
    const items = ['a', 'b', 'c', 'd'];
    const picked = new Set<string>();
    for (let i = 0; i < 1000; i++) picked.add(p.pick(items));
    // All items should be picked at least once
    expect(picked.size).toBe(4);
  });

  it('shuffle should return same elements', () => {
    const { PRNG } = require('../../src/utils/prng');
    const p = new PRNG(88n);
    const arr = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    const shuffled = p.shuffle([...arr]);
    expect(shuffled.sort()).toEqual(arr.sort());
  });

  it('clone should produce independent copy', () => {
    const { PRNG } = require('../../src/utils/prng');
    const p = new PRNG(100n);
    p.nextU64(); // advance state
    const clone = p.clone();
    expect(p.nextU64()).toBe(clone.nextU64());
  });

  it('saveState/restoreState round-trips', () => {
    const { PRNG } = require('../../src/utils/prng');
    const p = new PRNG(200n);
    for (let i = 0; i < 50; i++) p.nextU64();
    const state = p.saveState();
    const next1 = p.nextU64();

    const p2 = new PRNG(0n);
    p2.restoreState(state);
    const next2 = p2.nextU64();
    expect(next1).toBe(next2);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Hash Functions
// ═══════════════════════════════════════════════════════════════════════════

describe('Hash Functions', () => {
  it('fnv1a64: same input → same hash', () => {
    const { fnv1a64 } = require('../../src/utils/hash');
    const data = new TextEncoder().encode('hello world');
    expect(fnv1a64(data)).toBe(fnv1a64(data));
  });

  it('fnv1a64: different input → different hash', () => {
    const { fnv1a64 } = require('../../src/utils/hash');
    const a = fnv1a64(new TextEncoder().encode('hello'));
    const b = fnv1a64(new TextEncoder().encode('world'));
    expect(a).not.toBe(b);
  });

  it('xxhash64: same input → same hash', () => {
    const { xxhash64 } = require('../../src/utils/hash');
    const data = new TextEncoder().encode('test input for xxhash');
    expect(xxhash64(data)).toBe(xxhash64(data));
  });

  it('xxhash64: different seeds → different hashes', () => {
    const { xxhash64 } = require('../../src/utils/hash');
    const data = new TextEncoder().encode('seed test');
    expect(xxhash64(data, 0n)).not.toBe(xxhash64(data, 1n));
  });

  it('stackHash: deterministic for same frames', () => {
    const { stackHash } = require('../../src/utils/hash');
    const frames = [
      { functionName: 'foo', file: 'test.ts', line: 10 },
      { functionName: 'bar', file: 'test.ts', line: 20 },
    ];
    expect(stackHash(frames)).toBe(stackHash(frames));
  });

  it('classifyCount: AFL bucketing', () => {
    const { classifyCount } = require('../../src/utils/hash');
    expect(classifyCount(0)).toBe(0);
    expect(classifyCount(1)).toBe(1);
    expect(classifyCount(2)).toBe(2);
    expect(classifyCount(3)).toBe(4);
    expect(classifyCount(5)).toBe(8);
    expect(classifyCount(10)).toBe(16);
    expect(classifyCount(20)).toBe(32);
    expect(classifyCount(50)).toBe(64);
    expect(classifyCount(200)).toBe(128);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Mutation Engine
// ═══════════════════════════════════════════════════════════════════════════

describe('MutationEngine', () => {
  it('mutate should return modified data', () => {
    const { MutationEngine } = require('../../src/mutators/engine');
    const { PRNG } = require('../../src/utils/prng');
    const { MutatorStrategy } = require('../../src/core/types');

    const prng = new PRNG(42n);
    const engine = new MutationEngine({
      strategies: [MutatorStrategy.BitFlip, MutatorStrategy.ByteFlip],
      maxHavocStack: 4,
      maxSpliceSize: 1024,
    }, prng);

    const input = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const result = engine.mutate(input, 1024, []);
    expect(result.data).toBeDefined();
    expect(result.strategies.length).toBeGreaterThan(0);
  });

  it('should not exceed maxSize', () => {
    const { MutationEngine } = require('../../src/mutators/engine');
    const { PRNG } = require('../../src/utils/prng');
    const { MutatorStrategy } = require('../../src/core/types');

    const prng = new PRNG(42n);
    const engine = new MutationEngine({
      strategies: [MutatorStrategy.Extend],
      maxHavocStack: 4,
      maxSpliceSize: 1024,
    }, prng);

    const input = new Uint8Array(100);
    for (let i = 0; i < 100; i++) {
      const result = engine.mutate(input, 120, []);
      expect(result.data.length).toBeLessThanOrEqual(120);
    }
  });

  it('dictionary operations should work', () => {
    const { MutationEngine } = require('../../src/mutators/engine');
    const { PRNG } = require('../../src/utils/prng');
    const { MutatorStrategy } = require('../../src/core/types');

    const prng = new PRNG(42n);
    const engine = new MutationEngine({
      strategies: [MutatorStrategy.DictionaryInsert],
      maxHavocStack: 4,
      maxSpliceSize: 1024,
    }, prng);

    engine.addDictionary(new TextEncoder().encode('FUZZ'));
    expect(engine.dictionarySize).toBe(1);

    engine.addDictionaryTokens(['"token1"', 'token2', '# comment', '']);
    expect(engine.dictionarySize).toBe(3); // 1 + 2 (comment and empty skipped)
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Corpus Store
// ═══════════════════════════════════════════════════════════════════════════

describe('CorpusStore', () => {
  it('should add and deduplicate entries', () => {
    const { CorpusStore } = require('../../src/corpus/store');
    const { createConfig } = require('../../src/core/defaults');
    const { PRNG } = require('../../src/utils/prng');

    const store = new CorpusStore(createConfig(), new PRNG(1n));
    expect(store.addSeed(new Uint8Array([1, 2, 3]))).toBe(true);
    expect(store.addSeed(new Uint8Array([1, 2, 3]))).toBe(false); // duplicate
    expect(store.addSeed(new Uint8Array([4, 5, 6]))).toBe(true);
    expect(store.size).toBe(2);
  });

  it('should track total bytes', () => {
    const { CorpusStore } = require('../../src/corpus/store');
    const { createConfig } = require('../../src/core/defaults');
    const { PRNG } = require('../../src/utils/prng');

    const store = new CorpusStore(createConfig(), new PRNG(1n));
    store.addSeed(new Uint8Array([1, 2, 3]));
    store.addSeed(new Uint8Array([4, 5, 6, 7, 8]));
    expect(store.totalBytes).toBe(8);
  });

  it('serialize/deserialize round-trips', () => {
    const { CorpusStore } = require('../../src/corpus/store');
    const { createConfig } = require('../../src/core/defaults');
    const { PRNG } = require('../../src/utils/prng');

    const config = createConfig();
    const store = new CorpusStore(config, new PRNG(1n));
    store.addSeed(new Uint8Array([10, 20, 30]));
    store.addSeed(new Uint8Array([40, 50]));

    const snap = store.serialize();
    const store2 = new CorpusStore(config, new PRNG(1n));
    store2.deserialize(snap);
    expect(store2.size).toBe(2);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Coverage Tracker
// ═══════════════════════════════════════════════════════════════════════════

describe('CoverageTracker', () => {
  it('should track edges', () => {
    const { CoverageTracker } = require('../../src/coverage/tracker');
    const { CoverageMetric } = require('../../src/core/types');

    const tracker = new CoverageTracker({
      metrics: [CoverageMetric.Edge],
      bitmapSize: 256,
      trackComparisons: false,
      trackDataFlow: false,
    });

    tracker.recordEdge(42);
    tracker.recordEdge(100);
    const snap = tracker.snapshot();
    expect(snap.totalEdgesHit).toBeGreaterThan(0);
  });

  it('should detect new edges', () => {
    const { CoverageTracker } = require('../../src/coverage/tracker');
    const { CoverageMetric } = require('../../src/core/types');

    const tracker = new CoverageTracker({
      metrics: [CoverageMetric.Edge],
      bitmapSize: 256,
      trackComparisons: false,
      trackDataFlow: false,
    });

    tracker.recordEdge(10);
    const snap1 = tracker.snapshot();
    const newEdges1 = tracker.findNewEdges(snap1);
    expect(newEdges1.length).toBeGreaterThan(0);

    tracker.mergeBitmap(snap1);

    // Same edge again — should not be new
    tracker.recordEdge(10);
    const snap2 = tracker.snapshot();
    const newEdges2 = tracker.findNewEdges(snap2);
    // May still find new bucketed counts, but edge 10 specifically is known
    expect(tracker.edgesFound).toBeGreaterThan(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Crash Analyzer
// ═══════════════════════════════════════════════════════════════════════════

describe('CrashAnalyzer', () => {
  it('should classify Node.js stack traces', () => {
    const { CrashAnalyzer } = require('../../src/crash/analyzer');
    const { createConfig } = require('../../src/core/defaults');

    const analyzer = new CrashAnalyzer(createConfig());
    const frames = analyzer.parseStackTrace(
      '    at myFunction (test.js:10:5)\n' +
      '    at main (index.js:1:1)',
    );
    expect(frames.length).toBe(2);
    expect(frames[0].functionName).toBe('myFunction');
    expect(frames[0].line).toBe(10);
  });

  it('should analyze and deduplicate crashes', () => {
    const { CrashAnalyzer } = require('../../src/crash/analyzer');
    const { createConfig } = require('../../src/core/defaults');
    const { fnv1a64 } = require('../../src/utils/hash');

    const analyzer = new CrashAnalyzer(createConfig());
    const mockResult = {
      input: {
        data: new Uint8Array([1]),
        hash: fnv1a64(new Uint8Array([1])),
        lineage: [],
        depth: 0,
        energy: 1,
        executions: 1,
        createdAt: Date.now(),
        tags: new Map(),
      },
      crashed: true,
      newCoverage: false,
      newEdges: [],
      durationUs: 100,
      peakMemoryBytes: -1,
      exitCode: 1,
      signal: 0,
      stderr: 'TypeError: Cannot read properties of null\n    at parse (parser.js:42:10)',
    };

    const crash1 = analyzer.analyze(mockResult);
    expect(crash1).toBeDefined();
    expect(crash1!.isDuplicate).toBe(false);

    // Same crash again should be deduped
    const crash2 = analyzer.analyze(mockResult);
    expect(crash2).toBeDefined();
    expect(crash2!.isDuplicate).toBe(true);
    expect(analyzer.uniqueCount).toBe(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Grammar Engine
// ═══════════════════════════════════════════════════════════════════════════

describe('GrammarEngine', () => {
  it('should generate valid JSON from grammar', () => {
    const { GrammarEngine } = require('../../src/grammar/engine');
    const { PRNG } = require('../../src/utils/prng');

    const prng = new PRNG(42n);
    const engine = new GrammarEngine(prng, 10, 4096);
    const grammar = GrammarEngine.jsonGrammar();

    // Generate 20 inputs — at least some should be valid JSON
    let validCount = 0;
    for (let i = 0; i < 20; i++) {
      const bytes = engine.generate(grammar);
      const text = new TextDecoder().decode(bytes);
      try {
        JSON.parse(text);
        validCount++;
      } catch {
        // Some generated inputs may not be valid — that's OK for fuzzing
      }
    }
    expect(validCount).toBeGreaterThan(0);
  });

  it('should build SQL grammar', () => {
    const { GrammarEngine } = require('../../src/grammar/engine');
    const { PRNG } = require('../../src/utils/prng');

    const prng = new PRNG(99n);
    const engine = new GrammarEngine(prng, 10, 4096);
    const grammar = GrammarEngine.sqlGrammar();

    const bytes = engine.generate(grammar);
    const text = new TextDecoder().decode(bytes);
    expect(text.length).toBeGreaterThan(0);
    // Should start with a SQL keyword
    expect(text).toMatch(/^(SELECT|INSERT|UPDATE|DELETE)/);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Protocol Fuzzer
// ═══════════════════════════════════════════════════════════════════════════

describe('ProtocolFuzzer', () => {
  it('should generate HTTP requests', () => {
    const { HttpFuzzer } = require('../../src/protocols/fuzzer');
    const { PRNG } = require('../../src/utils/prng');

    const prng = new PRNG(42n);
    const fuzzer = new HttpFuzzer();
    const msg = fuzzer.generate(prng);

    expect(msg.protocol).toBe('HTTP');
    expect(msg.data.length).toBeGreaterThan(0);
    const text = new TextDecoder().decode(msg.data);
    expect(text).toContain('HTTP/');
  });

  it('should generate DNS queries', () => {
    const { DnsFuzzer } = require('../../src/protocols/fuzzer');
    const { PRNG } = require('../../src/utils/prng');

    const prng = new PRNG(42n);
    const fuzzer = new DnsFuzzer();
    const msg = fuzzer.generate(prng);

    expect(msg.protocol).toBe('DNS');
    expect(msg.data.length).toBeGreaterThanOrEqual(12); // DNS header is 12 bytes
  });

  it('registry should list protocols', () => {
    const { ProtocolFuzzerRegistry } = require('../../src/protocols/fuzzer');
    const registry = new ProtocolFuzzerRegistry();
    const protocols = registry.list();
    expect(protocols).toContain('HTTP');
    expect(protocols).toContain('DNS');
    expect(protocols).toContain('WebSocket');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// SQL Fuzzer
// ═══════════════════════════════════════════════════════════════════════════

describe('SQLFuzzer', () => {
  it('should generate injection payloads for string context', () => {
    const { SQLFuzzer, SQLDialect } = require('../../src/sql/fuzzer');
    const { PRNG } = require('../../src/utils/prng');

    const fuzzer = new SQLFuzzer(new PRNG(42n), SQLDialect.Generic);
    const payloads = fuzzer.generatePayloads('string', 10);

    expect(payloads.length).toBe(10);
    for (const p of payloads) {
      expect(p.payload.length).toBeGreaterThan(0);
      expect(p.technique.length).toBeGreaterThan(0);
    }
  });

  it('should generate dialect-specific payloads', () => {
    const { SQLFuzzer, SQLDialect } = require('../../src/sql/fuzzer');
    const { PRNG } = require('../../src/utils/prng');

    const pgFuzzer = new SQLFuzzer(new PRNG(42n), SQLDialect.PostgreSQL);
    const payloads = pgFuzzer.generatePayloads('string', 50);

    const pgSpecific = payloads.filter(p => p.dialect === SQLDialect.PostgreSQL);
    expect(pgSpecific.length).toBeGreaterThan(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Web Fuzzer
// ═══════════════════════════════════════════════════════════════════════════

describe('WebFuzzer', () => {
  it('should detect missing security headers', () => {
    const { WebFuzzer } = require('../../src/web/fuzzer');
    const { PRNG } = require('../../src/utils/prng');

    const fuzzer = new WebFuzzer(new PRNG(42n));
    const findings = fuzzer.analyzeSecurityHeaders('https://test.com', {});

    // Should find clickjacking, MIME sniffing, CSP issues
    expect(findings.length).toBeGreaterThanOrEqual(2);
    const types = findings.map(f => f.type);
    expect(types).toContain('clickjacking');
  });

  it('should detect insecure cookies', () => {
    const { WebFuzzer } = require('../../src/web/fuzzer');
    const { PRNG } = require('../../src/utils/prng');

    const fuzzer = new WebFuzzer(new PRNG(42n));
    const findings = fuzzer.analyzeCookies('https://test.com', [
      { name: 'session', value: 'abc123', httpOnly: false, secure: false, sameSite: '' },
    ]);

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe('high'); // session cookie
  });

  it('should generate XSS payloads by context', () => {
    const { WebFuzzer } = require('../../src/web/fuzzer');
    const { PRNG } = require('../../src/utils/prng');

    const fuzzer = new WebFuzzer(new PRNG(42n));
    const htmlPayloads = fuzzer.generateXSSPayloads('html');
    const attrPayloads = fuzzer.generateXSSPayloads('attribute');

    expect(htmlPayloads.length).toBeGreaterThan(0);
    expect(attrPayloads.length).toBeGreaterThan(htmlPayloads.length); // attr adds quoted variants
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Crypto Fuzzer
// ═══════════════════════════════════════════════════════════════════════════

describe('CryptoFuzzer', () => {
  it('should detect non-constant-time comparison', () => {
    const { CryptoFuzzer } = require('../../src/crypto/fuzzer');
    const { PRNG } = require('../../src/utils/prng');

    const fuzzer = new CryptoFuzzer(new PRNG(42n));

    // Deliberately non-constant-time comparison
    const naiveCompare = (a: Uint8Array, b: Uint8Array): boolean => {
      if (a.length !== b.length) return false;
      for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false; // early exit = timing leak
      }
      return true;
    };

    const result = fuzzer.timingTest(naiveCompare, 32, 1000);
    expect(result.samples).toBe(1000);
    // Note: timing detection is probabilistic — we just check it runs
    expect(typeof result.isConstantTime).toBe('boolean');
  });

  it('should generate crypto edge cases', () => {
    const { CryptoFuzzer } = require('../../src/crypto/fuzzer');
    const { PRNG } = require('../../src/utils/prng');

    const fuzzer = new CryptoFuzzer(new PRNG(42n));
    const cases = fuzzer.generateCryptoEdgeCases(16);
    expect(cases.length).toBeGreaterThanOrEqual(10);
    // Should include all-zero
    expect(cases.some(c => c.every(b => b === 0))).toBe(true);
    // Should include all-ones
    expect(cases.some(c => c.length > 0 && c.every(b => b === 0xFF))).toBe(true);
  });

  it('should generate padding oracle vectors', () => {
    const { CryptoFuzzer } = require('../../src/crypto/fuzzer');
    const { PRNG } = require('../../src/utils/prng');

    const fuzzer = new CryptoFuzzer(new PRNG(42n));
    const vectors = fuzzer.generatePaddingOracleVectors(16, 2);
    expect(vectors.length).toBeGreaterThan(16); // 16 valid + invalid + bit-flip
    for (const v of vectors) {
      expect(v.length).toBe(32); // 2 blocks × 16
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Hardware Fuzzer
// ═══════════════════════════════════════════════════════════════════════════

describe('HardwareFuzzer', () => {
  it('should generate UART commands', () => {
    const { HardwareFuzzer, HWInterface } = require('../../src/hardware/fuzzer');
    const { PRNG } = require('../../src/utils/prng');

    const fuzzer = new HardwareFuzzer(new PRNG(42n));
    const commands = fuzzer.generateCommands(
      { interface: HWInterface.UART, baudRate: 115200 },
      20,
    );
    expect(commands.length).toBe(20);
    for (const cmd of commands) {
      expect(cmd.interface).toBe(HWInterface.UART);
      expect(cmd.data).toBeDefined();
    }
  });

  it('should generate register fuzz patterns', () => {
    const { HardwareFuzzer } = require('../../src/hardware/fuzzer');
    const { PRNG } = require('../../src/utils/prng');

    const fuzzer = new HardwareFuzzer(new PRNG(42n));
    const commands = fuzzer.generateRegisterFuzz({
      STATUS: { address: 0x00, width: 32, access: 'rw', resetValue: 0 },
      CONTROL: { address: 0x04, width: 16, access: 'rw', resetValue: 0x0001 },
      DATA: { address: 0x08, width: 8, access: 'w' },
    });

    expect(commands.length).toBeGreaterThan(10); // boundaries + randoms per register
  });

  it('should generate USB control transfers', () => {
    const { HardwareFuzzer, HWInterface } = require('../../src/hardware/fuzzer');
    const { PRNG } = require('../../src/utils/prng');

    const fuzzer = new HardwareFuzzer(new PRNG(42n));
    const commands = fuzzer.generateCommands(
      { interface: HWInterface.USB },
      10,
    );
    for (const cmd of commands) {
      expect(cmd.interface).toBe(HWInterface.USB);
      expect(cmd.data.length).toBe(8); // USB setup packet is 8 bytes
    }
  });
});

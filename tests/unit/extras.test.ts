/**
 * LombokFuzzer — Tests for mobile, cli, dashboard modules
 */

import { describe, it, expect } from '@jest/globals';
import { PRNG } from '../../src/utils/prng.js';
import { fnv1a64 } from '../../src/utils/hash.js';
import type { FuzzInput, FuzzStats, CrashInfo } from '../../src/core/types.js';
import { Severity, CrashCategory } from '../../src/core/types.js';

// ─── Helpers ────────────────────────────────────────────────────────────────

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

// ─── Mobile ─────────────────────────────────────────────────────────────────

import {
  MobileFuzzer,
  MobilePlatform,
  AndroidHarness,
  IOSHarness,
  ReactNativeHarness,
} from '../../src/mobile/fuzzer.js';

describe('AndroidHarness', () => {
  it('should create with default config', () => {
    const harness = new AndroidHarness({ packageName: 'com.example.app' });
    expect(harness.config.packageName).toBe('com.example.app');
    expect(harness.config.activityName).toBe('.MainActivity');
    expect(harness.config.captureLogcat).toBe(true);
    expect(harness.config.adbPath).toBe('adb');
    expect(harness.config.deviceInputDir).toBe('/data/local/tmp/fuzz_input');
  });

  it('should parse logcat crash output', () => {
    const harness = new AndroidHarness({ packageName: 'com.example.app' });
    const logcat = `
E AndroidRuntime: FATAL EXCEPTION: main
E AndroidRuntime: Process: com.example.app, PID: 12345
E AndroidRuntime: Thread: main
E AndroidRuntime: java.lang.NullPointerException: Attempt to read from null
E AndroidRuntime:   at com.example.app.Parser.parse(Parser.java:42)
    `;
    const report = harness.parseLogcat(logcat);
    expect(report).not.toBeNull();
    expect(report!.signal).toBe('JAVA_EXCEPTION');
    expect(report!.process).toBe('com.example.app');
  });

  it('should parse native crash logcat', () => {
    const harness = new AndroidHarness({ packageName: 'com.example.app' });
    const logcat = `
F DEBUG   : signal 11 (SIGSEGV), code 1 (SEGV_MAPERR)
F DEBUG   :     #00 pc 0000a1b2  /system/lib/libc.so (memcpy+42)
F DEBUG   :     #01 pc 00012345  /data/app/com.example.app/lib/arm/libnative.so (parse+100)
    `;
    const report = harness.parseLogcat(logcat);
    expect(report).not.toBeNull();
    expect(report!.signal).toBe('SIGSEGV');
    expect(report!.frames.length).toBe(2);
    expect(report!.category).toBe(CrashCategory.NullDeref);
    expect(report!.severity).toBe(Severity.Critical);
  });

  it('should return null for clean logcat', () => {
    const harness = new AndroidHarness({ packageName: 'com.example.app' });
    const report = harness.parseLogcat('I ActivityManager: Displayed com.example.app');
    expect(report).toBeNull();
  });

  it('should generate ADB commands', () => {
    const harness = new AndroidHarness({
      packageName: 'com.example.app',
      serial: 'emulator-5554',
    });
    const inputs = [new Uint8Array([1]), new Uint8Array([2])];
    const commands = harness.generateAdbCommands(inputs, 2);
    expect(commands.length).toBe(6); // 3 per input (push + start + logcat)
    expect(commands[0]).toContain('push');
    expect(commands[1]).toContain('am start');
    expect(commands[2]).toContain('logcat');
    expect(commands[0]).toContain('-s emulator-5554');
  });
});

describe('IOSHarness', () => {
  it('should create with default config', () => {
    const harness = new IOSHarness({ bundleId: 'com.example.app' });
    expect(harness.config.bundleId).toBe('com.example.app');
    expect(harness.config.udid).toBe('booted');
    expect(harness.config.xcrunPath).toBe('xcrun');
  });

  it('should parse iOS crash log', () => {
    const harness = new IOSHarness({ bundleId: 'com.example.app' });
    const crashLog = `
Incident Identifier: ABC-123
Exception Type:  EXC_BAD_ACCESS (SIGSEGV)
Crashed Thread:  0

Thread 0 Crashed:
0   libobjc.A.dylib   0x00007fff12345678 objc_msgSend + 22
1   UIKitCore         0x00007fff23456789 -[UIView setFrame:] + 150
    `;
    const report = harness.parseCrashLog(crashLog);
    expect(report).not.toBeNull();
    expect(report!.signal).toBe('SIGSEGV');
    expect(report!.frames.length).toBe(2);
    expect(report!.frames[0]!.library).toBe('libobjc.A.dylib');
  });

  it('should return null for non-crash text', () => {
    const harness = new IOSHarness({ bundleId: 'com.example.app' });
    const report = harness.parseCrashLog('Application launched successfully');
    expect(report).toBeNull();
  });
});

describe('ReactNativeHarness', () => {
  it('should create with default config', () => {
    const harness = new ReactNativeHarness({
      bridgeModule: 'MyModule',
      bridgeMethod: 'processData',
    });
    expect(harness.config.bridgeModule).toBe('MyModule');
    expect(harness.config.bridgeMethod).toBe('processData');
    expect(harness.config.metroUrl).toBe('http://localhost:8081');
    expect(harness.config.platform).toBe('android');
  });

  it('should generate bridge payloads', () => {
    const harness = new ReactNativeHarness({
      bridgeModule: 'Parser',
      bridgeMethod: 'parse',
    });
    const payloads = harness.generateBridgePayloads(10);
    expect(payloads.length).toBe(10);
    expect(payloads[0]!.module).toBe('Parser');
    expect(payloads[0]!.method).toBe('parse');

    // Should include type confusion payloads
    const hasNull = payloads.some(p => p.args[0] === null);
    expect(hasNull).toBe(true);
  });
});

describe('MobileFuzzer (facade)', () => {
  it('should create Android harness', () => {
    const h = MobileFuzzer.android({ packageName: 'com.test' });
    expect(h).toBeInstanceOf(AndroidHarness);
  });

  it('should create iOS harness', () => {
    const h = MobileFuzzer.ios({ bundleId: 'com.test' });
    expect(h).toBeInstanceOf(IOSHarness);
  });

  it('should create ReactNative harness', () => {
    const h = MobileFuzzer.reactNative({ bridgeModule: 'M', bridgeMethod: 'm' });
    expect(h).toBeInstanceOf(ReactNativeHarness);
  });
});

// ─── CLI ────────────────────────────────────────────────────────────────────

import {
  parseArgs,
  buildConfigFromFlags,
  handleVersion,
  handleHelp,
  handleCorpus,
  handleCrash,
  cli,
  CliCommand,
} from '../../src/cli/cli.js';
import { VERSION } from '../../src/index.js';

describe('parseArgs', () => {
  it('should parse command with flags', () => {
    const result = parseArgs(['run', '--name', 'test', '--max-execs', '1000']);
    expect(result.command).toBe(CliCommand.Run);
    expect(result.flags.get('name')).toBe('test');
    expect(result.flags.get('max-execs')).toBe('1000');
  });

  it('should parse --key=value syntax', () => {
    const result = parseArgs(['run', '--name=my-fuzzer', '--timeout=5000']);
    expect(result.flags.get('name')).toBe('my-fuzzer');
    expect(result.flags.get('timeout')).toBe('5000');
  });

  it('should parse boolean flags', () => {
    const result = parseArgs(['run', '--quiet', '--ecc']);
    expect(result.flags.get('quiet')).toBe('true');
    expect(result.flags.get('ecc')).toBe('true');
  });

  it('should parse short flags', () => {
    const result = parseArgs(['run', '-n', 'test']);
    expect(result.flags.get('n')).toBe('test');
  });

  it('should parse positional args', () => {
    const result = parseArgs(['help', 'run']);
    expect(result.command).toBe(CliCommand.Help);
    expect(result.positional).toEqual(['run']);
  });

  it('should map command aliases', () => {
    expect(parseArgs(['fuzz']).command).toBe(CliCommand.Run);
    expect(parseArgs(['crashes']).command).toBe(CliCommand.Crash);
    expect(parseArgs(['dashboard']).command).toBe(CliCommand.Report);
    expect(parseArgs(['min']).command).toBe(CliCommand.Minimize);
    expect(parseArgs(['-v']).command).toBe(CliCommand.Version);
    expect(parseArgs(['-h']).command).toBe(CliCommand.Help);
  });

  it('should default to help for unknown command', () => {
    expect(parseArgs(['unknown']).command).toBe(CliCommand.Help);
    expect(parseArgs([]).command).toBe(CliCommand.Help);
  });
});

describe('buildConfigFromFlags', () => {
  it('should build config from flags', () => {
    const flags = new Map([
      ['name', 'my-test'],
      ['mode', 'mutation'],
      ['max-execs', '50000'],
      ['max-time', '600'],
      ['timeout', '3000'],
      ['workers', '4'],
      ['seed', '42'],
    ]);

    const config = buildConfigFromFlags(flags);
    expect(config.name).toBe('my-test');
    expect(config.mode).toBe('mutation');
    expect(config.maxExecutions).toBe(50000);
    expect(config.maxTimeSeconds).toBe(600);
    expect(config.timeoutMs).toBe(3000);
    expect(config.workers).toBe(4);
    expect(config.seed).toBe(42n);
  });

  it('should configure reporters from flags', () => {
    const flags = new Map([
      ['json-report', 'stats.ndjson'],
      ['html-report', 'report.html'],
    ]);

    const config = buildConfigFromFlags(flags);
    expect(config.reporters).toBeDefined();
    const types = config.reporters!.map(r => r.type);
    expect(types).toContain('console');
    expect(types).toContain('json');
    expect(types).toContain('html');
  });

  it('should suppress console with --quiet', () => {
    const flags = new Map([['quiet', 'true']]);
    const config = buildConfigFromFlags(flags);
    const hasConsole = config.reporters?.some(r => r.type === 'console') ?? false;
    expect(hasConsole).toBe(false);
  });

  it('should set harness for target binary', () => {
    const flags = new Map([['target', './my_binary']]);
    const config = buildConfigFromFlags(flags);
    expect(config.harness?.targetBinary).toBe('./my_binary');
    expect(config.harness?.mode).toBe('fork_server');
  });

  it('should set network harness', () => {
    const flags = new Map([['network-target', 'localhost:8080']]);
    const config = buildConfigFromFlags(flags);
    expect(config.harness?.mode).toBe('network');
    expect(config.harness?.networkTarget).toBe('localhost:8080');
  });
});

describe('CLI command handlers', () => {
  it('handleVersion should return version string', () => {
    const result = handleVersion();
    expect(result.exitCode).toBe(0);
    expect(result.output).toContain(VERSION);
  });

  it('handleHelp should return help text', () => {
    const result = handleHelp();
    expect(result.exitCode).toBe(0);
    expect(result.output).toContain('USAGE');
    expect(result.output).toContain('COMMANDS');
  });

  it('handleHelp for run should return run-specific help', () => {
    const result = handleHelp('run');
    expect(result.output).toContain('--target');
    expect(result.output).toContain('--max-execs');
  });

  it('handleCorpus should return corpus info', () => {
    const result = handleCorpus(new Map([['dir', './my-corpus'], ['stats', 'true']]));
    expect(result.exitCode).toBe(0);
    expect(result.output).toContain('./my-corpus');
  });

  it('handleCrash should return crash info', () => {
    const result = handleCrash(new Map([['dir', './my-crashes'], ['triage', 'true']]));
    expect(result.exitCode).toBe(0);
    expect(result.output).toContain('./my-crashes');
    expect(result.output).toContain('Triage');
  });
});

describe('cli() dispatcher', () => {
  it('should handle version command', async () => {
    const result = await cli(['version']);
    expect(result.exitCode).toBe(0);
    expect(result.output).toContain(VERSION);
  });

  it('should handle help command', async () => {
    const result = await cli(['help']);
    expect(result.exitCode).toBe(0);
    expect(result.output).toContain('USAGE');
  });

  it('should handle run command', async () => {
    const result = await cli(['run', '--name', 'test-run']);
    expect(result.exitCode).toBe(0);
    expect(result.output).toContain('test-run');
  });

  it('should handle corpus command', async () => {
    const result = await cli(['corpus', '--dir', './corpus']);
    expect(result.exitCode).toBe(0);
  });

  it('should handle report command without input', async () => {
    const result = await cli(['report']);
    expect(result.exitCode).toBe(1);
    expect(result.output).toContain('--input');
  });

  it('should handle report command with input', async () => {
    const result = await cli(['report', '--input', 'stats.ndjson', '--html', 'out.html']);
    expect(result.exitCode).toBe(0);
    expect(result.output).toContain('stats.ndjson');
  });

  it('should handle minimize command', async () => {
    const result = await cli(['minimize', '--dir', './crashes']);
    expect(result.exitCode).toBe(0);
    expect(result.output).toContain('Minimizing');
  });
});

// ─── Dashboard ──────────────────────────────────────────────────────────────

import { DashboardBuilder } from '../../src/dashboard/dashboard.js';

describe('DashboardBuilder', () => {
  it('should create with default config', () => {
    const builder = new DashboardBuilder();
    // Should not throw
    expect(builder).toBeDefined();
  });

  it('should accept custom config', () => {
    const builder = new DashboardBuilder({
      campaignName: 'My Fuzzer',
      theme: 'dark',
      interactive: false,
    });
    expect(builder).toBeDefined();
  });

  it('should accumulate snapshots', () => {
    const builder = new DashboardBuilder({ campaignName: 'test' });
    const stats = makeStats({ elapsedMs: 1000, totalExecutions: 100 });
    builder.addSnapshot(stats);
    builder.addSnapshot(makeStats({ elapsedMs: 2000, totalExecutions: 200 }));

    // Snapshots tracked internally — verify via render
    const html = builder.render();
    expect(html).toContain('test');
  });

  it('should accumulate crashes', () => {
    const builder = new DashboardBuilder({ campaignName: 'test' });
    builder.addCrash(makeCrash());

    const html = builder.render();
    expect(html).toContain('crash-abc123');
    expect(html).toContain('CWE-476');
  });

  it('should render valid HTML', () => {
    const builder = new DashboardBuilder({ campaignName: 'Full Test' });
    const stats = makeStats();
    builder.addSnapshot(stats);
    builder.addCrash(makeCrash());
    builder.setFinalStats(stats);

    const html = builder.render();
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('Full Test');
    expect(html).toContain('LombokFuzzer Dashboard');
    expect(html).toContain('lombokcss');
    expect(html).toContain('lombokcharts');
    expect(html).toContain('chart-coverage');
    expect(html).toContain('chart-rate');
    expect(html).toContain('chart-corpus');
    expect(html).toContain('chart-mutators');
    // KPI values
    expect(html).toContain('45.5%');
    expect(html).toContain('100/220');
    expect(html).toContain('havoc');
  });

  it('should render HTML without crashes', () => {
    const builder = new DashboardBuilder({ campaignName: 'clean' });
    builder.setFinalStats(makeStats({ uniqueCrashes: 0 }));

    const html = builder.render();
    expect(html).toContain('No crashes found');
  });

  it('should render JSON data bundle', () => {
    const builder = new DashboardBuilder({ campaignName: 'json-test' });
    builder.addSnapshot(makeStats());
    builder.setFinalStats(makeStats());

    const json = builder.renderJson();
    const parsed = JSON.parse(json);
    expect(parsed.campaign).toBe('json-test');
    expect(parsed.snapshots.length).toBeGreaterThan(0);
    expect(parsed.stats).toBeDefined();
    expect(parsed.version).toBeDefined();
  });

  it('should handle dark theme', () => {
    const builder = new DashboardBuilder({ theme: 'dark' });
    builder.setFinalStats(makeStats());
    const html = builder.render();
    expect(html).toContain('data-theme="dark"');
  });

  it('should include refresh script when configured', () => {
    const builder = new DashboardBuilder({ refreshInterval: 5 });
    builder.setFinalStats(makeStats());
    const html = builder.render();
    expect(html).toContain('setTimeout');
    expect(html).toContain('5000');
  });

  it('should escape HTML in campaign name', () => {
    const builder = new DashboardBuilder({ campaignName: '<script>alert(1)</script>' });
    builder.setFinalStats(makeStats());
    const html = builder.render();
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;');
  });
});

/**
 * LombokFuzzer — Public API
 *
 * ```ts
 * import { LombokFuzzer, FuzzMode } from 'lombokfuzzer';
 *
 * const fuzzer = new LombokFuzzer({
 *   name: 'my-target',
 *   mode: FuzzMode.Mutation,
 *   maxExecutions: 100_000,
 *   harness: {
 *     mode: 'in_process',
 *     targetFunction: (data) => myParser(data),
 *   },
 * });
 *
 * fuzzer.on('crash_found', ({ crash }) => console.log('CRASH:', crash.id));
 * const stats = await fuzzer.run();
 * ```
 *
 * @license Apache-2.0
 * @see https://github.com/codinglombok/lombokfuzzer
 */

// ─── Core ───────────────────────────────────────────────────────────────────
export { FuzzEngine } from './core/engine.js';
export { FuzzEngine as LombokFuzzer } from './core/engine.js'; // Alias
export { FuzzEventEmitter } from './core/events.js';
export { createConfig } from './core/defaults.js';
export {
  // Enums
  FuzzMode,
  Severity,
  CrashCategory,
  MutatorStrategy,
  SchedulerAlgorithm,
  HarnessMode,
  CoverageMetric,
  FuzzEvent,
} from './core/types.js';
export type {
  // Core types
  FuzzConfig,
  FuzzInput,
  FuzzStats,
  ExecutionResult,
  CrashInfo,
  CoverageSnapshot,
  StackFrame,
  DictionaryEntry,
  FuzzEventMap,
  FuzzEventHandler,
  // Config types
  MutatorConfig,
  SchedulerConfig,
  CoverageConfig,
  HarnessConfig,
  HardwareProbeConfig,
  ReporterConfig,
  // Identifiers
  CorpusHash,
  ExecutionId,
  EdgeId,
  BranchId,
} from './core/types.js';

// ─── Subsystems ─────────────────────────────────────────────────────────────
export { MutationEngine } from './mutators/engine.js';
export { CorpusStore } from './corpus/store.js';
export { CoverageTracker } from './coverage/tracker.js';
export { CrashAnalyzer } from './crash/analyzer.js';
export { Scheduler } from './scheduler/scheduler.js';

// ─── Grammar ────────────────────────────────────────────────────────────────
export { GrammarEngine } from './grammar/engine.js';
export type { Grammar, GrammarNode } from './grammar/engine.js';
export { NodeKind } from './grammar/engine.js';

// ─── Protocol Fuzzing ───────────────────────────────────────────────────────
export { ProtocolFuzzerRegistry, HttpFuzzer, DnsFuzzer, WebSocketFuzzer } from './protocols/fuzzer.js';
export type { ProtocolMessage, ProtocolFuzzerModule } from './protocols/fuzzer.js';

// ─── API Fuzzing ────────────────────────────────────────────────────────────
export { ApiFuzzer, ApiVulnerability } from './api/fuzzer.js';
export type { ApiEndpoint, ApiRequest, ApiResponse, ApiFinding, ApiSchema, AuthConfig } from './api/fuzzer.js';

// ─── Web Fuzzing ────────────────────────────────────────────────────────────
export { WebFuzzer, WebVulnerability } from './web/fuzzer.js';
export type { WebTarget, WebPage, WebForm, WebCookie, WebFinding } from './web/fuzzer.js';

// ─── SQL Fuzzing ────────────────────────────────────────────────────────────
export { SQLFuzzer, SQLDialect } from './sql/fuzzer.js';
export type { SQLInjectionResult } from './sql/fuzzer.js';

// ─── Crypto Fuzzing ─────────────────────────────────────────────────────────
export { CryptoFuzzer, CryptoVulnerability } from './crypto/fuzzer.js';
export type { TimingTestResult, RNGTestResult, CryptoFinding } from './crypto/fuzzer.js';

// ─── Hardware Fuzzing ───────────────────────────────────────────────────────
export { HardwareFuzzer, HWInterface } from './hardware/fuzzer.js';
export type { HWFuzzTarget, RegisterMap, RegisterDef, HWFuzzCommand, HWFinding } from './hardware/fuzzer.js';

// ─── Generators ─────────────────────────────────────────────────────────────
export { GeneratorEngine, GeneratorKind } from './generators/engine.js';
export type {
  GeneratorConfig, GenerationResult, GenerationHistory, GenerationContext,
} from './generators/engine.js';

// ─── Harness ────────────────────────────────────────────────────────────────
export {
  HarnessManager, InProcessHarness, ForkServerHarness, NetworkHarness, WasmHarness,
} from './harness/manager.js';
export type { Harness, HarnessStats } from './harness/manager.js';

// ─── Reporters ──────────────────────────────────────────────────────────────
export {
  ReporterRegistry, ConsoleReporter, JsonReporter, HtmlReporter, CiReporter,
} from './reporters/reporter.js';
export type { Reporter } from './reporters/reporter.js';

// ─── Sanitizers ─────────────────────────────────────────────────────────────
export {
  SanitizerParser, SanitizerKind,
  JsBoundsChecker, JsLeakChecker, JsTypeChecker,
} from './sanitizers/bridge.js';
export type { SanitizerFinding } from './sanitizers/bridge.js';

// ─── Differential ───────────────────────────────────────────────────────────
export { DiffOracle, DivergenceKind } from './differential/oracle.js';
export type {
  Oracle, OracleOutput, DiffResult, Divergence, DiffOracleConfig, DiffStats,
} from './differential/oracle.js';

// ─── ECC Integrity ──────────────────────────────────────────────────────────
export { EccIntegrity, IntegrityStatus } from './ecc/integrity.js';
export type { IntegrityResult, EccConfig } from './ecc/integrity.js';

// ─── Mobile Fuzzing ─────────────────────────────────────────────────────────
export {
  MobileFuzzer, MobilePlatform,
  AndroidHarness, IOSHarness, ReactNativeHarness,
} from './mobile/fuzzer.js';
export type {
  AndroidConfig, IOSConfig, ReactNativeConfig,
  MobileCrashReport, MobileStackFrame, BridgePayload,
} from './mobile/fuzzer.js';

// ─── CLI ────────────────────────────────────────────────────────────────────
export {
  cli, parseArgs, buildConfigFromFlags, loadConfigFile,
  handleVersion, handleHelp, handleCorpus, handleCrash,
  CliCommand,
} from './cli/cli.js';
export type { CliArgs, CliResult } from './cli/cli.js';

// ─── Dashboard ──────────────────────────────────────────────────────────────
export { DashboardBuilder } from './dashboard/dashboard.js';
export type { StatsSnapshot, DashboardConfig, DashboardCrash } from './dashboard/dashboard.js';

// ─── Utilities ──────────────────────────────────────────────────────────────
export { PRNG } from './utils/prng.js';
export { fnv1a64, xxhash64, stackHash, edgeHash } from './utils/hash.js';

// ─── Version ────────────────────────────────────────────────────────────────
export { VERSION, CODENAME } from './version.js';

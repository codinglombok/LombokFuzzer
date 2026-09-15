"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.JsTypeChecker = exports.JsLeakChecker = exports.JsBoundsChecker = exports.SanitizerKind = exports.SanitizerParser = exports.CiReporter = exports.HtmlReporter = exports.JsonReporter = exports.ConsoleReporter = exports.ReporterRegistry = exports.WasmHarness = exports.NetworkHarness = exports.ForkServerHarness = exports.InProcessHarness = exports.HarnessManager = exports.GeneratorKind = exports.GeneratorEngine = exports.HWInterface = exports.HardwareFuzzer = exports.CryptoVulnerability = exports.CryptoFuzzer = exports.SQLDialect = exports.SQLFuzzer = exports.WebVulnerability = exports.WebFuzzer = exports.ApiVulnerability = exports.ApiFuzzer = exports.WebSocketFuzzer = exports.DnsFuzzer = exports.HttpFuzzer = exports.ProtocolFuzzerRegistry = exports.NodeKind = exports.GrammarEngine = exports.Scheduler = exports.CrashAnalyzer = exports.CoverageTracker = exports.CorpusStore = exports.MutationEngine = exports.FuzzEvent = exports.CoverageMetric = exports.HarnessMode = exports.SchedulerAlgorithm = exports.MutatorStrategy = exports.CrashCategory = exports.Severity = exports.FuzzMode = exports.createConfig = exports.FuzzEventEmitter = exports.LombokFuzzer = exports.FuzzEngine = void 0;
exports.CODENAME = exports.VERSION = exports.edgeHash = exports.stackHash = exports.xxhash64 = exports.fnv1a64 = exports.PRNG = exports.DashboardBuilder = exports.CliCommand = exports.handleCrash = exports.handleCorpus = exports.handleHelp = exports.handleVersion = exports.loadConfigFile = exports.buildConfigFromFlags = exports.parseArgs = exports.cli = exports.ReactNativeHarness = exports.IOSHarness = exports.AndroidHarness = exports.MobilePlatform = exports.MobileFuzzer = exports.IntegrityStatus = exports.EccIntegrity = exports.DivergenceKind = exports.DiffOracle = void 0;
// ─── Core ───────────────────────────────────────────────────────────────────
var engine_js_1 = require("./core/engine.js");
Object.defineProperty(exports, "FuzzEngine", { enumerable: true, get: function () { return engine_js_1.FuzzEngine; } });
var engine_js_2 = require("./core/engine.js"); // Alias
Object.defineProperty(exports, "LombokFuzzer", { enumerable: true, get: function () { return engine_js_2.FuzzEngine; } });
var events_js_1 = require("./core/events.js");
Object.defineProperty(exports, "FuzzEventEmitter", { enumerable: true, get: function () { return events_js_1.FuzzEventEmitter; } });
var defaults_js_1 = require("./core/defaults.js");
Object.defineProperty(exports, "createConfig", { enumerable: true, get: function () { return defaults_js_1.createConfig; } });
var types_js_1 = require("./core/types.js");
// Enums
Object.defineProperty(exports, "FuzzMode", { enumerable: true, get: function () { return types_js_1.FuzzMode; } });
Object.defineProperty(exports, "Severity", { enumerable: true, get: function () { return types_js_1.Severity; } });
Object.defineProperty(exports, "CrashCategory", { enumerable: true, get: function () { return types_js_1.CrashCategory; } });
Object.defineProperty(exports, "MutatorStrategy", { enumerable: true, get: function () { return types_js_1.MutatorStrategy; } });
Object.defineProperty(exports, "SchedulerAlgorithm", { enumerable: true, get: function () { return types_js_1.SchedulerAlgorithm; } });
Object.defineProperty(exports, "HarnessMode", { enumerable: true, get: function () { return types_js_1.HarnessMode; } });
Object.defineProperty(exports, "CoverageMetric", { enumerable: true, get: function () { return types_js_1.CoverageMetric; } });
Object.defineProperty(exports, "FuzzEvent", { enumerable: true, get: function () { return types_js_1.FuzzEvent; } });
// ─── Subsystems ─────────────────────────────────────────────────────────────
var engine_js_3 = require("./mutators/engine.js");
Object.defineProperty(exports, "MutationEngine", { enumerable: true, get: function () { return engine_js_3.MutationEngine; } });
var store_js_1 = require("./corpus/store.js");
Object.defineProperty(exports, "CorpusStore", { enumerable: true, get: function () { return store_js_1.CorpusStore; } });
var tracker_js_1 = require("./coverage/tracker.js");
Object.defineProperty(exports, "CoverageTracker", { enumerable: true, get: function () { return tracker_js_1.CoverageTracker; } });
var analyzer_js_1 = require("./crash/analyzer.js");
Object.defineProperty(exports, "CrashAnalyzer", { enumerable: true, get: function () { return analyzer_js_1.CrashAnalyzer; } });
var scheduler_js_1 = require("./scheduler/scheduler.js");
Object.defineProperty(exports, "Scheduler", { enumerable: true, get: function () { return scheduler_js_1.Scheduler; } });
// ─── Grammar ────────────────────────────────────────────────────────────────
var engine_js_4 = require("./grammar/engine.js");
Object.defineProperty(exports, "GrammarEngine", { enumerable: true, get: function () { return engine_js_4.GrammarEngine; } });
var engine_js_5 = require("./grammar/engine.js");
Object.defineProperty(exports, "NodeKind", { enumerable: true, get: function () { return engine_js_5.NodeKind; } });
// ─── Protocol Fuzzing ───────────────────────────────────────────────────────
var fuzzer_js_1 = require("./protocols/fuzzer.js");
Object.defineProperty(exports, "ProtocolFuzzerRegistry", { enumerable: true, get: function () { return fuzzer_js_1.ProtocolFuzzerRegistry; } });
Object.defineProperty(exports, "HttpFuzzer", { enumerable: true, get: function () { return fuzzer_js_1.HttpFuzzer; } });
Object.defineProperty(exports, "DnsFuzzer", { enumerable: true, get: function () { return fuzzer_js_1.DnsFuzzer; } });
Object.defineProperty(exports, "WebSocketFuzzer", { enumerable: true, get: function () { return fuzzer_js_1.WebSocketFuzzer; } });
// ─── API Fuzzing ────────────────────────────────────────────────────────────
var fuzzer_js_2 = require("./api/fuzzer.js");
Object.defineProperty(exports, "ApiFuzzer", { enumerable: true, get: function () { return fuzzer_js_2.ApiFuzzer; } });
Object.defineProperty(exports, "ApiVulnerability", { enumerable: true, get: function () { return fuzzer_js_2.ApiVulnerability; } });
// ─── Web Fuzzing ────────────────────────────────────────────────────────────
var fuzzer_js_3 = require("./web/fuzzer.js");
Object.defineProperty(exports, "WebFuzzer", { enumerable: true, get: function () { return fuzzer_js_3.WebFuzzer; } });
Object.defineProperty(exports, "WebVulnerability", { enumerable: true, get: function () { return fuzzer_js_3.WebVulnerability; } });
// ─── SQL Fuzzing ────────────────────────────────────────────────────────────
var fuzzer_js_4 = require("./sql/fuzzer.js");
Object.defineProperty(exports, "SQLFuzzer", { enumerable: true, get: function () { return fuzzer_js_4.SQLFuzzer; } });
Object.defineProperty(exports, "SQLDialect", { enumerable: true, get: function () { return fuzzer_js_4.SQLDialect; } });
// ─── Crypto Fuzzing ─────────────────────────────────────────────────────────
var fuzzer_js_5 = require("./crypto/fuzzer.js");
Object.defineProperty(exports, "CryptoFuzzer", { enumerable: true, get: function () { return fuzzer_js_5.CryptoFuzzer; } });
Object.defineProperty(exports, "CryptoVulnerability", { enumerable: true, get: function () { return fuzzer_js_5.CryptoVulnerability; } });
// ─── Hardware Fuzzing ───────────────────────────────────────────────────────
var fuzzer_js_6 = require("./hardware/fuzzer.js");
Object.defineProperty(exports, "HardwareFuzzer", { enumerable: true, get: function () { return fuzzer_js_6.HardwareFuzzer; } });
Object.defineProperty(exports, "HWInterface", { enumerable: true, get: function () { return fuzzer_js_6.HWInterface; } });
// ─── Generators ─────────────────────────────────────────────────────────────
var engine_js_6 = require("./generators/engine.js");
Object.defineProperty(exports, "GeneratorEngine", { enumerable: true, get: function () { return engine_js_6.GeneratorEngine; } });
Object.defineProperty(exports, "GeneratorKind", { enumerable: true, get: function () { return engine_js_6.GeneratorKind; } });
// ─── Harness ────────────────────────────────────────────────────────────────
var manager_js_1 = require("./harness/manager.js");
Object.defineProperty(exports, "HarnessManager", { enumerable: true, get: function () { return manager_js_1.HarnessManager; } });
Object.defineProperty(exports, "InProcessHarness", { enumerable: true, get: function () { return manager_js_1.InProcessHarness; } });
Object.defineProperty(exports, "ForkServerHarness", { enumerable: true, get: function () { return manager_js_1.ForkServerHarness; } });
Object.defineProperty(exports, "NetworkHarness", { enumerable: true, get: function () { return manager_js_1.NetworkHarness; } });
Object.defineProperty(exports, "WasmHarness", { enumerable: true, get: function () { return manager_js_1.WasmHarness; } });
// ─── Reporters ──────────────────────────────────────────────────────────────
var reporter_js_1 = require("./reporters/reporter.js");
Object.defineProperty(exports, "ReporterRegistry", { enumerable: true, get: function () { return reporter_js_1.ReporterRegistry; } });
Object.defineProperty(exports, "ConsoleReporter", { enumerable: true, get: function () { return reporter_js_1.ConsoleReporter; } });
Object.defineProperty(exports, "JsonReporter", { enumerable: true, get: function () { return reporter_js_1.JsonReporter; } });
Object.defineProperty(exports, "HtmlReporter", { enumerable: true, get: function () { return reporter_js_1.HtmlReporter; } });
Object.defineProperty(exports, "CiReporter", { enumerable: true, get: function () { return reporter_js_1.CiReporter; } });
// ─── Sanitizers ─────────────────────────────────────────────────────────────
var bridge_js_1 = require("./sanitizers/bridge.js");
Object.defineProperty(exports, "SanitizerParser", { enumerable: true, get: function () { return bridge_js_1.SanitizerParser; } });
Object.defineProperty(exports, "SanitizerKind", { enumerable: true, get: function () { return bridge_js_1.SanitizerKind; } });
Object.defineProperty(exports, "JsBoundsChecker", { enumerable: true, get: function () { return bridge_js_1.JsBoundsChecker; } });
Object.defineProperty(exports, "JsLeakChecker", { enumerable: true, get: function () { return bridge_js_1.JsLeakChecker; } });
Object.defineProperty(exports, "JsTypeChecker", { enumerable: true, get: function () { return bridge_js_1.JsTypeChecker; } });
// ─── Differential ───────────────────────────────────────────────────────────
var oracle_js_1 = require("./differential/oracle.js");
Object.defineProperty(exports, "DiffOracle", { enumerable: true, get: function () { return oracle_js_1.DiffOracle; } });
Object.defineProperty(exports, "DivergenceKind", { enumerable: true, get: function () { return oracle_js_1.DivergenceKind; } });
// ─── ECC Integrity ──────────────────────────────────────────────────────────
var integrity_js_1 = require("./ecc/integrity.js");
Object.defineProperty(exports, "EccIntegrity", { enumerable: true, get: function () { return integrity_js_1.EccIntegrity; } });
Object.defineProperty(exports, "IntegrityStatus", { enumerable: true, get: function () { return integrity_js_1.IntegrityStatus; } });
// ─── Mobile Fuzzing ─────────────────────────────────────────────────────────
var fuzzer_js_7 = require("./mobile/fuzzer.js");
Object.defineProperty(exports, "MobileFuzzer", { enumerable: true, get: function () { return fuzzer_js_7.MobileFuzzer; } });
Object.defineProperty(exports, "MobilePlatform", { enumerable: true, get: function () { return fuzzer_js_7.MobilePlatform; } });
Object.defineProperty(exports, "AndroidHarness", { enumerable: true, get: function () { return fuzzer_js_7.AndroidHarness; } });
Object.defineProperty(exports, "IOSHarness", { enumerable: true, get: function () { return fuzzer_js_7.IOSHarness; } });
Object.defineProperty(exports, "ReactNativeHarness", { enumerable: true, get: function () { return fuzzer_js_7.ReactNativeHarness; } });
// ─── CLI ────────────────────────────────────────────────────────────────────
var cli_js_1 = require("./cli/cli.js");
Object.defineProperty(exports, "cli", { enumerable: true, get: function () { return cli_js_1.cli; } });
Object.defineProperty(exports, "parseArgs", { enumerable: true, get: function () { return cli_js_1.parseArgs; } });
Object.defineProperty(exports, "buildConfigFromFlags", { enumerable: true, get: function () { return cli_js_1.buildConfigFromFlags; } });
Object.defineProperty(exports, "loadConfigFile", { enumerable: true, get: function () { return cli_js_1.loadConfigFile; } });
Object.defineProperty(exports, "handleVersion", { enumerable: true, get: function () { return cli_js_1.handleVersion; } });
Object.defineProperty(exports, "handleHelp", { enumerable: true, get: function () { return cli_js_1.handleHelp; } });
Object.defineProperty(exports, "handleCorpus", { enumerable: true, get: function () { return cli_js_1.handleCorpus; } });
Object.defineProperty(exports, "handleCrash", { enumerable: true, get: function () { return cli_js_1.handleCrash; } });
Object.defineProperty(exports, "CliCommand", { enumerable: true, get: function () { return cli_js_1.CliCommand; } });
// ─── Dashboard ──────────────────────────────────────────────────────────────
var dashboard_js_1 = require("./dashboard/dashboard.js");
Object.defineProperty(exports, "DashboardBuilder", { enumerable: true, get: function () { return dashboard_js_1.DashboardBuilder; } });
// ─── Utilities ──────────────────────────────────────────────────────────────
var prng_js_1 = require("./utils/prng.js");
Object.defineProperty(exports, "PRNG", { enumerable: true, get: function () { return prng_js_1.PRNG; } });
var hash_js_1 = require("./utils/hash.js");
Object.defineProperty(exports, "fnv1a64", { enumerable: true, get: function () { return hash_js_1.fnv1a64; } });
Object.defineProperty(exports, "xxhash64", { enumerable: true, get: function () { return hash_js_1.xxhash64; } });
Object.defineProperty(exports, "stackHash", { enumerable: true, get: function () { return hash_js_1.stackHash; } });
Object.defineProperty(exports, "edgeHash", { enumerable: true, get: function () { return hash_js_1.edgeHash; } });
// ─── Version ────────────────────────────────────────────────────────────────
exports.VERSION = '0.2.0';
exports.CODENAME = 'LombokFuzzer';
//# sourceMappingURL=index.js.map
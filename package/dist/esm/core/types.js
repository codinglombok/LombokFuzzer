/**
 * LombokFuzzer — Core Type System
 *
 * Every type in the framework derives from or references these foundational
 * interfaces. Designed for portability: each type maps cleanly to Go structs,
 * Rust enums/structs, Python dataclasses, C++ structs, PHP classes, and Java
 * records.
 *
 * @license Apache-2.0
 * @see https://github.com/codinglombok/lombokfuzzer
 */
// ─── Enumerations ───────────────────────────────────────────────────────────
/** Overall engine operating mode. */
export var FuzzMode;
(function (FuzzMode) {
    /** Mutation-based: mutate seed corpus inputs. */
    FuzzMode["Mutation"] = "mutation";
    /** Generation-based: synthesize inputs from grammar/model. */
    FuzzMode["Generation"] = "generation";
    /** Hybrid: alternate between mutation & generation phases. */
    FuzzMode["Hybrid"] = "hybrid";
    /** Differential: compare N implementations with same input. */
    FuzzMode["Differential"] = "differential";
    /** Directed: target specific code locations. */
    FuzzMode["Directed"] = "directed";
})(FuzzMode || (FuzzMode = {}));
/** Severity of a discovered crash/issue. */
export var Severity;
(function (Severity) {
    Severity["Info"] = "info";
    Severity["Low"] = "low";
    Severity["Medium"] = "medium";
    Severity["High"] = "high";
    Severity["Critical"] = "critical";
})(Severity || (Severity = {}));
/** Crash classification per CWE. */
export var CrashCategory;
(function (CrashCategory) {
    CrashCategory["BufferOverflow"] = "CWE-120";
    CrashCategory["UseAfterFree"] = "CWE-416";
    CrashCategory["NullDeref"] = "CWE-476";
    CrashCategory["IntegerOverflow"] = "CWE-190";
    CrashCategory["DivisionByZero"] = "CWE-369";
    CrashCategory["StackOverflow"] = "CWE-121";
    CrashCategory["HeapOverflow"] = "CWE-122";
    CrashCategory["FormatString"] = "CWE-134";
    CrashCategory["Assertion"] = "CWE-617";
    CrashCategory["Timeout"] = "CWE-835";
    CrashCategory["OOM"] = "CWE-400";
    CrashCategory["SQLInjection"] = "CWE-89";
    CrashCategory["XSS"] = "CWE-79";
    CrashCategory["CommandInjection"] = "CWE-78";
    CrashCategory["PathTraversal"] = "CWE-22";
    CrashCategory["SSRF"] = "CWE-918";
    CrashCategory["Deserialization"] = "CWE-502";
    CrashCategory["CryptoWeakness"] = "CWE-327";
    CrashCategory["RaceCondition"] = "CWE-362";
    CrashCategory["InformationLeak"] = "CWE-200";
    CrashCategory["Unknown"] = "CWE-0";
})(CrashCategory || (CrashCategory = {}));
/** Mutator strategy identifier. */
export var MutatorStrategy;
(function (MutatorStrategy) {
    MutatorStrategy["BitFlip"] = "bit_flip";
    MutatorStrategy["ByteFlip"] = "byte_flip";
    MutatorStrategy["ArithmeticInc"] = "arith_inc";
    MutatorStrategy["ArithmeticDec"] = "arith_dec";
    MutatorStrategy["InterestingValues"] = "interesting";
    MutatorStrategy["DictionaryInsert"] = "dict_insert";
    MutatorStrategy["DictionaryOverwrite"] = "dict_overwrite";
    MutatorStrategy["Havoc"] = "havoc";
    MutatorStrategy["Splice"] = "splice";
    MutatorStrategy["Trim"] = "trim";
    MutatorStrategy["Extend"] = "extend";
    MutatorStrategy["StructureAware"] = "structure_aware";
    MutatorStrategy["GrammarGuided"] = "grammar_guided";
    MutatorStrategy["TokenLevel"] = "token_level";
    MutatorStrategy["Custom"] = "custom";
})(MutatorStrategy || (MutatorStrategy = {}));
/** Scheduling algorithm for corpus entry selection. */
export var SchedulerAlgorithm;
(function (SchedulerAlgorithm) {
    /** Round-robin (baseline). */
    SchedulerAlgorithm["RoundRobin"] = "round_robin";
    /** AFL-style fast scheduling. */
    SchedulerAlgorithm["AFLFast"] = "afl_fast";
    /** Multi-Armed Bandit (UCB1). */
    SchedulerAlgorithm["MAB"] = "mab";
    /** Rare-branch prioritization. */
    SchedulerAlgorithm["RareBranch"] = "rare_branch";
    /** ECOFUZZ energy scheduling. */
    SchedulerAlgorithm["EcoFuzz"] = "eco_fuzz";
    /** Entropic: information-theoretic scheduling. */
    SchedulerAlgorithm["Entropic"] = "entropic";
    /** Custom user-provided scheduler. */
    SchedulerAlgorithm["Custom"] = "custom";
})(SchedulerAlgorithm || (SchedulerAlgorithm = {}));
/** Harness execution model. */
export var HarnessMode;
(function (HarnessMode) {
    /** Fuzz target runs in the same process. */
    HarnessMode["InProcess"] = "in_process";
    /** Fuzz target runs as a child process. */
    HarnessMode["ForkServer"] = "fork_server";
    /** Target is a network service. */
    HarnessMode["Network"] = "network";
    /** Target runs in WASM sandbox. */
    HarnessMode["WASM"] = "wasm";
    /** Target is hardware via debug probe. */
    HarnessMode["Hardware"] = "hardware";
    /** Target is a mobile app via ADB/XCUITest. */
    HarnessMode["Mobile"] = "mobile";
})(HarnessMode || (HarnessMode = {}));
/** Coverage metric type. */
export var CoverageMetric;
(function (CoverageMetric) {
    CoverageMetric["Edge"] = "edge";
    CoverageMetric["Branch"] = "branch";
    CoverageMetric["Path"] = "path";
    CoverageMetric["Line"] = "line";
    CoverageMetric["Function"] = "function";
    CoverageMetric["Comparison"] = "comparison";
    CoverageMetric["DataFlow"] = "data_flow";
})(CoverageMetric || (CoverageMetric = {}));
// ─── Event System ───────────────────────────────────────────────────────────
/** Events emitted by the fuzz engine. */
export var FuzzEvent;
(function (FuzzEvent) {
    FuzzEvent["Started"] = "started";
    FuzzEvent["InputGenerated"] = "input_generated";
    FuzzEvent["InputExecuted"] = "input_executed";
    FuzzEvent["NewCoverage"] = "new_coverage";
    FuzzEvent["CrashFound"] = "crash_found";
    FuzzEvent["TimeoutFound"] = "timeout_found";
    FuzzEvent["CrashMinimized"] = "crash_minimized";
    FuzzEvent["CorpusUpdated"] = "corpus_updated";
    FuzzEvent["StatsUpdated"] = "stats_updated";
    FuzzEvent["PhaseChanged"] = "phase_changed";
    FuzzEvent["Paused"] = "paused";
    FuzzEvent["Resumed"] = "resumed";
    FuzzEvent["Stopped"] = "stopped";
    FuzzEvent["Error"] = "error";
})(FuzzEvent || (FuzzEvent = {}));
//# sourceMappingURL=types.js.map
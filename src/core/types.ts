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

// ─── Identifiers ────────────────────────────────────────────────────────────

/** 64-bit corpus entry hash (FNV-1a or xxHash64 depending on config). */
export type CorpusHash = bigint;

/** Unique execution ID per fuzz run. */
export type ExecutionId = string;

/** Edge ID = (source_block << 16) | target_block. */
export type EdgeId = number;

/** Branch ID for branch coverage tracking. */
export type BranchId = number;

// ─── Enumerations ───────────────────────────────────────────────────────────

/** Overall engine operating mode. */
export enum FuzzMode {
  /** Mutation-based: mutate seed corpus inputs. */
  Mutation = 'mutation',
  /** Generation-based: synthesize inputs from grammar/model. */
  Generation = 'generation',
  /** Hybrid: alternate between mutation & generation phases. */
  Hybrid = 'hybrid',
  /** Differential: compare N implementations with same input. */
  Differential = 'differential',
  /** Directed: target specific code locations. */
  Directed = 'directed',
}

/** Severity of a discovered crash/issue. */
export enum Severity {
  Info = 'info',
  Low = 'low',
  Medium = 'medium',
  High = 'high',
  Critical = 'critical',
}

/** Crash classification per CWE. */
export enum CrashCategory {
  BufferOverflow = 'CWE-120',
  UseAfterFree = 'CWE-416',
  NullDeref = 'CWE-476',
  IntegerOverflow = 'CWE-190',
  DivisionByZero = 'CWE-369',
  StackOverflow = 'CWE-121',
  HeapOverflow = 'CWE-122',
  FormatString = 'CWE-134',
  Assertion = 'CWE-617',
  Timeout = 'CWE-835',
  OOM = 'CWE-400',
  SQLInjection = 'CWE-89',
  XSS = 'CWE-79',
  CommandInjection = 'CWE-78',
  PathTraversal = 'CWE-22',
  SSRF = 'CWE-918',
  Deserialization = 'CWE-502',
  CryptoWeakness = 'CWE-327',
  RaceCondition = 'CWE-362',
  InformationLeak = 'CWE-200',
  Unknown = 'CWE-0',
}

/** Mutator strategy identifier. */
export enum MutatorStrategy {
  BitFlip = 'bit_flip',
  ByteFlip = 'byte_flip',
  ArithmeticInc = 'arith_inc',
  ArithmeticDec = 'arith_dec',
  InterestingValues = 'interesting',
  DictionaryInsert = 'dict_insert',
  DictionaryOverwrite = 'dict_overwrite',
  Havoc = 'havoc',
  Splice = 'splice',
  Trim = 'trim',
  Extend = 'extend',
  StructureAware = 'structure_aware',
  GrammarGuided = 'grammar_guided',
  TokenLevel = 'token_level',
  Custom = 'custom',
}

/** Scheduling algorithm for corpus entry selection. */
export enum SchedulerAlgorithm {
  /** Round-robin (baseline). */
  RoundRobin = 'round_robin',
  /** AFL-style fast scheduling. */
  AFLFast = 'afl_fast',
  /** Multi-Armed Bandit (UCB1). */
  MAB = 'mab',
  /** Rare-branch prioritization. */
  RareBranch = 'rare_branch',
  /** ECOFUZZ energy scheduling. */
  EcoFuzz = 'eco_fuzz',
  /** Entropic: information-theoretic scheduling. */
  Entropic = 'entropic',
  /** Custom user-provided scheduler. */
  Custom = 'custom',
}

/** Harness execution model. */
export enum HarnessMode {
  /** Fuzz target runs in the same process. */
  InProcess = 'in_process',
  /** Fuzz target runs as a child process. */
  ForkServer = 'fork_server',
  /** Target is a network service. */
  Network = 'network',
  /** Target runs in WASM sandbox. */
  WASM = 'wasm',
  /** Target is hardware via debug probe. */
  Hardware = 'hardware',
  /** Target is a mobile app via ADB/XCUITest. */
  Mobile = 'mobile',
}

/** Coverage metric type. */
export enum CoverageMetric {
  Edge = 'edge',
  Branch = 'branch',
  Path = 'path',
  Line = 'line',
  Function = 'function',
  Comparison = 'comparison',
  DataFlow = 'data_flow',
}

// ─── Core Data Structures ───────────────────────────────────────────────────

/** A single test input (the unit of fuzzing). */
export interface FuzzInput {
  /** Raw bytes of the input. */
  readonly data: Uint8Array;
  /** Unique hash (computed lazily). */
  hash?: CorpusHash;
  /** Which mutator(s) produced this input. */
  lineage: MutatorStrategy[];
  /** Parent input hash (if mutated from existing). */
  parentHash?: CorpusHash;
  /** Generation depth from original seed. */
  depth: number;
  /** Energy score from scheduler. */
  energy: number;
  /** Execution count of this exact input. */
  executions: number;
  /** Timestamp when first created (ms since epoch). */
  createdAt: number;
  /** Metadata tags for domain-specific fuzzing. */
  tags: Map<string, string>;
}

/** Result of executing one input against the target. */
export interface ExecutionResult {
  /** The input that was executed. */
  input: FuzzInput;
  /** Whether the target crashed. */
  crashed: boolean;
  /** Whether a new coverage path was found. */
  newCoverage: boolean;
  /** New edge IDs discovered (empty if no new coverage). */
  newEdges: EdgeId[];
  /** Execution time in microseconds. */
  durationUs: number;
  /** Peak memory usage in bytes (-1 if unavailable). */
  peakMemoryBytes: number;
  /** Exit code of the target (0 = clean, -1 = in-process). */
  exitCode: number;
  /** Signal that killed the target (0 if none). */
  signal: number;
  /** Sanitizer output if any. */
  sanitizerOutput?: string;
  /** Standard error captured from target. */
  stderr?: string;
  /** Coverage snapshot at end of execution. */
  coverageSnapshot?: CoverageSnapshot;
}

/** Snapshot of coverage at a point in time. */
export interface CoverageSnapshot {
  /** Bitmap of edge hit counts (shared memory style). */
  edgeBitmap: Uint8Array;
  /** Number of unique edges hit. */
  totalEdgesHit: number;
  /** Total edges in the target binary. */
  totalEdges: number;
  /** Coverage percentage (0.0–100.0). */
  percentage: number;
  /** Metric type this snapshot represents. */
  metric: CoverageMetric;
  /** Per-branch hit counts (optional, for branch coverage). */
  branchHitCounts?: Map<BranchId, number>;
}

/** A crash found during fuzzing. */
export interface CrashInfo {
  /** Unique crash identifier (stack hash). */
  id: string;
  /** The input that triggered the crash. */
  input: FuzzInput;
  /** Stack trace frames. */
  stackTrace: StackFrame[];
  /** CWE-based classification. */
  category: CrashCategory;
  /** Assessed severity. */
  severity: Severity;
  /** Whether this is a duplicate of an existing crash. */
  isDuplicate: boolean;
  /** ID of the original crash if duplicate. */
  duplicateOf?: string;
  /** Signal or exception name. */
  signal: string;
  /** Sanitizer report (ASan, MSan, etc.). */
  sanitizerReport?: string;
  /** When the crash was first found. */
  discoveredAt: number;
  /** Number of times this crash has been reproduced. */
  reproCount: number;
  /** Minimized reproducer input (if minimization ran). */
  minimizedInput?: Uint8Array;
}

/** A single frame in a stack trace. */
export interface StackFrame {
  /** Function/method name. */
  functionName: string;
  /** Source file path (if available). */
  file?: string;
  /** Line number (if available). */
  line?: number;
  /** Column number (if available). */
  column?: number;
  /** Module/library name. */
  module?: string;
  /** Instruction address. */
  address?: bigint;
}

/** Dictionary entry for dictionary-based mutation. */
export interface DictionaryEntry {
  /** The token bytes. */
  value: Uint8Array;
  /** Level: auto-discovered (0), user-provided (1), override (2). */
  level: number;
  /** How many times this entry produced new coverage. */
  hitCount: number;
}

// ─── Configuration ──────────────────────────────────────────────────────────

/** Top-level fuzzer configuration. */
export interface FuzzConfig {
  /** Human-readable name for this fuzz campaign. */
  name: string;

  /** Operating mode. */
  mode: FuzzMode;

  /** Maximum number of executions (0 = unlimited). */
  maxExecutions: number;

  /** Maximum wall-clock time in seconds (0 = unlimited). */
  maxTimeSeconds: number;

  /** Maximum input size in bytes. */
  maxInputSize: number;

  /** Minimum input size in bytes. */
  minInputSize: number;

  /** Execution timeout per input in milliseconds. */
  timeoutMs: number;

  /** Memory limit per execution in MB (0 = unlimited). */
  memoryLimitMb: number;

  /** Number of parallel fuzzing workers. */
  workers: number;

  /** PRNG seed for reproducibility (0 = random). */
  seed: bigint;

  /** Path to seed corpus directory. */
  seedCorpusDir?: string;

  /** Path to output corpus directory. */
  outputCorpusDir: string;

  /** Path to crash output directory. */
  crashDir: string;

  /** Mutator configuration. */
  mutators: MutatorConfig;

  /** Scheduler configuration. */
  scheduler: SchedulerConfig;

  /** Coverage configuration. */
  coverage: CoverageConfig;

  /** Harness configuration. */
  harness: HarnessConfig;

  /** Reporter configuration. */
  reporters: ReporterConfig[];

  /** Dictionary file paths. */
  dictionaries: string[];

  /** Enable ECC-protected corpus (requires lombokecc). */
  eccProtectedCorpus: boolean;

  /** Custom environment variables for the target. */
  env: Record<string, string>;

  /** Sanitizers to enable. */
  sanitizers: string[];

  /** Whether to minimize crash inputs automatically. */
  autoMinimize: boolean;

  /** Whether to deduplicate crashes by stack hash. */
  deduplicateCrashes: boolean;

  /** Custom metadata for this campaign. */
  metadata: Record<string, unknown>;
}

/** Mutator subsystem configuration. */
export interface MutatorConfig {
  /** Which strategies to enable. */
  strategies: MutatorStrategy[];
  /** Max stacked mutations per havoc cycle. */
  maxHavocStack: number;
  /** Maximum splice overlay size (bytes). */
  maxSpliceSize: number;
  /** Custom mutator function (if strategy includes Custom). */
  customMutator?: (input: Uint8Array, maxSize: number) => Uint8Array;
}

/** Scheduler subsystem configuration. */
export interface SchedulerConfig {
  /** Scheduling algorithm. */
  algorithm: SchedulerAlgorithm;
  /** Initial energy per corpus entry. */
  initialEnergy: number;
  /** Minimum energy. */
  minEnergy: number;
  /** Maximum energy. */
  maxEnergy: number;
  /** Custom scoring function. */
  customScorer?: (entry: FuzzInput, stats: FuzzStats) => number;
}

/** Coverage subsystem configuration. */
export interface CoverageConfig {
  /** Which coverage metric(s) to track. */
  metrics: CoverageMetric[];
  /** Size of edge bitmap (power of 2, typical: 65536). */
  bitmapSize: number;
  /** Whether to track comparison operands (CmpLog). */
  trackComparisons: boolean;
  /** Whether to track data-flow tags. */
  trackDataFlow: boolean;
}

/** Harness subsystem configuration. */
export interface HarnessConfig {
  /** Execution model. */
  mode: HarnessMode;
  /** Path to target binary (for fork-server). */
  targetBinary?: string;
  /** Arguments for target binary. */
  targetArgs?: string[];
  /** Network target host:port (for network mode). */
  networkTarget?: string;
  /** In-process fuzz target function. */
  targetFunction?: (data: Uint8Array) => void;
  /** WASM module bytes (for WASM mode). */
  wasmModule?: Uint8Array;
  /** Hardware debug probe config (for hardware mode). */
  hardwareConfig?: HardwareProbeConfig;
}

/** Hardware debug probe configuration. */
export interface HardwareProbeConfig {
  /** Probe type: jtag, swd, uart, spi, i2c, usb. */
  probeType: string;
  /** Device path or URL. */
  devicePath: string;
  /** Baud rate (for UART). */
  baudRate?: number;
  /** Target chip ID. */
  chipId?: string;
  /** Flash base address. */
  flashBase?: bigint;
  /** RAM base address. */
  ramBase?: bigint;
}

/** Reporter configuration for one output sink. */
export interface ReporterConfig {
  /** Reporter type. */
  type: 'console' | 'json' | 'html' | 'ci' | 'custom';
  /** Output path (file or directory). */
  outputPath?: string;
  /** Reporting interval in seconds. */
  intervalSeconds: number;
  /** Custom reporter function. */
  customReporter?: (stats: FuzzStats) => void;
}

// ─── Runtime Statistics ─────────────────────────────────────────────────────

/** Live statistics of a fuzz campaign. */
export interface FuzzStats {
  /** Campaign execution ID. */
  executionId: ExecutionId;
  /** Campaign name. */
  campaignName: string;
  /** Campaign start time (ms since epoch). */
  startedAt: number;
  /** Current wall-clock elapsed time in ms. */
  elapsedMs: number;
  /** Total number of executions completed. */
  totalExecutions: number;
  /** Executions per second (current rate). */
  execsPerSecond: number;
  /** Peak executions per second seen. */
  peakExecsPerSecond: number;
  /** Current corpus size (number of entries). */
  corpusSize: number;
  /** Total bytes across all corpus entries. */
  corpusTotalBytes: number;
  /** Number of unique crashes found. */
  uniqueCrashes: number;
  /** Number of unique hangs/timeouts found. */
  uniqueTimeouts: number;
  /** Coverage percentage (current). */
  coveragePercent: number;
  /** Total unique edges discovered. */
  edgesFound: number;
  /** Total possible edges (from instrumentation). */
  edgesTotal: number;
  /** Last time a new edge was found (ms since epoch). */
  lastNewEdgeAt: number;
  /** Number of dictionary entries. */
  dictionarySize: number;
  /** Map of mutator strategy → times chosen. */
  mutatorHits: Map<MutatorStrategy, number>;
  /** Map of mutator strategy → new coverage finds. */
  mutatorFinds: Map<MutatorStrategy, number>;
  /** Stability: percentage of deterministic executions. */
  stability: number;
  /** Pending favorite corpus entries. */
  pendingFavorites: number;
  /** Current phase/stage name. */
  currentPhase: string;
  /** Crashes by severity. */
  crashesBySeverity: Map<Severity, number>;
}

// ─── Event System ───────────────────────────────────────────────────────────

/** Events emitted by the fuzz engine. */
export enum FuzzEvent {
  Started = 'started',
  InputGenerated = 'input_generated',
  InputExecuted = 'input_executed',
  NewCoverage = 'new_coverage',
  CrashFound = 'crash_found',
  TimeoutFound = 'timeout_found',
  CrashMinimized = 'crash_minimized',
  CorpusUpdated = 'corpus_updated',
  StatsUpdated = 'stats_updated',
  PhaseChanged = 'phase_changed',
  Paused = 'paused',
  Resumed = 'resumed',
  Stopped = 'stopped',
  Error = 'error',
}

/** Typed event handler. */
export type FuzzEventHandler<T = unknown> = (data: T) => void;

/** Event data types. */
export interface FuzzEventMap {
  [FuzzEvent.Started]: { config: FuzzConfig; executionId: ExecutionId };
  [FuzzEvent.InputGenerated]: { input: FuzzInput };
  [FuzzEvent.InputExecuted]: { result: ExecutionResult };
  [FuzzEvent.NewCoverage]: { result: ExecutionResult; newEdgeCount: number };
  [FuzzEvent.CrashFound]: { crash: CrashInfo };
  [FuzzEvent.TimeoutFound]: { input: FuzzInput; durationUs: number };
  [FuzzEvent.CrashMinimized]: { crash: CrashInfo; originalSize: number; minimizedSize: number };
  [FuzzEvent.CorpusUpdated]: { corpusSize: number; addedHash: CorpusHash };
  [FuzzEvent.StatsUpdated]: { stats: FuzzStats };
  [FuzzEvent.PhaseChanged]: { phase: string; reason: string };
  [FuzzEvent.Paused]: { reason: string };
  [FuzzEvent.Resumed]: Record<string, never>;
  [FuzzEvent.Stopped]: { reason: string; stats: FuzzStats };
  [FuzzEvent.Error]: { error: Error; context: string };
}

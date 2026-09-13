/**
 * LombokFuzzer — Fuzz Engine
 *
 * The central orchestrator. Manages the fuzz loop: pick input → mutate →
 * execute → evaluate coverage → update corpus → report → repeat.
 *
 * @license Apache-2.0
 */

import type {
  FuzzConfig,
  FuzzInput,
  FuzzStats,
  ExecutionResult,
  ExecutionId,
  FuzzEventHandler,
  FuzzEventMap,
} from './types.js';
import { FuzzEvent } from './types.js';
import { FuzzEventEmitter } from './events.js';
import { createConfig } from './defaults.js';
import { PRNG, fnv1a64 } from '../utils/index.js';
import { MutationEngine } from '../mutators/engine.js';
import { CorpusStore } from '../corpus/store.js';
import { CoverageTracker } from '../coverage/tracker.js';
import { CrashAnalyzer } from '../crash/analyzer.js';
import { Scheduler } from '../scheduler/scheduler.js';

export class FuzzEngine {
  readonly config: FuzzConfig;
  readonly events: FuzzEventEmitter;
  readonly prng: PRNG;
  readonly corpus: CorpusStore;
  readonly coverage: CoverageTracker;
  readonly mutator: MutationEngine;
  readonly crashes: CrashAnalyzer;
  readonly scheduler: Scheduler;

  private _running = false;
  private _paused = false;
  private _stats: FuzzStats;
  private _executionId: ExecutionId;
  private _startTime = 0;
  private _lastStatsReport = 0;
  private _totalExecs = 0;
  private _recentExecs = 0;
  private _recentExecsWindowStart = 0;

  constructor(userConfig: Partial<FuzzConfig> = {}) {
    this.config = createConfig(userConfig);
    this.events = new FuzzEventEmitter();
    this.prng = new PRNG(this.config.seed || BigInt(Date.now()));

    this._executionId = generateExecutionId();
    this._stats = this.initStats();

    // Subsystems
    this.corpus = new CorpusStore(this.config, this.prng);
    this.coverage = new CoverageTracker(this.config.coverage);
    this.mutator = new MutationEngine(this.config.mutators, this.prng);
    this.crashes = new CrashAnalyzer(this.config);
    this.scheduler = new Scheduler(this.config.scheduler, this.prng);
  }

  /** Start the fuzz campaign. Returns when done or stopped. */
  async run(): Promise<FuzzStats> {
    this._running = true;
    this._startTime = Date.now();
    this._recentExecsWindowStart = this._startTime;

    this.events.emit(FuzzEvent.Started, {
      config: this.config,
      executionId: this._executionId,
    });

    // Load seed corpus
    await this.loadSeedCorpus();

    // If no seeds, generate one random input
    if (this.corpus.size === 0) {
      const seed = this.generateRandomInput();
      this.corpus.add(seed);
    }

    // Main fuzz loop
    try {
      while (this._running && !this.shouldStop()) {
        if (this._paused) {
          await sleep(100);
          continue;
        }

        await this.fuzzOne();
        this._totalExecs++;

        // Periodic stats update
        if (Date.now() - this._lastStatsReport >= this.statsIntervalMs()) {
          this.updateAndReportStats();
        }
      }
    } finally {
      this._running = false;
      this.updateAndReportStats();
      this.events.emit(FuzzEvent.Stopped, {
        reason: this.stopReason(),
        stats: this._stats,
      });
    }

    return this._stats;
  }

  /** Execute one fuzz iteration. */
  private async fuzzOne(): Promise<void> {
    // 1) Pick a corpus entry via scheduler
    const parent = this.scheduler.select(this.corpus.entries, this._stats);
    if (!parent) return;

    // 2) Mutate the input
    const mutated = this.mutator.mutate(
      parent.data,
      this.config.maxInputSize,
      this.corpus.entries,
    );

    const input: FuzzInput = {
      data: mutated.data,
      lineage: mutated.strategies,
      parentHash: parent.hash,
      depth: parent.depth + 1,
      energy: parent.energy,
      executions: 0,
      createdAt: Date.now(),
      tags: new Map(),
    };
    input.hash = fnv1a64(input.data);

    this.events.emit(FuzzEvent.InputGenerated, { input });

    // 3) Execute against target
    const result = await this.executeInput(input);

    this.events.emit(FuzzEvent.InputExecuted, { result });

    // 4) Evaluate coverage
    if (result.newCoverage) {
      this.corpus.add(input);
      this.events.emit(FuzzEvent.NewCoverage, {
        result,
        newEdgeCount: result.newEdges.length,
      });
      this.events.emit(FuzzEvent.CorpusUpdated, {
        corpusSize: this.corpus.size,
        addedHash: input.hash!,
      });
    }

    // 5) Crash handling
    if (result.crashed) {
      const crash = this.crashes.analyze(result);
      if (crash && !crash.isDuplicate) {
        this.events.emit(FuzzEvent.CrashFound, { crash });
      }
    }

    // 6) Update scheduler energy
    this.scheduler.updateEnergy(parent, result);

    // Track exec rate
    this._recentExecs++;
  }

  /** Execute an input against the fuzz target. */
  private async executeInput(input: FuzzInput): Promise<ExecutionResult> {
    const startUs = performanceNow();
    let crashed = false;
    let exitCode = 0;
    let signal = 0;
    let stderr: string | undefined;
    let sanitizerOutput: string | undefined;

    const targetFn = this.config.harness.targetFunction;

    if (targetFn) {
      // In-process execution
      try {
        targetFn(input.data);
      } catch (err: unknown) {
        crashed = true;
        exitCode = 1;
        if (err instanceof Error) {
          stderr = `${err.name}: ${err.message}\n${err.stack ?? ''}`;
        }
      }
    } else {
      // Fork-server or network mode would go here
      // For v0.1.0, we support in-process only
      throw new Error(
        'LombokFuzzer v0.1.0: only InProcess harness is implemented. ' +
        'Set config.harness.targetFunction.',
      );
    }

    const durationUs = performanceNow() - startUs;
    input.executions++;

    // Coverage check
    const snapshot = this.coverage.snapshot();
    const newEdges = this.coverage.findNewEdges(snapshot);
    const newCoverage = newEdges.length > 0;

    if (newCoverage) {
      this.coverage.mergeBitmap(snapshot);
    }

    return {
      input,
      crashed,
      newCoverage,
      newEdges,
      durationUs,
      peakMemoryBytes: -1,
      exitCode,
      signal,
      sanitizerOutput,
      stderr,
      coverageSnapshot: snapshot,
    };
  }

  /** Generate a random input from scratch. */
  private generateRandomInput(): FuzzInput {
    const size = this.prng.nextRange(
      this.config.maxInputSize - this.config.minInputSize + 1,
    ) + this.config.minInputSize;

    const data = this.prng.randomBytes(size);
    const hash = fnv1a64(data);

    return {
      data,
      hash,
      lineage: [],
      depth: 0,
      energy: this.config.scheduler.initialEnergy,
      executions: 0,
      createdAt: Date.now(),
      tags: new Map(),
    };
  }

  /** Load seed corpus from directory. */
  private async loadSeedCorpus(): Promise<void> {
    if (!this.config.seedCorpusDir) return;
    // Node.js file I/O — deferred to platform adapter
    // In v0.1.0, seeds are added via corpus.addSeed()
  }

  // ─── Control ────────────────────────────────────────────────────────────

  /** Pause the fuzzer. */
  pause(): void {
    if (this._running && !this._paused) {
      this._paused = true;
      this.events.emit(FuzzEvent.Paused, { reason: 'user_requested' });
    }
  }

  /** Resume a paused fuzzer. */
  resume(): void {
    if (this._paused) {
      this._paused = false;
      this.events.emit(FuzzEvent.Resumed, {} as Record<string, never>);
    }
  }

  /** Stop the fuzzer gracefully. */
  stop(): void {
    this._running = false;
  }

  /**
   * Add a raw seed input to the corpus. Convenience wrapper over
   * `engine.corpus.addSeed`. Returns true if the seed was added (not a dup).
   */
  addSeed(data: Uint8Array): boolean {
    return this.corpus.addSeed(data);
  }

  /**
   * Subscribe to a fuzzer event. Convenience passthrough to the internal
   * event emitter, so callers can write `fuzzer.on(FuzzEvent.CrashFound, …)`
   * without reaching into `engine.events`.
   */
  on<E extends FuzzEvent>(event: E, handler: FuzzEventHandler<FuzzEventMap[E]>): this {
    this.events.on(event, handler);
    return this;
  }

  /** Subscribe to a fuzzer event once (auto-removed after first fire). */
  once<E extends FuzzEvent>(event: E, handler: FuzzEventHandler<FuzzEventMap[E]>): this {
    this.events.once(event, handler);
    return this;
  }

  /** Get current stats. */
  get stats(): Readonly<FuzzStats> {
    return this._stats;
  }

  /** Whether the engine is currently running. */
  get running(): boolean {
    return this._running;
  }

  // ─── Internal ───────────────────────────────────────────────────────────

  private shouldStop(): boolean {
    if (this.config.maxExecutions > 0 && this._totalExecs >= this.config.maxExecutions) {
      return true;
    }
    if (this.config.maxTimeSeconds > 0) {
      const elapsed = (Date.now() - this._startTime) / 1000;
      if (elapsed >= this.config.maxTimeSeconds) return true;
    }
    return false;
  }

  private stopReason(): string {
    if (this.config.maxExecutions > 0 && this._totalExecs >= this.config.maxExecutions) {
      return `max_executions_reached (${this.config.maxExecutions})`;
    }
    if (this.config.maxTimeSeconds > 0) {
      return `max_time_reached (${this.config.maxTimeSeconds}s)`;
    }
    return 'user_stopped';
  }

  private statsIntervalMs(): number {
    const reporters = this.config.reporters;
    if (reporters.length === 0) return 5000;
    return Math.min(...reporters.map(r => r.intervalSeconds * 1000));
  }

  private updateAndReportStats(): void {
    const now = Date.now();
    const windowMs = now - this._recentExecsWindowStart;
    const execsPerSec = windowMs > 0 ? (this._recentExecs / windowMs) * 1000 : 0;

    this._stats = {
      ...this._stats,
      elapsedMs: now - this._startTime,
      totalExecutions: this._totalExecs,
      execsPerSecond: Math.round(execsPerSec),
      peakExecsPerSecond: Math.max(this._stats.peakExecsPerSecond, Math.round(execsPerSec)),
      corpusSize: this.corpus.size,
      corpusTotalBytes: this.corpus.totalBytes,
      uniqueCrashes: this.crashes.uniqueCount,
      coveragePercent: this.coverage.percentage,
      edgesFound: this.coverage.edgesFound,
      edgesTotal: this.coverage.edgesTotal,
      lastNewEdgeAt: this.coverage.lastNewEdgeAt,
      dictionarySize: this.mutator.dictionarySize,
      stability: this.coverage.stability,
    };

    this._recentExecs = 0;
    this._recentExecsWindowStart = now;
    this._lastStatsReport = now;

    this.events.emit(FuzzEvent.StatsUpdated, { stats: this._stats });
  }

  private initStats(): FuzzStats {
    return {
      executionId: this._executionId,
      campaignName: this.config.name,
      startedAt: 0,
      elapsedMs: 0,
      totalExecutions: 0,
      execsPerSecond: 0,
      peakExecsPerSecond: 0,
      corpusSize: 0,
      corpusTotalBytes: 0,
      uniqueCrashes: 0,
      uniqueTimeouts: 0,
      coveragePercent: 0,
      edgesFound: 0,
      edgesTotal: 0,
      lastNewEdgeAt: 0,
      dictionarySize: 0,
      mutatorHits: new Map(),
      mutatorFinds: new Map(),
      stability: 100,
      pendingFavorites: 0,
      currentPhase: 'init',
      crashesBySeverity: new Map(),
    };
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────

function generateExecutionId(): ExecutionId {
  const ts = Date.now().toString(36);
  const rand = Math.random().toString(36).substring(2, 8);
  return `lkfuzz-${ts}-${rand}`;
}

function performanceNow(): number {
  if (typeof performance !== 'undefined') {
    return Math.round(performance.now() * 1000);
  }
  const [sec, nsec] = process.hrtime();
  return sec * 1_000_000 + Math.round(nsec / 1000);
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

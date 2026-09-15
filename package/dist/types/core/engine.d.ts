/**
 * LombokFuzzer — Fuzz Engine
 *
 * The central orchestrator. Manages the fuzz loop: pick input → mutate →
 * execute → evaluate coverage → update corpus → report → repeat.
 *
 * @license Apache-2.0
 */
import type { FuzzConfig, FuzzStats, FuzzEventHandler, FuzzEventMap } from './types.js';
import { FuzzEvent } from './types.js';
import { FuzzEventEmitter } from './events.js';
import { PRNG } from '../utils/index.js';
import { MutationEngine } from '../mutators/engine.js';
import { CorpusStore } from '../corpus/store.js';
import { CoverageTracker } from '../coverage/tracker.js';
import { CrashAnalyzer } from '../crash/analyzer.js';
import { Scheduler } from '../scheduler/scheduler.js';
export declare class FuzzEngine {
    readonly config: FuzzConfig;
    readonly events: FuzzEventEmitter;
    readonly prng: PRNG;
    readonly corpus: CorpusStore;
    readonly coverage: CoverageTracker;
    readonly mutator: MutationEngine;
    readonly crashes: CrashAnalyzer;
    readonly scheduler: Scheduler;
    private _running;
    private _paused;
    private _stats;
    private _executionId;
    private _startTime;
    private _lastStatsReport;
    private _totalExecs;
    private _recentExecs;
    private _recentExecsWindowStart;
    constructor(userConfig?: Partial<FuzzConfig>);
    /** Start the fuzz campaign. Returns when done or stopped. */
    run(): Promise<FuzzStats>;
    /** Execute one fuzz iteration. */
    private fuzzOne;
    /** Execute an input against the fuzz target. */
    private executeInput;
    /** Generate a random input from scratch. */
    private generateRandomInput;
    /** Load seed corpus from directory. */
    private loadSeedCorpus;
    /** Pause the fuzzer. */
    pause(): void;
    /** Resume a paused fuzzer. */
    resume(): void;
    /** Stop the fuzzer gracefully. */
    stop(): void;
    /**
     * Add a raw seed input to the corpus. Convenience wrapper over
     * `engine.corpus.addSeed`. Returns true if the seed was added (not a dup).
     */
    addSeed(data: Uint8Array): boolean;
    /**
     * Subscribe to a fuzzer event. Convenience passthrough to the internal
     * event emitter, so callers can write `fuzzer.on(FuzzEvent.CrashFound, …)`
     * without reaching into `engine.events`.
     */
    on<E extends FuzzEvent>(event: E, handler: FuzzEventHandler<FuzzEventMap[E]>): this;
    /** Subscribe to a fuzzer event once (auto-removed after first fire). */
    once<E extends FuzzEvent>(event: E, handler: FuzzEventHandler<FuzzEventMap[E]>): this;
    /** Get current stats. */
    get stats(): Readonly<FuzzStats>;
    /** Whether the engine is currently running. */
    get running(): boolean;
    private shouldStop;
    private stopReason;
    private statsIntervalMs;
    private updateAndReportStats;
    private initStats;
}
//# sourceMappingURL=engine.d.ts.map
/**
 * LombokFuzzer — Scheduler
 *
 * Selects which corpus entry to fuzz next and manages energy allocation.
 * Implements 7 scheduling algorithms based on fuzzing research:
 *
 * 1. RoundRobin    — baseline sequential
 * 2. AFLFast       — power schedules from AFL++
 * 3. MAB           — Multi-Armed Bandit (UCB1)
 * 4. RareBranch    — prioritize inputs hitting rare edges
 * 5. EcoFuzz       — adaptive energy from ECOFUZZ paper
 * 6. Entropic      — information-theoretic (from libFuzzer)
 * 7. Custom        — user-provided scoring function
 *
 * @license Apache-2.0
 */
import type { SchedulerConfig, FuzzInput, FuzzStats, ExecutionResult } from '../core/types.js';
import type { PRNG } from '../utils/prng.js';
export declare class Scheduler {
    private readonly config;
    private readonly prng;
    private _roundRobinIdx;
    private readonly _armRewards;
    private _totalSelections;
    constructor(config: SchedulerConfig, prng: PRNG);
    /** Select the next corpus entry to fuzz. */
    select(corpus: ReadonlyArray<FuzzInput>, stats: FuzzStats): FuzzInput | null;
    /** Update energy of an entry after execution. */
    updateEnergy(entry: FuzzInput, result: ExecutionResult): void;
    /** Simple round-robin (baseline). */
    private roundRobin;
    /** AFL-fast power schedule: favor less-executed, newly-found entries. */
    private aflFast;
    /** Multi-Armed Bandit with UCB1 exploration. */
    private mab;
    /** Rare-branch: prioritize entries that hit rarely-covered edges. */
    private rareBranch;
    /** ECOFUZZ: adaptive energy based on global coverage progress. */
    private ecoFuzz;
    /** Entropic: information-theoretic selection (feature frequency). */
    private entropic;
    /** Custom: user-provided scoring function. */
    private custom;
}
//# sourceMappingURL=scheduler.d.ts.map
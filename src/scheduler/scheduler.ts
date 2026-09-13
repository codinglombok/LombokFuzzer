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
import { SchedulerAlgorithm } from '../core/types.js';
import type { PRNG } from '../utils/prng.js';

export class Scheduler {
  private readonly config: SchedulerConfig;
  private readonly prng: PRNG;
  private _roundRobinIdx = 0;
  private readonly _armRewards = new Map<bigint, { total: number; count: number }>();
  private _totalSelections = 0;

  constructor(config: SchedulerConfig, prng: PRNG) {
    this.config = config;
    this.prng = prng;
  }

  /** Select the next corpus entry to fuzz. */
  select(
    corpus: ReadonlyArray<FuzzInput>,
    stats: FuzzStats,
  ): FuzzInput | null {
    if (corpus.length === 0) return null;

    this._totalSelections++;

    switch (this.config.algorithm) {
      case SchedulerAlgorithm.RoundRobin:
        return this.roundRobin(corpus);
      case SchedulerAlgorithm.AFLFast:
        return this.aflFast(corpus);
      case SchedulerAlgorithm.MAB:
        return this.mab(corpus);
      case SchedulerAlgorithm.RareBranch:
        return this.rareBranch(corpus, stats);
      case SchedulerAlgorithm.EcoFuzz:
        return this.ecoFuzz(corpus, stats);
      case SchedulerAlgorithm.Entropic:
        return this.entropic(corpus);
      case SchedulerAlgorithm.Custom:
        return this.custom(corpus, stats);
      default:
        return this.roundRobin(corpus);
    }
  }

  /** Update energy of an entry after execution. */
  updateEnergy(entry: FuzzInput, result: ExecutionResult): void {
    const reward = result.newCoverage ? 1 : (result.crashed ? 2 : 0);

    // Update MAB arm statistics
    const hash = entry.hash!;
    const arm = this._armRewards.get(hash) ?? { total: 0, count: 0 };
    arm.total += reward;
    arm.count++;
    this._armRewards.set(hash, arm);

    // Adjust energy based on result
    if (result.newCoverage) {
      entry.energy = Math.min(entry.energy * 2, this.config.maxEnergy);
    } else if (entry.executions > 10 && result.durationUs > 0) {
      // Decay energy for inputs that haven't found new coverage in a while
      entry.energy = Math.max(entry.energy * 0.95, this.config.minEnergy);
    }
  }

  // ─── Algorithms ─────────────────────────────────────────────────────────

  /** Simple round-robin (baseline). */
  private roundRobin(corpus: ReadonlyArray<FuzzInput>): FuzzInput {
    const entry = corpus[this._roundRobinIdx % corpus.length]!;
    this._roundRobinIdx++;
    return entry;
  }

  /** AFL-fast power schedule: favor less-executed, newly-found entries. */
  private aflFast(corpus: ReadonlyArray<FuzzInput>): FuzzInput {
    // Score: lower execution count + higher energy + recency bonus
    let bestScore = -Infinity;
    let best: FuzzInput = corpus[0]!;

    for (const entry of corpus) {
      const execFactor = 1 / (1 + Math.log2(1 + entry.executions));
      const depthFactor = 1 / (1 + entry.depth * 0.1);
      const energyFactor = entry.energy;
      const score = execFactor * depthFactor * energyFactor;

      if (score > bestScore || (score === bestScore && this.prng.nextBool(0.5))) {
        bestScore = score;
        best = entry;
      }
    }

    return best;
  }

  /** Multi-Armed Bandit with UCB1 exploration. */
  private mab(corpus: ReadonlyArray<FuzzInput>): FuzzInput {
    const lnTotal = Math.log(this._totalSelections + 1);
    let bestUcb = -Infinity;
    let best: FuzzInput = corpus[0]!;

    for (const entry of corpus) {
      const hash = entry.hash!;
      const arm = this._armRewards.get(hash);

      if (!arm || arm.count === 0) {
        // Unexplored arm → infinite UCB → select immediately
        return entry;
      }

      const avgReward = arm.total / arm.count;
      const exploration = Math.sqrt((2 * lnTotal) / arm.count);
      const ucb = avgReward + exploration;

      if (ucb > bestUcb) {
        bestUcb = ucb;
        best = entry;
      }
    }

    return best;
  }

  /** Rare-branch: prioritize entries that hit rarely-covered edges. */
  private rareBranch(corpus: ReadonlyArray<FuzzInput>, _stats: FuzzStats): FuzzInput {
    // Use energy as a proxy for rare-branch coverage
    // Higher energy = hit rarer branches
    const weights: number[] = [];
    let totalWeight = 0;

    for (const entry of corpus) {
      const w = entry.energy * (1 + 1 / (1 + entry.executions));
      weights.push(w);
      totalWeight += w;
    }

    if (totalWeight <= 0) return this.prng.pick([...corpus]);

    // Weighted random selection
    let target = this.prng.nextFloat() * totalWeight;
    for (let i = 0; i < corpus.length; i++) {
      target -= weights[i]!;
      if (target <= 0) return corpus[i]!;
    }

    return corpus[corpus.length - 1]!;
  }

  /** ECOFUZZ: adaptive energy based on global coverage progress. */
  private ecoFuzz(corpus: ReadonlyArray<FuzzInput>, stats: FuzzStats): FuzzInput {
    // When coverage is stalling, increase energy for least-explored inputs
    const timeSinceNewEdge = stats.elapsedMs - stats.lastNewEdgeAt;
    const isStalling = timeSinceNewEdge > 30_000; // 30 seconds with no new edge

    if (isStalling) {
      // Boost exploration: pick least-executed entries
      let minExecs = Infinity;
      let candidates: FuzzInput[] = [];
      for (const entry of corpus) {
        if (entry.executions < minExecs) {
          minExecs = entry.executions;
          candidates = [entry];
        } else if (entry.executions === minExecs) {
          candidates.push(entry);
        }
      }
      return this.prng.pick(candidates);
    }

    // Normal: AFL-fast style
    return this.aflFast(corpus);
  }

  /** Entropic: information-theoretic selection (feature frequency). */
  private entropic(corpus: ReadonlyArray<FuzzInput>): FuzzInput {
    // Compute "information score" based on input uniqueness
    // Score = -sum(p * log2(p)) where p = frequency of each byte value
    let bestEntropy = -1;
    let best: FuzzInput = corpus[0]!;

    for (const entry of corpus) {
      const entropy = shannonEntropy(entry.data);
      const score = entropy * entry.energy / (1 + entry.executions);

      if (score > bestEntropy) {
        bestEntropy = score;
        best = entry;
      }
    }

    return best;
  }

  /** Custom: user-provided scoring function. */
  private custom(corpus: ReadonlyArray<FuzzInput>, stats: FuzzStats): FuzzInput {
    if (!this.config.customScorer) return this.roundRobin(corpus);

    let bestScore = -Infinity;
    let best: FuzzInput = corpus[0]!;

    for (const entry of corpus) {
      const score = this.config.customScorer(entry, stats);
      if (score > bestScore) {
        bestScore = score;
        best = entry;
      }
    }

    return best;
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────

/** Compute Shannon entropy of a byte array (bits per byte). */
function shannonEntropy(data: Uint8Array): number {
  if (data.length === 0) return 0;

  const freq = new Uint32Array(256);
  for (let i = 0; i < data.length; i++) {
    const byteVal = data[i]!;
    freq[byteVal] = (freq[byteVal] ?? 0) + 1;
  }

  let entropy = 0;
  const len = data.length;
  for (let i = 0; i < 256; i++) {
    if (freq[i]! > 0) {
      const p = freq[i]! / len;
      entropy -= p * Math.log2(p);
    }
  }

  return entropy;
}

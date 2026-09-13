/**
 * LombokFuzzer — Default Configuration
 *
 * Sensible defaults for every config field. Users override only what they need.
 *
 * @license Apache-2.0
 */

import {
  type FuzzConfig,
  FuzzMode,
  MutatorStrategy,
  SchedulerAlgorithm,
  CoverageMetric,
  HarnessMode,
} from './types.js';

/** Build a complete FuzzConfig by merging user overrides onto defaults. */
export function createConfig(overrides: Partial<FuzzConfig> = {}): FuzzConfig {
  const defaults: FuzzConfig = {
    name: 'lombokfuzzer-campaign',
    mode: FuzzMode.Mutation,
    maxExecutions: 0,
    maxTimeSeconds: 0,
    maxInputSize: 1_048_576,    // 1 MiB
    minInputSize: 1,
    timeoutMs: 5_000,           // 5 seconds
    memoryLimitMb: 2_048,       // 2 GiB
    workers: 1,
    seed: 0n,
    outputCorpusDir: './corpus',
    crashDir: './crashes',
    mutators: {
      strategies: [
        MutatorStrategy.BitFlip,
        MutatorStrategy.ByteFlip,
        MutatorStrategy.ArithmeticInc,
        MutatorStrategy.ArithmeticDec,
        MutatorStrategy.InterestingValues,
        MutatorStrategy.Havoc,
        MutatorStrategy.Splice,
      ],
      maxHavocStack: 6,
      maxSpliceSize: 4096,
    },
    scheduler: {
      algorithm: SchedulerAlgorithm.AFLFast,
      initialEnergy: 1,
      minEnergy: 0.01,
      maxEnergy: 100,
    },
    coverage: {
      metrics: [CoverageMetric.Edge],
      bitmapSize: 65_536,
      trackComparisons: true,
      trackDataFlow: false,
    },
    harness: {
      mode: HarnessMode.InProcess,
    },
    reporters: [
      { type: 'console', intervalSeconds: 5 },
    ],
    dictionaries: [],
    eccProtectedCorpus: false,
    env: {},
    sanitizers: [],
    autoMinimize: true,
    deduplicateCrashes: true,
    metadata: {},
  };

  return deepMerge(defaults, overrides) as FuzzConfig;
}

/** Deep merge helper (source wins on conflicts). */
function deepMerge(target: Record<string, any>, source: Record<string, any>): Record<string, any> {
  const result = { ...target };
  for (const key of Object.keys(source)) {
    const sv = source[key];
    const tv = target[key];
    if (sv !== undefined) {
      if (
        sv !== null &&
        typeof sv === 'object' &&
        !Array.isArray(sv) &&
        !(sv instanceof Uint8Array) &&
        !(sv instanceof Map) &&
        tv !== null &&
        typeof tv === 'object' &&
        !Array.isArray(tv)
      ) {
        result[key] = deepMerge(tv as Record<string, any>, sv as Record<string, any>);
      } else {
        result[key] = sv;
      }
    }
  }
  return result;
}

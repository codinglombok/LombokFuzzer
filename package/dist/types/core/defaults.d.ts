/**
 * LombokFuzzer — Default Configuration
 *
 * Sensible defaults for every config field. Users override only what they need.
 *
 * @license Apache-2.0
 */
import { type FuzzConfig } from './types.js';
/** Build a complete FuzzConfig by merging user overrides onto defaults. */
export declare function createConfig(overrides?: Partial<FuzzConfig>): FuzzConfig;
//# sourceMappingURL=defaults.d.ts.map
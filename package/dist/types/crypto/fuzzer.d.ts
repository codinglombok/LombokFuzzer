/**
 * LombokFuzzer — Cryptographic Fuzzer
 *
 * Tests cryptographic implementations for:
 * - Timing side-channels (constant-time comparison)
 * - Padding oracle attacks
 * - RNG quality (NIST SP 800-22 subset)
 * - Key/nonce reuse detection
 * - Weak algorithm detection
 * - Edge-case inputs (zero, max, boundary values)
 *
 * @license Apache-2.0
 */
import type { PRNG } from '../utils/prng.js';
export interface TimingTestResult {
    operation: string;
    samples: number;
    meanDiffNs: number;
    maxDiffNs: number;
    isConstantTime: boolean;
    confidence: number;
    verdict: string;
}
export interface RNGTestResult {
    testName: string;
    passed: boolean;
    pValue: number;
    statistic: number;
    description: string;
}
export interface CryptoFinding {
    type: CryptoVulnerability;
    component: string;
    description: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    evidence: string;
    remediation: string;
}
export declare enum CryptoVulnerability {
    TimingSideChannel = "timing_side_channel",
    PaddingOracle = "padding_oracle",
    WeakRNG = "weak_rng",
    WeakAlgorithm = "weak_algorithm",
    NonceReuse = "nonce_reuse",
    KeyReuse = "key_reuse",
    InsecureDefault = "insecure_default",
    MalleableSig = "malleable_signature"
}
export declare class CryptoFuzzer {
    private readonly prng;
    private readonly findings;
    constructor(prng: PRNG);
    /** Test if a comparison function runs in constant time. */
    timingTest(compareFn: (a: Uint8Array, b: Uint8Array) => boolean, size?: number, samples?: number): TimingTestResult;
    /** Generate padding oracle test vectors. */
    generatePaddingOracleVectors(blockSize?: number, numBlocks?: number): Uint8Array[];
    /** Run basic RNG quality tests (NIST SP 800-22 subset). */
    testRNGQuality(rngFn: () => number, sampleSize?: number): RNGTestResult[];
    /** Generate edge-case inputs for crypto functions. */
    generateCryptoEdgeCases(keySize?: number): Uint8Array[];
    /** Get all findings. */
    get allFindings(): readonly CryptoFinding[];
}
//# sourceMappingURL=fuzzer.d.ts.map
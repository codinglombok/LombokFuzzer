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
export var CryptoVulnerability;
(function (CryptoVulnerability) {
    CryptoVulnerability["TimingSideChannel"] = "timing_side_channel";
    CryptoVulnerability["PaddingOracle"] = "padding_oracle";
    CryptoVulnerability["WeakRNG"] = "weak_rng";
    CryptoVulnerability["WeakAlgorithm"] = "weak_algorithm";
    CryptoVulnerability["NonceReuse"] = "nonce_reuse";
    CryptoVulnerability["KeyReuse"] = "key_reuse";
    CryptoVulnerability["InsecureDefault"] = "insecure_default";
    CryptoVulnerability["MalleableSig"] = "malleable_signature";
})(CryptoVulnerability || (CryptoVulnerability = {}));
// ─── Crypto Fuzzer ──────────────────────────────────────────────────────────
export class CryptoFuzzer {
    prng;
    findings = [];
    constructor(prng) {
        this.prng = prng;
    }
    /** Test if a comparison function runs in constant time. */
    timingTest(compareFn, size = 32, samples = 10000) {
        const correct = this.prng.randomBytes(size);
        // Measure: correct vs correct (baseline)
        const baselineTimes = [];
        for (let i = 0; i < samples; i++) {
            const start = performanceNow();
            compareFn(correct, correct);
            baselineTimes.push(performanceNow() - start);
        }
        // Measure: correct vs wrong-at-position-0
        const earlyWrong = new Uint8Array(correct);
        earlyWrong[0] = (earlyWrong[0] + 1) & 0xFF;
        const earlyTimes = [];
        for (let i = 0; i < samples; i++) {
            const start = performanceNow();
            compareFn(correct, earlyWrong);
            earlyTimes.push(performanceNow() - start);
        }
        // Measure: correct vs wrong-at-last-position
        const lateWrong = new Uint8Array(correct);
        lateWrong[size - 1] = (lateWrong[size - 1] + 1) & 0xFF;
        const lateTimes = [];
        for (let i = 0; i < samples; i++) {
            const start = performanceNow();
            compareFn(correct, lateWrong);
            lateTimes.push(performanceNow() - start);
        }
        const earlyMean = mean(earlyTimes);
        const lateMean = mean(lateTimes);
        const baselineMean = mean(baselineTimes);
        const diff = Math.abs(earlyMean - lateMean);
        const maxDiff = Math.max(Math.abs(earlyMean - baselineMean), Math.abs(lateMean - baselineMean));
        // Welch's t-test for significance
        const tStat = welchTTest(earlyTimes, lateTimes);
        const isConstantTime = Math.abs(tStat) < 4.5; // conservative threshold
        const confidence = Math.min(1, 1 - (1 / (1 + Math.abs(tStat))));
        const result = {
            operation: 'comparison',
            samples,
            meanDiffNs: diff,
            maxDiffNs: maxDiff,
            isConstantTime,
            confidence,
            verdict: isConstantTime
                ? 'PASS: No statistically significant timing difference detected'
                : 'FAIL: Timing difference detected — comparison may leak information',
        };
        if (!isConstantTime) {
            this.findings.push({
                type: CryptoVulnerability.TimingSideChannel,
                component: 'comparison',
                description: `Timing side-channel: ${diff.toFixed(1)}ns mean difference between early/late mismatch`,
                severity: 'high',
                evidence: `t-statistic: ${tStat.toFixed(2)}, samples: ${samples}`,
                remediation: 'Use constant-time comparison (crypto.timingSafeEqual or equivalent)',
            });
        }
        return result;
    }
    /** Generate padding oracle test vectors. */
    generatePaddingOracleVectors(blockSize = 16, numBlocks = 3) {
        const vectors = [];
        // Valid padding (PKCS#7)
        for (let padLen = 1; padLen <= blockSize; padLen++) {
            const data = this.prng.randomBytes(blockSize * numBlocks);
            // Set last padLen bytes to padLen
            for (let i = 0; i < padLen; i++) {
                data[data.length - 1 - i] = padLen;
            }
            vectors.push(data);
        }
        // Invalid padding variants
        const invalid = [
            0x00, // Zero padding byte
            blockSize + 1, // Padding value > block size
            0xFF, // Max byte
        ];
        for (const padByte of invalid) {
            const data = this.prng.randomBytes(blockSize * numBlocks);
            data[data.length - 1] = padByte;
            vectors.push(data);
        }
        // Bit-flip in each byte of the last block (for CBC oracle)
        for (let i = 0; i < blockSize; i++) {
            const data = this.prng.randomBytes(blockSize * numBlocks);
            // Set valid padding first
            data[data.length - 1] = 1;
            // Flip bit in second-to-last block (affects decrypted last block in CBC)
            const targetIdx = data.length - blockSize - blockSize + i;
            if (targetIdx >= 0) {
                data[targetIdx] = (data[targetIdx] ^ 1) & 0xFF;
            }
            vectors.push(data);
        }
        return vectors;
    }
    /** Run basic RNG quality tests (NIST SP 800-22 subset). */
    testRNGQuality(rngFn, sampleSize = 100000) {
        const results = [];
        const samples = [];
        for (let i = 0; i < sampleSize; i++) {
            samples.push(rngFn());
        }
        // 1. Frequency (monobit) test
        const bits = samples.map(s => s > 0.5 ? 1 : 0);
        const sum = bits.reduce((a, b) => a + b, 0);
        const freqStat = Math.abs(sum - sampleSize / 2) / Math.sqrt(sampleSize / 4);
        results.push({
            testName: 'Frequency (Monobit)',
            passed: freqStat < 3.29, // alpha = 0.001
            pValue: 2 * (1 - normalCDF(freqStat)),
            statistic: freqStat,
            description: 'Tests if the proportion of 0s and 1s is approximately equal',
        });
        // 2. Runs test
        const runs = countRuns(bits);
        const p = sum / sampleSize;
        const expectedRuns = 2 * sampleSize * p * (1 - p) + 1;
        const runsVariance = 2 * sampleSize * p * (1 - p) * (2 * sampleSize * p * (1 - p) - 1) / (sampleSize - 1);
        const runsStat = runsVariance > 0 ? Math.abs(runs - expectedRuns) / Math.sqrt(runsVariance) : 0;
        results.push({
            testName: 'Runs',
            passed: runsStat < 3.29,
            pValue: 2 * (1 - normalCDF(runsStat)),
            statistic: runsStat,
            description: 'Tests if the oscillation between 0s and 1s is too fast or slow',
        });
        // 3. Chi-squared uniformity test (10 bins)
        const bins = new Array(10).fill(0);
        for (const s of samples)
            bins[Math.min(9, Math.floor(s * 10))]++;
        const expected = sampleSize / 10;
        let chiSq = 0;
        for (const b of bins)
            chiSq += (b - expected) ** 2 / expected;
        results.push({
            testName: 'Chi-squared Uniformity',
            passed: chiSq < 27.88, // df=9, alpha=0.001
            pValue: 1 - chiSquaredCDF(chiSq, 9),
            statistic: chiSq,
            description: 'Tests if the output distribution is uniform across bins',
        });
        // Report weak RNG
        const failCount = results.filter(r => !r.passed).length;
        if (failCount > 0) {
            this.findings.push({
                type: CryptoVulnerability.WeakRNG,
                component: 'RNG',
                description: `RNG failed ${failCount}/${results.length} statistical tests`,
                severity: failCount >= 2 ? 'critical' : 'high',
                evidence: results.filter(r => !r.passed).map(r => `${r.testName}: stat=${r.statistic.toFixed(3)}`).join('; '),
                remediation: 'Use a cryptographically secure PRNG (e.g., crypto.getRandomValues)',
            });
        }
        return results;
    }
    /** Generate edge-case inputs for crypto functions. */
    generateCryptoEdgeCases(keySize = 32) {
        return [
            new Uint8Array(keySize), // All zeros
            new Uint8Array(keySize).fill(0xFF), // All ones
            new Uint8Array(keySize).fill(0x80), // MSB set
            new Uint8Array(keySize).fill(0x01), // LSB set
            new Uint8Array(0), // Empty
            new Uint8Array(1), // Single byte
            new Uint8Array(keySize - 1), // Off-by-one short
            new Uint8Array(keySize + 1), // Off-by-one long
            this.prng.randomBytes(keySize), // Random valid
            this.prng.randomBytes(keySize * 2), // Double size
            (() => { const a = new Uint8Array(keySize); a[0] = 1; return a; })(), // Minimal
        ];
    }
    /** Get all findings. */
    get allFindings() {
        return this.findings;
    }
}
// ─── Statistical Helpers ────────────────────────────────────────────────────
function mean(arr) {
    return arr.reduce((a, b) => a + b, 0) / arr.length;
}
function variance(arr) {
    const m = mean(arr);
    return arr.reduce((sum, x) => sum + (x - m) ** 2, 0) / (arr.length - 1);
}
function welchTTest(a, b) {
    const ma = mean(a), mb = mean(b);
    const va = variance(a), vb = variance(b);
    const na = a.length, nb = b.length;
    const denom = Math.sqrt(va / na + vb / nb);
    return denom === 0 ? 0 : (ma - mb) / denom;
}
function normalCDF(x) {
    const a1 = 0.254829592, a2 = -0.284496736, a3 = 1.421413741;
    const a4 = -1.453152027, a5 = 1.061405429, p = 0.3275911;
    const sign = x < 0 ? -1 : 1;
    const t = 1 / (1 + p * Math.abs(x));
    const y = 1 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * Math.exp(-x * x / 2);
    return 0.5 * (1 + sign * y);
}
function chiSquaredCDF(x, k) {
    return incompleteLowerGamma(k / 2, x / 2) / gamma(k / 2);
}
function gamma(n) {
    if (n <= 0)
        return Infinity;
    if (n < 0.5)
        return Math.PI / (Math.sin(Math.PI * n) * gamma(1 - n));
    n -= 1;
    const coeffs = [0.99999999999980993, 676.5203681218851, -1259.1392167224028,
        771.32342877765313, -176.61502916214059, 12.507343278686905,
        -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7];
    let x = coeffs[0];
    for (let i = 1; i < coeffs.length; i++)
        x += coeffs[i] / (n + i);
    const t = n + coeffs.length - 1.5;
    return Math.sqrt(2 * Math.PI) * Math.pow(t, n + 0.5) * Math.exp(-t) * x;
}
function incompleteLowerGamma(s, x) {
    let sum = 0, term = 1 / s;
    for (let n = 0; n < 200; n++) {
        sum += term;
        term *= x / (s + n + 1);
        if (Math.abs(term) < 1e-15)
            break;
    }
    return sum * Math.pow(x, s) * Math.exp(-x);
}
function countRuns(bits) {
    let runs = 1;
    for (let i = 1; i < bits.length; i++) {
        if (bits[i] !== bits[i - 1])
            runs++;
    }
    return runs;
}
function performanceNow() {
    if (typeof performance !== 'undefined')
        return performance.now() * 1e6;
    const [s, ns] = process.hrtime();
    return s * 1e9 + ns;
}
//# sourceMappingURL=fuzzer.js.map
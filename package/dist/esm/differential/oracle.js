/**
 * LombokFuzzer — Differential Oracle
 *
 * Compares N implementations of the same interface with the same input.
 * Any divergence (output mismatch, crash-vs-success, timing anomaly)
 * is flagged as a potential bug.
 *
 * Use cases:
 *   - Cross-language parity (TS vs Go vs Rust parser)
 *   - Regression testing (v1 vs v2)
 *   - Semantic equivalence (optimised vs reference)
 *
 * @license Apache-2.0
 */
import { Severity } from '../core/types.js';
/** Classification of divergence types. */
export var DivergenceKind;
(function (DivergenceKind) {
    /** Output bytes differ. */
    DivergenceKind["OutputMismatch"] = "output_mismatch";
    /** One crashed, the other didn't. */
    DivergenceKind["CrashDivergence"] = "crash_divergence";
    /** Both crashed but with different errors. */
    DivergenceKind["ErrorDivergence"] = "error_divergence";
    /** Execution time ratio exceeds threshold. */
    DivergenceKind["TimingAnomaly"] = "timing_anomaly";
    /** Output lengths differ. */
    DivergenceKind["LengthMismatch"] = "length_mismatch";
})(DivergenceKind || (DivergenceKind = {}));
// ─── Differential Oracle Engine ─────────────────────────────────────────────
export class DiffOracle {
    oracles = [];
    config;
    results = [];
    constructor(config) {
        this.config = {
            timingRatioThreshold: config?.timingRatioThreshold ?? 10,
            maxCompareBytes: config?.maxCompareBytes ?? 0,
            checkLengths: config?.checkLengths ?? true,
            checkTiming: config?.checkTiming ?? true,
        };
    }
    /** Register an oracle. At least 2 are required for differential testing. */
    addOracle(oracle) {
        this.oracles.push(oracle);
        return this;
    }
    /** Get registered oracle count. */
    get oracleCount() {
        return this.oracles.length;
    }
    /** Run all oracles on one input and compare results. */
    async compare(input) {
        if (this.oracles.length < 2) {
            throw new Error('DiffOracle requires at least 2 oracles');
        }
        const totalStart = hrtimeUs();
        const outputs = [];
        // Execute all oracles
        for (const oracle of this.oracles) {
            const start = hrtimeUs();
            let output;
            try {
                output = await oracle.execute(input.data);
            }
            catch (err) {
                const dur = hrtimeUs() - start;
                output = {
                    data: new Uint8Array(0),
                    durationUs: dur,
                    crashed: true,
                    error: err instanceof Error ? err.message : String(err),
                };
            }
            outputs.push(output);
        }
        const totalDurationUs = hrtimeUs() - totalStart;
        // Find divergences
        const divergences = this.findDivergences(outputs);
        const unanimous = divergences.length === 0;
        const result = {
            input,
            outputs,
            unanimous,
            divergences,
            totalDurationUs,
        };
        this.results.push(result);
        return result;
    }
    /** Get all results so far. */
    getResults() {
        return this.results;
    }
    /** Get divergence statistics. */
    getStats() {
        let totalComparisons = this.results.length;
        let totalDivergences = 0;
        let crashDivergences = 0;
        let outputMismatches = 0;
        let timingAnomalies = 0;
        for (const r of this.results) {
            for (const d of r.divergences) {
                totalDivergences++;
                switch (d.kind) {
                    case DivergenceKind.CrashDivergence:
                        crashDivergences++;
                        break;
                    case DivergenceKind.OutputMismatch:
                        outputMismatches++;
                        break;
                    case DivergenceKind.TimingAnomaly:
                        timingAnomalies++;
                        break;
                }
            }
        }
        return {
            totalComparisons,
            totalDivergences,
            crashDivergences,
            outputMismatches,
            timingAnomalies,
            unanimousRate: totalComparisons > 0
                ? ((totalComparisons - this.results.filter(r => !r.unanimous).length) / totalComparisons) * 100
                : 100,
        };
    }
    // ─── Private ────────────────────────────────────────────────────────────
    findDivergences(outputs) {
        const divergences = [];
        const names = this.oracles.map(o => o.name);
        for (let i = 0; i < outputs.length; i++) {
            for (let j = i + 1; j < outputs.length; j++) {
                const a = outputs[i];
                const b = outputs[j];
                const nameA = names[i] ?? String(i);
                const nameB = names[j] ?? String(j);
                const pair = [nameA, nameB];
                // Crash divergence
                if (a.crashed !== b.crashed) {
                    const who = a.crashed ? nameA : nameB;
                    divergences.push({
                        kind: DivergenceKind.CrashDivergence,
                        oracles: pair,
                        severity: Severity.High,
                        description: `${who} crashed but ${a.crashed ? nameB : nameA} succeeded`,
                    });
                    continue; // No point comparing output if one crashed
                }
                // Error divergence (both crashed but different errors)
                if (a.crashed && b.crashed && a.error !== b.error) {
                    divergences.push({
                        kind: DivergenceKind.ErrorDivergence,
                        oracles: pair,
                        severity: Severity.Medium,
                        description: `Both crashed with different errors: "${a.error}" vs "${b.error}"`,
                    });
                    continue;
                }
                // If both crashed identically, skip output comparison
                if (a.crashed && b.crashed)
                    continue;
                // Length mismatch
                if (this.config.checkLengths && a.data.length !== b.data.length) {
                    divergences.push({
                        kind: DivergenceKind.LengthMismatch,
                        oracles: pair,
                        severity: Severity.Medium,
                        description: `Output lengths differ: ${a.data.length} vs ${b.data.length}`,
                    });
                }
                // Byte-level output comparison
                const maxCmp = this.config.maxCompareBytes > 0
                    ? Math.min(a.data.length, b.data.length, this.config.maxCompareBytes)
                    : Math.min(a.data.length, b.data.length);
                let firstDiff = -1;
                for (let k = 0; k < maxCmp; k++) {
                    if (a.data[k] !== b.data[k]) {
                        firstDiff = k;
                        break;
                    }
                }
                if (firstDiff >= 0) {
                    divergences.push({
                        kind: DivergenceKind.OutputMismatch,
                        oracles: pair,
                        severity: Severity.High,
                        description: `Output bytes differ at offset ${firstDiff}: 0x${(a.data[firstDiff] ?? 0).toString(16)} vs 0x${(b.data[firstDiff] ?? 0).toString(16)}`,
                        firstDiffOffset: firstDiff,
                    });
                }
                // Timing anomaly
                if (this.config.checkTiming && a.durationUs > 0 && b.durationUs > 0) {
                    const ratio = Math.max(a.durationUs, b.durationUs) / Math.min(a.durationUs, b.durationUs);
                    if (ratio > this.config.timingRatioThreshold) {
                        const slower = a.durationUs > b.durationUs ? nameA : nameB;
                        divergences.push({
                            kind: DivergenceKind.TimingAnomaly,
                            oracles: pair,
                            severity: Severity.Low,
                            description: `Timing ratio ${ratio.toFixed(1)}x — ${slower} is significantly slower`,
                        });
                    }
                }
            }
        }
        return divergences;
    }
}
// ─── Helpers ────────────────────────────────────────────────────────────────
function hrtimeUs() {
    if (typeof performance !== 'undefined') {
        return Math.round(performance.now() * 1000);
    }
    const [sec, nsec] = process.hrtime();
    return sec * 1_000_000 + Math.round(nsec / 1000);
}
//# sourceMappingURL=oracle.js.map
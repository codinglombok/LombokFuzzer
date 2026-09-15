/**
 * LombokFuzzer — Dashboard Generator
 *
 * Generates a self-contained HTML dashboard for visualising fuzz
 * campaign results. Uses LombokCSS for styling and LombokCharts for
 * interactive charts, loaded from jsDelivr CDN.
 *
 * Dashboard sections:
 *   1. Campaign summary (KPI cards)
 *   2. Coverage timeline (line chart)
 *   3. Execution rate (line chart)
 *   4. Mutator effectiveness (bar chart)
 *   5. Crash table with severity + CWE
 *   6. Corpus size growth (area chart)
 *   7. Scheduler energy distribution (bar chart)
 *
 * @license Apache-2.0
 */
import type { FuzzStats, CrashInfo } from '../core/types.js';
/** A snapshot of stats at a point in time (for timeline charts). */
export interface StatsSnapshot {
    /** Milliseconds since campaign start. */
    elapsedMs: number;
    /** Total executions at this point. */
    totalExecutions: number;
    /** Execs/sec at this point. */
    execsPerSecond: number;
    /** Coverage percentage. */
    coveragePercent: number;
    /** Corpus size. */
    corpusSize: number;
    /** Edges found. */
    edgesFound: number;
    /** Unique crashes. */
    uniqueCrashes: number;
}
/** Dashboard configuration. */
export interface DashboardConfig {
    /** Campaign name. */
    campaignName: string;
    /** Whether to include interactive charts (requires JS). */
    interactive: boolean;
    /** Theme: 'light' | 'dark' | 'auto'. */
    theme: 'light' | 'dark' | 'auto';
    /** LombokCSS CDN URL. */
    cssCdn: string;
    /** LombokCharts CDN URL. */
    chartsCdn: string;
    /** Whether to embed data inline (vs external JSON). */
    embedData: boolean;
    /** Auto-refresh interval in seconds (0 = no refresh). */
    refreshInterval: number;
}
/** Crash entry for the dashboard table. */
export interface DashboardCrash {
    id: string;
    category: string;
    severity: string;
    signal: string;
    topFrame: string;
    inputSize: number;
    discoveredAt: number;
}
export declare class DashboardBuilder {
    private readonly config;
    private readonly snapshots;
    private readonly crashes;
    private finalStats;
    private mutatorStats;
    constructor(config?: Partial<DashboardConfig>);
    /** Add a stats snapshot (called periodically during fuzzing). */
    addSnapshot(stats: FuzzStats): void;
    /** Add a crash entry. */
    addCrash(crash: CrashInfo): void;
    /** Set the final campaign stats. */
    setFinalStats(stats: FuzzStats): void;
    /** Render the complete standalone HTML dashboard. */
    render(): string;
    /** Render the dashboard as a JSON data bundle (for external viewers). */
    renderJson(): string;
    private renderCrashTable;
}
//# sourceMappingURL=dashboard.d.ts.map
/**
 * LombokFuzzer — Reporter System
 *
 * Consumes FuzzStats snapshots and emits them to various sinks:
 *   - Console   — coloured terminal output with progress bar
 *   - JSON      — machine-readable NDJSON log
 *   - HTML      — standalone HTML dashboard (LombokCSS + LombokCharts)
 *   - CI        — GitHub Actions / GitLab CI annotations
 *   - Custom    — user-provided callback
 *
 * @license Apache-2.0
 */
import type { FuzzStats, CrashInfo, ReporterConfig } from '../core/types.js';
/** Every reporter implements this contract. */
export interface Reporter {
    /** Unique type tag. */
    readonly type: ReporterConfig['type'];
    /** Called once when the campaign starts. */
    onStart(stats: FuzzStats): void;
    /** Called periodically with updated stats. */
    onStats(stats: FuzzStats): void;
    /** Called when a new unique crash is found. */
    onCrash(crash: CrashInfo): void;
    /** Called once when the campaign ends. */
    onStop(stats: FuzzStats): void;
    /** Flush any buffered output. */
    flush(): void;
}
export declare class ConsoleReporter implements Reporter {
    readonly type: "console";
    onStart(stats: FuzzStats): void;
    onStats(stats: FuzzStats): void;
    onCrash(crash: CrashInfo): void;
    onStop(stats: FuzzStats): void;
    flush(): void;
    private log;
}
export declare class JsonReporter implements Reporter {
    readonly type: "json";
    private readonly lines;
    private readonly outputPath?;
    constructor(outputPath?: string);
    onStart(stats: FuzzStats): void;
    onStats(stats: FuzzStats): void;
    onCrash(crash: CrashInfo): void;
    onStop(stats: FuzzStats): void;
    flush(): void;
    /** Get all NDJSON lines (for programmatic use). */
    getLines(): readonly string[];
    private append;
}
/**
 * Generates a self-contained HTML file with:
 *   - LombokCSS for styling
 *   - LombokCharts for live/final charts
 *   - Stats summary, crash table, coverage timeline
 *
 * NOTE: LombokCSS and LombokCharts are optional peer deps. The generated
 * HTML loads them from jsDelivr CDN when available.
 */
export declare class HtmlReporter implements Reporter {
    readonly type: "html";
    private readonly snapshots;
    private readonly crashes;
    private finalStats;
    onStart(stats: FuzzStats): void;
    onStats(stats: FuzzStats): void;
    onCrash(crash: CrashInfo): void;
    onStop(stats: FuzzStats): void;
    flush(): void;
    /** Render the full standalone HTML report. */
    renderHtml(): string;
}
/**
 * Emits GitHub Actions annotations (`::warning::` / `::error::`) and a
 * step summary. Also works with GitLab CI `GL-SAST-REPORT-xxx`.
 */
export declare class CiReporter implements Reporter {
    readonly type: "ci";
    private readonly annotations;
    private readonly platform;
    constructor(platform?: 'github' | 'gitlab' | 'generic');
    onStart(_stats: FuzzStats): void;
    onStats(_stats: FuzzStats): void;
    onCrash(crash: CrashInfo): void;
    onStop(stats: FuzzStats): void;
    flush(): void;
    /** Get annotations for programmatic access. */
    getAnnotations(): readonly string[];
}
/**
 * Manages a set of active reporters. The FuzzEngine attaches one
 * ReporterRegistry and calls its methods at the right lifecycle points.
 */
export declare class ReporterRegistry {
    private readonly reporters;
    /** Create reporters from config entries. */
    static fromConfigs(configs: ReporterConfig[]): ReporterRegistry;
    add(reporter: Reporter): void;
    onStart(stats: FuzzStats): void;
    onStats(stats: FuzzStats): void;
    onCrash(crash: CrashInfo): void;
    onStop(stats: FuzzStats): void;
    /** Get reporter by type (for programmatic access). */
    get<T extends Reporter>(type: ReporterConfig['type']): T | undefined;
}
//# sourceMappingURL=reporter.d.ts.map
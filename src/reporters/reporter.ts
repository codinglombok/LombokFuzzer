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
import { Severity } from '../core/types.js';

// ─── Reporter Interface ─────────────────────────────────────────────────────

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

// ─── Console Reporter ───────────────────────────────────────────────────────

export class ConsoleReporter implements Reporter {
  readonly type = 'console' as const;


  onStart(stats: FuzzStats): void {

    this.log('═══════════════════════════════════════════════════════════════');
    this.log(`  LombokFuzzer — Campaign: ${stats.campaignName}`);
    this.log(`  Execution ID: ${stats.executionId}`);
    this.log('═══════════════════════════════════════════════════════════════');
  }

  onStats(stats: FuzzStats): void {
    const elapsed = formatDuration(stats.elapsedMs);
    const coverage = stats.coveragePercent.toFixed(1);
    const rate = stats.execsPerSecond;

    const line = [
      `[${elapsed}]`,
      `execs: ${stats.totalExecutions}`,
      `rate: ${rate}/s`,
      `corpus: ${stats.corpusSize}`,
      `edges: ${stats.edgesFound}/${stats.edgesTotal}`,
      `cov: ${coverage}%`,
      `crashes: ${stats.uniqueCrashes}`,
      `phase: ${stats.currentPhase}`,
    ].join(' │ ');

    this.log(line);
  }

  onCrash(crash: CrashInfo): void {
    const sev = crash.severity.toUpperCase();
    this.log(`  ⚠ CRASH [${sev}] ${crash.category} — ${crash.id}`);
    if (crash.stackTrace.length > 0) {
      const top = crash.stackTrace[0];
      if (top) {
        this.log(`    at ${top.functionName} (${top.file ?? '?'}:${top.line ?? '?'})`);
      }
    }
  }

  onStop(stats: FuzzStats): void {
    const elapsed = formatDuration(stats.elapsedMs);
    this.log('───────────────────────────────────────────────────────────────');
    this.log(`  Done in ${elapsed}.`);
    this.log(`  ${stats.totalExecutions} executions, ${stats.uniqueCrashes} unique crashes`);
    this.log(`  Coverage: ${stats.coveragePercent.toFixed(1)}% (${stats.edgesFound} edges)`);
    this.log('═══════════════════════════════════════════════════════════════');
  }

  flush(): void { /* stdout is unbuffered */ }

  private log(msg: string): void {
    // eslint-disable-next-line no-console
    console.log(msg);
  }
}

// ─── JSON Reporter ──────────────────────────────────────────────────────────

export class JsonReporter implements Reporter {
  readonly type = 'json' as const;
  private readonly lines: string[] = [];
  private readonly outputPath?: string;

  constructor(outputPath?: string) {
    this.outputPath = outputPath;
  }

  onStart(stats: FuzzStats): void {
    this.append({ event: 'start', stats: serializeStats(stats) });
  }

  onStats(stats: FuzzStats): void {
    this.append({ event: 'stats', stats: serializeStats(stats) });
  }

  onCrash(crash: CrashInfo): void {
    this.append({
      event: 'crash',
      crash: {
        id: crash.id,
        category: crash.category,
        severity: crash.severity,
        signal: crash.signal,
        isDuplicate: crash.isDuplicate,
        stackTop: crash.stackTrace[0]?.functionName ?? null,
        inputSize: crash.input.data.length,
        discoveredAt: crash.discoveredAt,
      },
    });
  }

  onStop(stats: FuzzStats): void {
    this.append({ event: 'stop', stats: serializeStats(stats) });
  }

  flush(): void {
    if (this.outputPath) {
      // Write-to-file is delegated to the CLI / Node adapter;
      // in-library we expose getLines() for programmatic access.
    }
  }

  /** Get all NDJSON lines (for programmatic use). */
  getLines(): readonly string[] {
    return this.lines;
  }

  private append(obj: Record<string, unknown>): void {
    this.lines.push(JSON.stringify({ ts: Date.now(), ...obj }));
  }
}

// ─── HTML Reporter ──────────────────────────────────────────────────────────

/**
 * Generates a self-contained HTML file with:
 *   - LombokCSS for styling
 *   - LombokCharts for live/final charts
 *   - Stats summary, crash table, coverage timeline
 *
 * NOTE: LombokCSS and LombokCharts are optional peer deps. The generated
 * HTML loads them from jsDelivr CDN when available.
 */
export class HtmlReporter implements Reporter {
  readonly type = 'html' as const;
  private readonly snapshots: ReturnType<typeof serializeStats>[] = [];
  private readonly crashes: CrashInfo[] = [];
  private finalStats: FuzzStats | null = null;

  onStart(stats: FuzzStats): void {
    this.snapshots.push(serializeStats(stats));
  }

  onStats(stats: FuzzStats): void {
    this.snapshots.push(serializeStats(stats));
  }

  onCrash(crash: CrashInfo): void {
    this.crashes.push(crash);
  }

  onStop(stats: FuzzStats): void {
    this.finalStats = stats;
    this.snapshots.push(serializeStats(stats));
  }

  flush(): void { /* no-op; call renderHtml() */ }

  /** Render the full standalone HTML report. */
  renderHtml(): string {
    const stats = this.finalStats;
    const name = stats?.campaignName ?? 'LombokFuzzer';
    const snap = JSON.stringify(this.snapshots);
    const crashRows = this.crashes.map(c => {
      const sev = c.severity.toUpperCase();
      return `<tr><td>${sev}</td><td>${c.category}</td><td>${c.id}</td>`
        + `<td>${c.stackTrace[0]?.functionName ?? '—'}</td>`
        + `<td>${c.input.data.length}B</td></tr>`;
    }).join('\n');

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${name} — LombokFuzzer Report</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/lombokcss@latest/dist/lombok.min.css">
<style>
body{font-family:system-ui,sans-serif;margin:2rem;max-width:960px;margin-inline:auto}
.stat{display:inline-block;padding:.5rem 1rem;margin:.25rem;border-radius:6px;background:var(--surface-2,#f0f0f0)}
.stat b{display:block;font-size:1.5rem}
table{width:100%;border-collapse:collapse;margin:1rem 0}
th,td{padding:.4rem .6rem;text-align:left;border-bottom:1px solid #ddd}
canvas{max-width:100%;margin:1rem 0}
</style>
</head>
<body>
<h1>🐛 ${name}</h1>
<p>Execution: ${stats?.executionId ?? '—'} · Elapsed: ${formatDuration(stats?.elapsedMs ?? 0)}</p>

<div>
  <div class="stat"><b>${stats?.totalExecutions ?? 0}</b>Executions</div>
  <div class="stat"><b>${stats?.execsPerSecond ?? 0}/s</b>Rate</div>
  <div class="stat"><b>${stats?.corpusSize ?? 0}</b>Corpus</div>
  <div class="stat"><b>${stats?.coveragePercent.toFixed(1) ?? 0}%</b>Coverage</div>
  <div class="stat"><b>${stats?.uniqueCrashes ?? 0}</b>Crashes</div>
</div>

<h2>Coverage Timeline</h2>
<canvas id="coverageChart" height="200"></canvas>

<h2>Crashes (${this.crashes.length})</h2>
${this.crashes.length > 0
  ? `<table><thead><tr><th>Severity</th><th>CWE</th><th>ID</th><th>Top Frame</th><th>Input</th></tr></thead><tbody>${crashRows}</tbody></table>`
  : '<p>No crashes found.</p>'}

<script src="https://cdn.jsdelivr.net/npm/lombokcharts@latest/dist/lombokcharts.min.js"></script>
<script>
const data = ${snap};
if (typeof LombokCharts !== 'undefined') {
  const labels = data.map((_,i) => String(i));
  const cov = data.map(d => d.coveragePercent);
  const execs = data.map(d => d.totalExecutions);
  LombokCharts.chart('#coverageChart', {
    mark: 'line',
    data: labels.map((l,i) => ({x:l, coverage: cov[i], executions: execs[i]})),
    x: 'x', y: 'coverage',
  });
}
</script>
</body>
</html>`;
  }
}

// ─── CI Reporter ────────────────────────────────────────────────────────────

/**
 * Emits GitHub Actions annotations (`::warning::` / `::error::`) and a
 * step summary. Also works with GitLab CI `GL-SAST-REPORT-xxx`.
 */
export class CiReporter implements Reporter {
  readonly type = 'ci' as const;
  private readonly annotations: string[] = [];
  private readonly platform: 'github' | 'gitlab' | 'generic';

  constructor(platform?: 'github' | 'gitlab' | 'generic') {
    this.platform = platform ?? detectCiPlatform();
  }

  onStart(_stats: FuzzStats): void { /* no-op */ }

  onStats(_stats: FuzzStats): void { /* no-op — only final matters */ }

  onCrash(crash: CrashInfo): void {
    if (this.platform === 'github') {
      const level = crash.severity === Severity.Critical || crash.severity === Severity.High
        ? 'error' : 'warning';
      const file = crash.stackTrace[0]?.file ?? '';
      const line = crash.stackTrace[0]?.line ?? '';
      const msg = `[${crash.severity.toUpperCase()}] ${crash.category}: ${crash.id}`;
      this.annotations.push(`::${level} file=${file},line=${line}::${msg}`);
    } else if (this.platform === 'gitlab') {
      this.annotations.push(JSON.stringify({
        type: 'sast',
        name: crash.id,
        description: `${crash.category} (${crash.severity})`,
        severity: crash.severity,
        location: {
          file: crash.stackTrace[0]?.file ?? 'unknown',
          start_line: crash.stackTrace[0]?.line ?? 0,
        },
      }));
    } else {
      this.annotations.push(
        `CRASH [${crash.severity}] ${crash.category} ${crash.id}`,
      );
    }
  }

  onStop(stats: FuzzStats): void {
    if (this.platform === 'github') {
      // Write job summary via GITHUB_STEP_SUMMARY
      const md = [
        '## 🐛 LombokFuzzer Results',
        '',
        `| Metric | Value |`,
        `| --- | --- |`,
        `| Executions | ${stats.totalExecutions} |`,
        `| Rate | ${stats.execsPerSecond}/s |`,
        `| Corpus | ${stats.corpusSize} |`,
        `| Coverage | ${stats.coveragePercent.toFixed(1)}% |`,
        `| Unique crashes | ${stats.uniqueCrashes} |`,
      ].join('\n');

      // Emit annotations
      for (const a of this.annotations) {
        // eslint-disable-next-line no-console
        console.log(a);
      }

      // Write step summary if env var is available
      if (typeof process !== 'undefined' && process.env?.GITHUB_STEP_SUMMARY) {
        try {
          // Dynamic import to avoid bundle issues in browser
          import('fs').then(fs => {
            fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY!, md + '\n');
          }).catch(() => { /* non-critical */ });
        } catch { /* non-critical */ }
      }
    }
  }

  flush(): void { /* no-op */ }

  /** Get annotations for programmatic access. */
  getAnnotations(): readonly string[] {
    return this.annotations;
  }
}

// ─── Reporter Registry ──────────────────────────────────────────────────────

/**
 * Manages a set of active reporters. The FuzzEngine attaches one
 * ReporterRegistry and calls its methods at the right lifecycle points.
 */
export class ReporterRegistry {
  private readonly reporters: Reporter[] = [];

  /** Create reporters from config entries. */
  static fromConfigs(configs: ReporterConfig[]): ReporterRegistry {
    const reg = new ReporterRegistry();
    for (const cfg of configs) {
      switch (cfg.type) {
        case 'console': reg.add(new ConsoleReporter()); break;
        case 'json':    reg.add(new JsonReporter(cfg.outputPath)); break;
        case 'html':    reg.add(new HtmlReporter()); break;
        case 'ci':      reg.add(new CiReporter()); break;
        case 'custom':
          if (cfg.customReporter) {
            reg.add(new CallbackReporter(cfg.customReporter));
          }
          break;
      }
    }
    return reg;
  }

  add(reporter: Reporter): void {
    this.reporters.push(reporter);
  }

  onStart(stats: FuzzStats): void {
    for (const r of this.reporters) r.onStart(stats);
  }

  onStats(stats: FuzzStats): void {
    for (const r of this.reporters) r.onStats(stats);
  }

  onCrash(crash: CrashInfo): void {
    for (const r of this.reporters) r.onCrash(crash);
  }

  onStop(stats: FuzzStats): void {
    for (const r of this.reporters) r.onStop(stats);
    for (const r of this.reporters) r.flush();
  }

  /** Get reporter by type (for programmatic access). */
  get<T extends Reporter>(type: ReporterConfig['type']): T | undefined {
    return this.reporters.find(r => r.type === type) as T | undefined;
  }
}

// ─── Callback Reporter ──────────────────────────────────────────────────────

class CallbackReporter implements Reporter {
  readonly type = 'custom' as const;
  private readonly cb: (stats: FuzzStats) => void;

  constructor(cb: (stats: FuzzStats) => void) {
    this.cb = cb;
  }

  onStart(stats: FuzzStats): void { this.cb(stats); }
  onStats(stats: FuzzStats): void { this.cb(stats); }
  onCrash(_crash: CrashInfo): void { /* not in simple callback API */ }
  onStop(stats: FuzzStats): void { this.cb(stats); }
  flush(): void { /* no-op */ }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function formatDuration(ms: number): string {
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  const h = Math.floor(m / 60);
  if (h > 0) return `${h}h${m % 60}m${s % 60}s`;
  if (m > 0) return `${m}m${s % 60}s`;
  return `${s}s`;
}

function serializeStats(stats: FuzzStats): Record<string, unknown> {
  return {
    executionId: stats.executionId,
    campaignName: stats.campaignName,
    elapsedMs: stats.elapsedMs,
    totalExecutions: stats.totalExecutions,
    execsPerSecond: stats.execsPerSecond,
    corpusSize: stats.corpusSize,
    uniqueCrashes: stats.uniqueCrashes,
    coveragePercent: stats.coveragePercent,
    edgesFound: stats.edgesFound,
    edgesTotal: stats.edgesTotal,
    stability: stats.stability,
    currentPhase: stats.currentPhase,
  };
}

function detectCiPlatform(): 'github' | 'gitlab' | 'generic' {
  if (typeof process !== 'undefined') {
    if (process.env?.GITHUB_ACTIONS) return 'github';
    if (process.env?.GITLAB_CI) return 'gitlab';
  }
  return 'generic';
}

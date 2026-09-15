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
import { VERSION } from '../index.js';

// ─── Types ──────────────────────────────────────────────────────────────────

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

// ─── Dashboard Builder ──────────────────────────────────────────────────────

export class DashboardBuilder {
  private readonly config: DashboardConfig;
  private readonly snapshots: StatsSnapshot[] = [];
  private readonly crashes: DashboardCrash[] = [];
  private finalStats: FuzzStats | null = null;
  private mutatorStats: Record<string, { hits: number; finds: number }> = {};

  constructor(config?: Partial<DashboardConfig>) {
    this.config = {
      campaignName: config?.campaignName ?? 'LombokFuzzer',
      interactive: config?.interactive ?? true,
      theme: config?.theme ?? 'auto',
      cssCdn: config?.cssCdn ?? 'https://cdn.jsdelivr.net/npm/lombokcss@latest/dist/lombok.min.css',
      chartsCdn: config?.chartsCdn ?? 'https://cdn.jsdelivr.net/npm/lombokcharts@latest/dist/lombokcharts.min.js',
      embedData: config?.embedData ?? true,
      refreshInterval: config?.refreshInterval ?? 0,
    };
  }

  /** Add a stats snapshot (called periodically during fuzzing). */
  addSnapshot(stats: FuzzStats): void {
    this.snapshots.push({
      elapsedMs: stats.elapsedMs,
      totalExecutions: stats.totalExecutions,
      execsPerSecond: stats.execsPerSecond,
      coveragePercent: stats.coveragePercent,
      corpusSize: stats.corpusSize,
      edgesFound: stats.edgesFound,
      uniqueCrashes: stats.uniqueCrashes,
    });

    // Track mutator stats
    for (const [strategy, hits] of stats.mutatorHits) {
      const key = strategy as string;
      if (!this.mutatorStats[key]) {
        this.mutatorStats[key] = { hits: 0, finds: 0 };
      }
      this.mutatorStats[key]!.hits = hits;
    }
    for (const [strategy, finds] of stats.mutatorFinds) {
      const key = strategy as string;
      if (!this.mutatorStats[key]) {
        this.mutatorStats[key] = { hits: 0, finds: 0 };
      }
      this.mutatorStats[key]!.finds = finds;
    }
  }

  /** Add a crash entry. */
  addCrash(crash: CrashInfo): void {
    this.crashes.push({
      id: crash.id,
      category: crash.category,
      severity: crash.severity,
      signal: crash.signal,
      topFrame: crash.stackTrace[0]?.functionName ?? '—',
      inputSize: crash.input.data.length,
      discoveredAt: crash.discoveredAt,
    });
  }

  /** Set the final campaign stats. */
  setFinalStats(stats: FuzzStats): void {
    this.finalStats = stats;
    this.addSnapshot(stats);
  }

  /** Render the complete standalone HTML dashboard. */
  render(): string {
    const s = this.finalStats;
    const name = this.config.campaignName;
    const theme = this.config.theme;
    const dataJson = JSON.stringify(this.snapshots);

    const mutatorJson = JSON.stringify(this.mutatorStats);

    return `<!DOCTYPE html>
<html lang="en" data-theme="${theme}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(name)} — LombokFuzzer Dashboard</title>
<link rel="stylesheet" href="${esc(this.config.cssCdn)}">
<style>
:root { --dash-bg: #f8f9fa; --card-bg: #fff; --border: #e0e0e0; --text: #1a1a2e; --muted: #6c757d; }
@media (prefers-color-scheme: dark) {
  :root { --dash-bg: #0d1117; --card-bg: #161b22; --border: #30363d; --text: #c9d1d9; --muted: #8b949e; }
}
[data-theme="dark"] { --dash-bg: #0d1117; --card-bg: #161b22; --border: #30363d; --text: #c9d1d9; --muted: #8b949e; }
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: system-ui, -apple-system, sans-serif; background: var(--dash-bg); color: var(--text); }
.container { max-width: 1120px; margin: 0 auto; padding: 1.5rem; }
header { margin-bottom: 2rem; }
header h1 { font-size: 1.5rem; font-weight: 700; }
header p { color: var(--muted); font-size: 0.875rem; margin-top: 0.25rem; }
.grid { display: grid; gap: 1rem; }
.grid-4 { grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }
.grid-2 { grid-template-columns: repeat(auto-fit, minmax(420px, 1fr)); }
.card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; }
.kpi { text-align: center; }
.kpi .value { font-size: 2rem; font-weight: 700; line-height: 1.2; }
.kpi .label { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.25rem; }
.chart-box { min-height: 220px; }
.chart-box h3 { font-size: 0.875rem; font-weight: 600; margin-bottom: 0.75rem; }
.chart-box canvas { width: 100%; height: 180px; }
table { width: 100%; border-collapse: collapse; font-size: 0.8125rem; }
th, td { padding: 0.5rem 0.75rem; text-align: left; border-bottom: 1px solid var(--border); }
th { font-weight: 600; font-size: 0.75rem; text-transform: uppercase; color: var(--muted); }
.sev-critical { color: #dc3545; font-weight: 700; }
.sev-high { color: #fd7e14; font-weight: 600; }
.sev-medium { color: #ffc107; }
.sev-low { color: #198754; }
.sev-info { color: var(--muted); }
footer { text-align: center; color: var(--muted); font-size: 0.75rem; margin-top: 2rem; padding: 1rem 0; border-top: 1px solid var(--border); }
</style>
</head>
<body>
<div class="container">

<header>
  <h1>🐛 ${esc(name)}</h1>
  <p>Execution ${esc(s?.executionId ?? '—')} · Elapsed ${formatDuration(s?.elapsedMs ?? 0)} · LombokFuzzer v${VERSION}</p>
</header>

<!-- KPI Cards -->
<div class="grid grid-4">
  <div class="card kpi"><div class="value">${fmtNum(s?.totalExecutions ?? 0)}</div><div class="label">Executions</div></div>
  <div class="card kpi"><div class="value">${fmtNum(s?.execsPerSecond ?? 0)}/s</div><div class="label">Rate</div></div>
  <div class="card kpi"><div class="value">${(s?.coveragePercent ?? 0).toFixed(1)}%</div><div class="label">Coverage</div></div>
  <div class="card kpi"><div class="value">${s?.edgesFound ?? 0}/${s?.edgesTotal ?? 0}</div><div class="label">Edges</div></div>
  <div class="card kpi"><div class="value">${s?.corpusSize ?? 0}</div><div class="label">Corpus</div></div>
  <div class="card kpi"><div class="value">${s?.uniqueCrashes ?? 0}</div><div class="label">Crashes</div></div>
  <div class="card kpi"><div class="value">${(s?.stability ?? 100).toFixed(1)}%</div><div class="label">Stability</div></div>
  <div class="card kpi"><div class="value">${s?.currentPhase ?? '—'}</div><div class="label">Phase</div></div>
</div>

<!-- Charts -->
<div class="grid grid-2" style="margin-top:1rem">
  <div class="card chart-box">
    <h3>Coverage Timeline</h3>
    <canvas id="chart-coverage"></canvas>
  </div>
  <div class="card chart-box">
    <h3>Execution Rate</h3>
    <canvas id="chart-rate"></canvas>
  </div>
  <div class="card chart-box">
    <h3>Corpus Growth</h3>
    <canvas id="chart-corpus"></canvas>
  </div>
  <div class="card chart-box">
    <h3>Mutator Effectiveness</h3>
    <canvas id="chart-mutators"></canvas>
  </div>
</div>

<!-- Crash Table -->
<div class="card" style="margin-top:1rem">
  <h3 style="font-size:0.875rem;font-weight:600;margin-bottom:0.75rem">Crashes (${this.crashes.length})</h3>
  ${this.crashes.length > 0 ? this.renderCrashTable() : '<p style="color:var(--muted)">No crashes found.</p>'}
</div>

<footer>
  Generated by LombokFuzzer v${VERSION} · LombokCSS + LombokCharts
</footer>

</div>

<script src="${esc(this.config.chartsCdn)}"></script>
<script>
(function(){
  const snapshots = ${dataJson};
  const mutators = ${mutatorJson};

  function labels(arr) { return arr.map(function(d,i){ return formatTime(d.elapsedMs); }); }
  function formatTime(ms) {
    var s = Math.floor(ms/1000);
    var m = Math.floor(s/60);
    if (m > 0) return m+'m'+s%60+'s';
    return s+'s';
  }

  if (typeof LombokCharts === 'undefined') return;
  var C = LombokCharts;

  // Coverage
  try {
    C.chart('#chart-coverage', {
      mark: 'line',
      data: snapshots.map(function(d,i){ return {x:formatTime(d.elapsedMs), y:d.coveragePercent}; }),
      x: 'x', y: 'y'
    });
  } catch(e){}

  // Rate
  try {
    C.chart('#chart-rate', {
      mark: 'line',
      data: snapshots.map(function(d){ return {x:formatTime(d.elapsedMs), y:d.execsPerSecond}; }),
      x: 'x', y: 'y'
    });
  } catch(e){}

  // Corpus
  try {
    C.chart('#chart-corpus', {
      mark: 'line',
      data: snapshots.map(function(d){ return {x:formatTime(d.elapsedMs), y:d.corpusSize}; }),
      x: 'x', y: 'y'
    });
  } catch(e){}

  // Mutators
  try {
    var mKeys = Object.keys(mutators);
    if (mKeys.length > 0) {
      C.chart('#chart-mutators', {
        mark: 'bar',
        data: mKeys.map(function(k){ return {x:k, hits:mutators[k].hits, finds:mutators[k].finds}; }),
        x: 'x', y: 'hits'
      });
    }
  } catch(e){}

  ${this.config.refreshInterval > 0 ? `setTimeout(function(){ location.reload(); }, ${this.config.refreshInterval * 1000});` : ''}
})();
</script>
</body>
</html>`;
  }

  /** Render the dashboard as a JSON data bundle (for external viewers). */
  renderJson(): string {
    return JSON.stringify({
      version: VERSION,
      campaign: this.config.campaignName,
      generatedAt: Date.now(),
      stats: this.finalStats ? serializeStats(this.finalStats) : null,
      snapshots: this.snapshots,
      crashes: this.crashes,
      mutators: this.mutatorStats,
    }, null, 2);
  }

  // ─── Private ────────────────────────────────────────────────────────────

  private renderCrashTable(): string {
    const rows = this.crashes.map(c => {
      const sevClass = `sev-${c.severity}`;
      const time = new Date(c.discoveredAt).toISOString().substring(11, 19);
      return `<tr>
  <td class="${sevClass}">${c.severity.toUpperCase()}</td>
  <td>${esc(c.category)}</td>
  <td><code>${esc(c.id.substring(0, 16))}</code></td>
  <td>${esc(c.topFrame)}</td>
  <td>${c.inputSize}B</td>
  <td>${time}</td>
</tr>`;
    }).join('\n');

    return `<table>
<thead><tr><th>Sev</th><th>CWE</th><th>ID</th><th>Top Frame</th><th>Input</th><th>Time</th></tr></thead>
<tbody>${rows}</tbody>
</table>`;
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function esc(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatDuration(ms: number): string {
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  const h = Math.floor(m / 60);
  if (h > 0) return `${h}h${m % 60}m${s % 60}s`;
  if (m > 0) return `${m}m${s % 60}s`;
  return `${s}s`;
}

function fmtNum(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
  if (n >= 1_000) return (n / 1_000).toFixed(1) + 'K';
  return String(n);
}

function serializeStats(stats: FuzzStats): Record<string, unknown> {
  return {
    executionId: stats.executionId,
    campaignName: stats.campaignName,
    elapsedMs: stats.elapsedMs,
    totalExecutions: stats.totalExecutions,
    execsPerSecond: stats.execsPerSecond,
    peakExecsPerSecond: stats.peakExecsPerSecond,
    corpusSize: stats.corpusSize,
    corpusTotalBytes: stats.corpusTotalBytes,
    uniqueCrashes: stats.uniqueCrashes,
    uniqueTimeouts: stats.uniqueTimeouts,
    coveragePercent: stats.coveragePercent,
    edgesFound: stats.edgesFound,
    edgesTotal: stats.edgesTotal,
    stability: stats.stability,
    currentPhase: stats.currentPhase,
    dictionarySize: stats.dictionarySize,
  };
}

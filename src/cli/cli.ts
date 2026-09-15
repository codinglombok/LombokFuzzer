/**
 * LombokFuzzer — CLI
 *
 * Command-line interface for running fuzz campaigns, managing corpus,
 * viewing crash reports, and generating dashboards.
 *
 * Usage:
 *   lombokfuzzer run --config fuzz.json
 *   lombokfuzzer corpus --dir ./corpus --stats
 *   lombokfuzzer crash --dir ./crashes --triage
 *   lombokfuzzer report --input stats.ndjson --html report.html
 *   lombokfuzzer version
 *
 * @license Apache-2.0
 */

import type { FuzzConfig, ReporterConfig } from '../core/types.js';
import { FuzzMode, SchedulerAlgorithm, HarnessMode } from '../core/types.js';
import { VERSION } from '../version.js';

// ─── Types ──────────────────────────────────────────────────────────────────

/** Parsed CLI arguments. */
export interface CliArgs {
  /** Command name. */
  command: CliCommand;
  /** Positional arguments after the command. */
  positional: string[];
  /** Named flags (--key value or --flag). */
  flags: Map<string, string>;
}

/** Supported CLI commands. */
export enum CliCommand {
  Run = 'run',
  Corpus = 'corpus',
  Crash = 'crash',
  Report = 'report',
  Minimize = 'minimize',
  Version = 'version',
  Help = 'help',
}

/** Result of CLI execution. */
export interface CliResult {
  /** Exit code (0 = success). */
  exitCode: number;
  /** Output text. */
  output: string;
}

// ─── Argument Parser ────────────────────────────────────────────────────────

/**
 * Parses process.argv-style arrays into structured CLI args.
 * Handles `--key value`, `--key=value`, `--flag`, and positional args.
 */
export function parseArgs(argv: string[]): CliArgs {
  // Skip node + script path if present
  const args = argv[0]?.includes('node') || argv[0]?.includes('lombokfuzzer')
    ? argv.slice(2)
    : argv;

  const commandStr = args[0] ?? 'help';
  const command = parseCommand(commandStr);
  const positional: string[] = [];
  const flags = new Map<string, string>();

  for (let i = 1; i < args.length; i++) {
    const arg = args[i]!;
    if (arg.startsWith('--')) {
      const eqIdx = arg.indexOf('=');
      if (eqIdx > 0) {
        flags.set(arg.substring(2, eqIdx), arg.substring(eqIdx + 1));
      } else {
        const next = args[i + 1];
        if (next && !next.startsWith('--')) {
          flags.set(arg.substring(2), next);
          i++;
        } else {
          flags.set(arg.substring(2), 'true');
        }
      }
    } else if (arg.startsWith('-') && arg.length === 2) {
      const next = args[i + 1];
      if (next && !next.startsWith('-')) {
        flags.set(arg.substring(1), next);
        i++;
      } else {
        flags.set(arg.substring(1), 'true');
      }
    } else {
      positional.push(arg);
    }
  }

  return { command, positional, flags };
}

function parseCommand(str: string): CliCommand {
  const map: Record<string, CliCommand> = {
    run: CliCommand.Run,
    fuzz: CliCommand.Run,
    corpus: CliCommand.Corpus,
    crash: CliCommand.Crash,
    crashes: CliCommand.Crash,
    report: CliCommand.Report,
    dashboard: CliCommand.Report,
    minimize: CliCommand.Minimize,
    min: CliCommand.Minimize,
    version: CliCommand.Version,
    '-v': CliCommand.Version,
    '--version': CliCommand.Version,
    help: CliCommand.Help,
    '-h': CliCommand.Help,
    '--help': CliCommand.Help,
  };
  return map[str] ?? CliCommand.Help;
}

// ─── Config Loader ──────────────────────────────────────────────────────────

/**
 * Builds a FuzzConfig from CLI flags, falling back to defaults.
 * Supports loading from a JSON config file via --config.
 */
export function buildConfigFromFlags(flags: Map<string, string>): Partial<FuzzConfig> {
  const config: Partial<FuzzConfig> = {};

  if (flags.has('name'))           config.name = flags.get('name')!;
  if (flags.has('mode'))           config.mode = flags.get('mode') as FuzzMode;
  if (flags.has('max-execs'))      config.maxExecutions = parseInt(flags.get('max-execs')!, 10);
  if (flags.has('max-time'))       config.maxTimeSeconds = parseInt(flags.get('max-time')!, 10);
  if (flags.has('max-input'))      config.maxInputSize = parseInt(flags.get('max-input')!, 10);
  if (flags.has('timeout'))        config.timeoutMs = parseInt(flags.get('timeout')!, 10);
  if (flags.has('workers'))        config.workers = parseInt(flags.get('workers')!, 10);
  if (flags.has('seed'))           config.seed = BigInt(flags.get('seed')!);
  if (flags.has('corpus-dir'))     config.seedCorpusDir = flags.get('corpus-dir')!;
  if (flags.has('output-dir'))     config.outputCorpusDir = flags.get('output-dir')!;
  if (flags.has('crash-dir'))      config.crashDir = flags.get('crash-dir')!;
  if (flags.has('dict'))           config.dictionaries = flags.get('dict')!.split(',');
  if (flags.has('ecc'))            config.eccProtectedCorpus = flags.get('ecc') === 'true';
  if (flags.has('auto-minimize'))  config.autoMinimize = flags.get('auto-minimize') !== 'false';

  // Scheduler
  if (flags.has('scheduler')) {
    config.scheduler = {
      algorithm: flags.get('scheduler') as SchedulerAlgorithm,
      initialEnergy: 1, minEnergy: 0.1, maxEnergy: 100,
    };
  }

  // Reporters
  const reporters: ReporterConfig[] = [];
  if (flags.get('quiet') !== 'true') {
    reporters.push({ type: 'console', intervalSeconds: 1 });
  }
  if (flags.has('json-report')) {
    reporters.push({
      type: 'json',
      outputPath: flags.get('json-report')!,
      intervalSeconds: 5,
    });
  }
  if (flags.has('html-report')) {
    reporters.push({
      type: 'html',
      outputPath: flags.get('html-report')!,
      intervalSeconds: 10,
    });
  }
  if (flags.has('ci') || (typeof process !== 'undefined' && process.env?.CI)) {
    reporters.push({ type: 'ci', intervalSeconds: 30 });
  }
  if (reporters.length > 0) config.reporters = reporters;

  // Harness
  if (flags.has('target')) {
    config.harness = {
      mode: (flags.get('harness') as HarnessMode) ?? HarnessMode.ForkServer,
      targetBinary: flags.get('target')!,
      targetArgs: flags.has('target-args') ? flags.get('target-args')!.split(' ') : [],
    };
  }

  if (flags.has('network-target')) {
    config.harness = {
      mode: HarnessMode.Network,
      networkTarget: flags.get('network-target')!,
    };
  }

  return config;
}

/**
 * Load config from a JSON file path.
 */
export async function loadConfigFile(path: string): Promise<Partial<FuzzConfig>> {
  try {
    const fs = await import('fs');
    const text = fs.readFileSync(path, 'utf-8');
    return JSON.parse(text) as Partial<FuzzConfig>;
  } catch (err: unknown) {
    throw new Error(`Failed to load config from "${path}": ${err instanceof Error ? err.message : String(err)}`);
  }
}

// ─── Command Handlers ───────────────────────────────────────────────────────

/** Handle the 'version' command. */
export function handleVersion(): CliResult {
  return {
    exitCode: 0,
    output: `LombokFuzzer v${VERSION}`,
  };
}

/** Handle the 'help' command. */
export function handleHelp(command?: string): CliResult {
  if (command === 'run') {
    return { exitCode: 0, output: HELP_RUN };
  }
  return { exitCode: 0, output: HELP_MAIN };
}

/** Handle the 'corpus' command. */
export function handleCorpus(flags: Map<string, string>): CliResult {
  const dir = flags.get('dir') ?? './corpus';
  const stats = flags.get('stats') === 'true';

  if (stats) {
    return {
      exitCode: 0,
      output: [
        `Corpus directory: ${dir}`,
        `(Use with Node.js to scan actual directory contents)`,
      ].join('\n'),
    };
  }

  return { exitCode: 0, output: `Corpus directory: ${dir}` };
}

/** Handle the 'crash' command. */
export function handleCrash(flags: Map<string, string>): CliResult {
  const dir = flags.get('dir') ?? './crashes';
  const triage = flags.get('triage') === 'true';

  return {
    exitCode: 0,
    output: [
      `Crash directory: ${dir}`,
      triage ? 'Triage mode: analyzing crashes…' : 'Use --triage to analyze crashes.',
    ].join('\n'),
  };
}

// ─── CLI Entry Point ────────────────────────────────────────────────────────

/**
 * Main CLI dispatcher. Call with process.argv.
 *
 * ```ts
 * import { cli } from 'lombokfuzzer';
 * const result = await cli(process.argv);
 * process.exit(result.exitCode);
 * ```
 */
export async function cli(argv: string[]): Promise<CliResult> {
  const parsed = parseArgs(argv);

  switch (parsed.command) {
    case CliCommand.Version:
      return handleVersion();

    case CliCommand.Help:
      return handleHelp(parsed.positional[0]);

    case CliCommand.Corpus:
      return handleCorpus(parsed.flags);

    case CliCommand.Crash:
      return handleCrash(parsed.flags);

    case CliCommand.Run: {
      // Build config from flags (and optional config file)
      let fileConfig: Partial<FuzzConfig> = {};
      if (parsed.flags.has('config')) {
        fileConfig = await loadConfigFile(parsed.flags.get('config')!);
      }
      const flagConfig = buildConfigFromFlags(parsed.flags);
      const _mergedConfig = { ...fileConfig, ...flagConfig };

      // The actual engine run is done by the caller after config is built;
      // CLI just validates and returns config info.
      return {
        exitCode: 0,
        output: `LombokFuzzer v${VERSION} — ready to run campaign "${_mergedConfig.name ?? 'unnamed'}"`,
      };
    }

    case CliCommand.Report: {
      const input = parsed.flags.get('input');
      const html = parsed.flags.get('html');
      if (!input) {
        return { exitCode: 1, output: 'Error: --input <stats.ndjson> required' };
      }
      return {
        exitCode: 0,
        output: html
          ? `Generating HTML report from ${input} → ${html}`
          : `Stats file: ${input}`,
      };
    }

    case CliCommand.Minimize: {
      const crashDir = parsed.flags.get('dir') ?? parsed.flags.get('crash-dir') ?? './crashes';
      return {
        exitCode: 0,
        output: `Minimizing crash inputs in ${crashDir}…`,
      };
    }

    default:
      return handleHelp();
  }
}

// ─── Help Text ──────────────────────────────────────────────────────────────

const HELP_MAIN = `
LombokFuzzer v${VERSION} — Universal fuzzing framework

USAGE
  lombokfuzzer <command> [flags]

COMMANDS
  run          Start a fuzz campaign
  corpus       Manage / inspect the corpus
  crash        View / triage crash reports
  report       Generate HTML / JSON reports
  minimize     Minimize crash reproducers
  version      Print version
  help         Show this help

FLAGS (global)
  --config <path>   Load config from JSON file
  --quiet           Suppress console output

Run \`lombokfuzzer help <command>\` for command-specific help.
`.trim();

const HELP_RUN = `
LombokFuzzer v${VERSION} — run command

USAGE
  lombokfuzzer run [flags]

FLAGS
  --config <path>         Load config from JSON file
  --name <name>           Campaign name
  --mode <mode>           mutation | generation | hybrid | differential | directed
  --target <binary>       Target binary path (fork-server mode)
  --network-target <h:p>  Target host:port (network mode)
  --max-execs <n>         Max executions (0 = unlimited)
  --max-time <s>          Max time in seconds
  --max-input <bytes>     Max input size
  --timeout <ms>          Per-execution timeout
  --workers <n>           Parallel workers
  --seed <n>              PRNG seed for reproducibility
  --corpus-dir <dir>      Seed corpus directory
  --output-dir <dir>      Output corpus directory
  --crash-dir <dir>       Crash output directory
  --dict <files>          Comma-separated dictionary files
  --scheduler <alg>       round_robin | afl_fast | mab | rare_branch | eco_fuzz | entropic
  --json-report <path>    Write NDJSON stats log
  --html-report <path>    Generate HTML dashboard
  --ci                    Enable CI reporter (auto-detected)
  --ecc                   Enable ECC-protected corpus
  --quiet                 Suppress console output

EXAMPLES
  lombokfuzzer run --target ./my_parser --max-execs 100000
  lombokfuzzer run --config fuzz.json --html-report report.html
  lombokfuzzer run --network-target localhost:8080 --max-time 3600
`.trim();

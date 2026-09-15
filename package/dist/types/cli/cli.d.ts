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
import type { FuzzConfig } from '../core/types.js';
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
export declare enum CliCommand {
    Run = "run",
    Corpus = "corpus",
    Crash = "crash",
    Report = "report",
    Minimize = "minimize",
    Version = "version",
    Help = "help"
}
/** Result of CLI execution. */
export interface CliResult {
    /** Exit code (0 = success). */
    exitCode: number;
    /** Output text. */
    output: string;
}
/**
 * Parses process.argv-style arrays into structured CLI args.
 * Handles `--key value`, `--key=value`, `--flag`, and positional args.
 */
export declare function parseArgs(argv: string[]): CliArgs;
/**
 * Builds a FuzzConfig from CLI flags, falling back to defaults.
 * Supports loading from a JSON config file via --config.
 */
export declare function buildConfigFromFlags(flags: Map<string, string>): Partial<FuzzConfig>;
/**
 * Load config from a JSON file path.
 */
export declare function loadConfigFile(path: string): Promise<Partial<FuzzConfig>>;
/** Handle the 'version' command. */
export declare function handleVersion(): CliResult;
/** Handle the 'help' command. */
export declare function handleHelp(command?: string): CliResult;
/** Handle the 'corpus' command. */
export declare function handleCorpus(flags: Map<string, string>): CliResult;
/** Handle the 'crash' command. */
export declare function handleCrash(flags: Map<string, string>): CliResult;
/**
 * Main CLI dispatcher. Call with process.argv.
 *
 * ```ts
 * import { cli } from 'lombokfuzzer';
 * const result = await cli(process.argv);
 * process.exit(result.exitCode);
 * ```
 */
export declare function cli(argv: string[]): Promise<CliResult>;
//# sourceMappingURL=cli.d.ts.map
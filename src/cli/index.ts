#!/usr/bin/env bun
/**
 * AppInspect CLI
 *
 * Standalone headless entry point. Analyses a file and emits the full result
 * as JSON or the security findings as SARIF 2.1.0. Imports the analysis layer
 * directly — no Electron dependency.
 */

import * as fs from "node:fs";

import { AnalysisSession } from "../main/analysis/orchestrator";
import { exportAnalysis } from "../main/export/json";
import { exportSarif, findingsAtOrAbove } from "../main/export/sarif";
import type { TabName } from "../shared/ipc-types";
import type { AnalysisResult } from "../shared/types";

const SECTION_NAMES: TabName[] = [
	"overview",
	"strings",
	"headers",
	"libraries",
	"symbols",
	"objc",
	"swift",
	"entitlements",
	"infoPlist",
	"electron",
	"hooks",
	"security",
	"files",
	"size"
];

const FAIL_ON_LEVELS = ["critical", "warning", "info", "none"] as const;

type FailOn = (typeof FAIL_ON_LEVELS)[number];
type OutputFormat = "json" | "sarif";

export interface CliOptions {
	file?: string;
	format: OutputFormat;
	sections?: TabName[];
	binary?: number;
	out?: string;
	noClobber: boolean;
	pretty: boolean;
	failOn: FailOn;
	quiet: boolean;
	version: boolean;
	help: boolean;
}

export class UsageError extends Error {}

const USAGE = `Usage: appinspect <file-or-folder> [options]

Analyse an iOS/macOS binary (IPA, DEB, .app bundle, .xcframework, Mach-O, or dylib),
or scan a folder for binaries and .deb packages.

Options:
  --json                Emit the full analysis as JSON (default)
  --sarif               Emit a SARIF 2.1.0 report of the security findings
  --section <name>      Limit --json output to a section (repeatable):
                        overview|strings|headers|libraries|symbols|classes|swift|
                        entitlements|infoPlist|electron|hooks|security|files|size
  --binary <index>      Analyse a specific binary index instead of the main one
  --out <path>          Write output to a file (overwrites if it exists; default: stdout)
  --no-clobber          Refuse to overwrite an existing --out file
  --pretty              Pretty-print JSON (default)
  --no-pretty           Minify JSON
  --fail-on <level>     Exit 3 when a finding at/above this severity exists:
                        critical|warning|info|none (default: none)
  --quiet               Suppress progress output on stderr
  --version             Print version
  --help, -h            Print this help`;

/** Parse CLI arguments. Pure — throws UsageError on invalid input. */
export function parseArgs(argv: string[]): CliOptions {
	const options: CliOptions = {
		format: "json",
		noClobber: false,
		pretty: true,
		failOn: "none",
		quiet: false,
		version: false,
		help: false
	};
	const sections: TabName[] = [];

	for (let i = 0; i < argv.length; i++) {
		const arg = argv[i]!;
		switch (arg) {
			case "--json":
				options.format = "json";
				break;
			case "--sarif":
				options.format = "sarif";
				break;
			case "--pretty":
				options.pretty = true;
				break;
			case "--no-pretty":
				options.pretty = false;
				break;
			case "--quiet":
				options.quiet = true;
				break;
			case "--version":
				options.version = true;
				break;
			case "--help":
			case "-h":
				options.help = true;
				break;
			case "--section": {
				const value = argv[++i];
				if (!value || !SECTION_NAMES.includes(value as TabName)) {
					throw new UsageError(`--section requires one of: ${SECTION_NAMES.join(", ")}`);
				}
				sections.push(value as TabName);
				break;
			}
			case "--binary": {
				const value = argv[++i];
				if (value === undefined || !/^\d+$/.test(value)) {
					throw new UsageError("--binary must be a non-negative integer");
				}
				options.binary = Number.parseInt(value, 10);
				break;
			}
			case "--out": {
				const value = argv[++i];
				if (!value) throw new UsageError("--out requires a path");
				options.out = value;
				break;
			}
			case "--no-clobber":
				options.noClobber = true;
				break;
			case "--fail-on": {
				const value = argv[++i];
				if (!value || !FAIL_ON_LEVELS.includes(value as FailOn)) {
					throw new UsageError(`--fail-on requires one of: ${FAIL_ON_LEVELS.join(", ")}`);
				}
				options.failOn = value as FailOn;
				break;
			}
			default:
				if (arg.startsWith("-")) throw new UsageError(`Unknown option: ${arg}`);
				if (options.file !== undefined) throw new UsageError(`Unexpected argument: ${arg}`);
				options.file = arg;
		}
	}

	if (sections.length > 0) options.sections = sections;
	return options;
}

function readVersion(): string {
	try {
		const pkg = JSON.parse(
			fs.readFileSync(new URL("../../package.json", import.meta.url), "utf8")
		) as { version?: string };
		return pkg.version ?? "0.0.0";
	} catch {
		return "0.0.0";
	}
}

async function main(argv: string[]): Promise<number> {
	let options: CliOptions;
	try {
		options = parseArgs(argv);
	} catch (err) {
		if (!(err instanceof UsageError)) throw err;
		process.stderr.write(`error: ${err.message}\n\n${USAGE}\n`);
		return 2;
	}

	if (options.help) {
		process.stdout.write(`${USAGE}\n`);
		return 0;
	}
	if (options.version) {
		process.stdout.write(`${readVersion()}\n`);
		return 0;
	}

	const file = options.file;
	if (!file) {
		process.stderr.write(`error: no input file\n\n${USAGE}\n`);
		return 2;
	}
	if (!fs.existsSync(file)) {
		process.stderr.write(`error: file not found: ${file}\n`);
		return 2;
	}

	const progress = options.quiet
		? () => {}
		: (phase: string, percent: number) => process.stderr.write(`${phase} (${percent}%)\n`);

	const session = new AnalysisSession();
	let result: AnalysisResult;
	try {
		result = await session.analyseFile(file, progress);
		if (options.binary !== undefined) {
			result = await session.analyseBinary(options.binary, progress);
		}
	} catch (err) {
		process.stderr.write(`error: ${err instanceof Error ? err.message : String(err)}\n`);
		return 1;
	}

	let output =
		options.format === "sarif" ? exportSarif(result) : exportAnalysis(result, options.sections);
	if (options.format === "json" && !options.pretty) {
		output = JSON.stringify(JSON.parse(output));
	}

	const text = `${output}\n`;
	if (options.out) {
		if (options.noClobber && fs.existsSync(options.out)) {
			process.stderr.write(`error: refusing to overwrite existing file: ${options.out}\n`);
			return 1;
		}
		fs.writeFileSync(options.out, text);
	} else {
		process.stdout.write(text);
	}

	if (
		options.failOn !== "none" &&
		findingsAtOrAbove(result.security.findings, options.failOn) > 0
	) {
		return 3;
	}
	return 0;
}

if (import.meta.main) {
	process.exit(await main(process.argv.slice(2)));
}

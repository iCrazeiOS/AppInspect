/**
 * AppInspect MCP Server
 *
 * Lightweight Model Context Protocol server that exposes binary analysis
 * capabilities to AI agents over stdio. Imports the analysis orchestrator
 * directly — no Electron dependency required.
 *
 * Each analyse_file call creates an isolated AnalysisSession keyed by file
 * path, so multiple subagents can analyse different files in parallel.
 *
 * Tools:
 *   analyse_file   — Load and analyse a file (IPA, Mach-O, DEB, .app)
 *   get_overview    — Analysis summary (header, hardening, hooks, etc.)
 *   get_section     — Detailed data for a specific section with filtering
 *   search          — Cross-binary search
 *   switch_binary   — Switch to a different binary in the container
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import type { SearchableTab } from "../main/analysis/orchestrator";
import { AnalysisSession, formatHexdump, pruneCache } from "../main/analysis/orchestrator";
import type { AnalysisResult } from "../shared/types";

// Keep stdout clean for MCP protocol — redirect console to stderr
console.log = console.error;
console.info = console.error;
console.warn = console.error;

// ── BigInt serialisation ─────────────────────────────────────────────

function bigintReplacer(_key: string, value: unknown): unknown {
	if (typeof value === "bigint") {
		if (value <= BigInt(Number.MAX_SAFE_INTEGER) && value >= BigInt(Number.MIN_SAFE_INTEGER)) {
			return Number(value);
		}
		return value.toString();
	}
	return value;
}

function sanitize<T>(obj: T): T {
	return JSON.parse(JSON.stringify(obj, bigintReplacer)) as T;
}

// ── Session management ──────────────────────────────────────────────

const sessions = new Map<string, AnalysisSession>();
let lastPath: string | null = null;

function getSession(filePath?: string): AnalysisSession {
	const key = filePath !== undefined ? filePath : lastPath;
	if (!key) throw new Error("No file loaded. Call analyse_file first.");
	const session = sessions.get(key);
	if (!session) throw new Error(`No session for ${key}. Call analyse_file first.`);
	return session;
}

// ── Constants ────────────────────────────────────────────────────────

const DEFAULT_LIMIT = 200;

type SectionName =
	| "strings"
	| "headers"
	| "libraries"
	| "symbols"
	| "classes"
	| "entitlements"
	| "infoPlist"
	| "security"
	| "files"
	| "hooks";

const SECTION_NAMES: SectionName[] = [
	"strings",
	"headers",
	"libraries",
	"symbols",
	"classes",
	"entitlements",
	"infoPlist",
	"security",
	"files",
	"hooks"
];

/** Sections that return filterable/paginatable arrays */
const PAGINATED_SECTIONS = new Set<SectionName>(["strings", "symbols", "classes", "libraries"]);

const PATH_PARAM = {
	type: "string",
	description:
		"Path of the file to query (optional — defaults to the last analysed file). " +
		"Required when multiple files have been analysed in parallel."
};

// ── Tool definitions ─────────────────────────────────────────────────

const TOOLS = [
	{
		name: "analyse_file",
		description:
			"Analyse an iOS/macOS binary file (IPA, Mach-O, DEB, or .app bundle). " +
			"Must be called before any other tool. Returns an overview summary " +
			"including source type, Mach-O header, build version, hardening flags, " +
			"and available binaries. The result is cached for the session — call " +
			"this once, then use the other tools to query the data. Multiple files " +
			"can be analysed in parallel; pass the file path to query tools to " +
			"target a specific analysis.",
		inputSchema: {
			type: "object" as const,
			properties: {
				path: {
					type: "string",
					description: "Absolute path to the file to analyse"
				}
			},
			required: ["path"]
		}
	},
	{
		name: "get_overview",
		description:
			"Get the analysis overview for a loaded file. Includes source type, " +
			"Mach-O header, build version, encryption info, hardening flags, " +
			"Info.plist summary, team ID, UUID, detected frameworks, and hook " +
			"detection.",
		inputSchema: {
			type: "object" as const,
			properties: {
				path: PATH_PARAM
			}
		}
	},
	{
		name: "get_section",
		description:
			"Get detailed data for a specific analysis section. Use filter, offset, " +
			"and limit for large sections (strings, symbols, classes, libraries). " +
			"Sections: strings (embedded binary strings + localisation), " +
			"headers (Mach-O header + load commands), libraries (linked dylibs/" +
			"frameworks), symbols (exported/imported/local), classes (ObjC classes " +
			"+ methods + protocols), entitlements (code signing), infoPlist " +
			"(Info.plist), security (findings + hardening), files (bundle file " +
			"tree), hooks (jailbreak hook detection).",
		inputSchema: {
			type: "object" as const,
			properties: {
				section: {
					type: "string",
					enum: SECTION_NAMES,
					description: "Section to retrieve"
				},
				filter: {
					type: "string",
					description:
						"Case-insensitive substring filter on primary field: " +
						"value (strings), name (symbols/classes/libraries)"
				},
				offset: {
					type: "number",
					description: "Items to skip (default: 0). Array sections only."
				},
				limit: {
					type: "number",
					description: `Max items to return (default: ${DEFAULT_LIMIT}). Array sections only.`
				},
				path: PATH_PARAM
			},
			required: ["section"]
		}
	},
	{
		name: "search",
		description:
			"Search across all binaries in the loaded container (main binary, " +
			"frameworks, extensions) for a query string. Returns matches with " +
			"binary name and index.",
		inputSchema: {
			type: "object" as const,
			properties: {
				query: { type: "string", description: "Search query" },
				tab: {
					type: "string",
					enum: ["classes", "strings", "symbols", "libraries"],
					description: "Data type to search"
				},
				isRegex: { type: "boolean", description: "Treat query as regex (default: false)" },
				caseSensitive: {
					type: "boolean",
					description: "Case-sensitive match (default: false)"
				},
				path: PATH_PARAM
			},
			required: ["query", "tab"]
		}
	},
	{
		name: "switch_binary",
		description:
			"Switch analysis to a different binary within the loaded container " +
			"(e.g. a framework or app extension). Use get_overview to see " +
			"available binaries and their indices in overview.ipa.binaries.",
		inputSchema: {
			type: "object" as const,
			properties: {
				binaryIndex: {
					type: "number",
					description: "Index of the binary (from overview.ipa.binaries)"
				},
				path: PATH_PARAM
			},
			required: ["binaryIndex"]
		}
	},
	{
		name: "read_hex",
		description:
			"Read raw hex bytes from the active binary at a given offset. " +
			"Returns formatted hex dump or raw byte array. Use for inspecting " +
			"raw binary content at specific offsets (e.g. segment/section data). " +
			"Max 65536 bytes per request.",
		inputSchema: {
			type: "object" as const,
			properties: {
				offset: {
					type: "number",
					description:
						"Byte offset within the binary (e.g. segment fileoff or section offset)"
				},
				length: {
					type: "number",
					description: "Number of bytes to read (max 65536, default 256)"
				},
				format: {
					type: "string",
					enum: ["raw", "hexdump"],
					description:
						"Output format: 'hexdump' returns formatted text (default), 'raw' returns byte array"
				},
				path: PATH_PARAM
			},
			required: ["offset"]
		}
	},
	{
		name: "disassemble",
		description:
			"Disassemble code from the active binary's __text section. Returns " +
			"instructions with addresses, bytes, mnemonics, operands, and symbol " +
			"labels. Use offset/limit for pagination through large sections. " +
			"Supports ARM, ARM64, x86, and x86_64 architectures.",
		inputSchema: {
			type: "object" as const,
			properties: {
				offset: {
					type: "number",
					description: "Byte offset within __text section (default: 0)"
				},
				limit: {
					type: "number",
					description: "Max bytes to disassemble (default: 4096, max: 65536)"
				},
				format: {
					type: "string",
					enum: ["json", "text"],
					description:
						"'json' returns structured data, 'text' returns formatted assembly (default: text)"
				},
				path: PATH_PARAM
			}
		}
	},
	{
		name: "search_disasm",
		description:
			"Search disassembled instructions for a mnemonic, operand, or address. " +
			"Returns matching instructions with their addresses and a preview.",
		inputSchema: {
			type: "object" as const,
			properties: {
				query: {
					type: "string",
					description: "Search query (mnemonic, operand text, or hex address)"
				},
				isRegex: {
					type: "boolean",
					description: "Treat query as regex (default: false)"
				},
				limit: {
					type: "number",
					description: "Max results (default: 100)"
				},
				path: PATH_PARAM
			},
			required: ["query"]
		}
	}
];

// ── Section data helpers ─────────────────────────────────────────────

function getSectionData(cached: AnalysisResult, section: SectionName): unknown {
	switch (section) {
		case "strings":
			return { binary: cached.strings, localisation: cached.localisationStrings ?? [] };
		case "headers":
			return cached.headers;
		case "libraries":
			return cached.libraries;
		case "symbols":
			return cached.symbols;
		case "classes":
			return { classes: cached.classes, protocols: cached.protocols ?? [] };
		case "entitlements": {
			const obj: Record<string, unknown> = {};
			if (Array.isArray(cached.entitlements)) {
				for (const e of cached.entitlements) obj[e.key] = e.value;
			}
			return obj;
		}
		case "infoPlist":
			return cached.infoPlist;
		case "security":
			return cached.security;
		case "files":
			return cached.files;
		case "hooks":
			return cached.hooks;
	}
}

/** Extract the filterable array from a section's data */
function getArray(data: unknown, section: SectionName): unknown[] {
	if (section === "strings") return (data as { binary: unknown[] }).binary;
	if (section === "classes") return (data as { classes: unknown[] }).classes;
	return data as unknown[];
}

/** Primary field to filter on per section */
function filterField(section: SectionName): string {
	return section === "strings" ? "value" : "name";
}

function buildPaginatedResult(
	data: unknown,
	section: SectionName,
	filter?: string,
	offset = 0,
	limit = DEFAULT_LIMIT
): unknown {
	const array = getArray(data, section);

	let filtered = array;
	if (filter) {
		const lower = filter.toLowerCase();
		const field = filterField(section);
		filtered = array.filter((item) => {
			const val = (item as Record<string, string>)[field];
			return val?.toLowerCase().includes(lower);
		});
	}

	const total = filtered.length;
	const sliced = sanitize(filtered.slice(offset, offset + limit));

	const result: Record<string, unknown> = { total, offset, limit, returned: sliced.length };

	if (section === "strings") {
		result.binary = sliced;
		result.localisation = sanitize((data as { localisation: unknown[] }).localisation);
	} else if (section === "classes") {
		result.classes = sliced;
		result.protocols = sanitize((data as { protocols: unknown[] }).protocols);
	} else {
		result.data = sliced;
	}

	return result;
}

// ── Response helpers ─────────────────────────────────────────────────

function ok(data: unknown) {
	return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
}

function fail(message: string) {
	return { content: [{ type: "text" as const, text: message }], isError: true as const };
}

// ── Tool dispatch ────────────────────────────────────────────────────

const noop = () => {};

async function handleToolCall(name: string, args: Record<string, unknown>) {
	switch (name) {
		case "analyse_file": {
			const filePath = args.path as string;
			if (!filePath) return fail("Missing required parameter: path");
			const session = new AnalysisSession();
			const result = await session.analyseFile(filePath, noop);
			sessions.set(filePath, session);
			lastPath = filePath;
			return ok(sanitize({ ...result.overview, hooks: result.hooks }));
		}

		case "get_overview": {
			const session = getSession(args.path as string | undefined);
			const cached = session.getResult();
			if (!cached) return fail("No analysis result available.");
			return ok(sanitize({ ...cached.overview, hooks: cached.hooks }));
		}

		case "get_section": {
			const session = getSession(args.path as string | undefined);
			const cached = session.getResult();
			if (!cached) return fail("No analysis result available.");
			const section = args.section as string;
			if (!SECTION_NAMES.includes(section as SectionName)) {
				return fail(`Unknown section: ${section}. Valid: ${SECTION_NAMES.join(", ")}`);
			}

			const s = section as SectionName;
			const data = getSectionData(cached, s);

			if (PAGINATED_SECTIONS.has(s)) {
				return ok(
					buildPaginatedResult(
						data,
						s,
						args.filter as string | undefined,
						args.offset as number | undefined,
						args.limit as number | undefined
					)
				);
			}

			return ok(sanitize(data));
		}

		case "search": {
			const session = getSession(args.path as string | undefined);
			const query = args.query as string;
			const tab = args.tab as SearchableTab;
			if (!query) return fail("Missing required parameter: query");
			const results = await session.searchAllBinaries(
				query,
				tab,
				noop,
				args.isRegex as boolean | undefined,
				args.caseSensitive as boolean | undefined
			);
			return ok(results);
		}

		case "switch_binary": {
			const session = getSession(args.path as string | undefined);
			const index = args.binaryIndex as number;
			if (index === undefined || index === null) {
				return fail("Missing required parameter: binaryIndex");
			}
			const result = await session.analyseBinary(index, noop);
			return ok(sanitize({ ...result.overview, hooks: result.hooks }));
		}

		case "read_hex": {
			const session = getSession(args.path as string | undefined);
			const offset = args.offset as number;
			if (offset === undefined || offset === null) {
				return fail("Missing required parameter: offset");
			}
			const length = (args.length as number) ?? 256;
			const format = (args.format as string) ?? "hexdump";

			const result = session.readHex(offset, length);
			if (!result) return fail("No binary loaded or offset out of range.");

			if (format === "hexdump") {
				return ok({
					offset: result.offset,
					length: result.length,
					fileSize: result.fileSize,
					hexdump: formatHexdump(result.data, result.offset)
				});
			}

			return ok(result);
		}

		case "disassemble": {
			const session = getSession(args.path as string | undefined);
			const offset = (args.offset as number) ?? 0;
			const limit = Math.min((args.limit as number) ?? 4096, 65536);
			const format = (args.format as string) ?? "text";

			const sections = session.getDisasmSections();
			if (sections.length === 0) {
				return fail("No __text section found in binary.");
			}

			const result = await session.readDisasm(0, offset, limit);
			if (!result || result.instructions.length === 0) {
				return fail("Failed to disassemble or no instructions found.");
			}

			if (format === "json") {
				return ok(sanitize(result.instructions));
			}

			// Text format
			const lines: string[] = [];
			for (const insn of result.instructions) {
				if (insn.label) {
					lines.push(`\n${insn.label}:`);
				}
				const addr = insn.address.toString(16).toUpperCase().padStart(12, "0");
				const bytes = insn.bytes
					.slice(0, 8)
					.map((b) => b.toString(16).toUpperCase().padStart(2, "0"))
					.join(" ")
					.padEnd(24);
				lines.push(`${addr}  ${bytes}  ${insn.mnemonic.padEnd(8)} ${insn.operands}`);
			}
			return ok({ disassembly: lines.join("\n"), count: result.instructions.length });
		}

		case "search_disasm": {
			const session = getSession(args.path as string | undefined);
			const query = args.query as string;
			if (!query) {
				return fail("Missing required parameter: query");
			}
			const isRegex = (args.isRegex as boolean) ?? false;
			const limit = (args.limit as number) ?? 100;

			const sections = session.getDisasmSections();
			if (sections.length === 0) {
				return fail("No __text section found in binary.");
			}

			const result = await session.searchDisasm(0, query, isRegex, limit);
			return ok(
				sanitize({
					matches: result.matches.map((m) => ({
						address: `0x${m.address.toString(16).toUpperCase()}`,
						offset: m.offset,
						preview: m.preview
					})),
					count: result.matches.length,
					hasMore: result.hasMore
				})
			);
		}

		default:
			return fail(`Unknown tool: ${name}`);
	}
}

// ── Server setup ─────────────────────────────────────────────────────

const server = new Server(
	{ name: "appinspect", version: "0.1.0" },
	{ capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
	tools: TOOLS
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
	try {
		return await handleToolCall(
			request.params.name,
			(request.params.arguments ?? {}) as Record<string, unknown>
		);
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		return fail(message);
	}
});

// Clean up stale cache entries on startup and exit
pruneCache();
process.on("exit", () => pruneCache());

const transport = new StdioServerTransport();
await server.connect(transport);

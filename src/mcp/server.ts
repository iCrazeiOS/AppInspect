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
 *   read_hex        — Read raw bytes from the active binary
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
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
	const key = filePath ?? lastPath;
	if (!key) throw new Error("No file loaded. Call analyse_file first.");
	const session = sessions.get(key);
	if (!session) throw new Error(`No session for ${key}. Call analyse_file first.`);
	return session;
}

/** Resolve an analysis result, optionally targeting a specific binary by index. */
async function resolveResult(filePath?: string, binary?: number): Promise<AnalysisResult> {
	const session = getSession(filePath);
	if (binary !== undefined) return (await session.resolveBinary(binary)).result;
	const cached = session.getResult();
	if (!cached) throw new Error("No analysis result available.");
	return cached;
}

// ── Constants ────────────────────────────────────────────────────────

const DEFAULT_LIMIT = 200;

const SECTION_NAMES = [
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
] as const;

type SectionName = (typeof SECTION_NAMES)[number];

/** Sections that return filterable/paginatable arrays */
const PAGINATED_SECTIONS = new Set<SectionName>(["strings", "symbols", "classes", "libraries"]);

const pathParam = z
	.string()
	.optional()
	.describe(
		"Path of the file to query (optional — defaults to the last analysed file). " +
			"Required when multiple files have been analysed in parallel."
	);

const binaryParam = z
	.number()
	.optional()
	.describe(
		"Index of the binary to target (from overview.ipa.binaries; defaults to the active binary). " +
			"Query any binary directly without switch_binary."
	);

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

const noop = () => {};

// ── Server setup ─────────────────────────────────────────────────────

const server = new McpServer({ name: "appinspect", version: "0.1.0" });

server.registerTool(
	"analyse_file",
	{
		description:
			"Analyse an iOS/macOS binary file (IPA, Mach-O, DEB, or .app bundle). " +
			"Must be called before any other tool. Returns an overview summary " +
			"including source type, Mach-O header, build version, hardening flags, " +
			"and available binaries. The result is cached for the session — call " +
			"this once, then use the other tools to query the data. Multiple files " +
			"can be analysed in parallel; pass the file path to query tools to " +
			"target a specific analysis.",
		inputSchema: {
			path: z.string().describe("Absolute path to the file to analyse")
		}
	},
	async ({ path }) => {
		const session = new AnalysisSession();
		const result = await session.analyseFile(path, noop);
		sessions.set(path, session);
		lastPath = path;
		return ok(sanitize({ ...result.overview, hooks: result.hooks }));
	}
);

server.registerTool(
	"get_overview",
	{
		description:
			"Get the analysis overview for a loaded file. Includes source type, " +
			"Mach-O header, build version, encryption info, hardening flags, " +
			"Info.plist summary, team ID, UUID, detected frameworks, and hook " +
			"detection.",
		inputSchema: { binary: binaryParam, path: pathParam }
	},
	async ({ binary, path }) => {
		const cached = await resolveResult(path, binary);
		return ok(sanitize({ ...cached.overview, hooks: cached.hooks }));
	}
);

server.registerTool(
	"get_section",
	{
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
			section: z.enum(SECTION_NAMES).describe("Section to retrieve"),
			filter: z
				.string()
				.optional()
				.describe(
					"Case-insensitive substring filter on primary field: " +
						"value (strings), name (symbols/classes/libraries)"
				),
			offset: z
				.number()
				.optional()
				.describe("Items to skip (default: 0). Array sections only."),
			limit: z
				.number()
				.optional()
				.describe(`Max items to return (default: ${DEFAULT_LIMIT}). Array sections only.`),
			binary: binaryParam,
			path: pathParam
		}
	},
	async ({ section, filter, offset, limit, binary, path }) => {
		const cached = await resolveResult(path, binary);
		const data = getSectionData(cached, section);

		if (PAGINATED_SECTIONS.has(section)) {
			return ok(buildPaginatedResult(data, section, filter, offset, limit));
		}

		return ok(sanitize(data));
	}
);

server.registerTool(
	"search",
	{
		description:
			"Search across all binaries in the loaded container (main binary, " +
			"frameworks, extensions) for a query string. Returns matches with " +
			"binary name and index.",
		inputSchema: {
			query: z.string().describe("Search query"),
			tab: z
				.enum(["classes", "strings", "symbols", "libraries"])
				.describe("Data type to search"),
			isRegex: z.boolean().optional().describe("Treat query as regex (default: false)"),
			caseSensitive: z.boolean().optional().describe("Case-sensitive match (default: false)"),
			path: pathParam
		}
	},
	async ({ query, tab, isRegex, caseSensitive, path }) => {
		const session = getSession(path);
		const results = await session.searchAllBinaries(
			query,
			tab as SearchableTab,
			noop,
			isRegex,
			caseSensitive
		);
		return ok(results);
	}
);

server.registerTool(
	"switch_binary",
	{
		description:
			"Switch the active binary within the loaded container (e.g. a framework " +
			"or app extension), so subsequent calls default to it. Use get_overview " +
			"to see available binaries and their indices in overview.ipa.binaries. " +
			"To query one binary without changing the active one, pass the `binary` " +
			"parameter to get_overview, get_section, or read_hex instead.",
		inputSchema: {
			binaryIndex: z.number().describe("Index of the binary (from overview.ipa.binaries)"),
			path: pathParam
		}
	},
	async ({ binaryIndex, path }) => {
		const session = getSession(path);
		const result = await session.analyseBinary(binaryIndex, noop);
		return ok(sanitize({ ...result.overview, hooks: result.hooks }));
	}
);

server.registerTool(
	"read_hex",
	{
		description:
			"Read raw hex bytes from the active binary at a given offset. " +
			"Returns formatted hex dump or raw byte array. Use for inspecting " +
			"raw binary content at specific offsets (e.g. segment/section data). " +
			"Max 65536 bytes per request.",
		inputSchema: {
			offset: z
				.number()
				.describe("Byte offset within the binary (e.g. segment fileoff or section offset)"),
			length: z
				.number()
				.optional()
				.describe("Number of bytes to read (max 65536, default 256)"),
			format: z
				.enum(["raw", "hexdump"])
				.optional()
				.describe(
					"Output format: 'hexdump' returns formatted text (default), 'raw' returns byte array"
				),
			binary: binaryParam,
			path: pathParam
		}
	},
	async ({ offset, length, format, binary, path }) => {
		const session = getSession(path);
		const len = length ?? 256;
		const result =
			binary !== undefined
				? await session.readHexForBinary(binary, offset, len)
				: session.readHex(offset, len);
		if (!result) throw new Error("No binary loaded or offset out of range.");

		if ((format ?? "hexdump") === "hexdump") {
			return ok({
				offset: result.offset,
				length: result.length,
				fileSize: result.fileSize,
				hexdump: formatHexdump(result.data, result.offset)
			});
		}

		return ok(result);
	}
);

// Clean up stale cache entries on startup and exit
pruneCache();
process.on("exit", () => pruneCache());

const transport = new StdioServerTransport();
await server.connect(transport);

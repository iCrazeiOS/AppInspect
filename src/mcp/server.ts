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
 * Security / trust model:
 *   This server runs with the privileges of the user who launched it and will
 *   read and parse any local path the connecting client names. Only run it on
 *   inputs and with agents you trust. To confine reads to a directory tree,
 *   set the APPINSPECT_ALLOW_ROOT environment variable (see below).
 *
 * Tools:
 *   analyse_file   — Load and analyse a file or folder (IPA, Mach-O, DEB, .app, .xcframework)
 *   get_overview    — Analysis summary (header, hardening, hooks, etc.)
 *   get_section     — Detailed data for a specific section with filtering
 *   search          — Cross-binary search
 *   get_size_tree   — Bundle files as a size tree, active binary split into modules
 *   switch_binary   — Switch to a different binary in the container
 *   read_hex        — Read raw bytes from the active binary
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import type { SearchableTab } from "../main/analysis/orchestrator";
import { AnalysisSession, formatHexdump, pruneCache } from "../main/analysis/orchestrator";
import { isInside } from "../main/util/safe-path";
import type { AnalysisResult, SizeTreeNode, SwiftMetadata } from "../shared/types";

// Keep stdout clean for MCP protocol — redirect console to stderr
console.log = console.error;
console.info = console.error;
console.warn = console.error;

// ── Optional path confinement ────────────────────────────────────────

// Optional confinement: when APPINSPECT_ALLOW_ROOT is set, analyse_file only
// accepts paths inside that directory. Unset (the default) preserves the
// original "read any local path" behaviour.
const allowRoot = process.env.APPINSPECT_ALLOW_ROOT;

function assertAllowed(filePath: string): void {
	if (!allowRoot) return;
	if (!isInside(allowRoot, filePath)) {
		throw new Error(`Path outside APPINSPECT_ALLOW_ROOT: ${filePath}`);
	}
}

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
	"swift",
	"entitlements",
	"infoPlist",
	"security",
	"files",
	"hooks",
	"size"
] as const;

type SectionName = (typeof SECTION_NAMES)[number];

/** Sections that return filterable/paginatable arrays */
const PAGINATED_SECTIONS = new Set<SectionName>([
	"strings",
	"symbols",
	"classes",
	"swift",
	"libraries"
]);

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
		case "swift":
			return cached.swift;
		case "entitlements": {
			// Null prototype: keys come from an untrusted plist inside the
			// analysed binary, so "__proto__" must not be the setter.
			const obj: Record<string, unknown> = Object.create(null);
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
		case "size":
			return cached.size;
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
	if (section === "swift") {
		const swift = data as SwiftMetadata;
		const lower = filter?.toLowerCase();
		const types = lower
			? swift.types.filter((t) => t.fullName.toLowerCase().includes(lower))
			: swift.types;
		const total = types.length;
		const sliced = sanitize(types.slice(offset, offset + limit));
		const returnedNames = new Set(sliced.map((t) => t.fullName));
		const conformances = sanitize(
			swift.conformances.filter((c) => returnedNames.has(c.typeName)).slice(0, 5000)
		);
		return {
			total,
			offset,
			limit,
			returned: sliced.length,
			types: sliced,
			protocols: sanitize(swift.protocols.slice(0, 2000)),
			protocolTotal: swift.protocols.length,
			conformances,
			conformanceTotal: swift.conformances.length,
			unresolvedConformances: swift.unresolvedConformances,
			present: swift.present
		};
	}

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
			"Analyse an iOS/macOS input: an IPA, Mach-O, DEB, .app bundle, .xcframework, " +
			"or a folder (scanned for Mach-O binaries and .deb packages). " +
			"Must be called before any other tool. Returns an overview summary " +
			"including source type, Mach-O header, build version, hardening flags, " +
			"and available binaries. The result is cached for the session — call " +
			"this once, then use the other tools to query the data. Multiple files " +
			"can be analysed in parallel; pass the file path to query tools to " +
			"target a specific analysis. By default this reads any local path the " +
			"client requests, running with your privileges; set APPINSPECT_ALLOW_ROOT " +
			"to confine reads to a directory tree.",
		inputSchema: {
			path: z.string().describe("Absolute path to the file to analyse")
		}
	},
	async ({ path }) => {
		assertAllowed(path);
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
			"+ methods + protocols), swift (Swift nominal types with stored " +
			"properties, superclasses, protocols, and protocol conformances), " +
			"entitlements (code signing), infoPlist " +
			"(Info.plist), security (findings + hardening), files (bundle file " +
			"tree), hooks (jailbreak hook detection), size (bytes per " +
			"segment/section and per module — Swift module, C++ namespace, ObjC " +
			"class prefix, C library — attributed from symbols and function starts).",
		inputSchema: {
			section: z.enum(SECTION_NAMES).describe("Section to retrieve"),
			filter: z
				.string()
				.optional()
				.describe(
					"Case-insensitive substring filter on primary field: " +
						"value (strings), name (symbols/classes/libraries), " +
						"fullName (swift types)"
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
	"get_size_tree",
	{
		description:
			"Bundle contents as a size tree (what the desktop app's Size > Blocks treemap " +
			"shows): every file in the bundle — for XCFrameworks, the active slice's " +
			".framework as embedded in an app, so Headers, PrivateHeaders, Modules " +
			"(.swiftmodule/.modulemap) and .tbd stubs are left out and listed in the " +
			"root's `excluded` — with the active binary split into its modules (kind " +
			"'module') and the bytes no module owns (kind 'overhead'). Core ML models " +
			"(.mlmodelc/.mlpackage/.mlmodel) are single 'mlmodel' leaves. Children are " +
			"sorted by size, descending.",
		inputSchema: {
			maxDepth: z
				.number()
				.optional()
				.describe("Levels of children to include below the root (default: 3)"),
			path: pathParam
		}
	},
	async ({ maxDepth = 3, path }) => {
		const prune = (node: SizeTreeNode, depth: number): SizeTreeNode => {
			if (!node.children) return node;
			if (depth >= maxDepth) {
				const { children, ...rest } = node;
				return { ...rest, childCount: children.length } as SizeTreeNode;
			}
			return { ...node, children: node.children.map((c) => prune(c, depth + 1)) };
		};
		return ok(prune(getSession(path).getSizeTree(), 0));
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

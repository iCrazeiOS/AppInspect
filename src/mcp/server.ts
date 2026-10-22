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
 *   search          — Cross-binary search (classes, strings, symbols, libraries, swift)
 *   get_size_tree   — Bundle files as a size tree, active binary split into modules
 *   switch_binary   — Switch to a different binary in the container
 *   read_hex        — Read raw bytes from the active binary
 *   get_library_graph — Dependency graph across all binaries in the container
 *   search_hex      — Search a binary for a byte pattern
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { MAX_HEX_MATCHES } from "../main/analysis/hex";
import type { SearchableTab } from "../main/analysis/orchestrator";
import { AnalysisSession, formatHexdump, pruneCache } from "../main/analysis/orchestrator";
import { isInside } from "../main/util/safe-path";
import { FILE_PREVIEW_BYTES, FILE_PREVIEW_FULL_BYTES } from "../shared/file-preview";
import type { AnalysisResult, AsarEntry, SizeTreeNode } from "../shared/types";
import {
	buildHexSearchResult,
	buildLibraryGraphResult,
	buildPaginatedResult,
	DEFAULT_LIMIT,
	getSectionData,
	ok,
	PAGINATED_SECTIONS,
	parseHexPattern,
	SECTION_NAMES,
	sanitize
} from "./format";

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

// ── Session management ──────────────────────────────────────────────

const sessions = new Map<string, AnalysisSession>();
let lastPath: string | null = null;

function getSession(filePath?: string): AnalysisSession {
	const key = filePath ?? lastPath;
	if (!key) throw new Error("No file loaded. Call analyse_file first.");
	const session = sessions.get(key);
	if (!session) throw new Error(`No session for ${key}. Call analyse_file first.`);
	if (!session.isExtractionPresent()) {
		throw new Error(`Cached extraction for ${key} was removed. Call analyse_file again.`);
	}
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

const noop = () => {};

/** Flatten an ASAR entry tree into its files, sorted by archive path. */
function flattenAsar(entries: AsarEntry[]): AsarEntry[] {
	const files: AsarEntry[] = [];
	const walk = (nodes: AsarEntry[]): void => {
		for (const node of nodes) {
			if (node.isDirectory) {
				if (node.children) walk(node.children);
			} else {
				files.push(node);
			}
		}
	};
	walk(entries);
	return files.sort((a, b) => a.path.localeCompare(b.path));
}

// ── Server setup ─────────────────────────────────────────────────────

const server = new McpServer({ name: "appinspect", version: "0.1.0" });

server.registerTool(
	"analyse_file",
	{
		description:
			"Analyse an iOS/macOS input: an IPA, Mach-O, DEB, .app bundle, .xcframework, " +
			"or a folder (scanned for Mach-O binaries and .deb packages). " +
			"A macOS Electron .app is analysed down to its app.asar archive too " +
			"(use list_asar and read_asar_file for its files). " +
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
		return ok(sanitize({ ...result.overview, hooks: result.hooks, electron: result.electron }));
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
		return ok(sanitize({ ...cached.overview, hooks: cached.hooks, electron: cached.electron }));
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
			"(Info.plist), electron (Electron version, fuses, ASAR integrity, " +
			"package.json, source maps, native addons), security (findings + hardening), " +
			"files (bundle file " +
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
				.enum(["classes", "strings", "symbols", "libraries", "swift"])
				.describe("Data type to search (swift matches Swift type full names)"),
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
	"list_asar",
	{
		description:
			"List the files inside an Electron app.asar archive (see the electron " +
			"section for fuses, integrity and package.json). Returns a flat list of " +
			"files sorted by archive path, with optional path filtering and pagination. " +
			"Empty when the analysed input is not an Electron bundle with a readable archive.",
		inputSchema: {
			filter: z
				.string()
				.optional()
				.describe("Case-insensitive substring filter on the archive path"),
			offset: z.number().optional().describe("Files to skip (default: 0)"),
			limit: z
				.number()
				.optional()
				.describe(`Max files to return (default: ${DEFAULT_LIMIT})`),
			path: pathParam
		}
	},
	async ({ filter, offset = 0, limit = DEFAULT_LIMIT, path }) => {
		const all = flattenAsar(getSession(path).getAsarTree()).map((entry) => ({
			path: entry.path,
			size: entry.size,
			unpacked: entry.unpacked === true
		}));
		const lower = filter?.toLowerCase();
		const filtered = lower
			? all.filter((file) => file.path.toLowerCase().includes(lower))
			: all;
		const start = Math.max(0, Math.floor(offset));
		const count = Math.min(1000, Math.max(0, Math.floor(limit)));
		return ok({
			total: filtered.length,
			offset: start,
			limit: count,
			files: filtered.slice(start, start + count)
		});
	}
);

server.registerTool(
	"read_asar_file",
	{
		description:
			"Read a file from an Electron app.asar archive by archive-relative path " +
			`(from list_asar). Text entries return their text (up to maxBytes, capped at ${
				FILE_PREVIEW_FULL_BYTES / (1024 * 1024)
			} MB); image ` +
			'entries return kind: "image" metadata without image bytes, and other ' +
			"binary entries return metadata only. Archive contents are never extracted.",
		inputSchema: {
			file: z.string().describe("Archive-relative path, e.g. from list_asar"),
			maxBytes: z
				.number()
				.optional()
				.describe(
					`Max bytes to read (default: ${FILE_PREVIEW_BYTES}; capped at ${
						FILE_PREVIEW_FULL_BYTES / (1024 * 1024)
					} MB)`
				),
			path: pathParam
		}
	},
	async ({ file, maxBytes = FILE_PREVIEW_BYTES, path }) => {
		const content = getSession(path).readAsarFile(file, maxBytes);
		if (!content) throw new Error(`Could not read ${file} from app.asar.`);
		return ok(content);
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
		return ok(sanitize({ ...result.overview, hooks: result.hooks, electron: result.electron }));
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

server.registerTool(
	"get_library_graph",
	{
		description:
			"Dependency graph across all binaries in the loaded container: nodes (binaries " +
			"and the libraries they link) and edges (which binary links which library, " +
			"weak or strong). Optionally narrow to one library category.",
		inputSchema: {
			category: z
				.enum(["system", "framework", "swift", "embedded"])
				.optional()
				.describe(
					"Only keep library nodes in this category, plus the edges that touch them " +
						"and those edges' other endpoints"
				),
			path: pathParam
		}
	},
	async ({ category, path }) => {
		const graph = await getSession(path).getLibraryGraph();
		return ok(sanitize(buildLibraryGraphResult(graph, category)));
	}
);

server.registerTool(
	"search_hex",
	{
		description:
			"Search a binary for a byte pattern and return the file offsets of matches " +
			"(use read_hex to inspect them). Pattern is hex or an ASCII/UTF-8 string " +
			'with a "text:" prefix. Max 10000 matches.',
		inputSchema: {
			pattern: z
				.string()
				.describe(
					'Byte pattern as hex (e.g. "de ad be ef" or "deadbeef"; spaces allowed), max 256 ' +
						'bytes. Use "text:" prefix for an ASCII/UTF-8 string, e.g. "text:Bearer ".'
				),
			regionOffset: z.number().optional().describe("Start offset of the region (default 0)"),
			regionSize: z
				.number()
				.optional()
				.describe("Region size in bytes (default: whole file)"),
			caseInsensitive: z
				.boolean()
				.optional()
				.describe("Match ASCII letters case-insensitively (default false)"),
			binary: binaryParam,
			path: pathParam
		}
	},
	async ({ pattern, regionOffset = 0, regionSize, caseInsensitive, binary, path }) => {
		const bytes = parseHexPattern(pattern);
		const session = getSession(path);
		const index = binary ?? session.getActiveBinaryIndex();
		const result = await session.searchHexForBinary(
			index,
			Math.max(0, Math.floor(regionOffset)),
			regionSize === undefined ? undefined : Math.max(0, Math.floor(regionSize)),
			bytes,
			caseInsensitive
		);
		if (!result) throw new Error("No binary loaded.");
		return ok(
			buildHexSearchResult(
				{ index, name: result.binaryName },
				result.regionOffset,
				result.regionSize,
				bytes,
				result.matches,
				MAX_HEX_MATCHES
			)
		);
	}
);

// Clean up stale cache entries on startup and exit
pruneCache();
process.on("exit", () => pruneCache());

const transport = new StdioServerTransport();
await server.connect(transport);

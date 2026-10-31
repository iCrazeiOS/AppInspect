/**
 * Pure formatting and parsing helpers for the MCP server.
 *
 * Kept free of SDK imports and I/O so they can be unit-tested without
 * starting the server.
 */

import { plural } from "../shared/format";
import type {
	AnalysisResult,
	LibraryGraphData,
	LibraryGraphNode,
	SwiftMetadata
} from "../shared/types";

export const DEFAULT_LIMIT = 200;

export const SECTION_NAMES = [
	"strings",
	"headers",
	"libraries",
	"symbols",
	"objc",
	"swift",
	"entitlements",
	"infoPlist",
	"electron",
	"security",
	"files",
	"hooks",
	"size"
] as const;

export type SectionName = (typeof SECTION_NAMES)[number];

/** Sections that return filterable/paginatable arrays */
export const PAGINATED_SECTIONS = new Set<SectionName>([
	"strings",
	"symbols",
	"objc",
	"swift",
	"libraries"
]);

// ── BigInt serialisation ─────────────────────────────────────────────

export function bigintReplacer(_key: string, value: unknown): unknown {
	if (typeof value === "bigint") {
		if (value <= BigInt(Number.MAX_SAFE_INTEGER) && value >= BigInt(Number.MIN_SAFE_INTEGER)) {
			return Number(value);
		}
		return value.toString();
	}
	return value;
}

export function sanitize<T>(obj: T): T {
	return JSON.parse(JSON.stringify(obj, bigintReplacer)) as T;
}

// ── Section data helpers ─────────────────────────────────────────────

export function getSectionData(cached: AnalysisResult, section: SectionName): unknown {
	switch (section) {
		case "strings":
			return { binary: cached.strings, localisation: cached.localisationStrings ?? [] };
		case "headers":
			return cached.headers;
		case "libraries":
			return cached.libraries;
		case "symbols":
			return cached.symbols;
		case "objc":
			return {
				classes: cached.objc.classes,
				categories: cached.objc.categories,
				protocols: cached.objc.protocols
			};
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
		case "electron":
			return cached.electron;
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
export function getArray(data: unknown, section: SectionName): unknown[] {
	if (section === "strings") return (data as { binary: unknown[] }).binary;
	if (section === "objc") return (data as { classes: unknown[] }).classes;
	return data as unknown[];
}

/** Primary field to filter on per section */
export function filterField(section: SectionName): string {
	return section === "strings" ? "value" : "name";
}

export function buildPaginatedResult(
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
	} else if (section === "objc") {
		result.classes = sliced;
		result.categories = sanitize((data as { categories: unknown[] }).categories ?? []);
		result.protocols = sanitize((data as { protocols: unknown[] }).protocols);
	} else {
		result.data = sliced;
	}

	return result;
}

// ── Library graph ────────────────────────────────────────────────────

export type LibraryCategory = NonNullable<LibraryGraphNode["category"]>;

/**
 * Narrow a graph to library nodes of one category. Edges are kept when they touch
 * a matching node, along with their other endpoint, so every edge still resolves.
 */
export function buildLibraryGraphResult(graph: LibraryGraphData, category?: LibraryCategory) {
	let { nodes, edges } = graph;
	if (category) {
		const matching = new Set(nodes.filter((n) => n.category === category).map((n) => n.id));
		edges = edges.filter((e) => matching.has(e.source) || matching.has(e.target));
		const keep = new Set(matching);
		for (const e of edges) {
			keep.add(e.source);
			keep.add(e.target);
		}
		nodes = nodes.filter((n) => keep.has(n.id));
	}
	return { nodeCount: nodes.length, edgeCount: edges.length, nodes, edges };
}

// ── Hex search ───────────────────────────────────────────────────────

export const MAX_HEX_PATTERN_BYTES = 256;

/** Parse a hex string ("de ad be ef") or a "text:" prefixed string into bytes. */
export function parseHexPattern(pattern: string): number[] {
	let bytes: number[];
	if (pattern.startsWith("text:")) {
		bytes = Array.from(new TextEncoder().encode(pattern.slice("text:".length)));
	} else {
		const digits = pattern.replace(/\s+/g, "");
		if (!/^[0-9a-fA-F]*$/.test(digits)) {
			throw new Error(
				'Pattern contains non-hex characters. Use hex digits (e.g. "de ad be ef") ' +
					'or prefix an ASCII string with "text:".'
			);
		}
		if (digits.length % 2 !== 0) throw new Error("Pattern has an odd number of hex digits.");
		bytes = [];
		for (let i = 0; i < digits.length; i += 2)
			bytes.push(Number.parseInt(digits.slice(i, i + 2), 16));
	}
	if (bytes.length === 0) throw new Error("Pattern is empty.");
	if (bytes.length > MAX_HEX_PATTERN_BYTES) {
		throw new Error(
			`Pattern is ${bytes.length} ${plural(bytes.length, "byte")}; the maximum is ${MAX_HEX_PATTERN_BYTES}.`
		);
	}
	return bytes;
}

export function buildHexSearchResult(
	binary: { index: number; name: string },
	regionOffset: number,
	regionSize: number,
	pattern: number[],
	matches: number[],
	maxMatches: number
) {
	return {
		binary,
		regionOffset,
		regionSize,
		pattern: pattern.map((b) => b.toString(16).padStart(2, "0")).join(""),
		matches,
		matchCount: matches.length,
		truncated: matches.length >= maxMatches
	};
}

// ── Response helper ──────────────────────────────────────────────────

export function ok(data: unknown) {
	return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
}

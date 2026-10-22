/**
 * Shared helpers for the file browser: tree types, path matching, counting and
 * file icons. Pure and DOM-free so the behaviour stays unit-testable.
 */

import { imageMimeType } from "../../shared/file-preview";
import { compileSafeRegex } from "../../shared/safe-regex";

/** Minimal shape shared by `FileEntry` and `AsarEntry`. */
export interface BrowserTreeNode {
	name: string;
	path: string;
	size: number;
	isDirectory: boolean;
	children?: BrowserTreeNode[];
}

export interface FileBadge {
	/** When omitted the badge renders as a compact coloured dot. */
	label?: string;
	/** CSS suffix, e.g. "unpacked", "link", "exec", "binary", "plist". */
	tone: string;
	title?: string;
}

/** Build a path matcher for the tree filter, or null for an invalid pattern. */
export function compilePathMatcher(
	term: string,
	isRegex: boolean,
	caseSensitive: boolean
): ((value: string) => boolean) | null {
	if (!term) return null;
	if (isRegex) {
		const re = compileSafeRegex(term, caseSensitive ? "" : "i");
		return re ? (value) => re.test(value) : null;
	}
	if (caseSensitive) return (value) => value.includes(term);
	const lower = term.toLowerCase();
	return (value) => value.toLowerCase().includes(lower);
}

/** Ancestor paths of a file, e.g. "a/b/c.js" -> ["a", "a/b"]. */
export function ancestorPaths(path: string): string[] {
	const segments = path.split("/");
	const out: string[] = [];
	for (let i = 1; i < segments.length; i++) {
		out.push(segments.slice(0, i).join("/"));
	}
	return out;
}

/**
 * Matching entry paths plus every ancestor, so a filtered tree keeps its
 * structure. `test` receives the entry itself, not just its path.
 */
export function collectMatchedPaths<T extends BrowserTreeNode>(
	entries: T[],
	test: (entry: T) => boolean,
	parentChain: string[] = []
): Set<string> {
	const result = new Set<string>();
	for (const entry of entries) {
		const chain = [...parentChain, entry.path];
		if (test(entry)) {
			for (const path of chain) result.add(path);
		}
		if (entry.children) {
			const sub = collectMatchedPaths(entry.children as T[], test, chain);
			for (const path of sub) result.add(path);
		}
	}
	return result;
}

/** Number of non-directory entries in the tree. */
export function countTreeFiles<T extends BrowserTreeNode>(entries: T[]): number {
	let count = 0;
	for (const entry of entries) {
		if (entry.isDirectory) {
			if (entry.children) count += countTreeFiles(entry.children as T[]);
		} else {
			count++;
		}
	}
	return count;
}

/** Number of non-directory entries accepted by `test`. */
export function countMatchedFiles<T extends BrowserTreeNode>(
	entries: T[],
	test: (entry: T) => boolean
): number {
	let count = 0;
	for (const entry of entries) {
		if (entry.isDirectory) {
			if (entry.children) count += countMatchedFiles(entry.children as T[], test);
		} else if (test(entry)) {
			count++;
		}
	}
	return count;
}

/** File count and summed size of the tree. */
export function treeTotals<T extends BrowserTreeNode>(
	entries: T[]
): {
	count: number;
	totalSize: number;
} {
	let count = 0;
	let totalSize = 0;
	for (const entry of entries) {
		if (entry.isDirectory) {
			if (entry.children) {
				const sub = treeTotals(entry.children as T[]);
				count += sub.count;
				totalSize += sub.totalSize;
			}
		} else {
			count++;
			totalSize += entry.size;
		}
	}
	return { count, totalSize };
}

/** Find a node by path anywhere in the tree. */
export function findEntry<T extends BrowserTreeNode>(entries: T[], path: string): T | null {
	for (const entry of entries) {
		if (entry.path === path) return entry;
		if (entry.children) {
			const found = findEntry(entry.children as T[], path);
			if (found) return found;
		}
	}
	return null;
}

const CODE_EXTENSIONS = new Set([
	"js",
	"mjs",
	"cjs",
	"jsx",
	"ts",
	"tsx",
	"css",
	"scss",
	"sass",
	"less",
	"html",
	"htm",
	"xhtml",
	"svg",
	"vue",
	"svelte",
	"sh",
	"py",
	"rb",
	"go",
	"rs",
	"c",
	"h",
	"cpp",
	"hpp",
	"java",
	"kt",
	"swift",
	"m"
]);

const DATA_EXTENSIONS = new Set([
	"json",
	"map",
	"json5",
	"yaml",
	"yml",
	"toml",
	"xml",
	"csv",
	"tsv",
	"plist",
	"webmanifest"
]);

const FONT_EXTENSIONS = new Set(["woff", "woff2", "ttf", "otf", "eot"]);

const ARCHIVE_EXTENSIONS = new Set(["zip", "tar", "gz", "tgz", "bz2", "xz", "7z", "rar", "asar"]);

const MEDIA_EXTENSIONS = new Set([
	"mp3",
	"wav",
	"ogg",
	"flac",
	"m4a",
	"aac",
	"mp4",
	"webm",
	"mov",
	"mkv",
	"avi"
]);

const BINARY_EXTENSIONS = new Set([
	"node",
	"dll",
	"dylib",
	"so",
	"exe",
	"wasm",
	"bin",
	"dat",
	"db"
]);

const DOC_EXTENSIONS = new Set(["md", "markdown", "txt", "log"]);

/** File icon for a browser tree row. */
export function fileIcon(name: string, isDirectory: boolean): string {
	if (isDirectory) return "\u{1F4C1}";
	if (imageMimeType(name)) return "\u{1F5BC}\u{FE0F}";
	const dot = name.lastIndexOf(".");
	const extension = dot > 0 ? name.slice(dot + 1).toLowerCase() : "";
	if (CODE_EXTENSIONS.has(extension)) return "\u{1F4DC}";
	if (DATA_EXTENSIONS.has(extension)) return "\u{1F5C2}\u{FE0F}";
	if (FONT_EXTENSIONS.has(extension)) return "\u{1F524}";
	if (ARCHIVE_EXTENSIONS.has(extension)) return "\u{1F4E6}";
	if (MEDIA_EXTENSIONS.has(extension)) return "\u{1F3B5}";
	if (BINARY_EXTENSIONS.has(extension)) return "\u2699\u{FE0F}";
	if (DOC_EXTENSIONS.has(extension)) return "\u{1F4DD}";
	return "\u{1F4C4}";
}

/**
 * Size tree for the treemap view.
 *
 * Walks a bundle directory into a size-annotated tree. Core ML models stay a
 * single leaf (their internals are not meaningful to users), and the binary
 * that has a size breakdown is split into its modules plus the bytes no
 * module owns, so the treemap shows code next to the resources it ships with.
 */

import * as fs from "node:fs";
import * as path from "node:path";

import type { AsarEntry, SizeBreakdown, SizeTreeNode } from "../../shared/types";
import { withoutAsar } from "../util/no-asar";

const ML_MODEL_EXTENSIONS = new Set([".mlmodelc", ".mlpackage", ".mlmodel"]);
/**
 * What Xcode's Embed Frameworks phase leaves behind when it copies a
 * framework into an app (`builtin-copy -exclude .DS_Store -exclude CVS
 * -exclude .svn -exclude .git -exclude .hg -exclude Headers -exclude
 * PrivateHeaders -exclude Modules -exclude *.tbd`), matched at any depth.
 */
const NOT_EMBEDDED_NAMES = new Set([
	".DS_Store",
	"CVS",
	".svn",
	".git",
	".hg",
	"Headers",
	"PrivateHeaders",
	"Modules"
]);

export function isStrippedWhenEmbedded(name: string): boolean {
	return NOT_EMBEDDED_NAMES.has(name) || name.toLowerCase().endsWith(".tbd");
}

/** Upper bound on visited entries so a pathological bundle can't stall the main process. */
const MAX_ENTRIES = 100_000;

export interface SplitBinary {
	path: string;
	breakdown: SizeBreakdown;
}

function bySizeDesc(a: SizeTreeNode, b: SizeTreeNode): number {
	return b.size - a.size;
}

/** Children of a binary file: its modules, then the bytes no module owns. */
export function splitBinaryNode(
	name: string,
	fileSize: number,
	breakdown: SizeBreakdown
): SizeTreeNode {
	const children: SizeTreeNode[] = [];
	for (const mod of breakdown.modules) {
		if (mod.kind === "unattributed" || mod.size === 0) continue;
		children.push({ name: mod.name, size: mod.size, kind: "module", moduleKind: mod.kind });
	}

	const linkedit = breakdown.segments.find((s) => s.name === "__LINKEDIT")?.fileSize ?? 0;
	const overhead: [string, number][] = [
		["Unattributed section data", breakdown.sectionSize - breakdown.attributedSize],
		["Link-edit data", linkedit],
		[
			"Headers & padding",
			breakdown.binarySize - breakdown.sectionSize - Math.min(linkedit, breakdown.binarySize)
		],
		// Fat files: the breakdown covers one slice
		["Other architecture slices", fileSize - breakdown.binarySize]
	];
	for (const [label, size] of overhead) {
		if (size > 0) children.push({ name: label, size, kind: "overhead" });
	}
	children.sort(bySizeDesc);
	return {
		name,
		size: children.reduce((sum, c) => sum + c.size, 0),
		kind: "binary",
		children
	};
}

/** Total bytes under a directory (regular files only; symlinks are not followed). */
function directorySize(dir: string, budget: { left: number }): number {
	let total = 0;
	let entries: fs.Dirent[];
	try {
		entries = fs.readdirSync(dir, { withFileTypes: true });
	} catch {
		return 0;
	}
	for (const entry of entries) {
		if (--budget.left < 0) break;
		const full = path.join(dir, entry.name);
		if (entry.isDirectory()) total += directorySize(full, budget);
		else if (entry.isFile()) {
			try {
				total += fs.statSync(full).size;
			} catch {
				/* unreadable — skip */
			}
		}
	}
	return total;
}

/**
 * Build the tree for `rootPath` (a directory, or a single binary file).
 * `split` names the binary to break into modules; `binaryPaths` marks the
 * other Mach-O files so they render as code rather than resources. With
 * `asEmbedded`, entries Xcode strips when embedding the framework in an app
 * are left out and listed in the root's `excluded`. With `asar`, the Electron
 * archive at that path is split into its packed contents.
 */
export function buildSizeTree(
	rootPath: string,
	split: SplitBinary | null,
	binaryPaths: ReadonlySet<string> = new Set(),
	asEmbedded = false,
	asar?: { path: string; entries: AsarEntry[] }
): SizeTreeNode {
	return withoutAsar(() => buildTree(rootPath, split, binaryPaths, asEmbedded, asar));
}

function buildTree(
	rootPath: string,
	split: SplitBinary | null,
	binaryPaths: ReadonlySet<string>,
	asEmbedded: boolean,
	asar: { path: string; entries: AsarEntry[] } | undefined
): SizeTreeNode {
	const budget = { left: MAX_ENTRIES };
	const excluded: { path: string; size: number }[] = [];
	const splitPath = split ? path.resolve(split.path) : null;
	const asarPath = asar ? path.resolve(asar.path) : null;

	/** Packed archive entries as directory/file nodes; unpacked ones are counted elsewhere. */
	const asarChildren = (entries: AsarEntry[]): SizeTreeNode[] => {
		const children: SizeTreeNode[] = [];
		for (const entry of entries) {
			if (entry.unpacked) continue;
			if (entry.isDirectory) {
				const dirChildren = asarChildren(entry.children ?? []);
				if (dirChildren.length === 0) continue;
				children.push({
					name: entry.name,
					size: dirChildren.reduce((sum, c) => sum + c.size, 0),
					kind: "directory",
					children: dirChildren
				});
			} else {
				if (entry.size === 0) continue;
				children.push({ name: entry.name, size: entry.size, kind: "file" });
			}
		}
		children.sort(bySizeDesc);
		return children;
	};

	const asarNode = (name: string, size: number): SizeTreeNode | null => {
		if (!asar) return null;
		const children = asarChildren(asar.entries);
		if (children.length === 0) return null;

		const packedSize = children.reduce((sum, c) => sum + c.size, 0);
		const overhead = size - packedSize;
		if (overhead > 0)
			children.push({ name: "Archive header & padding", size: overhead, kind: "overhead" });
		children.sort(bySizeDesc);

		return {
			name,
			size: children.reduce((sum, c) => sum + c.size, 0),
			kind: "asar",
			children
		};
	};

	const fileNode = (full: string, name: string, size: number): SizeTreeNode => {
		const resolved = path.resolve(full);
		if (split && resolved === splitPath) return splitBinaryNode(name, size, split.breakdown);
		if (asarPath && resolved === asarPath) {
			const node = asarNode(name, size);
			if (node) return node;
		}
		if (binaryPaths.has(resolved)) return { name, size, kind: "binary" };
		if (ML_MODEL_EXTENSIONS.has(path.extname(name).toLowerCase())) {
			return { name, size, kind: "mlmodel" };
		}
		return { name, size, kind: "file" };
	};

	const walk = (dir: string, name: string): SizeTreeNode => {
		const children: SizeTreeNode[] = [];
		let entries: fs.Dirent[] = [];
		try {
			entries = fs.readdirSync(dir, { withFileTypes: true });
		} catch {
			/* unreadable — empty */
		}
		for (const entry of entries) {
			if (--budget.left < 0) break;
			const full = path.join(dir, entry.name);
			if (asEmbedded && isStrippedWhenEmbedded(entry.name)) {
				let size = 0;
				try {
					if (entry.isDirectory()) size = directorySize(full, budget);
					else if (entry.isFile()) size = fs.statSync(full).size;
				} catch {
					/* unreadable — still excluded */
				}
				excluded.push({
					path: path.relative(rootPath, full).split(path.sep).join("/"),
					size
				});
				continue;
			}
			if (entry.isDirectory()) {
				const node = ML_MODEL_EXTENSIONS.has(path.extname(entry.name).toLowerCase())
					? {
							name: entry.name,
							size: directorySize(full, budget),
							kind: "mlmodel" as const
						}
					: walk(full, entry.name);
				if (node.size > 0) children.push(node);
			} else if (entry.isFile()) {
				let size = 0;
				try {
					size = fs.statSync(full).size;
				} catch {
					continue;
				}
				if (size > 0) children.push(fileNode(full, entry.name, size));
			}
			// Symlinks (e.g. macOS Versions/Current) are skipped so nothing is counted twice
		}
		children.sort(bySizeDesc);
		return {
			name,
			size: children.reduce((sum, c) => sum + c.size, 0),
			kind: "directory",
			children
		};
	};

	const name = path.basename(rootPath);
	const stat = fs.statSync(rootPath);
	if (!stat.isDirectory()) return fileNode(rootPath, name, stat.size);
	const tree = walk(rootPath, name);
	if (excluded.length > 0) tree.excluded = excluded.sort((a, b) => b.size - a.size);
	return tree;
}

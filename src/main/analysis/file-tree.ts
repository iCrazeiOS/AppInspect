/**
 * File tree builder.
 *
 * Recursively walks an extracted bundle directory into the FileEntry tree
 * shown in the Files tab.
 */

import * as fs from "node:fs";
import * as path from "node:path";

import type { FileEntry } from "../../shared/types";
import { withoutAsar } from "../util/no-asar";

export function buildFileTree(dirPath: string): FileEntry[] {
	return withoutAsar(() => buildTree(dirPath));
}

function buildTree(dirPath: string): FileEntry[] {
	try {
		const entries = fs.readdirSync(dirPath, { withFileTypes: true });
		const result: FileEntry[] = [];

		for (const entry of entries) {
			const fullPath = path.join(dirPath, entry.name);
			let stat: fs.Stats;

			try {
				stat = fs.statSync(fullPath);
			} catch {
				// skip entries we can't stat
				continue;
			}

			if (entry.isDirectory()) {
				const children = buildFileTree(fullPath);
				let size = 0;
				// Ignore the directory's own mtime: extraction tools often stamp it
				// with the unpack time, so the contents are more meaningful.
				let mtimeMs = children.length > 0 ? 0 : stat.mtimeMs;
				for (const child of children) {
					size += child.size;
					mtimeMs = Math.max(mtimeMs, child.mtimeMs);
				}
				result.push({
					name: entry.name,
					path: fullPath,
					size,
					mtimeMs,
					isDirectory: true,
					children
				});
			} else {
				result.push({
					name: entry.name,
					path: fullPath,
					size: stat.size,
					mtimeMs: stat.mtimeMs,
					isDirectory: false
				});
			}
		}

		return result.sort((a, b) => {
			// Directories first, then alphabetical
			if (a.isDirectory && !b.isDirectory) return -1;
			if (!a.isDirectory && b.isDirectory) return 1;
			return a.name.localeCompare(b.name);
		});
	} catch {
		return [];
	}
}

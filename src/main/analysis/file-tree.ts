/**
 * File tree builder.
 *
 * Recursively walks an extracted bundle directory into the FileEntry tree
 * shown in the Files tab.
 */

import * as fs from "node:fs";
import * as path from "node:path";

import type { FileEntry } from "../../shared/types";

export function buildFileTree(dirPath: string): FileEntry[] {
	try {
		const entries = fs.readdirSync(dirPath, { withFileTypes: true });
		const result: FileEntry[] = [];

		for (const entry of entries) {
			const fullPath = path.join(dirPath, entry.name);
			let size = 0;

			try {
				const stat = fs.statSync(fullPath);
				size = stat.size;
			} catch {
				// skip entries we can't stat
				continue;
			}

			if (entry.isDirectory()) {
				const children = buildFileTree(fullPath);
				result.push({
					name: entry.name,
					path: fullPath,
					size,
					isDirectory: true,
					children
				});
			} else {
				result.push({
					name: entry.name,
					path: fullPath,
					size,
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

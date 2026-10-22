/**
 * Extraction cache management.
 *
 * Stores extracted archive contents in ~/.appinspect/cache/ keyed by
 * MD5(path + size + mtime). Touches mtime on access for LRU-style pruning.
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

const CACHE_BASE = path.join(os.homedir(), ".appinspect", "cache");

/**
 * Deterministic cache directory for an extracted archive.
 * Key is derived from file path + size + mtime so modified files get a fresh dir.
 */
export function getCacheDir(filePath: string): string {
	const stat = fs.statSync(filePath);
	const key = crypto
		.createHash("md5")
		.update(`${filePath}\0${stat.size}\0${stat.mtimeMs}`)
		.digest("hex");
	return path.join(CACHE_BASE, key);
}

/** True when a cache dir exists and has content from a previous extraction.
 *  Touches the directory mtime on hit so pruneCache() uses last-accessed age. */
export function isCacheValid(dir: string): boolean {
	try {
		if (fs.readdirSync(dir).length > 0) {
			const now = new Date();
			fs.utimesSync(dir, now, now);
			return true;
		}
		return false;
	} catch {
		return false;
	}
}

/**
 * Safely extract into a cache directory, handling concurrent instances.
 *
 * Extracts to a temporary sibling directory first, then atomically renames
 * to the real cache path. If another instance already created it, the temp
 * is cleaned up and the existing cache is reused.
 *
 * Returns `true` when a valid cache already existed (extraction skipped).
 */
export async function extractToCache<T extends { success: boolean }>(
	cacheDir: string,
	extractFn: (destDir: string) => Promise<T>
): Promise<{ cached: true } | { cached: false; result: T }> {
	if (isCacheValid(cacheDir)) {
		return { cached: true };
	}

	const tempDir = `${cacheDir}-tmp-${process.pid}`;
	try {
		const result = await extractFn(tempDir);
		if (!result.success) {
			return { cached: false, result };
		}

		// Attempt atomic move — fails if another instance created cacheDir first
		try {
			fs.renameSync(tempDir, cacheDir);
		} catch {
			fs.rmSync(tempDir, { recursive: true, force: true });
		}

		return { cached: false, result };
	} catch (err) {
		try {
			fs.rmSync(tempDir, { recursive: true, force: true });
		} catch {
			/* best-effort */
		}
		throw err;
	}
}

/**
 * Remove cache entries older than `maxAgeDays` days.
 * Runs best-effort — errors on individual entries are silently ignored.
 */
export function pruneCache(maxAgeDays = 7): void {
	const maxAgeMs = maxAgeDays * 24 * 60 * 60 * 1000;
	const now = Date.now();

	let entries: string[];
	try {
		entries = fs.readdirSync(CACHE_BASE);
	} catch {
		return; // cache dir doesn't exist yet
	}

	for (const entry of entries) {
		try {
			const entryPath = path.join(CACHE_BASE, entry);
			const stat = fs.statSync(entryPath);
			if (stat.isDirectory() && now - stat.mtimeMs > maxAgeMs) {
				fs.rmSync(entryPath, { recursive: true, force: true });
			}
		} catch {
			// best-effort
		}
	}
}

/** Base directory holding every cached extraction. */
export function getCacheBase(): string {
	return CACHE_BASE;
}

/** Interrupted-extraction directories younger than this may still be written to. */
const TEMP_GRACE_MS = 10 * 60 * 1000;

export interface CacheInfo {
	path: string;
	/** Top-level entries, including `-tmp-` directories. */
	entryCount: number;
	/** Sum of file sizes, recursive. */
	totalBytes: number;
}

export interface CacheClearResult {
	removedEntries: number;
	removedBytes: number;
	/** Entries kept because an open session uses them. */
	keptInUse: number;
	/** `-tmp-` entries kept because they were written to recently. */
	keptRecentTemp: number;
	/** Entries that could not be removed. */
	failed: number;
}

/** Size of a path in bytes. Symlinks count for themselves and are never followed. */
async function sizeOf(target: string): Promise<number> {
	let stat: fs.Stats;
	try {
		stat = await fs.promises.lstat(target);
	} catch {
		return 0;
	}
	if (!stat.isDirectory()) return stat.size;

	let names: string[];
	try {
		names = await fs.promises.readdir(target);
	} catch {
		return 0;
	}
	let total = 0;
	for (const name of names) total += await sizeOf(path.join(target, name));
	return total;
}

async function listEntries(baseDir: string): Promise<string[]> {
	try {
		return await fs.promises.readdir(baseDir);
	} catch {
		return []; // cache dir doesn't exist yet
	}
}

/** Entry count and disk usage of the cache. Never creates the directory. */
export async function getCacheInfo(options: { baseDir?: string } = {}): Promise<CacheInfo> {
	const baseDir = options.baseDir ?? CACHE_BASE;
	const entries = await listEntries(baseDir);
	let totalBytes = 0;
	for (const entry of entries) {
		totalBytes += await sizeOf(path.join(baseDir, entry));
		await new Promise((resolve) => setImmediate(resolve));
	}
	return { path: baseDir, entryCount: entries.length, totalBytes };
}

/**
 * Remove cache entries except those in use. `inUse` is called before each
 * removal, so entries opened while the clear is running are still kept.
 * With `dryRun`, nothing is deleted and the result shows what would be.
 */
export async function clearCache(options: {
	baseDir?: string;
	inUse: () => ReadonlySet<string>;
	dryRun?: boolean;
}): Promise<CacheClearResult> {
	const baseDir = options.baseDir ?? CACHE_BASE;
	const result: CacheClearResult = {
		removedEntries: 0,
		removedBytes: 0,
		keptInUse: 0,
		keptRecentTemp: 0,
		failed: 0
	};

	for (const entry of await listEntries(baseDir)) {
		const entryPath = path.join(baseDir, entry);
		if (options.inUse().has(path.resolve(entryPath))) {
			result.keptInUse++;
			continue;
		}
		if (entry.includes("-tmp-")) {
			try {
				const stat = await fs.promises.lstat(entryPath);
				if (Date.now() - stat.mtimeMs < TEMP_GRACE_MS) {
					result.keptRecentTemp++;
					continue;
				}
			} catch {
				continue; // already gone
			}
		}

		const bytes = await sizeOf(entryPath);
		try {
			if (!options.dryRun) await fs.promises.rm(entryPath, { recursive: true, force: true });
			result.removedEntries++;
			result.removedBytes += bytes;
		} catch {
			result.failed++;
		}
		await new Promise((resolve) => setImmediate(resolve));
	}
	return result;
}

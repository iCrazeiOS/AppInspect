/**
 * Extraction cache management.
 *
 * Stores extracted archive contents in ~/.appinspect/cache/ keyed by
 * MD5(path + size + mtime). Touches mtime on access for LRU-style pruning.
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

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
  extractFn: (destDir: string) => Promise<T>,
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
    try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch { /* best-effort */ }
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

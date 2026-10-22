import { afterEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { clearCache, getCacheInfo } from "../cache";

const tempDirs: string[] = [];

function makeTempDir(): string {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "appinspect-cache-"));
	tempDirs.push(dir);
	return dir;
}

afterEach(() => {
	for (const dir of tempDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

function makeEntry(base: string, name: string, sizes: number[]): string {
	const dir = path.join(base, name, "nested");
	fs.mkdirSync(dir, { recursive: true });
	sizes.forEach((size, i) => {
		fs.writeFileSync(path.join(dir, `f${i}`), Buffer.alloc(size));
	});
	return path.join(base, name);
}

const none = () => new Set<string>();

describe("getCacheInfo", () => {
	it("returns zeros for a missing base without creating it", async () => {
		const base = path.join(makeTempDir(), "missing");
		expect(await getCacheInfo({ baseDir: base })).toEqual({
			path: base,
			entryCount: 0,
			totalBytes: 0
		});
		expect(fs.existsSync(base)).toBe(false);
	});

	it("sums sizes recursively and counts top-level entries", async () => {
		const base = makeTempDir();
		makeEntry(base, "aaa", [100, 50]);
		makeEntry(base, "bbb", [10]);
		const info = await getCacheInfo({ baseDir: base });
		expect(info.entryCount).toBe(2);
		expect(info.totalBytes).toBe(160);
	});
});

describe("clearCache", () => {
	it("returns zeros for a missing base without creating it", async () => {
		const base = path.join(makeTempDir(), "missing");
		const result = await clearCache({ baseDir: base, inUse: none });
		expect(result).toEqual({
			removedEntries: 0,
			removedBytes: 0,
			keptInUse: 0,
			keptRecentTemp: 0,
			failed: 0
		});
		expect(fs.existsSync(base)).toBe(false);
	});

	it("removes entries and reports removed bytes", async () => {
		const base = makeTempDir();
		makeEntry(base, "aaa", [100, 50]);
		makeEntry(base, "bbb", [10]);
		const result = await clearCache({ baseDir: base, inUse: none });
		expect(result.removedEntries).toBe(2);
		expect(result.removedBytes).toBe(160);
		expect(fs.readdirSync(base)).toEqual([]);
	});

	it("keeps in-use entries", async () => {
		const base = makeTempDir();
		const used = makeEntry(base, "aaa", [100]);
		makeEntry(base, "bbb", [10]);
		const result = await clearCache({
			baseDir: base,
			inUse: () => new Set([path.resolve(used)])
		});
		expect(result.keptInUse).toBe(1);
		expect(result.removedEntries).toBe(1);
		expect(fs.readdirSync(base)).toEqual(["aaa"]);
	});

	it("keeps fresh -tmp- entries and removes old ones", async () => {
		const base = makeTempDir();
		makeEntry(base, "aaa-tmp-1", [10]);
		const old = makeEntry(base, "bbb-tmp-2", [10]);
		const hourAgo = new Date(Date.now() - 60 * 60 * 1000);
		fs.utimesSync(old, hourAgo, hourAgo);
		const result = await clearCache({ baseDir: base, inUse: none });
		expect(result.keptRecentTemp).toBe(1);
		expect(result.removedEntries).toBe(1);
		expect(fs.readdirSync(base)).toEqual(["aaa-tmp-1"]);
	});

	it("does not follow symlinks", async () => {
		const base = makeTempDir();
		const outside = makeTempDir();
		fs.writeFileSync(path.join(outside, "keep"), Buffer.alloc(500));
		const entry = makeEntry(base, "aaa", [10]);
		fs.symlinkSync(outside, path.join(entry, "link"));
		const result = await clearCache({ baseDir: base, inUse: none });
		expect(result.removedEntries).toBe(1);
		expect(result.removedBytes).toBeLessThan(500);
		expect(fs.existsSync(path.join(outside, "keep"))).toBe(true);
	});

	it("deletes nothing in dry-run mode", async () => {
		const base = makeTempDir();
		makeEntry(base, "aaa", [100]);
		const result = await clearCache({ baseDir: base, inUse: none, dryRun: true });
		expect(result.removedEntries).toBe(1);
		expect(result.removedBytes).toBe(100);
		expect(fs.readdirSync(base)).toEqual(["aaa"]);
	});
});

import { afterEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { buildFileTree } from "../file-tree";

const tempDirs: string[] = [];
const EARLY = Date.UTC(2020, 0, 1);
const LATE = Date.UTC(2021, 5, 1);

function makeTempDir(): string {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "appinspect-tree-"));
	tempDirs.push(dir);
	return dir;
}

function setMtime(target: string, timestamp: number): void {
	fs.utimesSync(target, new Date(timestamp), new Date(timestamp));
}

afterEach(() => {
	for (const dir of tempDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe("buildFileTree", () => {
	it("totals folder sizes and reports the latest descendant mtime", () => {
		const root = makeTempDir();
		fs.mkdirSync(path.join(root, "Docs"), { recursive: true });
		fs.writeFileSync(path.join(root, "Docs", "a.txt"), Buffer.alloc(10));
		fs.writeFileSync(path.join(root, "Docs", "b.txt"), Buffer.alloc(25));
		fs.writeFileSync(path.join(root, "root.bin"), Buffer.alloc(5));
		setMtime(path.join(root, "Docs", "a.txt"), EARLY);
		setMtime(path.join(root, "Docs", "b.txt"), LATE);
		setMtime(path.join(root, "root.bin"), EARLY);

		const tree = buildFileTree(root);
		const docs = tree.find((entry) => entry.name === "Docs");
		const file = tree.find((entry) => entry.name === "root.bin");

		expect(docs?.size).toBe(35);
		expect(Math.round((docs?.mtimeMs ?? 0) / 1000)).toBe(LATE / 1000);
		expect(file?.size).toBe(5);
		expect(Math.round((file?.mtimeMs ?? 0) / 1000)).toBe(EARLY / 1000);
	});

	it("falls back to the folder's own mtime when it is empty", () => {
		const root = makeTempDir();
		const empty = path.join(root, "Empty");
		fs.mkdirSync(empty);
		setMtime(empty, EARLY);

		const tree = buildFileTree(root);
		expect(tree[0]?.name).toBe("Empty");
		expect(tree[0]?.size).toBe(0);
		expect(Math.round((tree[0]?.mtimeMs ?? 0) / 1000)).toBe(EARLY / 1000);
	});
});

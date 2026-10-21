import { afterEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { isInside, removeEscapingSymlinks, safeJoin } from "../safe-path";

/**
 * Create a temp dir under the *resolved* OS temp dir. On macOS `os.tmpdir()` is
 * `/var/folders/...`, which is a symlink to `/private/var/folders/...`; anchoring
 * tests to the real path keeps `removeEscapingSymlinks`'s resolve-vs-realpath
 * comparison meaningful.
 */
function makeTempDir(prefix: string): string {
	return fs.mkdtempSync(
		path.join(fs.realpathSync(os.tmpdir()), `appinspect-safe-path-${prefix}-`)
	);
}

const tempDirs: string[] = [];

afterEach(() => {
	for (const dir of tempDirs) {
		try {
			fs.rmSync(dir, { recursive: true, force: true });
		} catch {
			// Best-effort cleanup
		}
	}
	tempDirs.length = 0;
});

describe("safeJoin", () => {
	it("rejects parent-directory traversal", () => {
		expect(safeJoin("/base/dir", "../x")).toBeNull();
	});

	it("rejects absolute paths", () => {
		expect(safeJoin("/base/dir", "/etc/passwd")).toBeNull();
	});

	it("rejects traversal buried in the middle of the name", () => {
		expect(safeJoin("/base/dir", "a/../../b")).toBeNull();
	});

	it("accepts a flat member name", () => {
		expect(safeJoin("/base/dir", "data.tar.xz")).toBe(path.resolve("/base/dir", "data.tar.xz"));
	});
});

describe("isInside", () => {
	it("accepts a child path", () => {
		expect(isInside("/foo", "/foo/bar")).toBe(true);
	});

	it("accepts the root itself", () => {
		expect(isInside("/foo", "/foo")).toBe(true);
	});

	it("rejects a sibling sharing a name prefix", () => {
		expect(isInside("/foo", "/foo-bar")).toBe(false);
	});
});

describe("removeEscapingSymlinks", () => {
	it("keeps an in-tree symlink and removes nothing", () => {
		if (process.platform === "win32") return;

		const root = makeTempDir("intree");
		tempDirs.push(root);

		fs.writeFileSync(path.join(root, "real.txt"), "hello");
		fs.symlinkSync("real.txt", path.join(root, "link.txt"));

		expect(removeEscapingSymlinks(root)).toBe(0);
		expect(fs.existsSync(path.join(root, "link.txt"))).toBe(true);
	});

	it("removes a symlink pointing outside the root", () => {
		if (process.platform === "win32") return;

		const parent = makeTempDir("escape");
		tempDirs.push(parent);
		const root = path.join(parent, "root");
		fs.mkdirSync(root, { recursive: true });

		fs.writeFileSync(path.join(parent, "outside.txt"), "secret");
		fs.symlinkSync(path.join(parent, "outside.txt"), path.join(root, "escape.txt"));

		expect(removeEscapingSymlinks(root)).toBe(1);
		expect(fs.existsSync(path.join(root, "escape.txt"))).toBe(false);
		expect(fs.existsSync(path.join(parent, "outside.txt"))).toBe(true);
	});

	it("removes a broken symlink", () => {
		if (process.platform === "win32") return;

		const root = makeTempDir("dangling");
		tempDirs.push(root);

		fs.symlinkSync("does-not-exist.txt", path.join(root, "dangling.txt"));

		expect(removeEscapingSymlinks(root)).toBe(1);
		// Must use lstat: existsSync would report false for a still-present
		// dangling link because it follows the (broken) target.
		const stat = fs.lstatSync(path.join(root, "dangling.txt"), { throwIfNoEntry: false });
		expect(stat?.isSymbolicLink() ?? false).toBe(false);
	});

	it("checks inside symlinked directories and removes nothing valid", () => {
		if (process.platform === "win32") return;

		const root = makeTempDir("symdir");
		tempDirs.push(root);

		fs.mkdirSync(path.join(root, "Payload"));
		fs.writeFileSync(path.join(root, "Payload", "real.txt"), "x");
		fs.symlinkSync("Payload", path.join(root, "payload-link"));

		expect(removeEscapingSymlinks(root)).toBe(0);
		expect(fs.existsSync(path.join(root, "Payload", "real.txt"))).toBe(true);
	});

	it("returns 0 for an empty tree", () => {
		const root = makeTempDir("empty");
		tempDirs.push(root);

		expect(removeEscapingSymlinks(root)).toBe(0);
	});
});

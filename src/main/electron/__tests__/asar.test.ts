import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { createHash } from "node:crypto";
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	statSync,
	symlinkSync,
	writeFileSync
} from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";

import { type AsarArchive, extractAsarArchive, readAsarFile, readAsarHeader } from "../asar";

// ── Fixtures ───────────────────────────────────────────────────────────

let TMP_DIR = "";

beforeAll(() => {
	TMP_DIR = mkdtempSync(path.join(tmpdir(), "appinspect-asar-"));
});
afterAll(() => {
	rmSync(TMP_DIR, { recursive: true, force: true });
});

interface FixtureFile {
	data?: string | Buffer;
	unpacked?: boolean;
	executable?: boolean;
	link?: string;
	/** Write the computed offset as a decimal string (newer archives). */
	stringOffset?: boolean;
	/** Force the offset written to the header, without appending data. */
	offsetOverride?: number | string;
	/** Force the size written to the header. */
	sizeOverride?: number;
}

interface FixtureDir {
	files: FixtureTree;
}

type FixtureTree = Record<string, FixtureFile | FixtureDir>;

function align4(value: number): number {
	return (value + 3) & ~3;
}

function packAsar(json: string, data: Buffer): Buffer {
	const jsonBytes = Buffer.from(json);
	const headerSize = 8 + align4(jsonBytes.length);
	const buffer = Buffer.alloc(8 + headerSize + data.length);
	buffer.writeUInt32LE(4, 0);
	buffer.writeUInt32LE(headerSize, 4);
	buffer.writeUInt32LE(jsonBytes.length + 4, 8);
	buffer.writeUInt32LE(jsonBytes.length, 12);
	jsonBytes.copy(buffer, 16);
	data.copy(buffer, 8 + headerSize);
	return buffer;
}

function buildJson(
	tree: FixtureTree,
	state: { offset: number; chunks: Buffer[] }
): Record<string, unknown> {
	const result: Record<string, unknown> = {};
	for (const [name, item] of Object.entries(tree)) {
		if ("files" in item) {
			result[name] = { files: buildJson(item.files, state) };
			continue;
		}
		if (item.link !== undefined) {
			result[name] = { link: item.link };
			continue;
		}

		const data = Buffer.isBuffer(item.data) ? item.data : Buffer.from(item.data ?? "");
		const node: Record<string, unknown> = {};
		if (item.unpacked) {
			node.unpacked = true;
		} else {
			const offset = item.offsetOverride ?? state.offset;
			node.offset = item.stringOffset && typeof offset === "number" ? String(offset) : offset;
			if (item.offsetOverride === undefined) {
				state.chunks.push(data);
				state.offset += data.length;
			}
		}
		node.size = item.sizeOverride ?? data.length;
		if (item.executable) node.executable = true;
		result[name] = node;
	}
	return result;
}

function makeAsar(tree: FixtureTree): Buffer {
	const state = { offset: 0, chunks: [] as Buffer[] };
	const json = JSON.stringify({ files: buildJson(tree, state) });
	return packAsar(json, Buffer.concat(state.chunks));
}

function writeFixture(name: string, tree: FixtureTree): string {
	const filePath = path.join(TMP_DIR, name);
	writeFileSync(filePath, makeAsar(tree));
	return filePath;
}

function writeRaw(name: string, buffer: Buffer): string {
	const filePath = path.join(TMP_DIR, name);
	writeFileSync(filePath, buffer);
	return filePath;
}

function parse(filePath: string): AsarArchive {
	const result = readAsarHeader(filePath);
	if (!result.ok) throw new Error(result.error);
	return result.data;
}

function read(archive: AsarArchive, filePath: string, maxBytes = 1024 * 1024): Buffer {
	const result = readAsarFile(archive, filePath, maxBytes);
	if (!result.ok) throw new Error(result.error);
	return result.data.data;
}

// ── Tests ──────────────────────────────────────────────────────────────

describe("readAsarHeader", () => {
	it("parses nested entries and sorts directories first", () => {
		const archive = parse(
			writeFixture("nested.asar", {
				"index.js": { data: "console.log(1)" },
				assets: { files: { "logo.png": { data: Buffer.from([1, 2, 3]) } } },
				"package.json": { data: '{"name":"demo"}' }
			})
		);

		expect(archive.fileCount).toBe(3);
		expect(archive.unpackedCount).toBe(0);
		expect(archive.entries.map((entry) => entry.name)).toEqual([
			"assets",
			"index.js",
			"package.json"
		]);

		const assets = archive.entries[0];
		expect(assets?.isDirectory).toBe(true);
		expect(assets?.size).toBe(3);
		expect(assets?.children?.[0]?.path).toBe("assets/logo.png");
		expect(archive.files.get("assets/logo.png")?.size).toBe(3);
	});

	it("reads packed file data by offset", () => {
		const archive = parse(
			writeFixture("packed.asar", {
				"a.txt": { data: "alpha" },
				dir: { files: { "b.txt": { data: "beta" } } }
			})
		);

		expect(read(archive, "a.txt").toString()).toBe("alpha");
		expect(read(archive, "dir/b.txt").toString()).toBe("beta");
	});

	it("accepts decimal-string offsets", () => {
		const archive = parse(
			writeFixture("string-offset.asar", {
				dir: { files: { "a.txt": { data: "string offset", stringOffset: true } } }
			})
		);

		expect(read(archive, "dir/a.txt").toString()).toBe("string offset");
	});

	it("records executable and unpacked flags", () => {
		const archive = parse(
			writeFixture("flags.asar", {
				"run.sh": { data: "#!/bin/sh", executable: true },
				"native.node": { unpacked: true, data: "ignored" }
			})
		);

		expect(archive.files.get("run.sh")?.executable).toBe(true);
		expect(archive.entries.find((entry) => entry.name === "run.sh")?.executable).toBe(true);
		expect(archive.files.get("native.node")?.unpacked).toBe(true);
		expect(archive.unpackedCount).toBe(1);
	});

	it("hashes only the header JSON bytes", () => {
		const first = makeAsar({ "a.txt": { data: "aaaa" } });
		const second = makeAsar({ "a.txt": { data: "bbbb" } });
		const firstHash = parse(writeRaw("hash-a.asar", first)).headerHash;
		const secondHash = parse(writeRaw("hash-b.asar", second)).headerHash;

		expect(firstHash).toBe(secondHash);

		const jsonLength = first.readUInt32LE(12);
		const json = first.subarray(16, 16 + jsonLength);
		expect(firstHash).toBe(createHash("sha256").update(json).digest("hex"));
	});

	it("accepts an empty archive", () => {
		const archive = parse(writeFixture("empty.asar", {}));
		expect(archive.fileCount).toBe(0);
		expect(archive.entries).toEqual([]);
	});

	it("restores Electron's noAsar flag after a read", () => {
		const archive = parse(writeFixture("no-asar-flag.asar", { "a.txt": { data: "a" } }));
		const proc = process as unknown as { noAsar: boolean };
		proc.noAsar = true;
		read(archive, "a.txt");
		expect(proc.noAsar).toBe(true);
		proc.noAsar = false;
	});
});

describe("readAsarFile", () => {
	it("truncates at maxBytes", () => {
		const archive = parse(writeFixture("truncate.asar", { "a.txt": { data: "abcdefghij" } }));
		const result = readAsarFile(archive, "a.txt", 4);
		if (!result.ok) throw new Error(result.error);

		expect(result.data.data.toString()).toBe("abcd");
		expect(result.data.truncated).toBe(true);
		expect(read(archive, "a.txt").toString()).toBe("abcdefghij");
	});

	it("resolves relative and parent-relative links", () => {
		const archive = parse(
			writeFixture("links.asar", {
				a: {
					files: {
						"target.txt": { data: "target" },
						"alias.txt": { link: "target.txt" }
					}
				},
				"root-alias.txt": { link: "a/target.txt" }
			})
		);

		expect(read(archive, "a/alias.txt").toString()).toBe("target");
		expect(read(archive, "root-alias.txt").toString()).toBe("target");
		expect(archive.entries.find((entry) => entry.name === "root-alias.txt")?.link).toBe(
			"a/target.txt"
		);
	});

	it("rejects link cycles", () => {
		const archive = parse(
			writeFixture("cycle.asar", {
				"x.txt": { link: "y.txt" },
				"y.txt": { link: "x.txt" }
			})
		);

		expect(readAsarFile(archive, "x.txt", 1024).ok).toBe(false);
	});

	it("follows at most eight link hops", () => {
		const okTree: FixtureTree = { "end.txt": { data: "end" } };
		for (let i = 8; i >= 1; i--) {
			okTree[`l${i}.txt`] = { link: i === 8 ? "end.txt" : `l${i + 1}.txt` };
		}
		const okArchive = parse(writeFixture("hops-ok.asar", okTree));
		expect(read(okArchive, "l1.txt").toString()).toBe("end");

		const badTree: FixtureTree = { "end.txt": { data: "end" } };
		for (let i = 9; i >= 1; i--) {
			badTree[`l${i}.txt`] = { link: i === 9 ? "end.txt" : `l${i + 1}.txt` };
		}
		const badArchive = parse(writeFixture("hops-bad.asar", badTree));
		expect(readAsarFile(badArchive, "l1.txt", 1024).ok).toBe(false);
	});

	it("rejects links that escape the archive", () => {
		const archive = parse(
			writeFixture("escaping-links.asar", {
				"up.txt": { link: "../../etc/passwd" },
				"absolute.txt": { link: "/etc/passwd" }
			})
		);

		expect(readAsarFile(archive, "up.txt", 1024).ok).toBe(false);
		expect(readAsarFile(archive, "absolute.txt", 1024).ok).toBe(false);
	});

	it("reads unpacked files from the sibling directory", () => {
		const archivePath = writeFixture("unpacked.asar", {
			"native.node": { unpacked: true, data: "" }
		});
		const unpackedDir = `${archivePath}.unpacked`;
		mkdirSync(unpackedDir);
		writeFileSync(path.join(unpackedDir, "native.node"), "real content");

		const archive = parse(archivePath);
		expect(read(archive, "native.node").toString()).toBe("real content");

		const truncated = readAsarFile(archive, "native.node", 4);
		if (!truncated.ok) throw new Error(truncated.error);
		expect(truncated.data.data.toString()).toBe("real");
		expect(truncated.data.truncated).toBe(true);
	});

	it("returns an error when the unpacked directory is missing", () => {
		const archive = parse(
			writeFixture("missing-unpacked.asar", { "native.node": { unpacked: true, data: "" } })
		);
		expect(readAsarFile(archive, "native.node", 1024).ok).toBe(false);
	});

	it.skipIf(process.platform === "win32")("rejects unpacked symlinks that escape", () => {
		const archivePath = writeFixture("escaping-unpacked.asar", {
			"evil.txt": { unpacked: true, data: "" }
		});
		const unpackedDir = `${archivePath}.unpacked`;
		mkdirSync(unpackedDir);
		const outside = path.join(TMP_DIR, "outside.txt");
		writeFileSync(outside, "secret");
		symlinkSync(outside, path.join(unpackedDir, "evil.txt"));

		expect(readAsarFile(parse(archivePath), "evil.txt", 1024).ok).toBe(false);
	});

	it("returns an error for unknown entries", () => {
		const archive = parse(writeFixture("unknown.asar", { "a.txt": { data: "a" } }));
		expect(readAsarFile(archive, "missing.txt", 1024).ok).toBe(false);
	});
});

describe("extractAsarArchive", () => {
	function outputDir(name: string): string {
		return mkdtempSync(path.join(TMP_DIR, `${name}-`));
	}

	it("extracts packed files and nested directories", () => {
		const archive = parse(
			writeFixture("extract-packed.asar", {
				"index.js": { data: "main" },
				assets: { files: { "logo.txt": { data: "png data" } } }
			})
		);

		const out = outputDir("extract-packed");
		const result = extractAsarArchive(archive, out);
		if (!result.ok) throw new Error(result.error);

		expect(result.data).toEqual({ files: 2, bytes: 12, skipped: 0 });
		expect(readFileSync(path.join(out, "index.js"), "utf8")).toBe("main");
		expect(readFileSync(path.join(out, "assets", "logo.txt"), "utf8")).toBe("png data");
	});

	it("copies unpacked files from the sibling directory", () => {
		const archivePath = writeFixture("extract-unpacked.asar", {
			build: { files: { "native.node": { unpacked: true, data: "" } } }
		});
		const unpackedDir = path.join(`${archivePath}.unpacked`, "build");
		mkdirSync(unpackedDir, { recursive: true });
		writeFileSync(path.join(unpackedDir, "native.node"), "native");

		const out = outputDir("extract-unpacked");
		const result = extractAsarArchive(parse(archivePath), out);
		if (!result.ok) throw new Error(result.error);

		expect(result.data.skipped).toBe(0);
		expect(readFileSync(path.join(out, "build", "native.node"), "utf8")).toBe("native");
	});

	it("writes links as regular files with their target's data", () => {
		const archive = parse(
			writeFixture("extract-links.asar", {
				a: {
					files: {
						"target.txt": { data: "target" },
						"alias.txt": { link: "target.txt" }
					}
				}
			})
		);

		const out = outputDir("extract-links");
		const result = extractAsarArchive(archive, out);
		if (!result.ok) throw new Error(result.error);

		expect(result.data).toEqual({ files: 2, bytes: 12, skipped: 0 });
		expect(readFileSync(path.join(out, "a", "alias.txt"), "utf8")).toBe("target");
		expect(statSync(path.join(out, "a", "alias.txt")).isFile()).toBe(true);
	});

	it("counts escaping links as skipped without writing them", () => {
		const archive = parse(
			writeFixture("extract-escape.asar", {
				"up.txt": { link: "../../etc/passwd" },
				"ok.txt": { data: "ok" }
			})
		);

		const out = outputDir("extract-escape");
		const result = extractAsarArchive(archive, out);
		if (!result.ok) throw new Error(result.error);

		expect(result.data).toMatchObject({ files: 1, skipped: 1 });
		expect(existsSync(path.join(out, "up.txt"))).toBe(false);
		expect(readFileSync(path.join(out, "ok.txt"), "utf8")).toBe("ok");
	});

	it.skipIf(process.platform === "win32")("marks executable entries executable", () => {
		const archive = parse(
			writeFixture("extract-exec.asar", {
				"run.sh": { data: "#!/bin/sh", executable: true },
				"readme.txt": { data: "hi" }
			})
		);

		const out = outputDir("extract-exec");
		const result = extractAsarArchive(archive, out);
		if (!result.ok) throw new Error(result.error);

		expect(statSync(path.join(out, "run.sh")).mode & 0o111).not.toBe(0);
		expect(statSync(path.join(out, "readme.txt")).mode & 0o111).toBe(0);
	});

	it("returns an error when the output directory cannot be created", () => {
		const archive = parse(writeFixture("extract-bad-output.asar", { "a.txt": { data: "a" } }));
		const blocker = path.join(TMP_DIR, "extract-output-blocker");
		writeFileSync(blocker, "not a directory");

		const result = extractAsarArchive(archive, path.join(blocker, "nested"));
		expect(result.ok).toBe(false);
	});
});

describe("readAsarHeader validation", () => {
	it("rejects missing and short files", () => {
		expect(readAsarHeader(path.join(TMP_DIR, "does-not-exist.asar")).ok).toBe(false);
		expect(readAsarHeader(writeRaw("short.asar", Buffer.alloc(10))).ok).toBe(false);
	});

	it("rejects an invalid header size", () => {
		const badPickle = makeAsar({ "a.txt": { data: "a" } });
		badPickle.writeUInt32LE(5, 0);
		expect(readAsarHeader(writeRaw("pickle-header.asar", badPickle)).ok).toBe(false);

		const below = makeAsar({ "a.txt": { data: "a" } });
		below.writeUInt32LE(0, 4);
		expect(readAsarHeader(writeRaw("header-small.asar", below)).ok).toBe(false);

		const above = makeAsar({ "a.txt": { data: "a" } });
		above.writeUInt32LE(64 * 1024 * 1024 + 1, 4);
		expect(readAsarHeader(writeRaw("header-large.asar", above)).ok).toBe(false);
	});

	it("rejects a header that extends beyond EOF", () => {
		const buffer = makeAsar({ "a.txt": { data: "a" } });
		buffer.writeUInt32LE(0x10000, 4);
		expect(readAsarHeader(writeRaw("header-eof.asar", buffer)).ok).toBe(false);
	});

	it("rejects a JSON length beyond the header", () => {
		const buffer = makeAsar({ "a.txt": { data: "a" } });
		buffer.writeUInt32LE(0x10000, 12);
		expect(readAsarHeader(writeRaw("json-length.asar", buffer)).ok).toBe(false);
	});

	it("rejects invalid JSON and non-object roots", () => {
		expect(
			readAsarHeader(writeRaw("bad-json.asar", packAsar("{not json", Buffer.alloc(0)))).ok
		).toBe(false);
		expect(
			readAsarHeader(writeRaw("array-root.asar", packAsar("[]", Buffer.alloc(0)))).ok
		).toBe(false);
		expect(
			readAsarHeader(writeRaw("array-files.asar", packAsar('{"files":[]}', Buffer.alloc(0))))
				.ok
		).toBe(false);
	});

	it("rejects packed entries beyond the data region", () => {
		const archive = writeFixture("out-of-bounds.asar", {
			"a.txt": { data: "abc", sizeOverride: 100 }
		});
		expect(readAsarHeader(archive).ok).toBe(false);
	});

	it("rejects negative and unsafe offsets", () => {
		const negative = writeFixture("negative-offset.asar", {
			"a.txt": { data: "abc", offsetOverride: -1 }
		});
		expect(readAsarHeader(negative).ok).toBe(false);

		const unsafe = writeFixture("unsafe-offset.asar", {
			"a.txt": { data: "abc", offsetOverride: "9007199254740993" }
		});
		expect(readAsarHeader(unsafe).ok).toBe(false);
	});

	it("rejects traversal and special characters in names", () => {
		for (const name of [".", "..", "a/b", "a\\b", "a:b", "a\0b", ""]) {
			const json = JSON.stringify({ files: { [name]: { size: 0, offset: 0 } } });
			const buffer = packAsar(json, Buffer.alloc(0));
			expect(readAsarHeader(writeRaw("name.asar", buffer)).ok).toBe(false);
		}
	});

	it("rejects over-long entry names", () => {
		const name = "a".repeat(4097);
		const json = JSON.stringify({ files: { [name]: { size: 0, offset: 0 } } });
		expect(readAsarHeader(writeRaw("long-name.asar", packAsar(json, Buffer.alloc(0)))).ok).toBe(
			false
		);
	});

	it("rejects directory nesting beyond 64 levels", () => {
		let tree: FixtureTree = { "leaf.txt": { data: "x" } };
		for (let i = 0; i < 65; i++) {
			tree = { [`d${i}`]: { files: tree } };
		}
		expect(readAsarHeader(writeFixture("deep.asar", tree)).ok).toBe(false);
	});
});

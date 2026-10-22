import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";

import type { ElectronInfo, SecurityFinding } from "../../../shared/types";
import { type AsarArchive, readAsarHeader } from "../asar";
import { readAsarTextFiles, scanElectron } from "../scan";

// ── Fixtures ───────────────────────────────────────────────────────────

let TMP_DIR = "";

beforeAll(() => {
	TMP_DIR = mkdtempSync(path.join(tmpdir(), "appinspect-electron-scan-"));
});
afterAll(() => {
	rmSync(TMP_DIR, { recursive: true, force: true });
});

interface FixtureFile {
	data?: string | Buffer;
	unpacked?: boolean;
}

interface FixtureDir {
	files: FixtureTree;
}

type FixtureTree = Record<string, FixtureFile | FixtureDir>;

function align4(value: number): number {
	return (value + 3) & ~3;
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
		const data = Buffer.isBuffer(item.data) ? item.data : Buffer.from(item.data ?? "");
		const node: Record<string, unknown> = { size: data.length };
		if (item.unpacked) {
			node.unpacked = true;
		} else {
			node.offset = state.offset;
			state.chunks.push(data);
			state.offset += data.length;
		}
		result[name] = node;
	}
	return result;
}

function makeAsar(tree: FixtureTree): Buffer {
	const state = { offset: 0, chunks: [] as Buffer[] };
	const jsonBytes = Buffer.from(JSON.stringify({ files: buildJson(tree, state) }));
	const data = Buffer.concat(state.chunks);
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

function writeFixture(name: string, tree: FixtureTree): string {
	const filePath = path.join(TMP_DIR, name);
	writeFileSync(filePath, makeAsar(tree));
	return filePath;
}

function parse(filePath: string): AsarArchive {
	const result = readAsarHeader(filePath);
	if (!result.ok) throw new Error(result.error);
	return result.data;
}

/** Read without touching the user's bundle size settings. */
const LIMITS = { maxFileSize: 10 * 1024 * 1024, maxBundleSize: 10 * 1024 * 1024 };

function makeInfo(overrides: Partial<ElectronInfo> = {}): ElectronInfo {
	return {
		fileCount: 0,
		unpackedCount: 0,
		fuses: [],
		sourceMaps: [],
		nativeAddons: [],
		...overrides
	};
}

function summary(finding: SecurityFinding): [string, string, string] {
	return [finding.severity, finding.category, finding.evidence ?? ""];
}

// ── readAsarTextFiles ──────────────────────────────────────────────────

describe("readAsarTextFiles", () => {
	it("reads scannable text files with an app.asar/ prefix and skips the rest", () => {
		const filePath = writeFixture("text.asar", {
			"index.js": { data: "console.log(1)" },
			config: { files: { "settings.json": { data: '{"a":1}' } } },
			"app.js.map": { data: '{"version":3}' },
			"logo.png": { data: Buffer.from([1, 2, 3]) },
			"binary.js": { data: Buffer.from([0x00, 0x01, 0x02]) },
			"empty.txt": { data: "" }
		});

		const files = readAsarTextFiles(parse(filePath), LIMITS);
		expect(files).toEqual([
			{ relativePath: "app.asar/index.js", content: "console.log(1)" },
			{ relativePath: "app.asar/config/settings.json", content: '{"a":1}' }
		]);
	});

	it("skips files over the per-file limit", () => {
		const filePath = writeFixture("single-limit.asar", {
			"small.js": { data: "small" },
			"big.js": { data: "x".repeat(1000) }
		});

		const files = readAsarTextFiles(parse(filePath), {
			maxFileSize: 500,
			maxBundleSize: 1024 * 1024
		});
		expect(files.map((f) => f.relativePath)).toEqual(["app.asar/small.js"]);
	});

	it("stops once the bundle size budget is reached", () => {
		const filePath = writeFixture("bundle-limit.asar", {
			"a.js": { data: "a".repeat(300) },
			"b.js": { data: "b".repeat(300) },
			"c.js": { data: "c".repeat(300) }
		});

		const files = readAsarTextFiles(parse(filePath), {
			maxFileSize: 1024 * 1024,
			maxBundleSize: 500
		});
		expect(files.map((f) => f.relativePath)).toEqual(["app.asar/a.js", "app.asar/b.js"]);
	});

	it("skips unpacked files, which are scanned from disk", () => {
		const filePath = writeFixture("unpacked.asar", {
			"unpacked.js": { data: "console.log(2)", unpacked: true }
		});
		const unpackedDir = `${filePath}.unpacked`;
		mkdirSync(unpackedDir, { recursive: true });
		writeFileSync(path.join(unpackedDir, "unpacked.js"), "console.log(2)");

		expect(readAsarTextFiles(parse(filePath), LIMITS)).toEqual([]);
	});
});

// ── scanElectron ───────────────────────────────────────────────────────

describe("scanElectron fuses", () => {
	it("reports risky enabled fuses and disabled load restrictions", () => {
		const info = makeInfo({
			fuses: [
				{ name: "RunAsNode", state: "enabled" },
				{ name: "EnableNodeOptionsEnvironmentVariable", state: "enabled" },
				{ name: "EnableNodeCliInspectArguments", state: "enabled" },
				{ name: "OnlyLoadAppFromAsar", state: "disabled" },
				{ name: "EnableEmbeddedAsarIntegrityValidation", state: "disabled" }
			]
		});

		expect(scanElectron(info, []).map(summary)).toEqual([
			["warning", "Electron", "RunAsNode=enabled"],
			["warning", "Electron", "EnableNodeOptionsEnvironmentVariable=enabled"],
			["warning", "Electron", "EnableNodeCliInspectArguments=enabled"],
			["info", "Electron", "OnlyLoadAppFromAsar=disabled"],
			["info", "Electron", "EnableEmbeddedAsarIntegrityValidation=disabled"]
		]);
	});

	it("stays quiet when the hardening fuses are enabled or removed", () => {
		const info = makeInfo({
			fuses: [
				{ name: "RunAsNode", state: "disabled" },
				{ name: "EnableNodeOptionsEnvironmentVariable", state: "removed" },
				{ name: "EnableNodeCliInspectArguments", state: "disabled" },
				{ name: "OnlyLoadAppFromAsar", state: "enabled" },
				{ name: "EnableEmbeddedAsarIntegrityValidation", state: "enabled" }
			]
		});
		expect(scanElectron(info, [])).toEqual([]);
	});
});

describe("scanElectron integrity and source maps", () => {
	it("reports an integrity mismatch with the expected and actual hashes", () => {
		const info = makeInfo({
			integrity: {
				algorithm: "SHA256",
				expected: "aa".repeat(32),
				actual: "bb".repeat(32),
				valid: false
			}
		});

		const [finding] = scanElectron(info, []);
		expect(finding?.severity).toBe("critical");
		expect(finding?.category).toBe("Electron");
		expect(finding?.source).toBe("app.asar");
		expect(finding?.evidence).toBe(`expected ${"aa".repeat(32)}, actual ${"bb".repeat(32)}`);
	});

	it("does not report a valid integrity hash", () => {
		const hash = "cc".repeat(32);
		const info = makeInfo({
			integrity: { algorithm: "SHA256", expected: hash, actual: hash, valid: true }
		});
		expect(scanElectron(info, [])).toEqual([]);
	});

	it("lists up to three shipped source maps", () => {
		const info = makeInfo({
			sourceMaps: ["dist/a.js.map", "dist/b.js.map", "dist/c.js.map", "dist/d.js.map"]
		});

		const [finding] = scanElectron(info, []);
		expect(finding?.severity).toBe("info");
		expect(finding?.message).toContain("4");
		expect(finding?.evidence).toBe("dist/a.js.map, dist/b.js.map, dist/c.js.map");
	});
});

describe("scanElectron webPreferences", () => {
	it("flags each weak webPreferences setting in archive text", () => {
		const filePath = writeFixture("prefs.asar", {
			"node.js": { data: "new BrowserWindow({ webPreferences: { nodeIntegration: true } })" },
			"context.js": { data: 'webPreferences: { "contextIsolation": false }' },
			"security.js": { data: "webPreferences: { webSecurity: false }" },
			"insecure.js": { data: "allowRunningInsecureContent: true" },
			"sandbox.js": { data: "sandbox: false" },
			"webview.js": { data: "'webviewTag': true" }
		});
		const files = readAsarTextFiles(parse(filePath), LIMITS);

		const bySource = new Map(scanElectron(makeInfo(), files).map((f) => [f.source, f]));
		expect([...bySource.keys()].sort()).toEqual([
			"app.asar/context.js",
			"app.asar/insecure.js",
			"app.asar/node.js",
			"app.asar/sandbox.js",
			"app.asar/security.js",
			"app.asar/webview.js"
		]);
		expect(bySource.get("app.asar/node.js")?.severity).toBe("warning");
		expect(bySource.get("app.asar/node.js")?.evidence).toBe("nodeIntegration: true");
		expect(bySource.get("app.asar/context.js")?.severity).toBe("warning");
		expect(bySource.get("app.asar/security.js")?.severity).toBe("warning");
		expect(bySource.get("app.asar/insecure.js")?.severity).toBe("warning");
		expect(bySource.get("app.asar/sandbox.js")?.severity).toBe("info");
		expect(bySource.get("app.asar/webview.js")?.severity).toBe("info");
	});

	it("dedupes repeated matches in one file and caps findings per category", () => {
		const tree: FixtureTree = {};
		for (let i = 0; i < 25; i++) {
			tree[`renderer-${i}.js`] = {
				data: `a(); b(); webPreferences: { nodeIntegration: true }`
			};
		}
		const files = readAsarTextFiles(parse(writeFixture("cap.asar", tree)), LIMITS);
		expect(scanElectron(makeInfo(), files)).toHaveLength(20);
	});

	it("reports a file once even when the same setting appears twice", () => {
		const files = [
			{
				relativePath: "app.asar/index.js",
				content: "nodeIntegration: true; nodeIntegration: true"
			}
		];
		expect(scanElectron(makeInfo(), files)).toHaveLength(1);
	});
});

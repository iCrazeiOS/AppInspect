import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";

import type { ElectronInfo, SecurityFinding } from "../../../shared/types";
import { type AsarArchive, readAsarHeader } from "../asar";
import {
	isElectronVersionSupported,
	MIN_SUPPORTED_ELECTRON_MAJOR,
	parseElectronMajor,
	readAsarTextFiles,
	readAsarUnpackedHtmlFiles,
	scanElectron,
	scanElectronMetadata
} from "../scan";

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

function scanText(content: string, relativePath = "app.asar/main.js"): SecurityFinding[] {
	return scanElectron(makeInfo(), [{ relativePath, content }]);
}

function scanCsp(content: string, relativePath = "app.asar/index.html"): SecurityFinding[] {
	return scanElectron(makeInfo(), [{ relativePath, content }]).filter(
		(finding) => finding.category === "electron-csp"
	);
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
	it("reads .mjs and .cjs files", () => {
		const filePath = writeFixture("esm.asar", {
			"main.mjs": { data: "export default 1" },
			"preload.cjs": { data: "require('electron')" }
		});

		const files = readAsarTextFiles(parse(filePath), LIMITS);
		expect(files.map((f) => f.relativePath)).toEqual([
			"app.asar/main.mjs",
			"app.asar/preload.cjs"
		]);
	});
	it("reads key material files but not certificates or PKCS#12 stores", () => {
		const pem = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----";
		const filePath = writeFixture("keys.asar", {
			certs: {
				files: {
					"server.pem": { data: pem },
					"server.cer": { data: "-----BEGIN CERTIFICATE-----" }
				}
			},
			keys: {
				files: {
					"server.key": { data: pem },
					"AuthKey_ABC123.p8": { data: pem },
					"store.p12": { data: Buffer.from([0x00, 0x01, 0x02, 0x03]) }
				}
			}
		});

		const files = readAsarTextFiles(parse(filePath), LIMITS);
		expect(files.map((f) => f.relativePath)).toEqual([
			"app.asar/certs/server.pem",
			"app.asar/keys/server.key",
			"app.asar/keys/AuthKey_ABC123.p8"
		]);
	});
});

describe("scanElectron fuses", () => {
	it("reports risky enabled fuses and disabled or removed hardening fuses", () => {
		const info = makeInfo({
			fuses: [
				{ name: "RunAsNode", state: "enabled" },
				{ name: "EnableCookieEncryption", state: "disabled" },
				{ name: "EnableNodeOptionsEnvironmentVariable", state: "enabled" },
				{ name: "EnableNodeCliInspectArguments", state: "enabled" },
				{ name: "OnlyLoadAppFromAsar", state: "disabled" },
				{ name: "EnableEmbeddedAsarIntegrityValidation", state: "disabled" },
				{ name: "GrantFileProtocolExtraPrivileges", state: "enabled" }
			]
		});

		expect(scanElectron(info, []).map(summary)).toEqual([
			["warning", "electron-fuses", "RunAsNode=enabled"],
			["info", "electron-fuses", "EnableCookieEncryption=disabled"],
			["warning", "electron-fuses", "EnableNodeOptionsEnvironmentVariable=enabled"],
			["warning", "electron-fuses", "EnableNodeCliInspectArguments=enabled"],
			["info", "electron-fuses", "OnlyLoadAppFromAsar=disabled"],
			["info", "electron-fuses", "EnableEmbeddedAsarIntegrityValidation=disabled"],
			["warning", "electron-fuses", "GrantFileProtocolExtraPrivileges=enabled"]
		]);
	});

	it("reports removed hardening fuses as weak", () => {
		const info = makeInfo({
			fuses: [
				{ name: "OnlyLoadAppFromAsar", state: "removed" },
				{ name: "EnableEmbeddedAsarIntegrityValidation", state: "removed" }
			]
		});

		expect(scanElectron(info, []).map(summary)).toEqual([
			["info", "electron-fuses", "OnlyLoadAppFromAsar=removed"],
			["info", "electron-fuses", "EnableEmbeddedAsarIntegrityValidation=removed"]
		]);
	});

	it("stays quiet for removed permissive fuses but reports removed cookie encryption", () => {
		const info = makeInfo({
			fuses: [
				{ name: "RunAsNode", state: "removed" },
				{ name: "EnableNodeOptionsEnvironmentVariable", state: "removed" },
				{ name: "EnableNodeCliInspectArguments", state: "removed" },
				{ name: "GrantFileProtocolExtraPrivileges", state: "removed" }
			]
		});
		expect(scanElectron(info, [])).toEqual([]);

		const cookie = makeInfo({ fuses: [{ name: "EnableCookieEncryption", state: "removed" }] });
		expect(scanElectron(cookie, []).map(summary)).toEqual([
			["info", "electron-fuses", "EnableCookieEncryption=removed"]
		]);
	});

	it("stays quiet when the fuses are in their secure states", () => {
		const info = makeInfo({
			fuses: [
				{ name: "RunAsNode", state: "disabled" },
				{ name: "EnableCookieEncryption", state: "enabled" },
				{ name: "EnableNodeOptionsEnvironmentVariable", state: "disabled" },
				{ name: "EnableNodeCliInspectArguments", state: "disabled" },
				{ name: "OnlyLoadAppFromAsar", state: "enabled" },
				{ name: "EnableEmbeddedAsarIntegrityValidation", state: "enabled" },
				{ name: "GrantFileProtocolExtraPrivileges", state: "disabled" }
			]
		});
		expect(scanElectron(info, [])).toEqual([]);
	});

	it("reports no fuse wire only when a framework version is present", () => {
		const framework = scanElectronMetadata(makeInfo({ electronVersion: "44.0.0" }));
		expect(framework.map(summary)).toEqual([["info", "electron-fuses", "fuses=unavailable"]]);

		expect(scanElectronMetadata(makeInfo())).toEqual([]);
	});

	it("does not infer removed for fuses missing from a partial wire", () => {
		const info = makeInfo({ fuses: [{ name: "RunAsNode", state: "disabled" }] });
		expect(scanElectron(info, [])).toEqual([]);
	});

	it("reports fuse findings without a readable archive", () => {
		const info = makeInfo({
			electronVersion: "44.0.0",
			fuses: [{ name: "RunAsNode", state: "enabled" }]
		});
		expect(scanElectronMetadata(info).map(summary)).toEqual([
			["warning", "electron-fuses", "RunAsNode=enabled"]
		]);
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
		expect(finding?.category).toBe("electron-integrity");
		expect(finding?.source).toBe("app.asar");
		expect(finding?.message).toContain("header");
		expect(finding?.message).not.toContain("contents verified");
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
		expect(finding?.category).toBe("electron-integrity");
		expect(finding?.message).toContain("4");
		expect(finding?.evidence).toBe("dist/a.js.map, dist/b.js.map, dist/c.js.map");
	});

	function integrity(info: Partial<ElectronInfo>): SecurityFinding[] {
		return scanElectronMetadata(makeInfo(info)).filter(
			(finding) => finding.category === "electron-integrity"
		);
	}

	it("warns when the integrity fuse is enabled but the entry is missing", () => {
		const [finding] = integrity({
			asarPath: "/tmp/app.asar",
			integrityIssue: { kind: "missing" },
			fuses: [{ name: "EnableEmbeddedAsarIntegrityValidation", state: "enabled" }]
		});
		expect(finding?.severity).toBe("warning");
		expect(finding?.evidence).toBe("integrity=missing");
		expect(finding?.message).toContain("no ElectronAsarIntegrity");
		expect(finding?.message).toContain("header hash only");
	});

	it("reports a missing entry as info when the fuse is off", () => {
		const [finding] = integrity({
			asarPath: "/tmp/app.asar",
			integrityIssue: { kind: "missing" },
			fuses: [{ name: "EnableEmbeddedAsarIntegrityValidation", state: "disabled" }]
		});
		expect(finding?.severity).toBe("info");
		expect(finding?.evidence).toBe("integrity=missing");
	});

	it("ignores an integrity issue without a readable archive", () => {
		expect(integrity({ integrityIssue: { kind: "missing" } })).toEqual([]);
	});

	it("warns about an unsupported algorithm when the fuse is enabled", () => {
		const [finding] = integrity({
			asarPath: "/tmp/app.asar",
			integrityIssue: { kind: "unsupported-algorithm", algorithm: "MD5" },
			fuses: [{ name: "EnableEmbeddedAsarIntegrityValidation", state: "enabled" }]
		});
		expect(finding?.severity).toBe("warning");
		expect(finding?.evidence).toContain("algorithm=MD5");
		expect(finding?.message).toContain("MD5");
	});

	it("reports an unsupported algorithm as info when the fuse is off", () => {
		const [finding] = integrity({
			asarPath: "/tmp/app.asar",
			integrityIssue: { kind: "unsupported-algorithm", algorithm: "MD5" },
			fuses: [{ name: "EnableEmbeddedAsarIntegrityValidation", state: "disabled" }]
		});
		expect(finding?.severity).toBe("info");
	});

	it("reports a malformed entry as info when the fuse is off", () => {
		const [finding] = integrity({
			asarPath: "/tmp/app.asar",
			integrityIssue: { kind: "malformed" },
			fuses: [{ name: "EnableEmbeddedAsarIntegrityValidation", state: "disabled" }]
		});
		expect(finding?.severity).toBe("info");
		expect(finding?.evidence).toBe("integrity=malformed");
	});

	it("does not report when there is no integrity entry or issue", () => {
		expect(integrity({ asarPath: "/tmp/app.asar" })).toEqual([]);
	});
});

describe("scanElectron version support", () => {
	function versions(info: Partial<ElectronInfo>): SecurityFinding[] {
		return scanElectronMetadata(makeInfo(info)).filter(
			(finding) => finding.category === "electron-version"
		);
	}

	it("warns about an end-of-support major", () => {
		const [finding] = versions({ electronVersion: "12.0.0" });
		expect(finding?.severity).toBe("warning");
		expect(finding?.evidence).toBe("electronVersion=12.0.0");
		expect(finding?.message).toContain(String(MIN_SUPPORTED_ELECTRON_MAJOR));
	});

	it("stays quiet for a future major", () => {
		expect(versions({ electronVersion: "999.0.0" })).toEqual([]);
	});

	it("stays quiet for an unparseable version", () => {
		expect(versions({ electronVersion: "nightly" })).toEqual([]);
	});

	it("stays quiet without a version", () => {
		expect(versions({ electronVersion: undefined })).toEqual([]);
	});
});

describe("Electron version parsing", () => {
	it("parses supported version shapes", () => {
		expect(parseElectronMajor("45.0.0")).toBe(45);
		expect(parseElectronMajor("44.9")).toBe(44);
		expect(parseElectronMajor("44")).toBe(44);
		expect(parseElectronMajor(" 45.0.0 ")).toBe(45);
		expect(parseElectronMajor("45.0.0-beta.1")).toBe(45);
		expect(parseElectronMajor("45.0.0+build.1")).toBe(45);
	});

	it("rejects malformed versions", () => {
		expect(parseElectronMajor("v45.0.0")).toBeNull();
		expect(parseElectronMajor("45.0.0.1")).toBeNull();
		expect(parseElectronMajor("")).toBeNull();
		expect(parseElectronMajor("nightly")).toBeNull();
		expect(parseElectronMajor("0.0.0")).toBeNull();
	});

	it("compares against an injected minimum", () => {
		expect(isElectronVersionSupported("42.9.9", 43)).toBe(false);
		expect(isElectronVersionSupported("43.0.0", 43)).toBe(true);
		expect(isElectronVersionSupported("45.0.0", 43)).toBe(true);
		expect(isElectronVersionSupported("42.0.0", 40)).toBe(true);
		expect(isElectronVersionSupported("nightly", 43)).toBeNull();
	});
});

describe("scanElectron runtime API checks", () => {
	it("flags an unconditional certificate-error trust handler", () => {
		const findings = scanText(
			'app.on("certificate-error", (event, wc, url, error, cert, callback) => ' +
				"{ event.preventDefault(); callback(true); })"
		);
		expect(findings).toHaveLength(1);
		expect(findings[0]?.severity).toBe("critical");
		expect(findings[0]?.category).toBe("electron-runtime");
		expect(findings[0]?.evidence).toContain("callback(true)");
	});

	it("ignores a certificate handler without preventDefault", () => {
		expect(
			scanText(
				'app.on("certificate-error", (event, wc, url, error, cert, callback) => { callback(true); })'
			)
		).toEqual([]);
	});

	it("ignores a scoped certificate handler", () => {
		expect(
			scanText(
				'app.on("certificate-error", (event, wc, url, error, cert, callback) => { ' +
					'if (url.startsWith("https://example.com")) { event.preventDefault(); callback(true); } ' +
					"else { callback(false); } })"
			)
		).toEqual([]);
	});

	it("flags a blindly accepting certificate verify proc", () => {
		const findings = scanText(
			"session.setCertificateVerifyProc((request, callback) => callback(0))"
		);
		expect(findings[0]?.severity).toBe("critical");
		expect(findings[0]?.evidence).toContain("setCertificateVerifyProc");
	});

	it("ignores a verify proc that rejects", () => {
		// -2 rejects, -3 defers to Chromium; neither is a trust decision.
		expect(
			scanText("session.setCertificateVerifyProc((request, callback) => callback(-2))")
		).toEqual([]);
	});

	it("ignores a scoped certificate pin", () => {
		expect(
			scanText(
				"session.setCertificateVerifyProc((request, callback) => { " +
					'if (request.hostname === "api.example.com") callback(0); else callback(-2); })'
			)
		).toEqual([]);
	});

	it("flags a permission request handler that grants everything", () => {
		const findings = scanText(
			"session.setPermissionRequestHandler((wc, permission, callback) => callback(true))"
		);
		expect(findings[0]?.severity).toBe("warning");
	});

	it("ignores a scoped permission request handler", () => {
		expect(
			scanText(
				"session.setPermissionRequestHandler((wc, permission, callback) => { " +
					'if (permission === "notifications") callback(true); else callback(false); })'
			)
		).toEqual([]);
	});

	it("flags a permission check handler that always returns true", () => {
		const findings = scanText("session.setPermissionCheckHandler((wc, permission) => true)");
		expect(findings[0]?.severity).toBe("warning");
	});

	it("ignores a scoped permission check handler", () => {
		expect(
			scanText(
				"session.setPermissionCheckHandler((wc, permission) => { " +
					'if (permission === "media") return true; return false; })'
			)
		).toEqual([]);
	});

	it("flags an always-allow window open handler", () => {
		const findings = scanText('wc.setWindowOpenHandler(() => ({ action: "allow" }))');
		expect(findings[0]?.severity).toBe("warning");
	});

	it("ignores a denying window open handler", () => {
		expect(scanText('wc.setWindowOpenHandler(({ url }) => ({ action: "deny" }))')).toEqual([]);
	});

	it("ignores a window open handler with an origin check", () => {
		expect(
			scanText(
				'wc.setWindowOpenHandler(({ url }) => { if (url.startsWith("https://example.com")) ' +
					'return { action: "allow" }; return { action: "deny" }; })'
			)
		).toEqual([]);
	});

	it("flags a non-literal shell.openExternal argument", () => {
		const findings = scanText("shell.openExternal(link)");
		expect(findings[0]?.severity).toBe("info");
		expect(findings[0]?.evidence).toContain("shell.openExternal");
	});

	it("ignores a literal shell.openExternal URL", () => {
		expect(scanText('shell.openExternal("https://example.com")')).toEqual([]);
	});

	it("flags an interpolated shell.openExternal template literal", () => {
		const findings = scanText("shell.openExternal(`$" + "{base}/docs`)");
		expect(findings[0]?.severity).toBe("info");
	});

	it("flags shell.openExternal with an options object", () => {
		const findings = scanText("shell.openExternal(target, { activate: true })");
		expect(findings[0]?.severity).toBe("info");
		expect(findings[0]?.category).toBe("electron-runtime");
	});

	it("does not flag a local SafeShell wrapper that reuses the shell name", () => {
		const content =
			"class SafeShell { openExternal(url, type) { " +
			"if (!SafeUrls.canLaunch(url, type)) return; " +
			"return this.shell.openExternal(url, UrlType.WebUrl); } }";
		expect(scanText(content)).toEqual([]);
	});

	it("does not flag an unknown shell chain", () => {
		expect(scanText("foo.shell.openExternal(url)")).toEqual([]);
	});

	it("skips a non-options second argument", () => {
		expect(scanText("shell.openExternal(url, UrlType.WebUrl)")).toEqual([]);
	});

	it("follows a require namespace alias", () => {
		const findings = scanText(
			'const electron_1 = require("electron");electron_1.shell.openExternal(target);'
		);
		expect(findings).toHaveLength(1);
		expect(findings[0]?.severity).toBe("info");
		expect(findings[0]?.evidence).toContain("electron_1.shell.openExternal");
	});

	it("follows ES import aliases and destructured requires", () => {
		const esm = scanText(
			'import * as electron from "electron";\nelectron.shell.openExternal(target);'
		);
		expect(esm).toHaveLength(1);

		const destructured = scanText(
			'const { shell: electronShell } = require("electron");\nelectronShell.openExternal(target);'
		);
		expect(destructured).toHaveLength(1);
	});

	it("flags raw ipcRenderer exposed through contextBridge", () => {
		const findings = scanText(
			'contextBridge.exposeInMainWorld("api", ipcRenderer)',
			"app.asar/preload.js"
		);
		expect(findings).toHaveLength(1);
		expect(findings[0]?.severity).toBe("warning");
		expect(findings[0]?.source).toBe("app.asar/preload.js");
	});

	it("flags ipcRenderer exposed as an object property", () => {
		const findings = scanText(
			'contextBridge.exposeInMainWorld("api", { ipcRenderer })',
			"app.asar/preload.js"
		);
		expect(findings).toHaveLength(1);
		expect(findings[0]?.severity).toBe("warning");
	});

	it("flags an ipcRenderer member exposed through the API", () => {
		const findings = scanText(
			'contextBridge.exposeInMainWorld("api", { on: ipcRenderer.on })',
			"app.asar/preload.js"
		);
		expect(findings).toHaveLength(1);
		expect(findings[0]?.severity).toBe("warning");
	});

	it("flags arbitrary-channel forwarding in a preload", () => {
		const findings = scanText("ipcRenderer.invoke(channel, payload)", "app.asar/preload.js");
		expect(findings).toHaveLength(1);
		expect(findings[0]?.severity).toBe("warning");
	});

	it("ignores a literal IPC channel", () => {
		expect(
			scanText('ipcRenderer.invoke("app:get-state", payload)', "app.asar/preload.js")
		).toEqual([]);
	});

	it("ignores a forwarded channel validated by an allowlist guard", () => {
		const findings = scanText(
			"const validChannels = ['app:get-state', 'app:set-state'];\n" +
				"contextBridge.exposeInMainWorld('api', {\n" +
				"\tinvoke: (channel, data) => {\n" +
				"\t\tif (validChannels.includes(channel)) return ipcRenderer.invoke(channel, data);\n" +
				"\t}\n" +
				"});",
			"app.asar/preload.js"
		);
		expect(findings).toEqual([]);
	});

	it("ignores a named helper called only with literal channels", () => {
		const findings = scanText(
			"function E(_,...T){return ipcRenderer.invoke(_,...T)}" +
				'contextBridge.exposeInMainWorld("api",{relaunch:()=>E("APP_RELAUNCH"),setBadge:_=>E("SET_BADGE",_)})',
			"app.asar/preload.js"
		);
		expect(findings).toEqual([]);
	});

	it("ignores a concise arrow helper called only with literal channels", () => {
		expect(
			scanText(
				'const E=(_,...T)=>ipcRenderer.invoke(_,...T);E("APP_RELAUNCH");',
				"app.asar/preload.js"
			)
		).toEqual([]);
	});

	it("flags a helper that forwards a dynamic channel", () => {
		const findings = scanText(
			"function E(_,...T){return ipcRenderer.invoke(_,...T)}" +
				'contextBridge.exposeInMainWorld("api",{invoke:(channel,data)=>E(channel,data)})',
			"app.asar/preload.js"
		);
		expect(findings).toHaveLength(1);
		expect(findings[0]?.message).toContain("arbitrary IPC channel");
	});

	it("flags a helper exposed as a value even when internal calls use literals", () => {
		const findings = scanText(
			"function E(_,...T){return ipcRenderer.invoke(_,...T)}" +
				'E("APP_RELAUNCH");contextBridge.exposeInMainWorld("api",{invoke:E})',
			"app.asar/preload.js"
		);
		expect(findings).toHaveLength(1);
	});

	it("still flags a channel guarded only through another variable", () => {
		const findings = scanText("ipcRenderer.invoke(channel, payload)", "app.asar/preload.js");
		expect(findings).toHaveLength(1);

		expect(
			scanText(
				"if (validChannels.includes(otherChannel)) ipcRenderer.invoke(channel, payload)",
				"app.asar/preload.js"
			)
		).toHaveLength(1);

		// A similarly named variable must not satisfy the guard for `channel`.
		expect(
			scanText(
				"if (mychannel !== null) ipcRenderer.invoke(channel, payload)",
				"app.asar/preload.js"
			)
		).toHaveLength(1);
	});

	it("ignores IPC forwarding outside a preload", () => {
		expect(scanText("ipcRenderer.invoke(channel, payload)", "app.asar/main.js")).toEqual([]);
	});

	it("ignores IPC wiring in node_modules", () => {
		expect(
			scanText("ipcRenderer.send(channel, data)", "app.asar/node_modules/vendor/preload.js")
		).toEqual([]);
	});

	it("treats a referenced preload path as a preload", () => {
		const findings = scanElectron(makeInfo(), [
			{
				relativePath: "app.asar/main.js",
				content:
					'new BrowserWindow({ webPreferences: { preload: path.join(__dirname, "bridge.js") } })'
			},
			{ relativePath: "app.asar/bridge.js", content: "ipcRenderer.send(channel, data)" }
		]);
		expect(findings).toHaveLength(1);
		expect(findings[0]?.source).toBe("app.asar/bridge.js");
	});

	it("caps findings per check", () => {
		const files = Array.from({ length: 12 }, (_, index) => ({
			relativePath: `app.asar/preload-${index}.js`,
			content: 'contextBridge.exposeInMainWorld("api", ipcRenderer)'
		}));
		const findings = scanElectron(makeInfo(), files).filter(
			(finding) => finding.category === "electron-runtime"
		);
		expect(findings).toHaveLength(3);
	});

	it("keeps critical runtime findings when enableRemoteModule fills the category", () => {
		const files = Array.from({ length: 25 }, (_, index) => ({
			relativePath: `app.asar/config-${index}.js`,
			content: "enableRemoteModule: true"
		}));
		files.push({
			relativePath: "app.asar/session.js",
			content: "session.setCertificateVerifyProc((request, callback) => callback(0))"
		});

		const findings = scanElectron(makeInfo(), files);
		const critical = findings.find(
			(finding) =>
				finding.severity === "critical" &&
				finding.message.includes("setCertificateVerifyProc")
		);
		expect(critical?.source).toBe("app.asar/session.js");
		expect(findings.filter((finding) => finding.category === "electron-runtime")).toHaveLength(
			20
		);
	});
});

describe("scanElectron command-line switches", () => {
	it("flags each dangerous appendSwitch with its severity", () => {
		const cases: Array<[string, SecurityFinding["severity"]]> = [
			["disable-web-security", "warning"],
			["ignore-certificate-errors", "warning"],
			["allow-running-insecure-content", "warning"],
			["disable-site-isolation-trials", "warning"],
			["inspect", "info"],
			["inspect-brk", "info"]
		];

		for (const [name, severity] of cases) {
			const [finding] = scanText(`app.commandLine.appendSwitch("${name}")`);
			expect(finding?.category).toBe("electron-switches");
			expect(finding?.severity).toBe(severity);
			expect(finding?.evidence).toBe(`appendSwitch("${name}")`);
		}
	});

	it("accepts appendArgument and additionalArguments forms", () => {
		const argument = scanText('app.commandLine.appendArgument("--disable-web-security")');
		expect(argument[0]?.severity).toBe("warning");

		const inspect = scanText('app.commandLine.appendArgument("--inspect=9229")');
		expect(inspect[0]?.severity).toBe("info");

		const prefs = scanText(
			'new BrowserWindow({ webPreferences: { additionalArguments: ["--inspect=9229"] } })'
		);
		expect(prefs[0]?.severity).toBe("info");
		expect(prefs[0]?.message).toContain("launch-time argv");
	});

	it("does not flag the wrong appendSwitch form", () => {
		expect(scanText('app.commandLine.appendSwitch("--disable-web-security")')).toEqual([]);
	});

	it("handles whitespace and quote variants", () => {
		expect(scanText('app.commandLine.appendSwitch( "disable-web-security" )')).toHaveLength(1);
		expect(scanText("app.commandLine.appendSwitch('ignore-certificate-errors')")).toHaveLength(
			1
		);
		expect(
			scanText("app.commandLine.appendSwitch(\n\t'allow-running-insecure-content'\n)")
		).toHaveLength(1);
	});

	it("matches minified call sites", () => {
		const findings = scanText(
			'!function(){app.commandLine.appendSwitch("disable-web-security"),' +
				'app.commandLine.appendSwitch("ignore-certificate-errors")}()'
		);
		expect(findings.map((f) => f.severity)).toEqual(["warning", "warning"]);
	});

	it("reports a remote debugging port on loopback as a warning", () => {
		const findings = scanText(
			'app.commandLine.appendSwitch("remote-debugging-port", "9222");' +
				'app.commandLine.appendSwitch("remote-debugging-address", "127.0.0.1")'
		);
		expect(findings).toHaveLength(1);
		expect(findings[0]?.severity).toBe("warning");
		expect(findings[0]?.message).toContain("local processes");
	});

	it("escalates a port bound beyond loopback to critical", () => {
		const [finding] = scanText(
			'app.commandLine.appendArgument("--remote-debugging-port=9222");' +
				'app.commandLine.appendArgument("--remote-debugging-address=0.0.0.0")'
		);
		expect(finding?.severity).toBe("critical");
		expect(finding?.message).toContain("0.0.0.0");
		expect(finding?.evidence).toContain("remote-debugging-address");
	});

	it("ignores a non-loopback address far from the port", () => {
		const [finding] = scanText(
			'app.commandLine.appendSwitch("remote-debugging-port", "9222");' +
				"x".repeat(5000) +
				'app.commandLine.appendSwitch("remote-debugging-address", "0.0.0.0")'
		);
		expect(finding?.severity).toBe("warning");
		expect(finding?.message).toContain("local processes");
		expect(finding?.evidence).not.toContain("remote-debugging-address");
	});

	it("reports process.argv debug-flag handling as info", () => {
		const [finding] = scanText('if (process.argv.includes("--inspect")) { }');
		expect(finding?.severity).toBe("info");
		expect(finding?.category).toBe("electron-switches");
		expect(finding?.evidence).toContain("--inspect");
	});

	it("skips docs, tests and lockfiles", () => {
		const files = [
			{
				relativePath: "app.asar/README.txt",
				content: 'appendSwitch("disable-web-security")'
			},
			{
				relativePath: "app.asar/__tests__/main.js",
				content: 'appendSwitch("disable-web-security")'
			},
			{
				relativePath: "app.asar/package-lock.json",
				content: 'appendSwitch("disable-web-security")'
			}
		];
		expect(scanElectron(makeInfo(), files)).toEqual([]);
	});

	it("ignores bare switch constants", () => {
		expect(scanText('const BLOCKED = ["disable-web-security", "--inspect"];')).toEqual([]);
	});

	it("skips a commented switch and reports a later real one", () => {
		const [finding] = scanText(
			'// app.commandLine.appendSwitch("disable-web-security")\n' +
				'app.commandLine.appendSwitch("disable-web-security")'
		);
		expect(finding?.category).toBe("electron-switches");
		expect(finding?.severity).toBe("warning");
	});

	it("ignores switches and cleartext loads in vendor code", () => {
		const content =
			'app.commandLine.appendSwitch("disable-web-security");' +
			'win.loadURL("http://example.com")';
		const findings = scanElectron(makeInfo(), [
			{ relativePath: "app.asar/node_modules/vendor/index.js", content },
			{ relativePath: "app.asar/main.js", content }
		]);
		expect(findings.map((finding) => [finding.category, finding.source])).toEqual([
			["electron-switches", "app.asar/main.js"],
			["electron-cleartext", "app.asar/main.js"]
		]);
	});

	it("caps findings in the new category", () => {
		const files = Array.from({ length: 25 }, (_, i) => ({
			relativePath: `app.asar/chunk-${i}.js`,
			content: 'app.commandLine.appendSwitch("disable-web-security")'
		}));
		expect(scanElectron(makeInfo(), files)).toHaveLength(20);
	});
});

describe("scanElectron cleartext loadURL", () => {
	it("flags literals and templates that load http content", () => {
		const cases = [
			'win.loadURL("http://example.com/app")',
			"win.loadURL('http://example.com/app')",
			"win.loadURL(`http://example.com/app`)",
			"win.loadURL(`http://$" + "{host}/app`)"
		];
		for (const content of cases) {
			const [finding] = scanText(content);
			expect(finding?.category).toBe("electron-cleartext");
			expect(finding?.severity).toBe("warning");
			expect(finding?.evidence.startsWith("loadURL(")).toBe(true);
		}
	});

	it("downgrades loopback URLs to info", () => {
		for (const url of ["http://localhost:3000", "http://127.0.0.1:8080", "http://[::1]:3000"]) {
			const [finding] = scanText(`win.loadURL("${url}")`);
			expect(finding?.severity).toBe("info");
		}
	});

	it("does not whitelist lookalike hosts", () => {
		const [finding] = scanText('win.loadURL("http://localhost.evil.com/")');
		expect(finding?.severity).toBe("warning");
	});

	it("ignores https and URLs that only mention http in a query", () => {
		expect(scanText('win.loadURL("https://example.com/app")')).toEqual([]);
		expect(scanText('win.loadURL("https://example.com/?next=http://other")')).toEqual([]);
	});

	it("matches new BrowserWindow(...).loadURL and whitespace variants", () => {
		const [finding] = scanText('new BrowserWindow({}).loadURL(\n\t"http://example.com"\n)');
		expect(finding?.severity).toBe("warning");
	});

	it("matches the scheme case-insensitively", () => {
		const [finding] = scanText('win.loadURL("HTTP://EXAMPLE.COM")');
		expect(finding?.severity).toBe("warning");
	});

	it("leaves openExternal and indirect variables alone", () => {
		expect(scanText('shell.openExternal("http://example.com")')).toEqual([]);
		expect(scanText('const url = "http://example.com"; win.loadURL(url)')).toEqual([]);
	});

	it("skips documentation and test files", () => {
		expect(
			scanElectron(makeInfo(), [
				{
					relativePath: "app.asar/docs/example.html",
					content: 'win.loadURL("http://example.com")'
				},
				{
					relativePath: "app.asar/main.test.js",
					content: 'win.loadURL("http://example.com")'
				}
			])
		).toEqual([]);
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

		const findings = scanElectron(makeInfo(), files);
		const combos = findings.filter((finding) => finding.severity === "critical");
		expect(combos).toHaveLength(1);
		expect(combos[0]?.category).toBe("electron-renderer");
		expect(combos[0]?.message).toContain("full RCE");
		expect(combos[0]?.evidence).toContain("app.asar/node.js");
		expect(combos[0]?.evidence).toContain("app.asar/context.js");

		const bySource = new Map(
			findings
				.filter((finding) => finding.severity !== "critical")
				.map((finding) => [finding.source, finding])
		);
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
		expect(bySource.get("app.asar/security.js")?.category).toBe("electron-renderer");
		expect(bySource.get("app.asar/insecure.js")?.severity).toBe("info");
		expect(bySource.get("app.asar/sandbox.js")?.severity).toBe("warning");
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

	it("skips a commented first match and reports a later real one", () => {
		const [finding] = scanElectron(makeInfo(), [
			{
				relativePath: "app.asar/main.js",
				content: "// nodeIntegration: true\nconst prefs = { nodeIntegration: true }"
			}
		]);
		expect(finding?.severity).toBe("warning");
		expect(finding?.evidence).toBe("nodeIntegration: true");
	});
});

describe("scanElectron renderer detection", () => {
	function scanPrefs(
		content: string,
		relativePath = "app.asar/main.js",
		info: ElectronInfo = makeInfo()
	): SecurityFinding[] {
		return scanElectron(info, [{ relativePath, content }]);
	}

	it("matches minified true and false values", () => {
		const node = scanPrefs("webPreferences:{nodeIntegration:!0}");
		expect(node).toHaveLength(1);
		expect(node[0]?.severity).toBe("warning");
		expect(node[0]?.evidence).toBe("nodeIntegration:!0");

		const isolation = scanPrefs("webPreferences:{contextIsolation:!1}");
		expect(isolation[0]?.severity).toBe("warning");
		expect(isolation[0]?.evidence).toBe("contextIsolation:!1");

		const sandbox = scanPrefs("webPreferences:{sandbox:!1}");
		expect(sandbox[0]?.severity).toBe("warning");
		expect(sandbox[0]?.evidence).toBe("sandbox:!1");
	});

	it("reports one critical for the minified combo and suppresses implied settings", () => {
		const findings = scanPrefs(
			"new BrowserWindow({webPreferences:{nodeIntegration:!0,contextIsolation:!1,sandbox:!1}})"
		);
		expect(findings).toHaveLength(1);
		expect(findings[0]?.severity).toBe("critical");
		expect(findings[0]?.category).toBe("electron-renderer");
		expect(findings[0]?.evidence).toContain("nodeIntegration:!0");
		expect(findings[0]?.evidence).toContain("contextIsolation:!1");
	});

	it("ignores commented-out settings and markup", () => {
		expect(scanPrefs("// nodeIntegration: true")).toEqual([]);
		expect(scanPrefs("/* sandbox: false */")).toEqual([]);
		expect(scanPrefs("/*\n * contextIsolation: false\n */")).toEqual([]);
		expect(
			scanPrefs("<html><!-- <webview allowpopups> --></html>", "app.asar/index.html")
		).toEqual([]);
	});

	it("only scans configuration-capable extensions", () => {
		expect(scanPrefs("nodeIntegration: true", "app.asar/README.txt")).toEqual([]);
		const [finding] = scanPrefs("nodeIntegrationInWorker: !0", "app.asar/main.mjs");
		expect(finding?.severity).toBe("warning");
		expect(finding?.message).toContain("web workers");
	});

	it("downgrades vendored matches", () => {
		const findings = scanElectron(makeInfo(), [
			{ relativePath: "app.asar/node_modules/sdk/index.js", content: "webSecurity: false" },
			{ relativePath: "app.asar/main.js", content: "webSecurity: false" }
		]);
		const vendor = findings.find((finding) => finding.source?.includes("node_modules"));
		expect(vendor?.severity).toBe("info");
		expect(vendor?.vendor).toBe(true);
		expect(vendor?.message).toContain("(vendor code)");

		const firstParty = findings.find((finding) => finding.source === "app.asar/main.js");
		expect(firstParty?.severity).toBe("warning");
		expect(firstParty?.vendor).toBeUndefined();
	});

	it("treats the app's own package inside node_modules as first-party", () => {
		const info = makeInfo({ packageJson: { name: "demo", main: "index.js" } });
		const findings = scanElectron(info, [
			{
				relativePath: "app.asar/node_modules/demo/dist/main.js",
				content: "webSecurity: false"
			}
		]);
		expect(findings).toHaveLength(1);
		expect(findings[0]?.severity).toBe("warning");
		expect(findings[0]?.vendor).toBeUndefined();
	});

	it("caps vendor findings", () => {
		const files = Array.from({ length: 25 }, (_, index) => ({
			relativePath: `app.asar/node_modules/pkg/file-${index}.js`,
			content: "webSecurity: false"
		}));
		expect(scanElectron(makeInfo(), files)).toHaveLength(5);
	});

	it("reports a cross-file nodeIntegration + contextIsolation combo", () => {
		const findings = scanElectron(makeInfo(), [
			{ relativePath: "app.asar/main.js", content: "nodeIntegration: true" },
			{ relativePath: "app.asar/window.js", content: "contextIsolation: false" }
		]);
		const critical = findings.filter((finding) => finding.severity === "critical");
		expect(critical).toHaveLength(1);
		expect(critical[0]?.source).toBe("app.asar/main.js");
		expect(critical[0]?.evidence).toContain("app.asar/main.js");
		expect(critical[0]?.evidence).toContain("app.asar/window.js");
		expect(findings).toHaveLength(3);
	});

	it("reports the additional renderer settings", () => {
		const worker = scanPrefs("nodeIntegrationInWorker: !0");
		expect(worker[0]?.severity).toBe("warning");
		const subFrames = scanPrefs("nodeIntegrationInSubFrames: true");
		expect(subFrames[0]?.severity).toBe("warning");
		const blink = scanPrefs('enableBlinkFeatures: "SharedArrayBuffer"');
		expect(blink[0]?.severity).toBe("info");
	});

	it("gates the remote module on the Electron major version", () => {
		const [legacy] = scanPrefs("enableRemoteModule: true");
		expect(legacy?.severity).toBe("warning");

		const retired = scanPrefs(
			"enableRemoteModule: true",
			"app.asar/main.js",
			makeInfo({ electronVersion: "40.4.0" })
		).find((finding) => finding.category === "electron-runtime");
		expect(retired?.severity).toBe("info");
		expect(retired?.message).toContain("removed in Electron 14");
	});

	it("reads webview markup", () => {
		const [popups] = scanPrefs(
			'<webview src="x" allowpopups></webview>',
			"app.asar/index.html"
		);
		expect(popups?.severity).toBe("info");
		expect(popups?.message).toContain("allowpopups");

		const combo = scanPrefs(
			'<webview webpreferences="nodeIntegration=yes, contextIsolation=no" src="x">',
			"app.asar/index.html"
		);
		expect(combo).toHaveLength(1);
		expect(combo[0]?.severity).toBe("critical");
	});

	it("keeps the renderer and fuse caps independent", () => {
		const files = Array.from({ length: 25 }, (_, index) => ({
			relativePath: `app.asar/page-${index}.js`,
			content: "nodeIntegration: true"
		}));
		const info = makeInfo({
			fuses: [
				{ name: "RunAsNode", state: "enabled" },
				{ name: "EnableNodeOptionsEnvironmentVariable", state: "enabled" },
				{ name: "EnableNodeCliInspectArguments", state: "enabled" },
				{ name: "OnlyLoadAppFromAsar", state: "disabled" },
				{ name: "EnableEmbeddedAsarIntegrityValidation", state: "disabled" }
			]
		});
		const findings = scanElectron(info, files);
		expect(findings.filter((finding) => finding.category === "electron-renderer")).toHaveLength(
			20
		);
		expect(findings.filter((finding) => finding.category === "electron-fuses")).toHaveLength(5);
	});
});

// ── Content-Security-Policy ────────────────────────────────────────────

function meta(content: string): string {
	return `<meta http-equiv="Content-Security-Policy" content="${content}">`;
}

describe("scanElectron content security policy", () => {
	it("flags a script-bearing page without a CSP meta tag", () => {
		const [finding] = scanCsp("<script>1</script>");
		expect(finding?.severity).toBe("info");
		expect(finding?.category).toBe("electron-csp");
		expect(finding?.source).toBe("app.asar/index.html");
		expect(finding?.message).toContain("meta tag");
		expect(finding?.evidence).toContain("1 script tag");
	});

	it("ignores pages without executable script", () => {
		expect(scanCsp("<p>hello</p>")).toEqual([]);
		expect(scanCsp(`<script type="application/ld+json">{}</script>`)).toEqual([]);
		expect(scanCsp(`<script type="text/plain">hello</script>`)).toEqual([]);
		expect(scanCsp(`<script type="text/x-handlebars-template"><b>x</b></script>`)).toEqual([]);
	});

	it("flags inline handlers on a page without a CSP meta tag", () => {
		const [finding] = scanCsp(`<button onclick="go()">go</button>`);
		expect(finding?.severity).toBe("info");
		expect(finding?.evidence).toContain("inline event handlers");
	});

	it("accepts a strong policy", () => {
		expect(
			scanCsp(`${meta("default-src 'self'; script-src 'self'")}<script></script>`)
		).toEqual([]);
	});

	it("flags an effective 'unsafe-inline' script source", () => {
		const [finding] = scanCsp(`${meta("script-src 'self' 'unsafe-inline'")}<script></script>`);
		expect(finding?.severity).toBe("warning");
		expect(finding?.message).toContain("unsafe-inline");
	});

	it("treats 'unsafe-inline' as inert next to a nonce", () => {
		expect(
			scanCsp(`${meta("script-src 'self' 'unsafe-inline' 'nonce-abc'")}<script></script>`)
		).toEqual([]);
	});

	it("treats 'unsafe-inline' as inert next to 'strict-dynamic'", () => {
		expect(
			scanCsp(`${meta("script-src 'unsafe-inline' 'strict-dynamic'")}<script></script>`)
		).toEqual([]);
	});

	it("ignores style-src 'unsafe-inline'", () => {
		expect(
			scanCsp(
				`${meta("default-src 'self'; script-src 'self'; style-src 'unsafe-inline'")}<script></script>`
			)
		).toEqual([]);
	});

	it("flags a policy that does not govern scripts", () => {
		const [finding] = scanCsp(`${meta("style-src 'unsafe-inline'")}<script></script>`);
		expect(finding?.severity).toBe("info");
		expect(finding?.message).toContain("does not restrict scripts");
	});

	it("ignores non-script directives with weak sources", () => {
		expect(scanCsp(`${meta("default-src 'self'; img-src data:")}<script></script>`)).toEqual(
			[]
		);
	});

	it("uses script-src over default-src for script elements", () => {
		expect(
			scanCsp(`${meta("script-src 'self'; default-src 'unsafe-inline'")}<script></script>`)
		).toEqual([]);
	});

	it("parses uppercase and minified policy attributes", () => {
		const html = `<META CONTENT="SCRIPT-SRC 'SELF'; STYLE-SRC 'UNSAFE-INLINE'" HTTP-EQUIV="Content-Security-Policy"><SCRIPT></SCRIPT>`;
		expect(scanCsp(html)).toEqual([]);
	});

	it("parses multiline meta tags with any attribute order", () => {
		const html = `<meta
			content="default-src 'self'"
			http-equiv="Content-Security-Policy"
		><script></script>`;
		expect(scanCsp(html)).toEqual([]);
	});

	it("treats multiple policies as an intersection", () => {
		const html = `${meta("script-src 'unsafe-inline'")}${meta(
			"script-src 'self'"
		)}<script></script>`;
		expect(scanCsp(html)).toEqual([]);
	});

	it("flags multiple policies when every one is weak", () => {
		const html = `${meta("script-src 'unsafe-inline'")}${meta(
			"script-src 'unsafe-inline'"
		)}<script></script>`;
		const findings = scanCsp(html);
		expect(findings).toHaveLength(1);
		expect(findings[0]?.severity).toBe("warning");
	});

	it("ignores duplicate directives after the first", () => {
		expect(
			scanCsp(`${meta("script-src 'self'; script-src 'unsafe-inline'")}<script></script>`)
		).toEqual([]);
	});

	it("flags wildcard and scheme script sources", () => {
		expect(scanCsp(`${meta("script-src *")}<script></script>`)[0]?.severity).toBe("warning");
		expect(scanCsp(`${meta("script-src http:")}<script></script>`)[0]?.severity).toBe(
			"warning"
		);
		expect(scanCsp(`${meta("script-src https:")}<script></script>`)[0]?.severity).toBe(
			"warning"
		);
		expect(scanCsp(`${meta("script-src data:")}<script></script>`)[0]?.severity).toBe(
			"warning"
		);
	});

	it("reports lower-risk scheme script sources as info", () => {
		const [finding] = scanCsp(`${meta("script-src blob:")}<script></script>`);
		expect(finding?.severity).toBe("info");
		expect(finding?.message).toContain("blob:");
	});

	it("flags 'unsafe-eval'", () => {
		const [finding] = scanCsp(`${meta("script-src 'unsafe-eval'")}<script></script>`);
		expect(finding?.severity).toBe("warning");
		expect(finding?.message).toContain("unsafe-eval");
	});

	it("ignores 'wasm-unsafe-eval'", () => {
		expect(scanCsp(`${meta("script-src 'wasm-unsafe-eval'")}<script></script>`)).toEqual([]);
	});

	it("ignores host and scheme sources beside 'strict-dynamic'", () => {
		expect(scanCsp(`${meta("script-src 'strict-dynamic' https:")}<script></script>`)).toEqual(
			[]
		);
	});

	it("uses script-src-elem for script elements", () => {
		const html = `${meta("script-src-elem 'self'; script-src 'unsafe-inline'")}<script></script>`;
		expect(scanCsp(html)).toEqual([]);
	});

	it("falls back to script-src for inline handlers", () => {
		const html = `${meta("script-src-elem 'self'; script-src 'unsafe-inline'")}<body onload="go()"></body>`;
		const [finding] = scanCsp(html);
		expect(finding?.severity).toBe("warning");
		expect(finding?.message).toContain("inline event handlers");
	});

	it("emits one finding per document with the highest severity", () => {
		const findings = scanCsp(
			`${meta("script-src 'self' 'unsafe-inline' blob:")}<script></script><script></script>`
		);
		expect(findings).toHaveLength(1);
		expect(findings[0]?.severity).toBe("warning");
		expect(findings[0]?.message).toContain("unsafe-inline");
		expect(findings[0]?.message).toContain("blob:");
	});

	it("dedupes the same file reported twice", () => {
		const entry = { relativePath: "app.asar/index.html", content: "<script></script>" };
		expect(scanElectron(makeInfo(), [entry, entry])).toHaveLength(1);
	});

	it("caps findings per category", () => {
		const files = Array.from({ length: 25 }, (_, index) => ({
			relativePath: `app.asar/page-${index}.html`,
			content: "<script></script>"
		}));
		const findings = scanElectron(makeInfo(), files).filter(
			(finding) => finding.category === "electron-csp"
		);
		expect(findings).toHaveLength(20);
	});

	it("ignores commented-out CSP meta tags", () => {
		const [finding] = scanCsp(`<!-- ${meta("script-src 'self'")} --><script></script>`);
		expect(finding?.severity).toBe("info");
		expect(finding?.message).toContain("No Content-Security-Policy meta tag");
	});

	it("reads .htm and unpacked HTML from the archive fixture", () => {
		const filePath = writeFixture("csp.asar", {
			"index.htm": { data: "<script></script>" },
			"unpacked.html": { data: "<script></script>", unpacked: true }
		});
		const unpackedDir = `${filePath}.unpacked`;
		mkdirSync(unpackedDir, { recursive: true });
		writeFileSync(path.join(unpackedDir, "unpacked.html"), "<script></script>");

		const archive = parse(filePath);
		const packed = readAsarTextFiles(archive, LIMITS);
		const unpacked = readAsarUnpackedHtmlFiles(archive, LIMITS);

		expect(unpacked).toEqual([
			{ relativePath: "app.asar.unpacked/unpacked.html", content: "<script></script>" }
		]);
		const sources = scanElectron(makeInfo(), [...packed, ...unpacked]).map(
			(finding) => finding.source
		);
		expect(new Set(sources)).toEqual(
			new Set(["app.asar/index.htm", "app.asar.unpacked/unpacked.html"])
		);
	});
});

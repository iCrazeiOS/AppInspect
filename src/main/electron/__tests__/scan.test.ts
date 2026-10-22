import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";

import type { ElectronInfo, SecurityFinding } from "../../../shared/types";
import { type AsarArchive, readAsarHeader } from "../asar";
import { readAsarTextFiles, readAsarUnpackedHtmlFiles, scanElectron } from "../scan";

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
			["warning", "electron-fuses", "RunAsNode=enabled"],
			["info", "electron-fuses", "EnableNodeOptionsEnvironmentVariable=enabled"],
			["info", "electron-fuses", "EnableNodeCliInspectArguments=enabled"],
			["info", "electron-fuses", "OnlyLoadAppFromAsar=disabled"],
			["info", "electron-fuses", "EnableEmbeddedAsarIntegrityValidation=disabled"]
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
		expect(finding?.category).toBe("electron-integrity");
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
		expect(finding?.category).toBe("electron-integrity");
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

		const [retired] = scanPrefs(
			"enableRemoteModule: true",
			"app.asar/main.js",
			makeInfo({ electronVersion: "40.4.0" })
		);
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

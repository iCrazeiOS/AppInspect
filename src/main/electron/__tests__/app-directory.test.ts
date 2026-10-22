import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";

import type { ElectronInfo, SecurityFinding } from "../../../shared/types";
import { readAppDirectoryTextFiles, scanElectronText } from "../scan";

let TMP_DIR = "";

beforeAll(() => {
	TMP_DIR = mkdtempSync(path.join(tmpdir(), "appinspect-electron-app-"));
});
afterAll(() => {
	rmSync(TMP_DIR, { recursive: true, force: true });
});

/** Read without touching the user's bundle size settings. */
const LIMITS = { maxFileSize: 10 * 1024 * 1024, maxBundleSize: 10 * 1024 * 1024 };

type FixtureTree = Record<string, string | Buffer>;

function writeTree(name: string, tree: FixtureTree): string {
	const root = path.join(TMP_DIR, name);
	for (const [relativePath, content] of Object.entries(tree)) {
		const filePath = path.join(root, relativePath);
		mkdirSync(path.dirname(filePath), { recursive: true });
		writeFileSync(filePath, content);
	}
	return root;
}

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

describe("readAppDirectoryTextFiles", () => {
	it("reads scannable text files with an app/ prefix and skips the rest", () => {
		const appDir = writeTree("Demo/Contents/Resources/app", {
			"out/main.js": "console.log(1)",
			"out/index.html": "<script></script>",
			"out/app.js.map": '{"version":3}',
			"out/logo.png": Buffer.from([1, 2, 3]),
			"out/binary.js": Buffer.from([0x00, 0x01, 0x02]),
			"out/empty.txt": "",
			"node_modules/vendor/index.js": "module.exports = 1",
			"package.json": '{"name":"demo","main":"out/main.js"}'
		});

		expect(readAppDirectoryTextFiles(appDir, LIMITS)).toEqual([
			{ relativePath: "app/out/index.html", content: "<script></script>" },
			{ relativePath: "app/out/main.js", content: "console.log(1)" },
			{ relativePath: "app/package.json", content: '{"name":"demo","main":"out/main.js"}' }
		]);
	});

	it("skips files over the per-file limit", () => {
		const appDir = writeTree("Limits/app", {
			"small.js": "small",
			"big.js": "x".repeat(1000)
		});

		const files = readAppDirectoryTextFiles(appDir, {
			maxFileSize: 500,
			maxBundleSize: 1024 * 1024
		});
		expect(files.map((file) => file.relativePath)).toEqual(["app/small.js"]);
	});

	it("stops once the bundle size budget is reached", () => {
		const appDir = writeTree("Budget/app", {
			"a.js": "a".repeat(300),
			"b.js": "b".repeat(300),
			"c.js": "c".repeat(300)
		});

		const files = readAppDirectoryTextFiles(appDir, {
			maxFileSize: 1024 * 1024,
			maxBundleSize: 500
		});
		expect(files.map((file) => file.relativePath)).toEqual(["app/a.js", "app/b.js"]);
	});

	it("does not follow symlinks outside the directory", () => {
		if (process.platform === "win32") return;

		const outsideDir = writeTree("Outside", { "secret.js": "const key = 'x'" });
		const appDir = writeTree("Symlinks/app", { "main.js": "console.log(1)" });

		try {
			symlinkSync(path.join(outsideDir, "secret.js"), path.join(appDir, "linked.js"));
			symlinkSync(outsideDir, path.join(appDir, "linked-dir"));
		} catch {
			return; // symlink creation may require privileges
		}

		expect(readAppDirectoryTextFiles(appDir, LIMITS).map((file) => file.relativePath)).toEqual([
			"app/main.js"
		]);
	});
});

describe("scanElectronText with an app/ directory", () => {
	it("flags renderer preferences in app-prefixed files", () => {
		const findings = scanElectronText(makeInfo(), [
			{
				relativePath: "app/out/main.js",
				content:
					"new BrowserWindow({webPreferences:{nodeIntegration:!0,contextIsolation:!1}})"
			}
		]);

		expect(findings).toHaveLength(1);
		expect(findings[0]?.severity).toBe("critical");
		expect(findings[0]?.category).toBe("electron-renderer");
		expect(findings[0]?.source).toBe("app/out/main.js");
	});

	it("flags a script-bearing page without a CSP in app-prefixed files", () => {
		const findings = scanElectronText(makeInfo(), [
			{ relativePath: "app/out/index.html", content: "<script></script>" }
		]);

		expect(findings).toHaveLength(1);
		expect(findings[0]?.category).toBe("electron-csp");
		expect(findings[0]?.source).toBe("app/out/index.html");
	});

	it("treats the app's package main and vendor code like an archive", () => {
		const info = makeInfo({ packageJson: { name: "demo", main: "out/main.js" } });
		const findings = scanElectronText(info, [
			{ relativePath: "app/out/main.js", content: 'app.commandLine.appendSwitch("inspect")' },
			{ relativePath: "app/node_modules/vendor/index.js", content: "webSecurity: false" }
		]);

		expect(findings.map(summary)).toEqual([
			["info", "electron-renderer", "webSecurity: false"],
			["info", "electron-switches", 'appendSwitch("inspect")']
		]);
		expect(findings[0]?.vendor).toBe(true);
		expect(findings[0]?.message).toContain("(vendor code)");
		expect(findings[1]?.vendor).toBeUndefined();
	});

	it("detects preload IPC forwarding in an app/ preload", () => {
		const findings = scanElectronText(makeInfo(), [
			{ relativePath: "app/out/preload.js", content: "ipcRenderer.invoke(channel, payload)" }
		]);

		expect(findings).toHaveLength(1);
		expect(findings[0]?.category).toBe("electron-runtime");
		expect(findings[0]?.source).toBe("app/out/preload.js");
	});
});

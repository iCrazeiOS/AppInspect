import { describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { StringEntry } from "../../../shared/types";
import { checkDebugArtifacts, findBundleDebugArtifacts } from "../debug-artifacts";

// ── Helpers ──

function makeStr(value: string, offset = 0): StringEntry {
	return { value, sectionSource: "__cstring", offset };
}

function params(overrides: Partial<Parameters<typeof checkDebugArtifacts>[0]> = {}) {
	return {
		segmentNames: [],
		sectionNames: [],
		strings: [],
		debugSymbolCount: 0,
		...overrides
	};
}

// ── Binary-level artifacts ──

describe("checkDebugArtifacts", () => {
	it("warns on a DWARF segment", () => {
		const findings = checkDebugArtifacts(params({ segmentNames: ["__DWARF"] }));
		expect(findings).toHaveLength(1);
		expect(findings[0]!.severity).toBe("warning");
		expect(findings[0]!.category).toBe("debug-artifacts");
		expect(findings[0]!.message).toContain("DWARF");
		expect(findings[0]!.evidence).toContain("__DWARF");
	});

	it("warns on DWARF debug sections", () => {
		const findings = checkDebugArtifacts(params({ sectionNames: ["__debug_info"] }));
		expect(findings).toHaveLength(1);
		expect(findings[0]!.severity).toBe("warning");
		expect(findings[0]!.evidence).toContain("__debug_info");
	});

	it("reports retained STABS symbols as info", () => {
		const findings = checkDebugArtifacts(params({ debugSymbolCount: 3 }));
		expect(findings).toHaveLength(1);
		expect(findings[0]!.severity).toBe("info");
		expect(findings[0]!.category).toBe("debug-artifacts");
		expect(findings[0]!.message).toContain("3");
		expect(findings[0]!.evidence).toBe("stabs=3");
	});

	it("emits nothing for a stripped binary carrying only production strings", () => {
		// Must supply realistic-but-benign input: an all-empty fixture would pass
		// against any implementation that returned [] unconditionally.
		expect(
			checkDebugArtifacts(
				params({
					segmentNames: ["__TEXT", "__DATA", "__LINKEDIT"],
					sectionNames: ["__text", "__cstring", "__const", "__objc_methname"],
					strings: [
						makeStr("LoginViewController"),
						makeStr("https://api.example.com/v1/users"),
						makeStr("/System/Library/Frameworks/UIKit.framework/UIKit"),
						makeStr("Failed to load view")
					]
				})
			)
		).toEqual([]);
	});

	it("flags developer source paths but not system paths or URLs", () => {
		const findings = checkDebugArtifacts(
			params({
				strings: [
					makeStr("/Users/alice/dev/app/Sources/Login.swift", 0x40),
					makeStr("/usr/lib/libSystem.dylib"),
					makeStr("https://example.com/a/b"),
					makeStr("a/b/c")
				]
			})
		);
		const paths = findings.filter((f) => f.category === "leaked-source-path");
		expect(paths).toHaveLength(1);
		expect(paths[0]!.severity).toBe("info");
		expect(paths[0]!.evidence).toBe("/Users/alice/dev/app/Sources/Login.swift");
		expect(paths[0]!.location).toBe("offset=0x40");
	});

	it("does not flag system headers matched by the source-extension heuristic", () => {
		const findings = checkDebugArtifacts(
			params({ strings: [makeStr("/usr/include/stdio.h")] })
		);
		expect(findings.filter((f) => f.category === "leaked-source-path")).toHaveLength(0);
	});

	it("dedupes and caps source-path findings at 10", () => {
		const strings = Array.from({ length: 15 }, (_, i) =>
			makeStr(`/Users/alice/dev/project${i}/File.swift`)
		);
		// Duplicate one entry to confirm dedupe
		strings.push(makeStr("/Users/alice/dev/project0/File.swift"));

		const findings = checkDebugArtifacts(params({ strings }));
		const paths = findings.filter((f) => f.category === "leaked-source-path");
		expect(paths).toHaveLength(10);
	});
});

// ── Bundle-level artifacts ──

function makeBundle(files: Record<string, string>, run: (root: string) => void): void {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "appinspect-bundle-"));
	try {
		for (const [relativePath, content] of Object.entries(files)) {
			const fullPath = path.join(root, relativePath);
			fs.mkdirSync(path.dirname(fullPath), { recursive: true });
			fs.writeFileSync(fullPath, content);
		}
		run(root);
	} finally {
		fs.rmSync(root, { recursive: true, force: true });
	}
}

describe("findBundleDebugArtifacts", () => {
	it("classifies source maps by runtime type", () => {
		makeBundle(
			{
				"main.js.map": "{}",
				"main.css.map": "{}",
				"app.ts.map": "{}",
				"UPPER.JS.MAP": "{}",
				"types.d.ts.map": "{}",
				"types.d.mts.map": "{}",
				"types.d.cts.map": "{}",
				"data.map": "{}"
			},
			(root) => {
				const findings = findBundleDebugArtifacts(root);
				const bySource = new Map(findings.map((finding) => [finding.source, finding]));
				expect([...bySource.keys()].sort()).toEqual([
					"UPPER.JS.MAP",
					"app.ts.map",
					"data.map",
					"main.css.map",
					"main.js.map"
				]);

				for (const source of ["main.js.map", "app.ts.map", "UPPER.JS.MAP"]) {
					const script = bySource.get(source);
					expect(script?.severity).toBe("warning");
					expect(script?.message).toContain("JavaScript source map");
				}

				const css = bySource.get("main.css.map");
				expect(css?.severity).toBe("warning");
				expect(css?.message).toContain("CSS source map");

				const unknown = bySource.get("data.map");
				expect(unknown?.severity).toBe("info");
				expect(unknown?.message).toBe("Source map shipped in bundle");
			}
		);
	});

	it("tags vendor maps, caps them at five and keeps app-owned maps", () => {
		const files: Record<string, string> = { "app.js.map": "{}" };
		for (let i = 0; i < 6; i++) {
			files[`node_modules/pkg/map-${i}.js.map`] = "{}";
		}

		makeBundle(files, (root) => {
			const maps = findBundleDebugArtifacts(root).filter(
				(finding) => finding.category === "source-map"
			);
			const vendor = maps.filter((finding) => finding.vendor);
			expect(vendor).toHaveLength(5);
			expect(vendor[0]?.severity).toBe("warning");

			const appOwned = maps.find((finding) => finding.source === "app.js.map");
			expect(appOwned).toBeDefined();
			expect(appOwned?.vendor).toBeUndefined();
		});
	});

	it("visits app-owned directories before vendor directories", () => {
		const files: Record<string, string> = { "zz-app/app.js.map": "{}" };
		for (let i = 0; i < 26; i++) {
			files[`vendor/leak-${i}.dSYM/Contents/Info.plist`] = "";
		}

		makeBundle(files, (root) => {
			// A filesystem that returns `vendor` first would let the dSYM findings
			// fill the 25-finding cap before the app's own map is reached.
			const findings = findBundleDebugArtifacts(root);
			expect(findings).toHaveLength(25);
			const maps = findings.filter((finding) => finding.category === "source-map");
			expect(maps.map((finding) => finding.source)).toEqual(["zz-app/app.js.map"]);
		});
	});

	it("finds shipped build artifacts and ignores normal files", () => {
		const root = fs.mkdtempSync(path.join(os.tmpdir(), "appinspect-bundle-"));
		try {
			fs.mkdirSync(path.join(root, "App.dSYM", "Contents"), { recursive: true });
			fs.writeFileSync(path.join(root, "App.dSYM", "Contents", "leaked.map"), "");
			fs.mkdirSync(path.join(root, "_CodeSignature"), { recursive: true });
			fs.writeFileSync(path.join(root, "_CodeSignature", "skip.map"), "");
			fs.writeFileSync(path.join(root, "main.js"), "console.log(1)");
			fs.writeFileSync(path.join(root, "main.js.map"), "{}");
			fs.writeFileSync(path.join(root, "Foo.swiftinterface"), "// swift");

			const findings = findBundleDebugArtifacts(root);
			expect(findings).toHaveLength(3);

			const sourceMap = findings.find((f) => f.category === "source-map");
			expect(sourceMap).toBeDefined();
			expect(sourceMap!.severity).toBe("warning");
			expect(sourceMap!.source).toBe("main.js.map");

			const swiftInterface = findings.find((f) => f.source === "Foo.swiftinterface");
			expect(swiftInterface).toBeDefined();
			expect(swiftInterface!.severity).toBe("info");
			expect(swiftInterface!.category).toBe("debug-artifacts");

			const dsym = findings.find((f) => f.source === "App.dSYM");
			expect(dsym).toBeDefined();
			expect(dsym!.severity).toBe("warning");
			expect(dsym!.category).toBe("debug-artifacts");
		} finally {
			fs.rmSync(root, { recursive: true, force: true });
		}
	});
});

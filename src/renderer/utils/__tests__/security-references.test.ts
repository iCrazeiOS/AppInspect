import { describe, expect, it } from "bun:test";
import type { SecurityFinding } from "../../../shared/types";
import {
	collectTreePaths,
	matchBinaryName,
	matchTreePath,
	parseLocationOffset,
	resolveFindingTargets,
	resolveHardeningTarget,
	resolveReference,
	type SecurityReferenceContext
} from "../security-references";

function finding(partial: Partial<SecurityFinding>): SecurityFinding {
	return {
		severity: "warning",
		category: "credential-leak",
		message: "Finding",
		evidence: "",
		...partial
	};
}

const emptyContext: SecurityReferenceContext = {
	binaries: [],
	currentBinaryIndex: 0,
	hasElectron: false,
	fuseNames: []
};

describe("parseLocationOffset", () => {
	it("parses hex offsets and rejects missing or malformed values", () => {
		expect(parseLocationOffset("offset=0x1a2b")).toBe(0x1a2b);
		expect(parseLocationOffset(undefined)).toBeNull();
		expect(parseLocationOffset("section=__TEXT")).toBeNull();
		expect(parseLocationOffset("offset=0xzz")).toBeNull();
	});
});

describe("matchBinaryName", () => {
	const ctx: SecurityReferenceContext = {
		...emptyContext,
		binaries: [
			{ name: "App", type: "main" },
			{ name: "Frameworks/Bar.framework/Bar", type: "framework" }
		]
	};

	it("matches base names and relative paths", () => {
		expect(matchBinaryName("Bar", ctx)).toBe(1);
		expect(matchBinaryName("Frameworks/Bar.framework/Bar", ctx)).toBe(1);
		expect(matchBinaryName("www/js/app.js", ctx)).toBeNull();
	});
});

describe("matchTreePath", () => {
	it("resolves relative paths against absolute tree paths", () => {
		expect(matchTreePath(["/tmp/x/App.app/www/js/app.js"], "www/js/app.js")).toBe(
			"/tmp/x/App.app/www/js/app.js"
		);
	});

	it("prefers exact matches and rejects ambiguous base names", () => {
		expect(matchTreePath(["/a/b.js", "/c/b.js"], "/a/b.js")).toBe("/a/b.js");
		expect(matchTreePath(["/a/b.js", "/c/b.js"], "b.js")).toBeNull();
		expect(matchTreePath([], "b.js")).toBeNull();
	});
});

describe("collectTreePaths", () => {
	it("flattens nested trees", () => {
		interface TreeNode {
			path: string;
			children?: TreeNode[];
		}
		const tree: TreeNode[] = [
			{
				path: "/root/a",
				children: [{ path: "/root/a/b", children: [{ path: "/root/a/b/c" }] }]
			},
			{ path: "/root/d" }
		];
		expect(collectTreePaths(tree)).toEqual(["/root/a", "/root/a/b", "/root/a/b/c", "/root/d"]);
	});
});

describe("resolveReference", () => {
	it("routes binary string offsets to Strings", () => {
		const target = resolveReference(
			finding({ category: "credential-leak", location: "offset=0x40" }),
			"location",
			emptyContext
		);
		expect(target).toEqual({ sectionTab: "strings", kind: "string", offset: 0x40 });
	});

	it("routes bundle findings to Files when a source path is present", () => {
		const target = resolveReference(
			finding({ category: "credential-leak", source: "www/js/app.js" }),
			"source",
			emptyContext
		);
		expect(target).toEqual({ sectionTab: "files", kind: "file", path: "www/js/app.js" });
	});

	it("does not route a finding from another binary", () => {
		const ctx: SecurityReferenceContext = {
			...emptyContext,
			binaries: [
				{ name: "App", type: "main" },
				{ name: "Foo", type: "framework" }
			]
		};
		expect(resolveReference(finding({ source: "Foo" }), "source", ctx)).toBeNull();
	});

	it("does not route a folder binary's own relative name", () => {
		const ctx: SecurityReferenceContext = {
			...emptyContext,
			binaries: [{ name: "Frameworks/Bar.framework/Bar", type: "framework" }]
		};
		expect(
			resolveReference(finding({ source: "Frameworks/Bar.framework/Bar" }), "source", ctx)
		).toBeNull();
	});

	it("routes unsafe API evidence to Symbols", () => {
		expect(
			resolveReference(
				finding({ category: "unsafe-api", evidence: "_CC_MD5" }),
				"evidence",
				emptyContext
			)
		).toEqual({ sectionTab: "symbols", kind: "symbol", name: "_CC_MD5" });
		expect(
			resolveReference(
				finding({ category: "weak-crypto", evidence: "_MD5_Init" }),
				"evidence",
				emptyContext
			)
		).toEqual({ sectionTab: "symbols", kind: "symbol", name: "_MD5_Init" });
	});

	it("routes function names to Symbols", () => {
		expect(
			resolveReference(
				finding({
					category: "credential-leak",
					functionName: "-[AppDelegate application:didFinishLaunchingWithOptions:]"
				}),
				"functionName",
				emptyContext
			)
		).toEqual({
			sectionTab: "symbols",
			kind: "symbol",
			name: "-[AppDelegate application:didFinishLaunchingWithOptions:]"
		});
	});

	describe("Electron", () => {
		const ctx: SecurityReferenceContext = {
			...emptyContext,
			hasElectron: true,
			fuseNames: ["RunAsNode"]
		};

		it("routes known fuses to the package view", () => {
			expect(
				resolveReference(
					finding({ category: "electron-fuses", evidence: "RunAsNode=enabled" }),
					"evidence",
					ctx
				)
			).toEqual({
				sectionTab: "electron",
				kind: "electron",
				view: "package",
				fuse: "RunAsNode"
			});
		});

		it("leaves unknown fuses non-navigable", () => {
			expect(
				resolveReference(
					finding({ category: "electron-fuses", evidence: "FuseNope=enabled" }),
					"evidence",
					ctx
				)
			).toBeNull();
		});

		it("routes integrity findings to the integrity card", () => {
			expect(
				resolveReference(
					finding({
						category: "electron-integrity",
						source: "app.asar",
						evidence: "expected aa, actual bb"
					}),
					"source",
					ctx
				)
			).toEqual({ sectionTab: "electron", kind: "electron", view: "package" });
		});

		it("routes shipped source maps to the matching path button", () => {
			expect(
				resolveReference(
					finding({
						category: "electron-integrity",
						source: "app.asar",
						message: "Shipped source maps (2) expose original source",
						evidence: "renderer/app.js.map, main/index.js.map"
					}),
					"source",
					ctx
				)
			).toEqual({
				sectionTab: "electron",
				kind: "electron",
				view: "package",
				sourceMap: "renderer/app.js.map"
			});
		});

		it("routes archive files to the Electron file tree", () => {
			expect(
				resolveReference(
					finding({
						category: "electron-renderer",
						source: "app.asar/renderer/index.js"
					}),
					"source",
					ctx
				)
			).toEqual({
				sectionTab: "electron",
				kind: "electron",
				view: "files",
				path: "renderer/index.js"
			});
		});

		it("routes unpacked archive files to the Electron file tree", () => {
			expect(
				resolveReference(
					finding({ category: "electron-csp", source: "app.asar.unpacked/index.html" }),
					"source",
					ctx
				)
			).toEqual({
				sectionTab: "electron",
				kind: "electron",
				view: "files",
				path: "index.html"
			});
		});

		it("ignores Electron sources without Electron data", () => {
			expect(
				resolveReference(
					finding({ category: "electron-renderer", source: "app.asar/index.js" }),
					"source",
					emptyContext
				)
			).toBeNull();
		});
	});

	it("routes debug artifacts and source maps to Files", () => {
		for (const category of ["debug-artifacts", "source-map"]) {
			expect(
				resolveReference(
					finding({ category, source: "assets/main.js.map" }),
					"source",
					emptyContext
				)
			).toEqual({ sectionTab: "files", kind: "file", path: "assets/main.js.map" });
		}
	});
});

describe("resolveHardeningTarget", () => {
	it("maps hardening messages to Overview row keys", () => {
		expect(
			resolveHardeningTarget(
				finding({
					category: "binary-hardening",
					message: "PIE (Position Independent Executable) is not enabled"
				})
			)
		).toEqual({ sectionTab: "overview", kind: "hardening", key: "pie" });
		expect(
			resolveHardeningTarget(
				finding({ category: "binary-hardening", message: "Stack canaries not detected" })
			)
		).toEqual({ sectionTab: "overview", kind: "hardening", key: "stackCanaries" });
		expect(
			resolveHardeningTarget(
				finding({
					category: "binary-hardening",
					message: "ARC (Automatic Reference Counting) not detected"
				})
			)
		).toEqual({ sectionTab: "overview", kind: "hardening", key: "arc" });
		expect(
			resolveHardeningTarget(
				finding({
					category: "binary-hardening",
					message: "Rpath present — potential hijack vector on macOS"
				})
			)
		).toEqual({ sectionTab: "overview", kind: "hardening", key: "rpath" });
	});

	it("ignores other categories", () => {
		expect(resolveHardeningTarget(finding({ category: "credential-leak" }))).toBeNull();
	});
});

describe("resolveFindingTargets", () => {
	it("collects every navigable field", () => {
		const targets = resolveFindingTargets(
			finding({
				category: "credential-leak",
				functionName: "_main",
				source: "www/app.js",
				evidence: "token=abc"
			}),
			emptyContext
		);
		expect(targets.functionName).toEqual({
			sectionTab: "symbols",
			kind: "symbol",
			name: "_main"
		});
		expect(targets.source).toEqual({
			sectionTab: "files",
			kind: "file",
			path: "www/app.js"
		});
		expect(targets.evidence).toBeUndefined();
	});
});

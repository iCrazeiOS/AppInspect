/**
 * Tests for JSON export (json.ts).
 */

import { describe, expect, it } from "bun:test";
import type {
	AnalysisResult,
	BinaryHardening,
	MachOHeader,
	PlistValue
} from "../../../shared/types";
import { EMPTY_SIZE_BREAKDOWN } from "../../analysis/size-breakdown";
import { exportAnalysis } from "../json";

const HEADER: MachOHeader = {
	magic: 0xfeedfacf,
	cputype: 0x0100000c,
	cpusubtype: 0,
	filetype: 2,
	ncmds: 0,
	sizeofcmds: 0,
	flags: 0,
	reserved: 0
};

const HARDENING: BinaryHardening = {
	pie: true,
	arc: true,
	stackCanaries: true,
	encrypted: false,
	stripped: true
};

function makeResult(
	infoPlist: { [key: string]: PlistValue } = {},
	debVersion?: string
): AnalysisResult {
	return {
		overview: {
			sourceType: "ipa",
			filePath: "/tmp/Example.ipa",
			ipa: {
				bundlePath: "/tmp/Example.app",
				appName: "Example",
				binaries: [
					{ name: "Example", path: "/tmp/Example.app/Example", type: "main", size: 0 }
				]
			},
			header: HEADER,
			fatArchs: [],
			buildVersion: null,
			encryptionInfo: null,
			hardening: HARDENING,
			debControl:
				debVersion === undefined
					? undefined
					: {
							package: "com.example.app",
							name: "Example",
							version: debVersion,
							architecture: "iphoneos-arm",
							description: "Example"
						}
		},
		hooks: { frameworks: [], targetBundles: [], hookedClasses: [], hookSymbols: [] },
		size: EMPTY_SIZE_BREAKDOWN,
		electron: null,
		strings: [],
		localisationStrings: [],
		headers: { machO: HEADER, fatArchs: [], loadCommands: [] },
		libraries: [],
		symbols: [],
		objc: { classes: [], categories: [], protocols: [], protocolDetails: [] },
		swift: {
			types: [],
			protocols: [],
			conformances: [],
			present: false,
			unresolvedConformances: 0
		},
		entitlements: [],
		infoPlist,
		security: { findings: [], hardening: HARDENING },
		files: []
	};
}

function wrapper(result: AnalysisResult): {
	exportedAt: string;
	appName: string;
	version: string;
	data: Record<string, unknown>;
} {
	return JSON.parse(exportAnalysis(result));
}

describe("json export", () => {
	it("emits the plist short version string", () => {
		const exported = wrapper(
			makeResult({
				CFBundleShortVersionString: "2026.9.1",
				CFBundleVersion: "20260901"
			})
		);
		expect(exported.version).toBe("2026.9.1");
		expect(exported.appName).toBe("Example");
	});

	it("falls back to the build number when the short version is missing or empty", () => {
		expect(wrapper(makeResult({ CFBundleVersion: "42" })).version).toBe("42");
		expect(
			wrapper(makeResult({ CFBundleShortVersionString: "  ", CFBundleVersion: "42" })).version
		).toBe("42");
	});

	it("falls back to the DEB package version", () => {
		expect(wrapper(makeResult({}, "1.2.3-1")).version).toBe("1.2.3-1");
	});

	it("reports Unknown without any version metadata", () => {
		expect(wrapper(makeResult()).version).toBe("Unknown");
	});

	it("keeps the wrapper for filtered exports", () => {
		const exported = wrapper(makeResult({ CFBundleShortVersionString: "9.9.9" }));
		expect(exported.data.overview).toBeDefined();

		const filtered = JSON.parse(exportAnalysis(makeResult(), ["overview"]));
		expect(filtered.version).toBe("Unknown");
		expect(filtered.data).toHaveProperty("overview");
		expect(filtered.data).not.toHaveProperty("infoPlist");
	});

	it("exports the objc tab as a single consolidated key", () => {
		const filtered = JSON.parse(exportAnalysis(makeResult(), ["objc"]));
		expect(filtered.data).toHaveProperty("objc");
		expect(filtered.data.objc).toHaveProperty("classes");
		expect(filtered.data.objc).toHaveProperty("categories");
		expect(filtered.data.objc).toHaveProperty("protocolDetails");
		expect(filtered.data).not.toHaveProperty("classes");
	});
});

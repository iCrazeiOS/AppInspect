/**
 * Tests for SARIF export (sarif.ts).
 */

import { describe, expect, it } from "bun:test";
import type {
	AnalysisResult,
	BinaryHardening,
	MachOHeader,
	SecurityFinding
} from "../../../shared/types";
import { EMPTY_SIZE_BREAKDOWN } from "../../analysis/size-breakdown";
import { exportSarif, findingsAtOrAbove } from "../sarif";

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

function makeResult(findings: SecurityFinding[]): AnalysisResult {
	return {
		overview: {
			sourceType: "macho",
			filePath: "/tmp/Example.app/Example",
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
			hardening: HARDENING
		},
		hooks: { frameworks: [], targetBundles: [], hookedClasses: [], hookSymbols: [] },
		size: EMPTY_SIZE_BREAKDOWN,
		strings: [],
		localisationStrings: [],
		headers: { machO: HEADER, fatArchs: [], loadCommands: [] },
		libraries: [],
		symbols: [],
		classes: [],
		protocols: [],
		protocolDetails: [],
		swift: {
			types: [],
			protocols: [],
			conformances: [],
			present: false,
			unresolvedConformances: 0
		},
		entitlements: [],
		infoPlist: {},
		security: { findings, hardening: HARDENING },
		files: []
	};
}

const FINDINGS: SecurityFinding[] = [
	{
		severity: "critical",
		category: "credential-leak",
		message: "Hardcoded AWS access key",
		evidence: "AKIAIOSFODNN7EXAMPLE",
		source: "Payload/Example.app/main.js"
	},
	{
		severity: "warning",
		category: "binary-hardening",
		message: "Stack canaries not detected",
		evidence: "No stack canary symbols found"
	},
	{
		severity: "info",
		category: "weak-crypto",
		message: "Weak cryptographic function used",
		evidence: "_CC_MD5",
		location: "offset=0x1234",
		functionName: "md5_hash"
	},
	{
		severity: "warning",
		category: "credential-leak",
		message: "Hardcoded password",
		evidence: "password=hunter2"
	}
];

describe("sarif export", () => {
	it("emits a SARIF 2.1.0 log from the AppInspect driver", () => {
		const log = JSON.parse(exportSarif(makeResult(FINDINGS)));
		expect(log.version).toBe("2.1.0");
		expect(log.$schema).toBe("https://json.schemastore.org/sarif-2.1.0.json");
		expect(log.runs[0].tool.driver.name).toBe("AppInspect");
	});

	it("dedupes rules by id and keeps the highest severity level", () => {
		const log = JSON.parse(exportSarif(makeResult(FINDINGS)));
		const rules = log.runs[0].tool.driver.rules;
		const ids = rules.map((r: { id: string }) => r.id);

		expect(ids).toEqual([
			"appinspect/binary-hardening",
			"appinspect/credential-leak",
			"appinspect/weak-crypto"
		]);
		expect(ids.filter((id: string) => id === "appinspect/credential-leak")).toHaveLength(1);
		expect(
			rules.find((r: { id: string }) => r.id === "appinspect/credential-leak")
				.defaultConfiguration.level
		).toBe("error");
	});

	it("maps severity to SARIF levels", () => {
		const log = JSON.parse(exportSarif(makeResult(FINDINGS)));
		const levels = log.runs[0].results.map((r: { level: string }) => r.level);
		expect(levels).toEqual(["error", "warning", "note", "warning"]);
	});

	it("resolves ruleIndex and ruleId per result", () => {
		const log = JSON.parse(exportSarif(makeResult(FINDINGS)));
		const result = log.runs[0].results[0];
		expect(result.ruleId).toBe("appinspect/credential-leak");
		expect(log.runs[0].tool.driver.rules[result.ruleIndex].id).toBe(
			"appinspect/credential-leak"
		);
	});

	it("parses an offset location into byteOffset and snippet", () => {
		const log = JSON.parse(exportSarif(makeResult(FINDINGS)));
		const region = log.runs[0].results[2].locations[0].physicalLocation.region;
		expect(region.byteOffset).toBe(0x1234);
		expect(region.snippet.text).toBe("_CC_MD5");
	});

	it("uses functionName as a logical location", () => {
		const log = JSON.parse(exportSarif(makeResult(FINDINGS)));
		const logical = log.runs[0].results[2].locations[0].logicalLocations;
		expect(logical[0].name).toBe("md5_hash");
	});

	it("uses finding source, else the analysed file basename", () => {
		const log = JSON.parse(exportSarif(makeResult(FINDINGS)));
		const [first, second] = log.runs[0].results;
		expect(first.locations[0].physicalLocation.artifactLocation.uri).toBe(
			"Payload/Example.app/main.js"
		);
		expect(second.locations[0].physicalLocation.artifactLocation.uri).toBe("Example");
		expect(second.locations[0].physicalLocation.artifactLocation.uriBaseId).toBe("SRCROOT");
	});

	it("emits no undefined values anywhere in the serialised log", () => {
		const output = exportSarif(makeResult(FINDINGS));
		expect(output.includes("undefined")).toBe(false);
	});
});

describe("findingsAtOrAbove", () => {
	it("counts findings at or above a severity threshold", () => {
		expect(findingsAtOrAbove(FINDINGS, "critical")).toBe(1);
		expect(findingsAtOrAbove(FINDINGS, "warning")).toBe(3);
		expect(findingsAtOrAbove(FINDINGS, "info")).toBe(4);
	});
});

import { describe, expect, it } from "bun:test";
import type { EncryptionInfo, StringEntry, SymbolEntry } from "../../../shared/types";
import { getBinaryHardening, runSecurityScan, type SecurityScanParams } from "../security";

// ── Helpers ──

function makeStr(value: string, offset = 0): StringEntry {
	return { value, sectionSource: "__cstring", offset };
}

function makeSym(name: string, type: SymbolEntry["type"] = "imported"): SymbolEntry {
	return { name, type, address: 0n, sectionIndex: 0 };
}

const MH_PIE = 0x200000;

function baseParams(overrides?: Partial<SecurityScanParams>): SecurityScanParams {
	return {
		strings: [],
		symbols: [],
		headerFlags: MH_PIE,
		encryption: null,
		loadCommands: [],
		...overrides
	};
}

// ── Tests ──

describe("Security Scan Engine", () => {
	// ── Credential patterns ──

	it("detects AWS access keys", () => {
		const findings = runSecurityScan(
			baseParams({
				strings: [makeStr("key=AKIA1234567890ABCDEF")]
			})
		);
		const critical = findings.filter(
			(f) => f.severity === "critical" && f.category === "credential-leak"
		);
		expect(critical.length).toBeGreaterThanOrEqual(1);
		expect(critical.some((f) => f.evidence.includes("AKIA"))).toBe(true);
	});

	it("detects MongoDB connection URIs", () => {
		const findings = runSecurityScan(
			baseParams({
				strings: [makeStr("mongodb://user:pass@host/db")]
			})
		);
		const critical = findings.filter(
			(f) => f.severity === "critical" && f.category === "credential-leak"
		);
		// Should match both MongoDB URI and URL-with-credentials patterns
		expect(critical.length).toBeGreaterThanOrEqual(1);
		expect(critical.some((f) => f.evidence.includes("mongodb"))).toBe(true);
	});

	it("detects PostgreSQL URIs", () => {
		const findings = runSecurityScan(
			baseParams({
				strings: [makeStr("postgresql://admin:secret@db.host:5432/mydb")]
			})
		);
		const dbFindings = findings.filter(
			(f) => f.severity === "critical" && f.evidence.includes("postgresql")
		);
		expect(dbFindings.length).toBeGreaterThanOrEqual(1);
	});

	it("detects private keys", () => {
		const findings = runSecurityScan(
			baseParams({
				strings: [makeStr("-----BEGIN RSA PRIVATE KEY-----")]
			})
		);
		expect(
			findings.some((f) => f.severity === "critical" && f.evidence.includes("PRIVATE KEY"))
		).toBe(true);
	});

	it("detects Slack tokens", () => {
		const findings = runSecurityScan(
			baseParams({
				strings: [makeStr("xoxb-1234-5678-abcdef")]
			})
		);
		expect(
			findings.some((f) => f.severity === "critical" && f.evidence.includes("xoxb-"))
		).toBe(true);
	});

	// ── PIE ──

	it("reports PIE enabled when MH_PIE flag is set", () => {
		const findings = runSecurityScan(baseParams({ headerFlags: MH_PIE }));
		const pie = findings.find((f) => f.message.includes("PIE") && f.severity === "info");
		expect(pie).toBeDefined();
	});

	it("reports missing PIE as info", () => {
		const findings = runSecurityScan(baseParams({ headerFlags: 0 }));
		const pie = findings.find((f) => f.message.includes("PIE") && f.severity === "info");
		expect(pie).toBeDefined();
	});

	// ── Stack canaries ──

	it("detects stack canaries via symbol names", () => {
		const params = baseParams({
			symbols: [makeSym("___stack_chk_guard")]
		});
		const findings = runSecurityScan(params);
		expect(
			findings.some((f) => f.message.includes("Stack canaries") && f.severity === "info")
		).toBe(true);

		const hardening = getBinaryHardening({
			symbols: params.symbols,
			headerFlags: params.headerFlags,
			encryption: null
		});
		expect(hardening.stackCanaries).toBe(true);
	});

	// ── Insecure APIs ──

	it("warns on memory-unsafe functions like _strcpy", () => {
		const findings = runSecurityScan(
			baseParams({
				symbols: [makeSym("_strcpy"), makeSym("_gets")]
			})
		);
		const unsafe = findings.filter((f) => f.category === "unsafe-api");
		expect(unsafe.length).toBe(2);
		expect(unsafe[0]!.severity).toBe("warning");
	});

	it("reports weak crypto functions as info", () => {
		const findings = runSecurityScan(
			baseParams({
				symbols: [makeSym("_CC_MD5")]
			})
		);
		const weak = findings.filter((f) => f.category === "weak-crypto");
		expect(weak.length).toBe(1);
		expect(weak[0]!.severity).toBe("info");
		expect(weak[0]!.evidence).toBe("_CC_MD5");
	});

	it("reports dynamic loading as info", () => {
		const findings = runSecurityScan(baseParams({ symbols: [makeSym("_dlopen")] }));
		const dl = findings.filter((f) => f.category === "dynamic-loading");
		expect(dl.length).toBe(1);
		expect(dl[0]!.severity).toBe("info");
	});

	// ── Jailbreak detection ──

	it("detects jailbreak-detection strings", () => {
		const findings = runSecurityScan(
			baseParams({
				strings: [
					makeStr("cydia://"),
					makeStr("/Applications/Cydia.app"),
					makeStr("frida-server")
				]
			})
		);
		const jb = findings.filter((f) => f.category === "jailbreak-detection");
		expect(jb.length).toBe(3);
		expect(jb.every((f) => f.severity === "info")).toBe(true);
	});

	// ── No false positives ──

	it("does not flag common English words", () => {
		const findings = runSecurityScan(
			baseParams({
				strings: [
					makeStr("application"),
					makeStr("password-reset-flow"),
					makeStr("the system is running"),
					makeStr("substring copy complete")
				]
			})
		);
		const critical = findings.filter((f) => f.severity === "critical");
		expect(critical.length).toBe(0);
	});

	// ── Binary hardening summary ──

	it("returns correct BinaryHardening summary", () => {
		const h = getBinaryHardening({
			symbols: [
				makeSym("_objc_release"),
				makeSym("___stack_chk_fail"),
				// enough symbols so stripped is false
				...Array.from({ length: 20 }, (_, i) => makeSym(`_sym${i}`))
			],
			headerFlags: MH_PIE,
			encryption: { cryptoff: 0, cryptsize: 0, cryptid: 0 }
		});

		expect(h.pie).toBe(true);
		expect(h.arc).toBe(true);
		expect(h.stackCanaries).toBe(true);
		expect(h.encrypted).toBe(false); // cryptid == 0
		expect(h.stripped).toBe(false); // 22 symbols
	});

	it("reports stripped when symbol count < 10", () => {
		const h = getBinaryHardening({
			symbols: [makeSym("_main")],
			headerFlags: 0,
			encryption: null
		});
		expect(h.stripped).toBe(true);
		expect(h.pie).toBe(false);
	});

	// ── Encryption ──

	it("reports encryption status as info", () => {
		const findings = runSecurityScan(
			baseParams({
				encryption: { cryptoff: 0x1000, cryptsize: 0x2000, cryptid: 1 }
			})
		);
		const enc = findings.find((f) => f.message.includes("encrypted") && f.severity === "info");
		expect(enc).toBeDefined();
	});

	// ── Rpath ──

	it("reports LC_RPATH as warning on macOS", () => {
		const LC_RPATH_VAL = 0x8000001c;
		const findings = runSecurityScan(
			baseParams({
				loadCommands: [{ cmd: LC_RPATH_VAL, path: "/usr/lib" }],
				platform: 1 // macOS
			})
		);
		const rpath = findings.find((f) => f.message.includes("Rpath"));
		expect(rpath).toBeDefined();
		expect(rpath!.severity).toBe("warning");
	});

	it("suppresses PIE and rpath findings on iOS", () => {
		const LC_RPATH_VAL = 0x8000001c;
		const findings = runSecurityScan(
			baseParams({
				headerFlags: 0,
				loadCommands: [{ cmd: LC_RPATH_VAL, path: "/usr/lib" }],
				platform: 2 // iOS
			})
		);
		expect(findings.find((f) => f.message.includes("PIE"))).toBeUndefined();
		expect(findings.find((f) => f.message.includes("Rpath"))).toBeUndefined();
	});

	// ── iOS-specific severity adjustments ──

	it("downgrades unsafe C APIs to info on iOS", () => {
		const findings = runSecurityScan(
			baseParams({
				symbols: [makeSym("_strcpy")],
				platform: 2 // iOS
			})
		);
		const unsafe = findings.filter((f) => f.category === "unsafe-api");
		expect(unsafe.length).toBe(1);
		expect(unsafe[0]!.severity).toBe("info");
	});

	it("downgrades dangerous syscalls to info on iOS", () => {
		const findings = runSecurityScan(
			baseParams({
				symbols: [makeSym("_system"), makeSym("_fork")],
				platform: 2 // iOS
			})
		);
		const dangerous = findings.filter((f) => f.category === "dangerous-api");
		expect(dangerous.length).toBe(2);
		expect(dangerous.every((f) => f.severity === "info")).toBe(true);
	});

	// ── Google/Firebase key severity ──

	it("reports Google/Firebase API key as warning not critical", () => {
		const findings = runSecurityScan(
			baseParams({
				strings: [makeStr("AIzaSyA1234567890abcdefghijklmnopqrstuv")]
			})
		);
		const google = findings.filter(
			(f) => f.category === "credential-leak" && f.evidence.includes("AIza")
		);
		expect(google.length).toBeGreaterThanOrEqual(1);
		expect(google[0]!.severity).toBe("warning");
	});
});

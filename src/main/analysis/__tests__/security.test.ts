import { describe, expect, it } from "bun:test";
import type { SecurityFinding, StringEntry, SymbolEntry } from "../../../shared/types";
import {
	adjustElectronHardeningFindings,
	dedupeAndCapFindings,
	getBinaryHardening,
	isScannableExtension,
	MAX_FINDINGS_PER_CATEGORY,
	runSecurityScan,
	type SecurityScanParams,
	scanBundleFileContents
} from "../security";

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
		segmentNames: [],
		sectionNames: [],
		debugSymbolCount: 0,
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

	it("does not report a lone private key header", () => {
		const findings = runSecurityScan(
			baseParams({
				strings: [makeStr("-----BEGIN RSA PRIVATE KEY-----")]
			})
		);
		expect(findings.filter((f) => f.evidence.includes("PRIVATE KEY"))).toEqual([]);
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

	// baseParams() already defaults to headerFlags: MH_PIE, so every other test in
	// this file exercises the PIE-set branch. Only the negative case needs stating.
	it("does not report PIE when MH_PIE flag is set", () => {
		const findings = runSecurityScan(baseParams({ headerFlags: MH_PIE }));
		expect(findings.find((f) => f.message.includes("PIE"))).toBeUndefined();
	});

	it("reports missing PIE as warning", () => {
		const findings = runSecurityScan(baseParams({ headerFlags: 0 }));
		const pie = findings.find((f) => f.message.includes("PIE"));
		expect(pie).toBeDefined();
		expect(pie!.severity).toBe("warning");
		expect(pie!.message).toContain("not enabled");
	});

	// ── Stack canaries ──

	it("detects stack canaries via symbol names", () => {
		// A single canary symbol also leaves the binary "stripped", which emits an
		// unrelated finding — assert specifically on the canary rule.
		const params = baseParams({
			symbols: [makeSym("___stack_chk_guard")]
		});
		const findings = runSecurityScan(params);
		expect(findings.find((f) => f.message.includes("Stack canaries"))).toBeUndefined();

		const hardening = getBinaryHardening({
			symbols: params.symbols,
			headerFlags: params.headerFlags,
			encryption: null
		});
		expect(hardening.stackCanaries).toBe(true);
	});

	it("reports missing stack canaries when no canary symbol is present", () => {
		const findings = runSecurityScan(baseParams());
		const canary = findings.find((f) => f.message.includes("Stack canaries"));
		expect(canary).toBeDefined();
		expect(canary!.severity).toBe("warning");
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

	it("does not flag Frida as a substring of an English word", () => {
		const findings = runSecurityScan(
			baseParams({
				strings: [makeStr("Friday the 13th")]
			})
		);
		expect(findings.filter((f) => f.category === "jailbreak-detection")).toHaveLength(0);

		// Underscore-separated identifiers are still Frida references.
		const detected = runSecurityScan(
			baseParams({
				strings: [makeStr("frida_server")]
			})
		);
		expect(detected.filter((f) => f.category === "jailbreak-detection")).toHaveLength(1);
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

	it("emits no binary-hardening findings for a fully hardened binary", () => {
		const findings = runSecurityScan(
			baseParams({
				symbols: [
					makeSym("_objc_release"),
					makeSym("___stack_chk_guard"),
					...Array.from({ length: 10 }, (_, i) => makeSym(`_sym${i}`))
				],
				encryption: { cryptoff: 0, cryptsize: 0, cryptid: 0 }
			})
		);
		expect(findings.filter((f) => f.category === "binary-hardening")).toHaveLength(0);
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

describe("scannable extensions", () => {
	it("treats modern module extensions as scannable", () => {
		expect(isScannableExtension(".mjs")).toBe(true);
		expect(isScannableExtension(".cjs")).toBe(true);
	});

	it("treats key material extensions as scannable, but not certificates", () => {
		expect(isScannableExtension(".pem")).toBe(true);
		expect(isScannableExtension(".key")).toBe(true);
		expect(isScannableExtension(".p8")).toBe(true);
		expect(isScannableExtension(".p12")).toBe(false);
		expect(isScannableExtension(".crt")).toBe(false);
		expect(isScannableExtension(".cer")).toBe(false);
	});
});

// ── G4: expanded key/credential coverage ──

const ALNUM = "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5hI7";

function fill(len: number, alphabet = ALNUM): string {
	return alphabet.repeat(Math.ceil(len / alphabet.length)).slice(0, len);
}

function b64(value: string): string {
	return Buffer.from(value).toString("base64");
}

function jwt(payload: object): string {
	const enc = (value: object): string => Buffer.from(JSON.stringify(value)).toString("base64url");
	return `${enc({ alg: "HS256", typ: "JWT" })}.${enc(payload)}.${fill(43)}`;
}

function credentialFindings(strings: string[]): SecurityFinding[] {
	return runSecurityScan(baseParams({ strings: strings.map((s) => makeStr(s)) })).filter(
		(f) => f.category === "credential-leak"
	);
}

describe("expanded credential patterns", () => {
	it("detects GitHub classic and fine-grained tokens", () => {
		for (const token of [
			`ghp_${fill(36)}`,
			`github_pat_${fill(22)}_${fill(59, "L2mN4pQ6rS8tU0vW")}`
		]) {
			const [finding] = credentialFindings([token]).filter((f) =>
				f.message.includes("GitHub token")
			);
			expect(finding?.severity).toBe("critical");
			// The retained prefix is capped; a "… (N chars)" note may follow.
			expect((finding?.evidence ?? "").length).toBeLessThanOrEqual(64 + 20);
		}
	});

	it("detects live Stripe keys but not test keys", () => {
		for (const token of [`sk_live_${fill(24)}`, `rk_live_${fill(24)}`]) {
			const [finding] = credentialFindings([token]).filter((f) =>
				f.message.includes("Stripe live")
			);
			expect(finding?.severity).toBe("critical");
		}
		expect(
			credentialFindings([`sk_test_${fill(24)}`]).filter((f) => f.message.includes("Stripe"))
		).toEqual([]);
	});

	it("detects a SendGrid API key", () => {
		const token = `SG.${fill(22)}.${fill(43, "wXyZ0aBcD")}`;
		const [finding] = credentialFindings([token]).filter((f) => f.message.includes("SendGrid"));
		expect(finding?.severity).toBe("critical");
		expect(
			credentialFindings(["SG.abc.def"]).filter((f) => f.message.includes("SendGrid"))
		).toEqual([]);
	});

	it("reports a Twilio SID as a warning", () => {
		const token = `SK${fill(32, "0123456789abcdef")}`;
		const [finding] = credentialFindings([token]).filter((f) => f.message.includes("Twilio"));
		expect(finding?.severity).toBe("warning");

		// Account SIDs are public identifiers.
		expect(
			credentialFindings([`AC${fill(32, "0123456789abcdef")}`]).filter((f) =>
				f.message.includes("Twilio")
			)
		).toEqual([]);
	});

	it("detects Discord webhook URLs", () => {
		const token = `https://discord.com/api/webhooks/${fill(19, "123456789")}/${fill(68)}`;
		const [finding] = credentialFindings([token]).filter((f) => f.message.includes("Discord"));
		expect(finding?.severity).toBe("critical");
		expect(
			credentialFindings(["https://discord.com/api/webhooks/123"]).filter((f) =>
				f.message.includes("Discord")
			)
		).toEqual([]);
	});

	it("classifies JWTs, escalating a Supabase service_role claim", () => {
		const generic = credentialFindings([jwt({ sub: "user-123" })]).filter((f) =>
			f.message.includes("JWT")
		);
		expect(generic[0]?.severity).toBe("warning");

		const service = credentialFindings([jwt({ role: "service_role" })]).filter((f) =>
			f.message.includes("service_role")
		);
		expect(service[0]?.severity).toBe("critical");
	});

	it("detects an Azure Storage account key", () => {
		const token = `AccountKey=${fill(86, "aBcDeFgHiJkLmNoP")}==`;
		const [finding] = credentialFindings([token]).filter((f) => f.message.includes("Azure"));
		expect(finding?.severity).toBe("critical");
		expect(
			credentialFindings(["AccountKey=short"]).filter((f) => f.message.includes("Azure"))
		).toEqual([]);
	});

	it("suppresses placeholder tokens", () => {
		expect(credentialFindings([`ghp_${"x".repeat(36)}`])).toEqual([]);
		expect(
			credentialFindings(["AKIAIOSFODNN7EXAMPLE"]).filter((f) => f.message.includes("AWS"))
		).toEqual([]);
	});
});

describe("password assignment precision", () => {
	function passwordFindings(text: string): SecurityFinding[] {
		return credentialFindings([text]).filter((f) => f.message.includes("password"));
	}

	it("ignores property names, enums, selectors, docs and fixtures", () => {
		// Real false positives from the Bitwarden, Signal and VSCodium audits.
		const falsePositives = [
			'SetInitialPassword:"set-initial-password"',
			'UnlockMethod = { MasterPassword: "masterPassword" }',
			'password="myp@ssword123"',
			'password:"password"',
			'removePassword: "removePassword"',
			'Password: "masterPassword"',
			'password: "[type=password]"',
			'password: "myPassword"',
			'password = "test1234"',
			'password = "qwerty123"'
		];
		for (const text of falsePositives) {
			expect(passwordFindings(text), text).toEqual([]);
		}
	});

	it("keeps real-looking hardcoded passwords", () => {
		for (const text of ['password = "Tr0ub4dor&3"', "password='S3cr3t!Value'"]) {
			const [finding] = passwordFindings(text);
			expect(finding?.severity, text).toBe("critical");
			expect(finding?.evidence, text).toContain("password");
		}
	});

	it("ignores password assignments inside comments", () => {
		for (const text of [
			'// password = "Tr0ub4dor&3"',
			'/* password = "Tr0ub4dor&3" */',
			' * password = "Tr0ub4dor&3"'
		]) {
			expect(passwordFindings(text), text).toEqual([]);
		}
	});
});

describe("AWS key precision", () => {
	function awsFindings(text: string): SecurityFinding[] {
		return credentialFindings([text]).filter((f) => f.message.includes("AWS"));
	}

	it("ignores AKIA substrings inside base64 data", () => {
		// Coincidental base64 substrings from Signal and VSCodium bundles.
		for (const text of ["AKIAAADCAAAA6AAAABYB", "AKIAAAB0AAAAAAAAAKMA"]) {
			expect(awsFindings(text), text).toEqual([]);
		}
	});

	it("keeps real-looking AWS access keys", () => {
		for (const text of ["key=AKIAZ7Q2M4X8P1L5K9R3", "key=AKIA1234567890ABCDEF"]) {
			expect(awsFindings(text).length, text).toBeGreaterThanOrEqual(1);
		}
	});
});

describe("PEM variants", () => {
	function pemStrings(begin: string, lines: string[], end: string): string[] {
		return [begin, ...lines, end];
	}

	it("reassembles OpenSSH and PKCS#8 private keys", () => {
		const variants: Array<[string, string]> = [
			["-----BEGIN OPENSSH PRIVATE KEY-----", "-----END OPENSSH PRIVATE KEY-----"],
			["-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"]
		];
		for (const [begin, end] of variants) {
			const findings = credentialFindings(pemStrings(begin, [fill(70), fill(70)], end));
			const [finding] = findings.filter((f) => f.message.includes("full PEM block"));
			expect(finding?.severity).toBe("critical");
			expect(finding?.evidence).toContain(begin);
		}
	});

	it("does not report lone encrypted and PGP headers", () => {
		for (const header of [
			"-----BEGIN ENCRYPTED PRIVATE KEY-----",
			"-----BEGIN PGP PRIVATE KEY BLOCK-----"
		]) {
			expect(credentialFindings([header]), header).toEqual([]);
		}
	});

	it("ignores a private key header used as a regex literal", () => {
		const findings = credentialFindings([
			"const re = /-----BEGIN ENCRYPTED PRIVATE KEY-----/;"
		]);
		expect(findings).toEqual([]);
	});

	it("reassembles a full PEM block in bundle content and evidences only the header", () => {
		const prefix = 'const key = "not-evidence";';
		const content = [
			`${prefix}-----BEGIN RSA PRIVATE KEY-----`,
			fill(64),
			fill(64),
			"-----END RSA PRIVATE KEY-----"
		].join("\n");
		const findings = scanBundleFileContents([{ relativePath: "app/key.js", content }]).filter(
			(f) => f.message.includes("full PEM block")
		);
		expect(findings).toHaveLength(1);
		expect(findings[0]!.evidence.startsWith("-----BEGIN RSA PRIVATE KEY-----")).toBe(true);
		expect(findings[0]!.evidence).not.toContain(prefix);
	});

	it("ignores public keys and certificates", () => {
		expect(
			credentialFindings([
				"-----BEGIN PUBLIC KEY-----",
				"-----BEGIN CERTIFICATE-----",
				"-----BEGIN PGP PUBLIC KEY BLOCK-----"
			])
		).toEqual([]);
	});
});

describe("base64-encoded secrets", () => {
	const SECRET_JSON = '{"api_key":"AKIAZ7Q2M4X8P1L5K9R3"}';

	it("finds a secret inside an embedded base64 blob", () => {
		const [finding] = credentialFindings([`config={"blob":"${b64(SECRET_JSON)}"}`]).filter(
			(f) => f.message.includes("base64 encoded")
		);
		expect(finding?.severity).toBe("critical");
		expect(finding?.evidence).toContain("AKIA");
	});

	it("finds a double-encoded secret", () => {
		const findings = credentialFindings([b64(b64(SECRET_JSON))]).filter((f) =>
			f.message.includes("base64 encoded")
		);
		expect(findings.some((f) => f.evidence.includes("AKIA"))).toBe(true);
	});

	it("decodes a secret nested in a larger blob", () => {
		const blob = b64(JSON.stringify({ nested: { api_key: "AKIAZ7Q2M4X8P1L5K9R3" } }));
		const findings = credentialFindings([blob]).filter((f) =>
			f.message.includes("base64 encoded")
		);
		expect(findings.some((f) => f.evidence.includes("AKIA"))).toBe(true);
	});

	it("ignores harmless and non-printable base64", () => {
		expect(credentialFindings([b64(JSON.stringify({ hello: "world" }))])).toEqual([]);
		const binary = Buffer.from(Array.from({ length: 60 }, (_, i) => i + 1)).toString("base64");
		expect(credentialFindings([binary])).toEqual([]);
	});

	it("skips long hex digests", () => {
		expect(credentialFindings([fill(40, "abcdef0123456789")])).toEqual([]);
	});

	it("applies the same decoding to bundle files", () => {
		const findings = scanBundleFileContents([
			{ relativePath: "app/index.js", content: `const blob = "${b64(SECRET_JSON)}";` }
		]).filter((f) => f.message.includes("base64 encoded"));
		expect(findings.some((f) => f.evidence.includes("AKIA"))).toBe(true);
		expect(findings[0]?.message).toContain("(in bundle file)");
	});
});

describe("dedupeAndCapFindings", () => {
	function finding(overrides: Partial<SecurityFinding>): SecurityFinding {
		return {
			severity: "critical",
			category: "credential-leak",
			message: "Secret found",
			evidence: "SECRET",
			...overrides
		};
	}

	it("collapses the same credential across sources", () => {
		const result = dedupeAndCapFindings([
			finding({ source: "a.js" }),
			finding({ source: "b.js" })
		]);
		expect(result).toHaveLength(1);
	});

	it("ignores the bundle suffix when collapsing", () => {
		const result = dedupeAndCapFindings([
			finding({ message: "AWS access key found in binary strings" }),
			finding({ message: "AWS access key found in binary strings (in bundle file)" })
		]);
		expect(result).toHaveLength(1);
	});

	it("keeps per-file source for non-credential categories", () => {
		const result = dedupeAndCapFindings([
			finding({ category: "Electron", source: "a.js" }),
			finding({ category: "Electron", source: "b.js" })
		]);
		expect(result).toHaveLength(2);
	});

	it("keeps distinct patterns with the same evidence", () => {
		const result = dedupeAndCapFindings([
			finding({ message: "MongoDB URI" }),
			finding({ message: "PostgreSQL URI" })
		]);
		expect(result).toHaveLength(2);
	});

	it("caps a category after keeping the highest severities", () => {
		const many: SecurityFinding[] = Array.from({ length: 60 }, (_, index) =>
			finding({
				severity: index < 10 ? "critical" : "info",
				evidence: `SECRET-${index}`
			})
		);
		const result = dedupeAndCapFindings(many);
		expect(result).toHaveLength(MAX_FINDINGS_PER_CATEGORY + 1);
		expect(result.filter((f) => f.severity === "critical")).toHaveLength(10);
		const note = result.find((f) => f.message.includes("omitted"));
		expect(note?.severity).toBe("info");
		expect(note?.message).toContain("10 findings omitted");
	});

	it("normalizes runSecurityScan output", () => {
		const strings = Array.from({ length: 25 }, (_, index) =>
			makeStr(`AKIA${fill(16, `ABCDEFGHJKLMNPQR${index}`)}`)
		);
		const normalized = dedupeAndCapFindings(runSecurityScan(baseParams({ strings })));
		const credentials = normalized.filter((f) => f.category === "credential-leak");
		expect(credentials.length).toBeLessThanOrEqual(MAX_FINDINGS_PER_CATEGORY + 1);
	});
});

describe("adjustElectronHardeningFindings", () => {
	function hardening(message: string, severity: SecurityFinding["severity"] = "warning") {
		return { severity, category: "binary-hardening", message, evidence: "evidence" };
	}

	it("drops ARC and stack-canary findings", () => {
		const result = adjustElectronHardeningFindings([
			hardening("ARC (Automatic Reference Counting) not detected"),
			hardening("Stack canaries not detected"),
			hardening("PIE (Position Independent Executable) is not enabled")
		]);
		expect(result.map((f) => f.message)).toEqual([
			"PIE (Position Independent Executable) is not enabled"
		]);
	});

	it("downgrades the macOS rpath warning to info", () => {
		const [finding] = adjustElectronHardeningFindings([
			hardening("Rpath present — potential hijack vector on macOS")
		]);
		expect(finding?.severity).toBe("info");
		expect(finding?.message).toBe("Rpath present — potential hijack vector on macOS");
	});

	it("leaves non-hardening findings and PIE untouched", () => {
		const findings: SecurityFinding[] = [
			hardening("PIE (Position Independent Executable) is not enabled"),
			{
				severity: "critical",
				category: "credential-leak",
				message: "Stack canaries not detected",
				evidence: "unrelated"
			}
		];
		expect(adjustElectronHardeningFindings(findings)).toEqual(findings);
	});
});

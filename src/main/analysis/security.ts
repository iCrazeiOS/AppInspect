/**
 * Security Scan Engine
 *
 * Pattern-matching and binary-hardening checks for Mach-O binaries.
 * Findings are emitted only when they are actionable or non-obvious; the
 * current-state hardening summary lives in the Overview tab.
 * No ML, no network requests — regex patterns only.
 */

import { formatCount } from "../../shared/format";
import type {
	BinaryHardening,
	EncryptionInfo,
	SecurityFinding,
	StringEntry,
	SymbolEntry
} from "../../shared/types";
import { LC_RPATH } from "../parser/load-commands";
import { loadSettings } from "../settings";
import { checkDebugArtifacts } from "./debug-artifacts";

// ── Constants ──

const MH_PIE = 0x200000;

// ── Credential / secret patterns ──

interface SecretPattern {
	name: string;
	pattern: RegExp;
	severity?: SecurityFinding["severity"];
	message: string;
	/** Characters of the match kept as evidence. Default 500. */
	maxEvidence?: number;
}

const SECRET_PATTERNS: SecretPattern[] = [
	{
		name: "AWS Access Key",
		pattern: /AKIA[0-9A-Z]{16}/,
		message: "AWS access key found in binary strings",
		maxEvidence: 32
	},
	{
		name: "API Key assignment",
		pattern: /[aA][pP][iI][-_]?[kK][eE][yY]\s*[:=]\s*['"][^'"]{8,}/,
		message: "Possible API key assignment found"
	},
	{
		name: "Bearer token",
		pattern: /[Bb]earer\s+[A-Za-z0-9\-._~+/]{20,}/,
		message: "Bearer token found in binary strings",
		maxEvidence: 64
	},
	{
		name: "MongoDB URI",
		pattern: /mongodb(\+srv)?:\/\/[^\s'"]+/,
		message: "MongoDB connection URI found"
	},
	{
		name: "PostgreSQL URI",
		pattern: /postgres(ql)?:\/\/[^\s'"]+/,
		message: "PostgreSQL connection URI found"
	},
	{
		name: "MySQL URI",
		pattern: /mysql:\/\/[^\s'"]+/,
		message: "MySQL connection URI found"
	},
	{
		name: "Secret Key assignment",
		pattern: /[sS]ecret[-_]?[kK]ey\s*[:=]\s*['"][^'"]{8,}/,
		message: "Possible secret key assignment found"
	},
	{
		name: "Password assignment",
		pattern: /[pP]assword\s*[:=]\s*['"][^'"]{4,}/,
		message: "Possible hardcoded password found"
	},
	{
		name: "URL with credentials",
		pattern: /https?:\/\/[^\s/:@'"]{1,64}:[^\s/@'"]{1,64}@[^\s'"]+/,
		message: "URL with embedded credentials found"
	},
	{
		name: "Google/Firebase API Key",
		pattern: /AIza[0-9A-Za-z\-_]{35}/,
		severity: "warning",
		message: "Google/Firebase/Gemini API key found",
		maxEvidence: 48
	},
	{
		name: "Slack token",
		pattern: /xox[bapcrsd]-[0-9A-Za-z-]{10,}/,
		message: "Slack token found in binary strings",
		maxEvidence: 64
	},
	{
		name: "OpenAI API Key",
		pattern: /sk-[A-Za-z0-9]{20,}/,
		message: "OpenAI API key found in binary strings",
		maxEvidence: 64
	},
	{
		name: "Anthropic API Key",
		pattern: /sk-ant-[A-Za-z0-9-]{20,}/,
		message: "Anthropic API key found in binary strings",
		maxEvidence: 72
	},
	{
		name: "GitHub token",
		pattern: /(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,255})/,
		message: "GitHub token found in binary strings",
		maxEvidence: 64
	},
	{
		name: "Stripe live key",
		pattern: /[sr]k_live_[A-Za-z0-9]{24,99}/,
		message: "Stripe live API key found",
		maxEvidence: 64
	},
	{
		name: "SendGrid API key",
		pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/,
		message: "SendGrid API key found",
		maxEvidence: 72
	},
	{
		name: "Twilio API key SID",
		pattern: /\bSK[0-9a-fA-F]{32}\b/,
		severity: "warning",
		message: "Twilio API key SID found (the signing secret is stored separately)",
		maxEvidence: 40
	},
	{
		name: "Discord webhook",
		pattern:
			/https:\/\/(?:discord(?:app)?)\.com\/api\/webhooks\/\d{17,20}\/[A-Za-z0-9_-]{60,90}/,
		message: "Discord webhook URL found",
		maxEvidence: 96
	},
	{
		name: "JWT",
		pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*/,
		severity: "warning",
		message: "JWT found in binary strings (may be a public anonymous key)",
		maxEvidence: 96
	},
	{
		name: "Azure Storage account key",
		pattern: /AccountKey=[A-Za-z0-9+/]{86}==/,
		message: "Azure Storage account key found",
		maxEvidence: 48
	}
];

/** Documentation snippets that quote a real-looking prefix without a usable body. */
const PLACEHOLDER_RE = /x{8,}|0{8,}|example|placeholder|your[-_]?(?:token|key)/i;

function isPlaceholderToken(value: string): boolean {
	return PLACEHOLDER_RE.test(value);
}

function secretEvidence(def: SecretPattern, match: string): string {
	const max = def.maxEvidence ?? 500;
	if (match.length <= max) return match;
	return `${match.slice(0, max)}... (${match.length} chars)`;
}

function readJwtRole(token: string): string | null {
	const payload = token.split(".")[1];
	// Untrusted input: do not decode/parse arbitrarily large claims.
	if (!payload || payload.length > 8192) return null;
	try {
		const claims: unknown = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
		if (typeof claims !== "object" || claims === null) return null;
		const role = (claims as { role?: unknown }).role;
		return typeof role === "string" ? role : null;
	} catch {
		return null;
	}
}

function classifySecret(
	def: SecretPattern,
	match: string
): { severity: SecurityFinding["severity"]; message: string } {
	if (def.name === "JWT" && readJwtRole(match) === "service_role") {
		return {
			severity: "critical",
			message: "JWT with service_role claim found (Supabase service key)"
		};
	}
	return { severity: def.severity ?? "critical", message: def.message };
}

// ── Insecure API patterns ──

const UNSAFE_API_SYMBOLS: Array<{
	names: string[];
	category: string;
	severity: SecurityFinding["severity"];
	/** If set, use this severity on iOS instead of the default */
	iosSeverity?: SecurityFinding["severity"];
	message: string;
}> = [
	{
		names: ["_strcpy", "_strcat", "_sprintf", "_gets", "_scanf", "_vsprintf"],
		category: "unsafe-api",
		severity: "warning",
		iosSeverity: "info",
		message: "Memory-unsafe function used"
	},
	{
		names: ["_CC_MD5", "_CC_SHA1", "_MD5_Init", "_SHA1_Init"],
		category: "weak-crypto",
		severity: "info",
		message: "Weak cryptographic function used"
	},
	{
		names: ["_system", "_popen", "_fork", "_execve"],
		category: "dangerous-api",
		severity: "warning",
		iosSeverity: "info",
		message: "Dangerous system call used"
	}
];

// ── Jailbreak detection patterns ──

const JAILBREAK_PATTERNS: RegExp[] = [
	/cydia:\/\//,
	/\/Applications\/Cydia\.app/,
	/frida/i,
	/substrate/,
	/MobileSubstrate/
];

// ── Bundle file scanning (React Native, Flutter, configs) ──

export interface BundleFileEntry {
	/** Path relative to the app bundle root */
	relativePath: string;
	/** File content as text */
	content: string;
}

/** File extensions to scan inside app bundles */
const SCANNABLE_EXTENSIONS = new Set([
	".js",
	".jsbundle",
	".bundle",
	".json",
	".xml",
	".yaml",
	".yml",
	".env",
	".html",
	".htm",
	".mjs",
	".cjs",
	".txt",
	".strings",
	".config",
	".cfg",
	".ini",
	".properties",
	".pem",
	".key",
	".p8"
]);

/**
 * Check if a file extension is scannable for secrets.
 */
export function isScannableExtension(ext: string): boolean {
	return SCANNABLE_EXTENSIONS.has(ext.toLowerCase());
}

/**
 * Quick heuristic to check if a JSON file is a Lottie animation or asset
 * data that won't contain secrets. Avoids scanning large asset files.
 */
function isAssetJSON(content: string): boolean {
	// Lottie animations start with {"v":"... or have common Lottie keys
	const head = content.slice(0, 200);
	if (
		/"v"\s*:\s*"[\d.]+"/.test(head) &&
		(/"fr"\s*:/.test(head) || /"ip"\s*:/.test(head) || /"op"\s*:/.test(head))
	) {
		return true;
	}
	return false;
}

/**
 * Scan text file contents from the app bundle for credential leaks
 * and jailbreak detection strings. Used for React Native JS bundles,
 * config files, and other non-binary content.
 *
 * Scans line-by-line to prevent greedy patterns (e.g. URL-with-credentials)
 * from spanning across unrelated content and producing false positives.
 */
export function scanBundleFileContents(files: BundleFileEntry[]): SecurityFinding[] {
	const findings: SecurityFinding[] = [];
	const seen = new Set<string>(); // dedupe by category+message+evidence+source
	const budget: SecretScanBudget = { base64Decodes: MAX_BUNDLE_BASE64_DECODES };
	const maxFileSize = loadSettings().maxFileSizeMB * 1024 * 1024;

	for (const file of files) {
		// Skip very large files
		if (file.content.length > maxFileSize) continue;

		// Skip Lottie/animation JSON files (large, never contain secrets)
		if (file.relativePath.endsWith(".json") && isAssetJSON(file.content)) continue;

		// Skip package manager metadata (npm registry URLs trigger false positives)
		const baseName = file.relativePath.split("/").pop() ?? "";
		if (baseName === "package-lock.json" || baseName === "yarn.lock") continue;

		const lines = file.content.split("\n");

		for (let li = 0; li < lines.length; li++) {
			const line = lines[li]!;
			const source = file.relativePath;

			// PEM private key reassembly across consecutive lines
			const pem = collectPemBlock(line, (index) => lines[index], li);
			if (pem) {
				const finding = pemFinding(pem, { source, suffix: BUNDLE_SUFFIX });
				if (finding && !seen.has(findingKey(finding))) {
					seen.add(findingKey(finding));
					findings.push(finding);
				}
				if (pem.foundEnd) li = pem.end;
				continue;
			}

			for (const finding of scanTextForSecrets(
				line,
				{ source, suffix: BUNDLE_SUFFIX },
				budget
			)) {
				const key = findingKey(finding);
				if (seen.has(key)) continue;
				seen.add(key);
				findings.push(finding);
			}

			// Check jailbreak detection patterns
			for (const jbPattern of JAILBREAK_PATTERNS) {
				const match = jbPattern.exec(line);
				if (match) {
					const finding: SecurityFinding = {
						severity: "info",
						category: "jailbreak-detection",
						message: "Jailbreak detection string found (in bundle file)",
						evidence: truncate(match[0]),
						source
					};
					const key = findingKey(finding);
					if (seen.has(key)) continue;
					seen.add(key);
					findings.push(finding);
				}
			}
		}
	}

	return findings;
}

// ── Public API ──

// iOS-family platforms (from LC_BUILD_VERSION)
const IOS_PLATFORMS = new Set([2, 3, 4, 7, 8, 9, 11, 12]); // iOS, tvOS, watchOS, simulators, visionOS

export interface SecurityScanParams {
	strings: StringEntry[];
	symbols: SymbolEntry[];
	headerFlags: number;
	encryption: EncryptionInfo | null;
	loadCommands: Array<{ cmd: number; [key: string]: unknown }>;
	/** Platform from LC_BUILD_VERSION (2 = iOS, 1 = macOS, etc.) */
	platform?: number;
	segmentNames: string[];
	sectionNames: string[];
	debugSymbolCount: number;
}

/**
 * Run all security checks and return an array of findings.
 */
export function runSecurityScan(params: SecurityScanParams): SecurityFinding[] {
	const findings: SecurityFinding[] = [];
	const isIOS = params.platform != null && IOS_PLATFORMS.has(params.platform);

	findings.push(...checkBinaryHardeningFindings(params));
	findings.push(...checkSecretPatterns(params.strings));
	findings.push(...checkInsecureAPIs(params.symbols, isIOS));
	findings.push(...checkJailbreakDetection(params.strings));
	findings.push(
		...checkDebugArtifacts({
			segmentNames: params.segmentNames,
			sectionNames: params.sectionNames,
			strings: params.strings,
			debugSymbolCount: params.debugSymbolCount
		})
	);

	return findings;
}

/**
 * Return a compact summary of binary hardening features.
 */
export function getBinaryHardening(params: {
	symbols: SymbolEntry[];
	headerFlags: number;
	encryption: EncryptionInfo | null;
}): BinaryHardening {
	const symbolNames = new Set(params.symbols.map((s) => s.name));

	return {
		pie: (params.headerFlags & MH_PIE) !== 0,
		arc: hasARC(symbolNames),
		stackCanaries: hasStackCanaries(symbolNames),
		encrypted: params.encryption !== null && params.encryption.cryptid !== 0,
		stripped: params.symbols.length < 10
	};
}

// ── Internal helpers ──

function hasStackCanaries(symbolNames: Set<string>): boolean {
	return symbolNames.has("___stack_chk_guard") || symbolNames.has("___stack_chk_fail");
}

function hasARC(symbolNames: Set<string>): boolean {
	return (
		symbolNames.has("_objc_release") ||
		symbolNames.has("_objc_autorelease") ||
		symbolNames.has("_objc_storeStrong")
	);
}

function truncate(s: string, max = 500): string {
	return s.length > max ? `${s.slice(0, max)}...` : s;
}

function checkBinaryHardeningFindings(params: SecurityScanParams): SecurityFinding[] {
	const findings: SecurityFinding[] = [];
	const symbolNames = new Set(params.symbols.map((s) => s.name));
	const isIOS = params.platform != null && IOS_PLATFORMS.has(params.platform);
	const isMacOS = params.platform === 1 || params.platform === 6; // macOS, Mac Catalyst

	// PIE (skip on iOS — always required by App Store)
	if (!isIOS && (params.headerFlags & MH_PIE) === 0) {
		findings.push({
			severity: "warning",
			category: "binary-hardening",
			message: "PIE (Position Independent Executable) is not enabled",
			evidence: `headerFlags=0x${params.headerFlags.toString(16)}`
		});
	}

	// Stack canaries
	if (!hasStackCanaries(symbolNames)) {
		findings.push({
			severity: "warning",
			category: "binary-hardening",
			message: "Stack canaries not detected",
			evidence: "No stack canary symbols found"
		});
	}

	// ARC
	if (!hasARC(symbolNames)) {
		findings.push({
			severity: "warning",
			category: "binary-hardening",
			message: "ARC (Automatic Reference Counting) not detected",
			evidence: "No ObjC ARC symbols found"
		});
	}

	// Rpath (warning on macOS only — potential hijack vector; skip on iOS — sandboxed)
	const hasRpath = params.loadCommands.some((lc) => lc.cmd === LC_RPATH);
	if (hasRpath && !isIOS) {
		findings.push({
			severity: isMacOS ? "warning" : "info",
			category: "binary-hardening",
			message: isMacOS ? "Rpath present — potential hijack vector on macOS" : "Rpath present",
			evidence: "LC_RPATH load command found"
		});
	}

	return findings;
}

// ── Shared secret matching ──

const BASE64_CANDIDATE_RE = /[A-Za-z0-9+/]{40,}={0,2}/g;
const MAX_BASE64_CANDIDATE = 8192;
const MAX_BASE64_CANDIDATES_PER_TEXT = 4;
const MAX_BINARY_BASE64_DECODES = 250;
const MAX_BUNDLE_BASE64_DECODES = 500;
const HEX_ONLY_RE = /^[0-9a-fA-F]+$/;

const BUNDLE_SUFFIX = " (in bundle file)";

interface SecretContext {
	source?: string;
	location?: string;
	/** Appended to the message, e.g. " (in bundle file)". */
	suffix?: string;
}

interface SecretScanBudget {
	base64Decodes: number;
}

function decodeBase64Text(value: string): string | null {
	try {
		const decoded = Buffer.from(value, "base64").toString("utf8");
		// Sanity check: decoded content should be mostly printable ASCII
		const printable = decoded.replace(/[^\x20-\x7e]/g, "");
		if (printable.length < decoded.length * 0.7) return null;
		return decoded;
	} catch {
		return null;
	}
}

/**
 * Match the secret-pattern table against one text, then optionally against
 * bounded base64 candidates. Patterns must stay non-global; this uses exec()
 * repeatedly. `depth` bounds base64-of-base64 recursion.
 */
function scanTextForSecrets(
	text: string,
	context: SecretContext,
	budget: SecretScanBudget,
	depth = 0
): SecurityFinding[] {
	const findings: SecurityFinding[] = [];
	for (const def of SECRET_PATTERNS) {
		const match = def.pattern.exec(text);
		if (!match || isPlaceholderToken(match[0])) continue;
		const { severity, message } = classifySecret(def, match[0]);
		findings.push({
			severity,
			category: "credential-leak",
			message: `${message}${context.suffix ?? ""}`,
			evidence: secretEvidence(def, match[0]),
			...(context.location ? { location: context.location } : {}),
			...(context.source ? { source: context.source } : {})
		});
	}

	if (depth >= 2) return findings;

	let inspected = 0;
	for (const candidate of text.matchAll(BASE64_CANDIDATE_RE)) {
		if (inspected >= MAX_BASE64_CANDIDATES_PER_TEXT || budget.base64Decodes <= 0) break;
		inspected++;
		const encoded = candidate[0]!;
		if (encoded.length > MAX_BASE64_CANDIDATE) continue;
		// SHA-1/SHA-256 hex digests are valid base64 and decode to binary; skip
		// them to preserve budget for real candidates.
		if (HEX_ONLY_RE.test(encoded)) continue;
		budget.base64Decodes--;
		const decoded = decodeBase64Text(encoded);
		if (!decoded || decoded.length < 8) continue;
		findings.push(
			...scanTextForSecrets(
				decoded,
				{ ...context, suffix: `${context.suffix ?? ""} (base64 encoded)` },
				budget,
				depth + 1
			)
		);
	}

	return findings;
}

// ── PEM blocks ──

const PEM_BEGIN_RE = /-----BEGIN ((?:[A-Z0-9]+ )*)PRIVATE KEY( BLOCK)?-----/;
const PEM_END_RE = /-----END ((?:[A-Z0-9]+ )*)PRIVATE KEY( BLOCK)?-----/;
const PEM_BASE64_LINE_RE = /^[A-Za-z0-9+/]{1,76}={0,2}$/;

interface PemBlock {
	header: string;
	body: string[];
	/** Footer index when found; last body index otherwise. */
	end: number;
	foundEnd: boolean;
}

function collectPemBlock(
	headerLine: string,
	lineAt: (index: number) => string | undefined,
	start: number
): PemBlock | null {
	if (!PEM_BEGIN_RE.test(headerLine)) return null;
	const body: string[] = [];
	let end = start;
	let foundEnd = false;
	for (let i = start + 1; i < start + 200; i++) {
		const next = lineAt(i)?.trim();
		if (next === undefined) break;
		if (PEM_END_RE.test(next)) {
			end = i;
			foundEnd = true;
			break;
		}
		if (!PEM_BASE64_LINE_RE.test(next)) break;
		body.push(next);
		end = i;
	}
	return { header: headerLine, body, end, foundEnd };
}

function pemEvidence(pem: PemBlock): string {
	const preview = pem.body.slice(0, 3).join("\n");
	const tail =
		pem.body.length > 0
			? `\n... ${pem.body.length} base64 lines${pem.foundEnd ? "" : " (no footer)"}`
			: "";
	return truncate(`${pem.header}${preview ? `\n${preview}` : ""}${tail}`, 320);
}

function pemFinding(pem: PemBlock, context: SecretContext): SecurityFinding | null {
	// Bare header+footer with nothing in between are just format strings used by
	// RSA utility code, not actual embedded keys; a lone header is suspicious.
	const hasKeyMaterial = pem.foundEnd ? pem.body.length > 0 : pem.body.length !== 1;
	if (!hasKeyMaterial) return null;
	const message = pem.foundEnd
		? "Private key embedded (full PEM block)"
		: "Private key header found";
	return {
		severity: "critical",
		category: "credential-leak",
		message: `${message}${context.suffix ?? ""}`,
		evidence: pemEvidence(pem),
		...(context.location ? { location: context.location } : {}),
		...(context.source ? { source: context.source } : {})
	};
}

// ── Dedupe and cap ──

export const MAX_FINDINGS_PER_CATEGORY = 50;

const SEVERITY_RANK: Record<SecurityFinding["severity"], number> = {
	critical: 3,
	warning: 2,
	info: 1
};

function normalizeEvidence(evidence: string): string {
	return evidence
		.trim()
		.replace(/\s+/g, " ")
		.replace(/^['"]|['"]$/g, "");
}

function findingKey(finding: SecurityFinding): string {
	return `${finding.category}|${finding.message}|${normalizeEvidence(finding.evidence)}|${
		finding.source ?? ""
	}`;
}

/**
 * Collapse duplicate findings and cap each category, keeping the highest
 * severities. Credentials dedupe across sources; other categories keep the
 * source in the key because their evidence is per-file.
 */
export function dedupeAndCapFindings(findings: SecurityFinding[]): SecurityFinding[] {
	const seen = new Set<string>();
	const unique: SecurityFinding[] = [];
	for (const finding of findings) {
		// The bundle suffix is presentation only; the same match in a binary and
		// a bundle file is one remediation item.
		const message = finding.message.replace(/ \(in bundle file\)/g, "");
		// Cross-file collapse is only safe for credentials: the same token is the
		// same remediation. Electron/webPreferences/debug findings are per-file
		// evidence, so keep their source in the key.
		const source = finding.category === "credential-leak" ? "" : (finding.source ?? "");
		const key = `${finding.category}|${message}|${normalizeEvidence(finding.evidence)}|${source}`;
		if (seen.has(key)) continue;
		seen.add(key);
		unique.push(finding);
	}

	const byCategory = new Map<string, SecurityFinding[]>();
	for (const finding of unique) {
		const group = byCategory.get(finding.category);
		if (group) group.push(finding);
		else byCategory.set(finding.category, [finding]);
	}

	const result: SecurityFinding[] = [];
	for (const [category, group] of byCategory) {
		const sorted = group
			.map((finding, index) => ({ finding, index }))
			.sort(
				(a, b) =>
					SEVERITY_RANK[b.finding.severity] - SEVERITY_RANK[a.finding.severity] ||
					a.index - b.index
			)
			.map((entry) => entry.finding);
		result.push(...sorted.slice(0, MAX_FINDINGS_PER_CATEGORY));
		const omitted = sorted.length - MAX_FINDINGS_PER_CATEGORY;
		if (omitted > 0) {
			result.push({
				severity: "info",
				category,
				message: `${formatCount(omitted, "finding")} omitted (category limit ${MAX_FINDINGS_PER_CATEGORY})`,
				evidence: `truncated=${omitted}`
			});
		}
	}
	return result;
}

function checkSecretPatterns(strings: StringEntry[]): SecurityFinding[] {
	const findings: SecurityFinding[] = [];
	const budget: SecretScanBudget = { base64Decodes: MAX_BINARY_BASE64_DECODES };

	for (let i = 0; i < strings.length; i++) {
		const entry = strings[i]!;

		// ── PEM private key reassembly ──
		// The header, base64 lines, and footer are separate null-terminated strings
		// in the binary. Collect adjacent strings to reconstruct the full PEM block.
		const pem = collectPemBlock(entry.value, (index) => strings[index]?.value, i);
		if (pem) {
			const finding = pemFinding(pem, {
				location: `offset=0x${entry.offset.toString(16)}`
			});
			if (finding) findings.push(finding);
			// Skip past the strings we consumed
			if (pem.foundEnd) i = pem.end;
			continue;
		}

		findings.push(
			...scanTextForSecrets(
				entry.value,
				{ location: `offset=0x${entry.offset.toString(16)}` },
				budget
			)
		);
	}

	return findings;
}

function checkInsecureAPIs(symbols: SymbolEntry[], isIOS: boolean): SecurityFinding[] {
	const findings: SecurityFinding[] = [];

	for (const sym of symbols) {
		for (const group of UNSAFE_API_SYMBOLS) {
			if (group.names.includes(sym.name)) {
				findings.push({
					severity: isIOS && group.iosSeverity ? group.iosSeverity : group.severity,
					category: group.category,
					message: `${group.message}: ${sym.name}`,
					evidence: sym.name
				});
			}
		}
	}

	return findings;
}

function checkJailbreakDetection(strings: StringEntry[]): SecurityFinding[] {
	const findings: SecurityFinding[] = [];

	for (const entry of strings) {
		for (const pattern of JAILBREAK_PATTERNS) {
			const match = pattern.exec(entry.value);
			if (match) {
				findings.push({
					severity: "info",
					category: "jailbreak-detection",
					message: "Jailbreak detection string found",
					evidence: truncate(match[0]),
					location: `offset=0x${entry.offset.toString(16)}`
				});
			}
		}
	}

	return findings;
}

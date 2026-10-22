/**
 * Electron `app.asar` scanning.
 *
 * Extracts scannable text files from an archive for the existing secret
 * scanner, and derives Electron-specific findings (fuse wire, ASAR integrity,
 * shipped source maps, dangerous `webPreferences`). Archive data is untrusted,
 * so every read is bounded by the bundle size settings.
 */

import * as path from "node:path";

import { formatCount } from "../../shared/format";
import type { ElectronInfo, SecurityFinding } from "../../shared/types";
import type { BundleFileEntry } from "../analysis/security";
import { isScannableExtension } from "../analysis/security";
import { loadSettings } from "../settings";
import type { AsarArchive } from "./asar";
import { readAsarFile } from "./asar";

const MAX_FINDINGS_PER_CATEGORY = 20;

/** Fuse states that weaken the Electron runtime sandbox. */
const RISKY_FUSES: Array<{ name: string; message: string }> = [
	{
		name: "RunAsNode",
		message: "RunAsNode is enabled — ELECTRON_RUN_AS_NODE runs the binary as plain Node"
	},
	{
		name: "EnableNodeOptionsEnvironmentVariable",
		message: "NODE_OPTIONS is honoured — environment variables can inject Node flags"
	},
	{
		name: "EnableNodeCliInspectArguments",
		message: "Node CLI inspect arguments are honoured — the debugger can attach"
	}
];

/** `webPreferences` settings that weaken an Electron renderer. */
const WEB_PREFERENCE_PATTERNS: Array<{
	severity: SecurityFinding["severity"];
	name: string;
	pattern: RegExp;
}> = [
	{
		severity: "warning",
		name: "nodeIntegration",
		pattern: /["']?nodeIntegration["']?\s*:\s*true/
	},
	{
		severity: "warning",
		name: "contextIsolation",
		pattern: /["']?contextIsolation["']?\s*:\s*false/
	},
	{
		severity: "warning",
		name: "webSecurity",
		pattern: /["']?webSecurity["']?\s*:\s*false/
	},
	{
		severity: "warning",
		name: "allowRunningInsecureContent",
		pattern: /["']?allowRunningInsecureContent["']?\s*:\s*true/
	},
	{
		severity: "info",
		name: "sandbox",
		pattern: /["']?sandbox["']?\s*:\s*false/
	},
	{
		severity: "info",
		name: "webviewTag",
		pattern: /["']?webviewTag["']?\s*:\s*true/
	}
];

// ── Content-Security-Policy ───────────────────────────────────────────

const CSP_CATEGORY = "electron-csp";
const MAX_CSP_EVIDENCE = 300;

/** Script directives, most specific first. */
const SCRIPT_DIRECTIVES = ["script-src-elem", "script-src", "default-src"] as const;
const ATTR_SCRIPT_DIRECTIVES = ["script-src-attr", "script-src", "default-src"] as const;
const EVAL_DIRECTIVES = ["script-src", "default-src"] as const;

const WEAK_SCRIPT_SOURCES = [
	"*",
	"http:",
	"https:",
	"data:",
	"blob:",
	"file:",
	"filesystem:"
] as const;

const WARNING_SCRIPT_SOURCES = new Set(["*", "http:", "https:", "data:"]);

const META_TAG_RE = /<meta\b[^>]*>/gi;
const SCRIPT_TAG_RE = /<script\b([^>]*)>/gi;
const ATTR_RE = /([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
const NONCE_OR_HASH_RE = /^'(?:nonce-|sha(?:256|384|512)-)/;
const INLINE_HANDLER_RE = /<[a-z][a-z0-9-]*\b[^>]*\son[a-z]+\s*=/i;

/** Inert regions: comments, template/noscript/textarea contents. */
const INERT_HTML_PATTERNS = [
	/<!--[\s\S]*?-->/g,
	/<template\b[^>]*>[\s\S]*?<\/template>/gi,
	/<noscript\b[^>]*>[\s\S]*?<\/noscript>/gi,
	/<textarea\b[^>]*>[\s\S]*?<\/textarea>/gi
];

/** Script types the HTML parser executes. Other types are inert data blocks. */
const JS_SCRIPT_TYPES = new Set([
	"",
	"module",
	"text/javascript",
	"application/javascript",
	"application/ecmascript",
	"text/ecmascript",
	"application/x-javascript"
]);

interface CspPolicy {
	/** Lowercased directive name → lowercased source tokens. */
	directives: Map<string, string[]>;
}

function readAttribute(attributes: string, name: string): string | null {
	for (const match of attributes.matchAll(ATTR_RE)) {
		if (match[1]?.toLowerCase() !== name) continue;
		return match[2] ?? match[3] ?? match[4] ?? "";
	}
	return null;
}

/** Parse one serialized policy. Duplicate directives keep the first value. */
function parseCspPolicy(content: string): CspPolicy {
	const directives = new Map<string, string[]>();
	for (const part of content.split(";")) {
		const tokens = part.trim().split(/\s+/).filter(Boolean);
		const name = tokens.shift()?.toLowerCase();
		if (!name || directives.has(name)) continue;
		directives.set(
			name,
			tokens.map((token) => token.toLowerCase())
		);
	}
	return { directives };
}

/** All CSP meta policies in document order. */
function parseCspPolicies(html: string): CspPolicy[] {
	const policies: CspPolicy[] = [];
	for (const match of html.matchAll(META_TAG_RE)) {
		const tag = match[0];
		const attributes = tag.slice(5, -1);
		const equiv = readAttribute(attributes, "http-equiv");
		if (equiv?.trim().toLowerCase() !== "content-security-policy") continue;
		policies.push(parseCspPolicy(readAttribute(attributes, "content") ?? ""));
	}
	return policies;
}

function sourceList(policy: CspPolicy, names: readonly string[]): string[] | null {
	for (const name of names) {
		const value = policy.directives.get(name);
		if (value !== undefined) return value;
	}
	return null;
}

/** Whether this source list allows all inline content of the given type. */
function allowsInline(list: string[] | null): boolean {
	if (list === null) return true;
	const overridden = list.some(
		(token) => NONCE_OR_HASH_RE.test(token) || token === "'strict-dynamic'"
	);
	return !overridden && list.includes("'unsafe-inline'");
}

function allowsEval(list: string[] | null): boolean {
	return list === null || list.includes("'unsafe-eval'");
}

function commonWeakSource(policies: CspPolicy[]): string | null {
	for (const token of WEAK_SCRIPT_SOURCES) {
		const allowed = policies.every((policy) => {
			const list = sourceList(policy, SCRIPT_DIRECTIVES);
			if (list === null) return true;
			// 'strict-dynamic' ignores host/scheme sources (including * and
			// scheme sources) when loading script.
			if (list.includes("'strict-dynamic'")) return false;
			return list.includes(token);
		});
		if (allowed) return token;
	}
	return null;
}

function describeWeakSource(token: string): string {
	switch (token) {
		case "*":
			return "any network origin (*)";
		case "http:":
			return "any HTTP origin (http:)";
		case "https:":
			return "any HTTPS origin (https:)";
		case "data:":
			return "data: URLs";
		case "blob:":
			return "blob: URLs";
		case "file:":
			return "file: URLs";
		default:
			return `${token} URLs`;
	}
}

function serializePolicy(policy: CspPolicy): string {
	const list = sourceList(policy, SCRIPT_DIRECTIVES);
	return list?.join(" ") ?? "no script-src or default-src";
}

function withoutInertHtml(html: string): string {
	let text = html;
	for (const pattern of INERT_HTML_PATTERNS) text = text.replace(pattern, "");
	return text;
}

function countExecutableScripts(html: string): number {
	let count = 0;
	for (const match of html.matchAll(SCRIPT_TAG_RE)) {
		const type = readAttribute(match[1] ?? "", "type");
		const mime = type?.split(";")[0]?.trim().toLowerCase();
		if (mime !== undefined && !JS_SCRIPT_TYPES.has(mime)) continue;
		count++;
	}
	return count;
}

function isHtmlPath(filePath: string): boolean {
	const lower = filePath.toLowerCase();
	return lower.endsWith(".html") || lower.endsWith(".htm");
}

function pathDepth(filePath: string): number {
	return filePath.split("/").length;
}

/** Flag missing or weak CSP meta tags in shipped HTML. */
export function checkContentSecurityPolicy(files: BundleFileEntry[]): SecurityFinding[] {
	const findings: SecurityFinding[] = [];
	const htmlFiles = files
		.filter((file) => isHtmlPath(file.relativePath))
		.sort((a, b) => {
			const depth = pathDepth(a.relativePath) - pathDepth(b.relativePath);
			return depth !== 0 ? depth : a.relativePath.localeCompare(b.relativePath);
		});

	for (const file of htmlFiles) {
		const html = withoutInertHtml(file.content);
		const scriptCount = countExecutableScripts(html);
		const hasHandlers = INLINE_HANDLER_RE.test(html);
		if (scriptCount === 0 && !hasHandlers) continue;

		const policies = parseCspPolicies(html);
		if (policies.length === 0) {
			const targets: string[] = [];
			if (scriptCount > 0) targets.push(formatCount(scriptCount, "script tag"));
			if (hasHandlers) targets.push("inline event handlers");
			findings.push({
				severity: "info",
				category: CSP_CATEGORY,
				message: "No Content-Security-Policy meta tag on a script-bearing page",
				evidence: `${targets.join(", ")}; header-delivered CSP is not visible in the bundle`,
				source: file.relativePath
			});
			continue;
		}

		const restrictsScripts = policies.some((policy) =>
			SCRIPT_DIRECTIVES.some((name) => policy.directives.has(name))
		);
		if (!restrictsScripts) {
			findings.push({
				severity: "info",
				category: CSP_CATEGORY,
				message: "CSP meta tag does not restrict scripts (no script-src or default-src)",
				evidence: policies
					.map((policy) => serializePolicy(policy))
					.join(" | ")
					.slice(0, MAX_CSP_EVIDENCE),
				source: file.relativePath
			});
			continue;
		}

		const issues: string[] = [];
		let severity: SecurityFinding["severity"] = "info";

		const inlineScripts =
			scriptCount > 0 &&
			policies.every((policy) => allowsInline(sourceList(policy, SCRIPT_DIRECTIVES)));
		const inlineHandlers =
			hasHandlers &&
			policies.every((policy) => allowsInline(sourceList(policy, ATTR_SCRIPT_DIRECTIVES)));
		if (inlineScripts || inlineHandlers) {
			const targets: string[] = [];
			if (inlineScripts) targets.push("inline <script>");
			if (inlineHandlers) targets.push("inline event handlers");
			issues.push(`'unsafe-inline' permits ${targets.join(" and ")}`);
			severity = "warning";
		}

		const hasUnsafeEval = policies.some((policy) =>
			(sourceList(policy, EVAL_DIRECTIVES) ?? []).includes("'unsafe-eval'")
		);
		if (
			hasUnsafeEval &&
			policies.every((policy) => allowsEval(sourceList(policy, EVAL_DIRECTIVES)))
		) {
			issues.push("'unsafe-eval' permits eval()");
			severity = "warning";
		}

		const weakSource = commonWeakSource(policies);
		if (weakSource) {
			issues.push(`script-src allows ${describeWeakSource(weakSource)}`);
			if (WARNING_SCRIPT_SOURCES.has(weakSource)) severity = "warning";
		}

		if (issues.length === 0) continue;
		findings.push({
			severity,
			category: CSP_CATEGORY,
			message: `CSP meta tag permits unsafe script execution: ${issues.join("; ")}`,
			evidence: policies
				.map((policy) => serializePolicy(policy))
				.join(" | ")
				.slice(0, MAX_CSP_EVIDENCE),
			source: file.relativePath
		});
	}

	return findings;
}

export interface AsarScanLimits {
	/** Largest single file to read, in bytes. Defaults to `maxFileSizeMB`. */
	maxFileSize: number;
	/** Total bytes to read across the archive. Defaults to `maxBundleSizeMB`. */
	maxBundleSize: number;
}

/** Read scannable text files from the archive, bounded by the bundle size settings. */
export function readAsarTextFiles(
	archive: AsarArchive,
	limits?: AsarScanLimits
): BundleFileEntry[] {
	const settings = loadSettings();
	const maxFileSize = limits?.maxFileSize ?? settings.maxFileSizeMB * 1024 * 1024;
	const maxBundleSize = limits?.maxBundleSize ?? settings.maxBundleSizeMB * 1024 * 1024;

	const files: BundleFileEntry[] = [];
	let totalSize = 0;

	for (const record of archive.files.values()) {
		if (totalSize >= maxBundleSize) break;
		// Links have no contents of their own; the target is scanned instead
		if (record.link !== undefined) continue;
		// Unpacked files live beside the archive; HTML is read separately for CSP
		// checks, and other text is scanned from disk by readBundleFiles.
		if (record.unpacked) continue;
		if (record.size === 0 || record.size > maxFileSize) continue;
		// Source maps are huge and already reported as shipped source maps
		if (record.path.toLowerCase().endsWith(".map")) continue;
		if (!isScannableExtension(path.extname(record.path))) continue;

		const result = readAsarFile(archive, record.path, maxFileSize);
		if (!result.ok) continue;
		const data = result.data.data;
		if (data.includes(0)) continue;

		files.push({
			relativePath: `app.asar/${record.path}`,
			content: data.toString("utf8")
		});
		totalSize += record.size;
	}

	return files;
}

/** Read `.html`/`.htm` entries that live in the archive's `.unpacked` sibling. */
export function readAsarUnpackedHtmlFiles(
	archive: AsarArchive,
	limits?: AsarScanLimits
): BundleFileEntry[] {
	const settings = loadSettings();
	const maxFileSize = limits?.maxFileSize ?? settings.maxFileSizeMB * 1024 * 1024;
	const maxBundleSize = limits?.maxBundleSize ?? settings.maxBundleSizeMB * 1024 * 1024;

	const files: BundleFileEntry[] = [];
	let totalSize = 0;

	for (const record of archive.files.values()) {
		if (totalSize >= maxBundleSize) break;
		if (!record.unpacked || record.link !== undefined) continue;
		if (record.size === 0 || record.size > maxFileSize) continue;
		if (!isHtmlPath(record.path)) continue;

		const result = readAsarFile(archive, record.path, maxFileSize);
		if (!result.ok) continue;
		const data = result.data.data;
		if (data.includes(0)) continue;

		files.push({
			relativePath: `app.asar.unpacked/${record.path}`,
			content: data.toString("utf8")
		});
		totalSize += record.size;
	}

	return files;
}

/** Derive Electron findings from the bundle metadata and archive text files. */
export function scanElectron(info: ElectronInfo, files: BundleFileEntry[]): SecurityFinding[] {
	const findings: SecurityFinding[] = [];
	const seen = new Set<string>();
	const counts = new Map<string, number>();

	const push = (finding: SecurityFinding): void => {
		const key = `${finding.category}|${finding.source ?? ""}|${finding.evidence ?? ""}`;
		if (seen.has(key)) return;
		const count = counts.get(finding.category) ?? 0;
		if (count >= MAX_FINDINGS_PER_CATEGORY) return;
		seen.add(key);
		counts.set(finding.category, count + 1);
		findings.push(finding);
	};

	const fuseStates = new Map(info.fuses.map((fuse) => [fuse.name, fuse.state]));

	for (const { name, message } of RISKY_FUSES) {
		if (fuseStates.get(name) !== "enabled") continue;
		push({
			severity: "warning",
			category: "Electron",
			message,
			evidence: `${name}=enabled`
		});
	}

	if (fuseStates.get("OnlyLoadAppFromAsar") === "disabled") {
		push({
			severity: "info",
			category: "Electron",
			message: "OnlyLoadAppFromAsar is disabled — the app can load unpacked app code",
			evidence: "OnlyLoadAppFromAsar=disabled"
		});
	}

	if (fuseStates.get("EnableEmbeddedAsarIntegrityValidation") === "disabled") {
		push({
			severity: "info",
			category: "Electron",
			message:
				"EnableEmbeddedAsarIntegrityValidation is disabled — app.asar can be modified without detection",
			evidence: "EnableEmbeddedAsarIntegrityValidation=disabled"
		});
	}

	const integrity = info.integrity;
	if (integrity && !integrity.valid) {
		push({
			severity: "critical",
			category: "Electron",
			message: "app.asar header does not match the ElectronAsarIntegrity hash",
			evidence: `expected ${integrity.expected}, actual ${integrity.actual}`,
			source: "app.asar"
		});
	}

	if (info.sourceMaps.length > 0) {
		push({
			severity: "info",
			category: "Electron",
			message: `Shipped source maps (${info.sourceMaps.length}) expose original source`,
			evidence: info.sourceMaps.slice(0, 3).join(", "),
			source: "app.asar"
		});
	}

	for (const file of files) {
		for (const { severity, name, pattern } of WEB_PREFERENCE_PATTERNS) {
			const match = pattern.exec(file.content);
			if (!match) continue;
			push({
				severity,
				category: "Electron",
				message: `webPreferences weakens the renderer: ${name}`,
				evidence: match[0],
				source: file.relativePath
			});
		}
	}

	for (const finding of checkContentSecurityPolicy(files)) push(finding);

	return findings;
}

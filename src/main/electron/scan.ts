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
import type { ElectronFuseState, ElectronInfo, SecurityFinding } from "../../shared/types";
import type { BundleFileEntry } from "../analysis/security";
import { isScannableExtension } from "../analysis/security";
import { loadSettings } from "../settings";
import type { AsarArchive } from "./asar";
import { readAsarFile } from "./asar";
import { findRuntimeApiFindings } from "./runtime";

const MAX_FINDINGS_PER_CATEGORY = 20;
/** Vendor bundles ship every dependency's defaults; report a sample, not a flood. */
const MAX_VENDOR_FINDINGS = 5;

type ElectronCategory =
	| "electron-fuses"
	| "electron-renderer"
	| "electron-csp"
	| "electron-integrity"
	| "electron-runtime"
	| "electron-version";

interface FuseRule {
	name: string;
	/** States that weaken the runtime, with the finding to emit for each. */
	findings: Partial<
		Record<ElectronFuseState, { severity: SecurityFinding["severity"]; message: string }>
	>;
}

/**
 * Fuse defaults and secure states from Electron's fuse docs.
 *
 * | Fuse | Default | Secure |
 * |---|---|---|
 * | RunAsNode | enabled | disabled |
 * | EnableCookieEncryption | disabled | enabled |
 * | EnableNodeOptionsEnvironmentVariable | enabled | disabled |
 * | EnableNodeCliInspectArguments | enabled | disabled |
 * | OnlyLoadAppFromAsar | disabled | enabled |
 * | EnableEmbeddedAsarIntegrityValidation | disabled | enabled |
 * | LoadBrowserProcessSpecificV8Snapshot | disabled | enabled |
 * | GrantFileProtocolExtraPrivileges | enabled | disabled |
 * | WasmTrapHandlers | enabled | enabled |
 *
 * `removed` means the feature is compiled out permanently. For a permissive fuse
 * that is safe; for a hardening fuse it is as weak as `disabled`.
 *
 * Grouped permissive → restricting → `file://` privilege; this is not wire order.
 */
const FUSE_RULES: FuseRule[] = [
	{
		name: "RunAsNode",
		findings: {
			enabled: {
				severity: "warning",
				message: "RunAsNode is enabled — ELECTRON_RUN_AS_NODE runs the binary as plain Node"
			}
		}
	},
	{
		name: "EnableCookieEncryption",
		findings: {
			disabled: {
				severity: "info",
				message:
					"EnableCookieEncryption is disabled — cookies are stored unencrypted " +
					"in Chromium's SQLite cookie store"
			},
			removed: {
				severity: "info",
				message:
					"EnableCookieEncryption is removed — this build cannot encrypt cookies at rest"
			}
		}
	},
	{
		name: "EnableNodeOptionsEnvironmentVariable",
		findings: {
			enabled: {
				severity: "warning",
				message: "NODE_OPTIONS is honoured — environment variables can inject Node flags"
			}
		}
	},
	{
		name: "EnableNodeCliInspectArguments",
		findings: {
			enabled: {
				severity: "warning",
				message: "Node CLI inspect arguments are honoured — the debugger can attach"
			}
		}
	},
	{
		name: "OnlyLoadAppFromAsar",
		findings: {
			disabled: {
				severity: "info",
				message: "OnlyLoadAppFromAsar is disabled — the app can load unpacked app code"
			},
			removed: {
				severity: "info",
				message:
					"OnlyLoadAppFromAsar is removed — this build cannot restrict app loading " +
					"to app.asar"
			}
		}
	},
	{
		name: "EnableEmbeddedAsarIntegrityValidation",
		findings: {
			disabled: {
				severity: "info",
				message:
					"EnableEmbeddedAsarIntegrityValidation is disabled — app.asar integrity " +
					"is not enforced at launch"
			},
			removed: {
				severity: "info",
				message:
					"EnableEmbeddedAsarIntegrityValidation is removed — this build cannot " +
					"enforce app.asar integrity at launch"
			}
		}
	},
	{
		name: "GrantFileProtocolExtraPrivileges",
		findings: {
			enabled: {
				severity: "warning",
				message:
					"GrantFileProtocolExtraPrivileges is enabled — file:// pages can fetch " +
					"local assets, use service workers, and access child file:// frames " +
					"regardless of sandbox"
			}
		}
	}
];

const INTEGRITY_FUSE = "EnableEmbeddedAsarIntegrityValidation";

/**
 * Oldest Electron major with upstream security support.
 *
 * Electron supports the latest three stable majors. As of 2026-10-22:
 *   45.x current, 44.x supported, 43.x supported, 42.x end-of-life.
 * Bump this when a new major ships (roughly every 8 weeks) and the oldest
 * major drops out of support. Last verified: 2026-10-22.
 */
export const MIN_SUPPORTED_ELECTRON_MAJOR = 43;

const ELECTRON_VERSION_RE = /^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+][0-9A-Za-z.-]+)?$/;

/** Major version of an Electron `CFBundleVersion`, or null when it cannot be parsed. */
export function parseElectronMajor(version: string): number | null {
	const match = ELECTRON_VERSION_RE.exec(version.trim());
	if (!match) return null;
	const major = Number.parseInt(match[1]!, 10);
	return Number.isSafeInteger(major) && major > 0 ? major : null;
}

/**
 * Compare an Electron version against a minimum major. Returns null when the
 * version cannot be parsed. The `minimum` parameter is injectable for tests.
 */
export function isElectronVersionSupported(
	version: string,
	minimum: number = MIN_SUPPORTED_ELECTRON_MAJOR
): boolean | null {
	const major = parseElectronMajor(version);
	return major === null ? null : major >= minimum;
}

/** Terser/esbuild/swc emit `!0`/`!1` for `true`/`false` in minified output. */
const TRUE_VALUE = "(?:true|!0)";
const FALSE_VALUE = "(?:false|!1)";
/** Rejects longer identifiers such as `!00`. */
const VALUE_END = "(?![\\w$])";

/** `key: <value>` in an object literal, including quoted keys and minified values. */
function preferencePattern(name: string, value: string): RegExp {
	return new RegExp(`["']?\\b${name}["']?\\s*:\\s*${value}${VALUE_END}`);
}

interface ElectronCheck {
	name: string;
	severity: SecurityFinding["severity"];
	category: ElectronCategory;
	message: string;
	pattern: RegExp;
}

/** `webPreferences` settings that weaken an Electron renderer. */
const WEB_PREFERENCE_PATTERNS: ElectronCheck[] = [
	{
		name: "nodeIntegration",
		severity: "warning",
		category: "electron-renderer",
		message: "Renderer runs with Node.js integration",
		pattern: preferencePattern("nodeIntegration", TRUE_VALUE)
	},
	{
		name: "nodeIntegrationInWorker",
		severity: "warning",
		category: "electron-renderer",
		message: "Node.js integration is enabled in web workers",
		pattern: preferencePattern("nodeIntegrationInWorker", TRUE_VALUE)
	},
	{
		name: "nodeIntegrationInSubFrames",
		severity: "warning",
		category: "electron-renderer",
		message: "Node.js integration is enabled in sub-frames",
		pattern: preferencePattern("nodeIntegrationInSubFrames", TRUE_VALUE)
	},
	{
		name: "contextIsolation",
		severity: "warning",
		category: "electron-renderer",
		message: "Renderer context isolation is disabled",
		pattern: preferencePattern("contextIsolation", FALSE_VALUE)
	},
	{
		name: "sandbox",
		severity: "warning",
		category: "electron-renderer",
		message: "Renderer sandbox is disabled",
		pattern: preferencePattern("sandbox", FALSE_VALUE)
	},
	{
		name: "webSecurity",
		severity: "warning",
		category: "electron-renderer",
		message: "Same-origin policy is disabled",
		pattern: preferencePattern("webSecurity", FALSE_VALUE)
	},
	{
		name: "allowRunningInsecureContent",
		severity: "info",
		category: "electron-renderer",
		message: "Mixed content is allowed",
		pattern: preferencePattern("allowRunningInsecureContent", TRUE_VALUE)
	},
	{
		name: "webviewTag",
		severity: "info",
		category: "electron-renderer",
		message: "<webview> tag is enabled",
		pattern: preferencePattern("webviewTag", TRUE_VALUE)
	},
	{
		name: "enableRemoteModule",
		severity: "warning",
		category: "electron-runtime",
		message: "Legacy remote module is enabled",
		pattern: preferencePattern("enableRemoteModule", TRUE_VALUE)
	},
	{
		name: "enableBlinkFeatures",
		severity: "info",
		category: "electron-renderer",
		message: "Extra Blink features are enabled",
		pattern: /["']?\benableBlinkFeatures["']?\s*:\s*["']([^"']{1,160})["']/
	}
];

/**
 * `<webview>` markup. Names deliberately match the JS checks so the
 * nodeIntegration + contextIsolation combo also fires for markup.
 */
const WEBVIEW_PATTERNS: ElectronCheck[] = [
	{
		name: "nodeIntegration",
		severity: "warning",
		category: "electron-renderer",
		message: "webview guest runs with Node.js integration",
		pattern:
			/<webview\b[^>]*\bwebpreferences\s*=\s*["'][^"']*\bnodeIntegration\s*=\s*(?:yes|true)\b/i
	},
	{
		name: "contextIsolation",
		severity: "warning",
		category: "electron-renderer",
		message: "webview guest disables context isolation",
		pattern:
			/<webview\b[^>]*\bwebpreferences\s*=\s*["'][^"']*\bcontextIsolation\s*=\s*(?:no|false)\b/i
	},
	{
		name: "sandbox",
		severity: "warning",
		category: "electron-renderer",
		message: "webview guest disables the sandbox",
		pattern: /<webview\b[^>]*\bwebpreferences\s*=\s*["'][^"']*\bsandbox\s*=\s*(?:no|false)\b/i
	},
	{
		name: "allowpopups",
		severity: "info",
		category: "electron-renderer",
		message: "<webview allowpopups> lets guest content open new windows",
		pattern: /<webview\b[^>]*\ballowpopups\b/i
	}
];

/** Files that can hold renderer configuration; excludes prose and bundled assets. */
const WEB_PREFERENCE_EXTENSIONS = new Set([
	".js",
	".mjs",
	".cjs",
	".jsbundle",
	".json",
	".html",
	".htm"
]);

const VENDOR_SEGMENT = /(^|\/)(node_modules|vendor|third_party|3rdparty)(\/|$)/i;

/** True when the file is the app's own code rather than a bundled dependency. */
function isFirstParty(relativePath: string, info: ElectronInfo): boolean {
	const name = info.packageJson?.name;
	if (typeof name === "string" && relativePath.startsWith(`app.asar/node_modules/${name}/`)) {
		// electron-builder's two-package layout ships the app itself under node_modules
		return true;
	}
	const main = info.packageJson?.main;
	if (typeof main === "string") {
		const mainPath = `app.asar/${main.replace(/^[./]+/, "")}`;
		if (relativePath === mainPath) return true;
	}
	return !VENDOR_SEGMENT.test(relativePath);
}

/** True when the match is inside an HTML comment or preceded by a comment marker. */
function isCommented(content: string, index: number): boolean {
	const htmlOpen = content.lastIndexOf("<!--", index);
	if (htmlOpen !== -1 && content.lastIndexOf("-->", index) < htmlOpen) return true;
	const lineStart = content.lastIndexOf("\n", index - 1) + 1;
	// Bounded window: minified bundles are one huge line, so never slice the whole prefix
	const prefix = content.slice(Math.max(lineStart, index - 200), index).trimStart();
	return (
		prefix.startsWith("//") ||
		prefix.startsWith("/*") ||
		prefix.startsWith("*") ||
		prefix.startsWith("<!--")
	);
}

// ── Dangerous command-line switches ──

/**
 * Match the forms a Chromium switch takes in app code:
 *   appendSwitch("name")                    — switch name without leading `--`
 *   appendArgument("--name[=value]")        — full argument, with leading `--`
 *   additionalArguments: ["--name[=value]"] — forwarded to renderer argv
 *
 * `additionalArguments` is excluded for browser-process switches such as
 * `remote-debugging-port`, where it would not open a listener.
 */
function switchPattern(name: string, includeAdditionalArguments = true): RegExp {
	const call =
		`\\bappendSwitch\\s*\\(\\s*["']${name}["'](?:\\s*,\\s*["'][^"']*["'])?\\s*\\)` +
		`|\\bappendArgument\\s*\\(\\s*["']--${name}(?:=[^"']*)?["']\\s*\\)`;
	if (!includeAdditionalArguments) return new RegExp(call);
	return new RegExp(
		`${call}|\\badditionalArguments\\s*:\\s*\\[[^\\]]{0,500}?` + `["']--${name}(?:=[^"']*)?["']`
	);
}

const DANGEROUS_SWITCHES: Array<{
	id: string;
	severity: SecurityFinding["severity"];
	pattern: RegExp;
	message: string;
}> = [
	{
		id: "disable-web-security",
		severity: "warning",
		pattern: switchPattern("disable-web-security"),
		message: "disable-web-security is set — the renderer skips the same-origin policy"
	},
	{
		id: "ignore-certificate-errors",
		severity: "warning",
		pattern: switchPattern("ignore-certificate-errors"),
		message: "ignore-certificate-errors is set — TLS certificates are not validated"
	},
	{
		id: "allow-running-insecure-content",
		severity: "warning",
		pattern: switchPattern("allow-running-insecure-content"),
		message: "allow-running-insecure-content is set — active mixed content is allowed"
	},
	{
		id: "disable-site-isolation-trials",
		severity: "warning",
		pattern: switchPattern("disable-site-isolation-trials"),
		message: "disable-site-isolation-trials is set — per-site process isolation is disabled"
	},
	{
		id: "inspect",
		severity: "info",
		pattern: switchPattern("inspect"),
		message:
			"Node inspector flag 'inspect' is referenced — a launch-time argv flag, " +
			"not a Chromium switch the app can enable at runtime"
	},
	{
		id: "inspect-brk",
		severity: "info",
		pattern: switchPattern("inspect-brk"),
		message:
			"Node inspector flag 'inspect-brk' is referenced — a launch-time argv flag, " +
			"not a Chromium switch the app can enable at runtime"
	}
];

/** `remote-debugging-port` is handled separately to correlate the bind address. */
const DEBUG_PORT_PATTERN = switchPattern("remote-debugging-port", false);

/** Value of `remote-debugging-address` in the two browser-process forms. */
const DEBUG_ADDRESS_PATTERN = new RegExp(
	`\\bappendSwitch\\s*\\(\\s*["']remote-debugging-address["']\\s*,\\s*["']([^"']+)["']` +
		`|\\bappendArgument\\s*\\(\\s*["']--remote-debugging-address=([^"']+)["']`
);

/** A debug flag read from process.argv; the app does not enable it by itself. */
const ARGV_DEBUG_PATTERN =
	/\bprocess\.argv[\s\S]{0,120}?["']--(inspect(?:-brk)?|remote-debugging-port|remote-debugging-address)(?:=[^"']*)?["']/;

const MAX_EVIDENCE_LENGTH = 200;

function clip(value: string): string {
	return value.length > MAX_EVIDENCE_LENGTH
		? `${value.slice(0, MAX_EVIDENCE_LENGTH - 3)}...`
		: value;
}

function isLoopbackHost(host: string): boolean {
	const value = host.trim().toLowerCase();
	return (
		value === "localhost" ||
		value === "::1" ||
		value === "[::1]" ||
		/^127(?:\.\d{1,3}){3}$/.test(value)
	);
}

/** Documentation, tests and lockfiles that quote switches without running them. */
const NON_RUNTIME_PATH =
	/(^|\/)(?:readme|changelog|license|notice|contributing)(?:\.[^/]*)?$|(^|\/)(?:docs?|documentation|__tests__|__mocks__|tests?|specs?)\/|\.(?:test|spec)\.[^/]+$|(^|\/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$/i;

// ── Cleartext content loading ──

/** `loadURL("http://…")`, `'http://…'`, or a template literal. */
const CLEARTEXT_LOAD_URL = /\bloadURL\s*\(\s*(["'`])(http:\/\/[^"'`\n]{0,200})\1\s*[,)]/i;

/** Loopback cleartext is local-only; never treat `localhost.evil.com` as loopback. */
const LOOPBACK_HTTP =
	/^http:\/\/(?:localhost|127(?:\.\d{1,3}){3}|\[::1\])(?::[^/?#]*)?(?:[/?#]|$)/i;

// ── Content-Security-Policy ───────────────────────────────────────────

const CSP_CATEGORY: ElectronCategory = "electron-csp";
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

type FindingPush = (finding: SecurityFinding) => void;

function createFindingCollector(): {
	findings: SecurityFinding[];
	push: FindingPush;
} {
	const findings: SecurityFinding[] = [];
	const seen = new Set<string>();
	const counts = new Map<string, number>();
	let vendorCount = 0;

	const push: FindingPush = (finding) => {
		const key = `${finding.category}|${finding.source ?? ""}|${finding.evidence ?? ""}`;
		if (seen.has(key)) return;
		if (finding.vendor && vendorCount >= MAX_VENDOR_FINDINGS) return;
		const count = counts.get(finding.category) ?? 0;
		if (count >= MAX_FINDINGS_PER_CATEGORY) return;
		seen.add(key);
		counts.set(finding.category, count + 1);
		if (finding.vendor) vendorCount++;
		findings.push(finding);
	};

	return { findings, push };
}

function collectFuseFindings(info: ElectronInfo, push: FindingPush): void {
	const fuseStates = new Map(info.fuses.map((fuse) => [fuse.name, fuse.state]));

	for (const rule of FUSE_RULES) {
		const state = fuseStates.get(rule.name);
		if (!state) continue;
		const finding = rule.findings[state];
		if (!finding) continue;
		push({
			severity: finding.severity,
			category: "electron-fuses",
			message: finding.message,
			evidence: `${rule.name}=${state}`
		});
	}

	// `fuses: []` is ambiguous: an asar-only folder has no framework binary, while an
	// older Electron build (pre-12) or an unreadable wire has a framework but no wire.
	// `electronVersion` is only set when the framework Info.plist was readable, so use it
	// as the "framework present" signal and stay quiet for asar-only inputs.
	if (info.fuses.length === 0 && info.electronVersion !== undefined) {
		push({
			severity: "info",
			category: "electron-fuses",
			message:
				"No Electron fuse wire was found — this build predates fuses or the " +
				"framework binary could not be read; fuse hardening was not assessed",
			evidence: "fuses=unavailable"
		});
	}
}

function collectIntegrityFindings(info: ElectronInfo, push: FindingPush): void {
	const fuseStates = new Map(info.fuses.map((fuse) => [fuse.name, fuse.state]));

	if (info.integrity && !info.integrity.valid) {
		push({
			severity: "critical",
			category: "electron-integrity",
			message:
				"app.asar header does not match the ElectronAsarIntegrity hash " +
				"(AppInspect compares the header hash only, not file contents)",
			evidence: `expected ${info.integrity.expected}, actual ${info.integrity.actual}`,
			source: "app.asar"
		});
		return;
	}

	if (!info.integrityIssue || !info.asarPath) return;

	const enforced = fuseStates.get(INTEGRITY_FUSE) === "enabled";
	const issue = info.integrityIssue;

	let detail = "the ElectronAsarIntegrity entry for app.asar is unusable";
	switch (issue.kind) {
		case "missing":
			detail = "no ElectronAsarIntegrity entry exists for app.asar";
			break;
		case "unsupported-algorithm":
			detail =
				`the ElectronAsarIntegrity algorithm ${issue.algorithm || "unknown"} ` +
				"is not SHA-256";
			break;
		case "malformed":
			detail = "the ElectronAsarIntegrity entry for app.asar is malformed";
			break;
	}

	push({
		severity: enforced ? "warning" : "info",
		category: "electron-integrity",
		message: enforced
			? `The ASAR integrity fuse is enabled but ${detail} — the archive cannot be ` +
				"verified (header hash only) and the app may fail to launch"
			: `ASAR integrity cannot be verified — ${detail} (header hash only)`,
		evidence: `integrity=${issue.kind}${issue.algorithm ? `, algorithm=${issue.algorithm}` : ""}`,
		source: "app.asar"
	});
}

function collectVersionFindings(info: ElectronInfo, push: FindingPush): void {
	const version = info.electronVersion;
	if (!version) return;

	const major = parseElectronMajor(version);
	if (major === null || major >= MIN_SUPPORTED_ELECTRON_MAJOR) return;

	push({
		severity: "warning",
		category: "electron-version",
		message:
			`Electron ${version} is no longer supported — it misses Chromium and ` +
			`Node.js security fixes (oldest supported major: ${MIN_SUPPORTED_ELECTRON_MAJOR})`,
		evidence: `electronVersion=${version}`
	});
}

function collectInfoFindings(info: ElectronInfo, push: FindingPush): void {
	collectFuseFindings(info, push);
	collectIntegrityFindings(info, push);

	if (info.sourceMaps.length > 0) {
		push({
			severity: "info",
			category: "electron-integrity",
			message: `Shipped source maps (${info.sourceMaps.length}) expose original source`,
			evidence: info.sourceMaps.slice(0, 3).join(", "),
			source: "app.asar"
		});
	}

	collectVersionFindings(info, push);
}

function collectTextFindings(
	info: ElectronInfo,
	files: BundleFileEntry[],
	push: FindingPush
): void {
	// ── Renderer configuration ──
	const electronMajor = parseElectronMajor(info.electronVersion ?? "");
	const remoteModuleRetired = electronMajor !== null && electronMajor >= 14;

	type MatchedCheck = ElectronCheck & { evidence: string };
	const perFile: Array<{ source: string; vendor: boolean; matches: Map<string, MatchedCheck> }> =
		[];

	for (const file of files) {
		const ext = path.extname(file.relativePath).toLowerCase();
		if (!WEB_PREFERENCE_EXTENSIONS.has(ext)) continue;

		const matches = new Map<string, MatchedCheck>();
		for (const check of [...WEB_PREFERENCE_PATTERNS, ...WEBVIEW_PATTERNS]) {
			const match = check.pattern.exec(file.content);
			if (!match || isCommented(file.content, match.index)) continue;
			// First match wins: object prefs and markup rarely coexist in one file
			if (matches.has(check.name)) continue;
			matches.set(check.name, { ...check, evidence: match[0].trim() });
		}
		if (matches.size === 0) continue;
		perFile.push({
			source: file.relativePath,
			vendor: !isFirstParty(file.relativePath, info),
			matches
		});
	}

	const hasCombo = (matches: Map<string, MatchedCheck>): boolean =>
		matches.has("nodeIntegration") && matches.has("contextIsolation");

	// The full-RCE combo first, so the per-category cap can never drop it
	const comboFiles = perFile.filter((file) => hasCombo(file.matches));
	for (const file of comboFiles) {
		push({
			severity: "critical",
			category: "electron-renderer",
			message:
				"nodeIntegration and contextIsolation: false together — renderer content can reach Node.js (full RCE)",
			evidence: `${file.matches.get("nodeIntegration")!.evidence} + ${
				file.matches.get("contextIsolation")!.evidence
			}`,
			source: file.source,
			...(file.vendor ? { vendor: true } : {})
		});
	}

	if (comboFiles.length === 0) {
		const nodeFile = perFile.find(
			(file) => file.matches.has("nodeIntegration") && !file.vendor
		);
		const isolationFile = perFile.find(
			(file) => file.matches.has("contextIsolation") && !file.vendor
		);
		if (nodeFile && isolationFile && nodeFile !== isolationFile) {
			push({
				severity: "critical",
				category: "electron-renderer",
				message:
					"nodeIntegration and contextIsolation: false are both enabled — renderer content can reach Node.js (full RCE)",
				evidence: `${nodeFile.source} (nodeIntegration) + ${isolationFile.source} (contextIsolation)`,
				source: nodeFile.source
			});
		}
	}

	for (const file of perFile) {
		const combo = hasCombo(file.matches);
		for (const matched of file.matches.values()) {
			// Covered by the combo; nodeIntegration also implies sandbox:false
			if (
				combo &&
				["nodeIntegration", "contextIsolation", "sandbox"].includes(matched.name)
			) {
				continue;
			}
			const retired = matched.name === "enableRemoteModule" && remoteModuleRetired;
			const severity = file.vendor || retired ? "info" : matched.severity;
			push({
				severity,
				category: matched.category,
				message: `${matched.message}${file.vendor ? " (vendor code)" : ""}${
					retired ? " (removed in Electron 14)" : ""
				}`,
				evidence: matched.evidence,
				source: file.source,
				...(file.vendor ? { vendor: true } : {})
			});
		}
	}

	// ── Command-line switches and cleartext loading ──
	for (const file of files) {
		if (NON_RUNTIME_PATH.test(file.relativePath)) continue;

		const emitSwitches = (
			severity: SecurityFinding["severity"],
			message: string,
			evidence: string
		): void => {
			push({
				severity,
				category: "electron-switches",
				message,
				evidence: clip(evidence),
				source: file.relativePath
			});
		};

		for (const { severity, pattern, message } of DANGEROUS_SWITCHES) {
			const match = pattern.exec(file.content);
			if (match) emitSwitches(severity, message, match[0]);
		}

		// A port on its own is loopback-only. Only a non-loopback address is remote RCE.
		const port = DEBUG_PORT_PATTERN.exec(file.content);
		if (port) {
			const address = DEBUG_ADDRESS_PATTERN.exec(file.content);
			const host = address?.[1] ?? address?.[2] ?? "";
			const exposed = host.length > 0 && !isLoopbackHost(host);
			push({
				severity: exposed ? "critical" : "warning",
				category: "electron-switches",
				message: exposed
					? `remote-debugging-port is bound to ${host} — the DevTools protocol allows remote code execution`
					: "remote-debugging-port is enabled — local processes can drive the app through the DevTools protocol",
				evidence: clip(address ? `${port[0]} ${address[0]}` : port[0]),
				source: file.relativePath
			});
		}

		const argv = ARGV_DEBUG_PATTERN.exec(file.content);
		if (argv) {
			emitSwitches(
				"info",
				`process.argv is inspected for --${argv[1] ?? ""} — the flag is only effective when passed at launch`,
				argv[0]
			);
		}

		const load = CLEARTEXT_LOAD_URL.exec(file.content);
		if (load) {
			const url = load[2] ?? "";
			const loopback = LOOPBACK_HTTP.test(url);
			push({
				severity: loopback ? "info" : "warning",
				category: "electron-cleartext",
				message: loopback
					? "loadURL loads content over cleartext HTTP from loopback — not exposed beyond the local machine"
					: "loadURL loads remote content over cleartext HTTP — traffic can be read or modified in transit",
				evidence: clip(load[0]),
				source: file.relativePath
			});
		}
	}

	for (const finding of findRuntimeApiFindings(files)) push(finding);

	for (const finding of checkContentSecurityPolicy(files)) push(finding);
}

/** Metadata-only findings: safe to run without a readable app.asar. */
export function scanElectronMetadata(info: ElectronInfo): SecurityFinding[] {
	const { findings, push } = createFindingCollector();
	collectInfoFindings(info, push);
	return findings;
}

/** Archive text findings: require the extracted scannable files. */
export function scanElectronText(info: ElectronInfo, files: BundleFileEntry[]): SecurityFinding[] {
	const { findings, push } = createFindingCollector();
	collectTextFindings(info, files, push);
	return findings;
}

/** Existing API: all Electron findings for an info object plus archive text. */
export function scanElectron(info: ElectronInfo, files: BundleFileEntry[]): SecurityFinding[] {
	const { findings, push } = createFindingCollector();
	collectInfoFindings(info, push);
	collectTextFindings(info, files, push);
	return findings;
}

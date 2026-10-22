/**
 * Electron runtime API checks.
 *
 * Static, line-oriented heuristics over `app.asar` text for wiring that
 * weakens the runtime trust boundary: blind certificate trust, permissive
 * permission handlers, unvalidated window/external opening, and over-exposed
 * IPC. There is no JavaScript parser in the project, so these checks look at
 * call arguments and deliberately skip branching handlers.
 */

import * as path from "node:path";

import type { SecurityFinding } from "../../shared/types";
import type { BundleFileEntry } from "../analysis/security";

const CATEGORY = "electron-runtime";
const MAX_EVIDENCE = 160;
const MAX_CALL_ARGUMENTS = 600;
/** Six checks × 3 = 18, below MAX_FINDINGS_PER_CATEGORY (20). */
const MAX_FINDINGS_PER_CHECK = 3;

/**
 * Tokens that make a handler conditional. Branching handlers are treated as
 * scoped and left alone: proving that a branch is unsafe is out of scope.
 */
const GUARD_RE = /\bif\s*\(|\bswitch\s*\(|\?|&&|\|\||===|!==|\.includes\s*\(|\.startsWith\s*\(/;

const STATIC_STRING_RE = /^(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`[^`$]*`)$/;

interface RuntimeHit {
	severity: SecurityFinding["severity"];
	message: string;
	evidence: string;
}

interface CallSite {
	index: number;
	args: string;
	/** The call text from the callee to the closing parenthesis. */
	text: string;
}

function escapeRegExp(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Text between the parentheses at `open`, ignoring parens inside strings. */
function balancedSlice(content: string, open: number, max: number): string | null {
	let depth = 0;
	let quote = "";
	const end = Math.min(content.length, open + max);
	for (let i = open; i < end; i++) {
		const ch = content[i]!;
		if (quote) {
			if (ch === "\\") i++;
			else if (ch === quote) quote = "";
			continue;
		}
		if (ch === '"' || ch === "'" || ch === "`") quote = ch;
		else if (ch === "(") depth++;
		else if (ch === ")" && --depth === 0) return content.slice(open + 1, i);
	}
	return null;
}

function callSites(content: string, callee: string): CallSite[] {
	const re = new RegExp(`\\b${escapeRegExp(callee)}\\s*\\(`, "g");
	const sites: CallSite[] = [];
	for (const match of content.matchAll(re)) {
		const index = match.index ?? 0;
		const open = index + match[0].length - 1;
		const args = balancedSlice(content, open, MAX_CALL_ARGUMENTS);
		if (args === null) continue;
		sites.push({ index, args, text: content.slice(index, open + args.length + 2) });
	}
	return sites;
}

/** Split call arguments at top-level commas. */
function splitArguments(args: string): string[] {
	const parts: string[] = [];
	let depth = 0;
	let quote = "";
	let start = 0;
	for (let i = 0; i < args.length; i++) {
		const ch = args[i]!;
		if (quote) {
			if (ch === "\\") i++;
			else if (ch === quote) quote = "";
			continue;
		}
		if (ch === '"' || ch === "'" || ch === "`") quote = ch;
		else if (ch === "(" || ch === "[" || ch === "{") depth++;
		else if (ch === ")" || ch === "]" || ch === "}") depth--;
		else if (ch === "," && depth === 0) {
			parts.push(args.slice(start, i).trim());
			start = i + 1;
		}
	}
	parts.push(args.slice(start).trim());
	return parts;
}

function evidence(text: string): string {
	const normalized = text.replace(/\s+/g, " ").trim();
	return normalized.length > MAX_EVIDENCE
		? `${normalized.slice(0, MAX_EVIDENCE - 1)}…`
		: normalized;
}

/** Runtime checks are first-party only; dependency code is deliberately skipped. */
function isFirstParty(relativePath: string): boolean {
	return !relativePath.split("/").includes("node_modules");
}

// ── Certificate trust ──────────────────────────────────────────────────

function certificateErrorHits(content: string): RuntimeHit[] {
	const hits: RuntimeHit[] = [];
	const re = /["'`]certificate-error["'`]/g;
	for (const match of content.matchAll(re)) {
		const index = match.index ?? 0;
		// The call's "(" sits before the event string: app.on("certificate-error", ...)
		const open = content.lastIndexOf("(", index);
		if (open === -1) continue;
		const args = balancedSlice(content, open, MAX_CALL_ARGUMENTS);
		if (args === null) continue;

		// Without preventDefault the default verification still rejects, so this is
		// intent, not an exploitable trust decision.
		if (!/preventDefault\s*\(\s*\)/.test(args)) continue;
		if (!/\b(?:callback|cb|done)\s*\(\s*true\s*\)/.test(args)) continue;
		if (GUARD_RE.test(args)) continue;

		hits.push({
			severity: "critical",
			message: "certificate-error handler trusts certificates without verification",
			evidence: evidence(content.slice(index, open + args.length + 2))
		});
	}
	return hits;
}

function certificateVerifyProcHits(content: string): RuntimeHit[] {
	const hits: RuntimeHit[] = [];
	for (const site of callSites(content, "setCertificateVerifyProc")) {
		// 0 accepts; `true` is the legacy boolean form. -2 rejects, -3 defers to
		// Chromium, so neither is a trust decision.
		if (!/\b(?:callback|cb|done|verify)\s*\(\s*(?:0|true)\s*\)/.test(site.args)) continue;
		if (GUARD_RE.test(site.args) || /-\s*[23]\b/.test(site.args)) continue;

		hits.push({
			severity: "critical",
			message: "setCertificateVerifyProc blindly accepts certificates",
			evidence: evidence(site.text)
		});
	}
	return hits;
}

function certificateTrustHits(content: string): RuntimeHit[] {
	return [...certificateErrorHits(content), ...certificateVerifyProcHits(content)];
}

// ── Permission handlers ────────────────────────────────────────────────

function permissionRequestHits(content: string): RuntimeHit[] {
	const hits: RuntimeHit[] = [];
	for (const site of callSites(content, "setPermissionRequestHandler")) {
		if (!/\bcallback\s*\(\s*true\s*\)/.test(site.args)) continue;
		if (GUARD_RE.test(site.args)) continue;
		hits.push({
			severity: "warning",
			message: "Permission request handler grants every requested permission",
			evidence: evidence(site.text)
		});
	}
	return hits;
}

const ALWAYS_TRUE_RE = /=>\s*(?:\{\s*)?(?:return\s+)?true\b/;

function permissionCheckHits(content: string): RuntimeHit[] {
	const hits: RuntimeHit[] = [];
	for (const site of callSites(content, "setPermissionCheckHandler")) {
		if (!ALWAYS_TRUE_RE.test(site.args)) continue;
		if (GUARD_RE.test(site.args)) continue;
		hits.push({
			severity: "warning",
			message: "Permission check handler allows every permission",
			evidence: evidence(site.text)
		});
	}
	return hits;
}

function permissionHits(content: string): RuntimeHit[] {
	return [...permissionRequestHits(content), ...permissionCheckHits(content)];
}

// ── Window and external opening ────────────────────────────────────────

function windowOpenHits(content: string): RuntimeHit[] {
	const hits: RuntimeHit[] = [];
	for (const site of callSites(content, "setWindowOpenHandler")) {
		if (!/action\s*:\s*["']allow["']/.test(site.args)) continue;
		if (GUARD_RE.test(site.args)) continue;
		hits.push({
			severity: "warning",
			message: "setWindowOpenHandler allows every new window without a URL check",
			evidence: evidence(site.text)
		});
	}
	return hits;
}

function openExternalHits(content: string): RuntimeHit[] {
	const hits: RuntimeHit[] = [];
	for (const site of callSites(content, "shell.openExternal")) {
		const argument = splitArguments(site.args)[0] ?? "";
		if (STATIC_STRING_RE.test(argument)) continue;
		hits.push({
			severity: "info",
			message: "shell.openExternal receives a non-literal URL — verify it is validated",
			evidence: evidence(site.text)
		});
	}
	return hits;
}

// ── IPC exposure ───────────────────────────────────────────────────────

const PRELOAD_REFERENCE_RE = /(?:^|[,{]\s*)["']?preload["']?\s*:\s*([^\n}]{1,200})/g;
const STRING_LITERAL_RE = /["'`]([^"'`]+)["'`]/g;
const GENERIC_SCRIPT_NAMES = new Set(["index.js", "index.mjs", "index.cjs", "main.js"]);

function normalizeArchivePath(value: string): string {
	return value.replace(/^\.\//, "").replace(/\\/g, "/").toLowerCase();
}

function collectPreloadPaths(files: BundleFileEntry[]): Set<string> {
	const paths = new Set<string>();
	for (const file of files) {
		if (!isFirstParty(file.relativePath)) continue;
		for (const match of file.content.matchAll(PRELOAD_REFERENCE_RE)) {
			for (const literal of (match[1] ?? "").matchAll(STRING_LITERAL_RE)) {
				const value = literal[1];
				if (!value || value.includes("${")) continue;
				paths.add(normalizeArchivePath(value));
			}
		}
	}
	return paths;
}

function isPreloadFile(relativePath: string, preloadPaths: Set<string>): boolean {
	const archivePath = normalizeArchivePath(relativePath.replace(/^app\.asar\//, ""));
	const base = path.posix.basename(archivePath);
	if (base.startsWith("preload")) return true;
	if (/(^|\/)preload[^/]*\//.test(archivePath)) return true;
	if (preloadPaths.has(archivePath)) return true;
	// A bare "index.js"/"main.js" reference would mark every bundle file, so
	// generic basenames only count when the path itself was named.
	return !GENERIC_SCRIPT_NAMES.has(base) && preloadPaths.has(base);
}

const EXPOSED_IPC_MEMBER_RE =
	/(?:^|[,{]\s*)(?:[A-Za-z_$][\w$]*\s*:\s*)?ipcRenderer(?:\s*\.\s*[A-Za-z_$][\w$]*(?:\s*\.\s*bind\s*\(\s*ipcRenderer\s*\))?)?\s*(?=,|})/;

function ipcExposureHits(content: string): RuntimeHit[] {
	const hits: RuntimeHit[] = [];
	for (const site of callSites(content, "contextBridge.exposeInMainWorld")) {
		const exposed = (splitArguments(site.args)[1] ?? "").trim();
		if (exposed === "ipcRenderer") {
			hits.push({
				severity: "warning",
				message: "contextBridge exposes the raw ipcRenderer to the renderer",
				evidence: evidence(site.text)
			});
			continue;
		}
		if (!exposed.startsWith("{") || !EXPOSED_IPC_MEMBER_RE.test(exposed)) continue;
		hits.push({
			severity: "warning",
			message: "contextBridge exposes ipcRenderer through the preload API",
			evidence: evidence(site.text)
		});
	}
	return hits;
}

const FORWARDED_IPC_METHODS = ["send", "sendSync", "invoke", "postMessage", "on", "once"];

function forwardedChannelHits(content: string): RuntimeHit[] {
	const hits: RuntimeHit[] = [];
	for (const method of FORWARDED_IPC_METHODS) {
		for (const site of callSites(content, `ipcRenderer.${method}`)) {
			const channel = splitArguments(site.args)[0] ?? "";
			if (STATIC_STRING_RE.test(channel)) continue;
			hits.push({
				severity: "warning",
				message: "preload forwards an arbitrary IPC channel",
				evidence: evidence(site.text)
			});
		}
	}
	return hits;
}

// ── Orchestration ──────────────────────────────────────────────────────

interface RuntimeCheck {
	id: string;
	scope: "all" | "preload";
	run: (content: string) => RuntimeHit[];
}

const RUNTIME_CHECKS: RuntimeCheck[] = [
	{ id: "certificate-trust", scope: "all", run: certificateTrustHits },
	{ id: "permission-handlers", scope: "all", run: permissionHits },
	{ id: "ipc-exposure", scope: "preload", run: ipcExposureHits },
	{ id: "ipc-forwarding", scope: "preload", run: forwardedChannelHits },
	{ id: "window-open", scope: "all", run: windowOpenHits },
	{ id: "external-open", scope: "all", run: openExternalHits }
];

/** Runtime API findings for first-party archive text, ordered by impact. */
export function findRuntimeApiFindings(files: BundleFileEntry[]): SecurityFinding[] {
	const preloadPaths = collectPreloadPaths(files);
	const findings: SecurityFinding[] = [];

	for (const check of RUNTIME_CHECKS) {
		let count = 0;
		for (const file of files) {
			if (count >= MAX_FINDINGS_PER_CHECK) break;
			if (!isFirstParty(file.relativePath)) continue;
			if (check.scope === "preload" && !isPreloadFile(file.relativePath, preloadPaths)) {
				continue;
			}
			for (const hit of check.run(file.content)) {
				if (count >= MAX_FINDINGS_PER_CHECK) break;
				findings.push({ ...hit, category: CATEGORY, source: file.relativePath });
				count++;
			}
		}
	}

	return findings;
}

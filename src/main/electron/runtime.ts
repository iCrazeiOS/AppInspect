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

interface FunctionScope {
	name: string;
	params: string;
	headerStart: number;
	bodyStart: number;
	bodyEnd: number;
}

/** Text between the braces at `open`, ignoring braces inside strings. */
function balancedBraces(content: string, open: number, max = 1_000_000): string | null {
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
		else if (ch === "{") depth++;
		else if (ch === "}" && --depth === 0) return content.slice(open + 1, i);
	}
	return null;
}

/** End of a concise arrow body, stopping at a top-level semicolon or newline. */
function expressionEnd(content: string, start: number, max = 20_000): number {
	let depth = 0;
	let quote = "";
	const end = Math.min(content.length, start + max);
	for (let i = start; i < end; i++) {
		const ch = content[i]!;
		if (quote) {
			if (ch === "\\") i++;
			else if (ch === quote) quote = "";
			continue;
		}
		if (ch === '"' || ch === "'" || ch === "`") quote = ch;
		else if (ch === "(" || ch === "[" || ch === "{") depth++;
		else if (ch === ")" || ch === "]" || ch === "}") depth--;
		else if ((ch === ";" || ch === "\n") && depth === 0) return i;
	}
	return end;
}

/**
 * Named function declarations and arrow functions with their body ranges.
 * Only named functions are collected: forwarding through an anonymous wrapper
 * has no call sites to check, so those stay flagged.
 */
function functionScopes(content: string): FunctionScope[] {
	const scopes: FunctionScope[] = [];

	const declarations = /\bfunction\s+([A-Za-z_$][\w$]*)\s*\(/g;
	for (const match of content.matchAll(declarations)) {
		const headerStart = match.index ?? 0;
		const open = headerStart + match[0].length - 1;
		const params = balancedSlice(content, open, 2_000);
		if (params === null) continue;
		let brace = open + params.length + 2;
		while (brace < content.length && /\s/.test(content[brace]!)) brace++;
		if (content[brace] !== "{") continue;
		const body = balancedBraces(content, brace);
		if (body === null) continue;
		scopes.push({
			name: match[1]!,
			params,
			headerStart,
			bodyStart: brace,
			bodyEnd: brace + body.length + 2
		});
	}

	const arrows =
		/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:function\s*)?\(/g;
	for (const match of content.matchAll(arrows)) {
		const headerStart = match.index ?? 0;
		const open = headerStart + match[0].length - 1;
		const params = balancedSlice(content, open, 2_000);
		if (params === null) continue;
		let arrow = open + params.length + 2;
		while (arrow < content.length && /\s/.test(content[arrow]!)) arrow++;
		if (content[arrow] !== "=" || content[arrow + 1] !== ">") continue;
		arrow += 2;
		while (arrow < content.length && /\s/.test(content[arrow]!)) arrow++;
		if (content[arrow] === "{") {
			const body = balancedBraces(content, arrow);
			if (body === null) continue;
			scopes.push({
				name: match[1]!,
				params,
				headerStart,
				bodyStart: arrow,
				bodyEnd: arrow + body.length + 2
			});
		} else {
			scopes.push({
				name: match[1]!,
				params,
				headerStart,
				bodyStart: arrow,
				bodyEnd: expressionEnd(content, arrow)
			});
		}
	}

	return scopes;
}

/** Innermost named function containing `index`. */
function enclosingScope(scopes: FunctionScope[], index: number): FunctionScope | null {
	let found: FunctionScope | null = null;
	for (const scope of scopes) {
		if (scope.bodyStart > index || scope.bodyEnd <= index) continue;
		if (!found || scope.bodyStart > found.bodyStart) found = scope;
	}
	return found;
}

/**
 * A named helper that only ever receives literal channels is an internal
 * convenience wrapper, not an arbitrary forwarder. If the name is used as a
 * value anywhere (for example handed to `exposeInMainWorld`), stay flagged.
 */
function isLiteralOnlyWrapper(
	content: string,
	scopes: FunctionScope[],
	index: number,
	channel: string
): boolean {
	const scope = enclosingScope(scopes, index);
	if (!scope) return false;
	const firstParam = (splitArguments(scope.params)[0] ?? "")
		.trim()
		.replace(/^\.\.\./, "")
		.split("=")[0]!
		.trim();
	if (firstParam !== channel.trim()) return false;

	const name = new RegExp(`(?<![\\w$])${escapeRegExp(scope.name)}(?![\\w$])`, "g");
	let calls = 0;
	for (const match of content.matchAll(name)) {
		const at = match.index ?? 0;
		if (at >= scope.headerStart && at < scope.bodyStart) continue;
		let open = at + scope.name.length;
		while (open < content.length && /\s/.test(content[open]!)) open++;
		if (content[open] !== "(") return false;
		const args = balancedSlice(content, open, MAX_CALL_ARGUMENTS * 20);
		if (args === null) return false;
		calls++;
		if (!STATIC_STRING_RE.test((splitArguments(args)[0] ?? "").trim())) return false;
	}
	return calls > 0;
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

interface ElectronShellAliases {
	/** Aliases of the whole `electron` module, for `X.shell.openExternal`. */
	namespaces: Set<string>;
	/** Aliases of `electron.shell`, for `Y.openExternal`. */
	shells: Set<string>;
}

/** Local names bound to the Electron shell by requires and ES imports. */
function electronShellAliases(content: string): ElectronShellAliases {
	const namespaces = new Set<string>();
	const shells = new Set<string>();

	const addSpecifiers = (specifiers: string): void => {
		for (const raw of splitArguments(specifiers.replace(/\s+as\s+/g, ":"))) {
			const [imported = "", local = ""] = raw.split(":");
			if (imported.trim() !== "shell") continue;
			shells.add(local.trim() || "shell");
		}
	};

	for (const match of content.matchAll(
		/\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\(\s*["']electron["']\s*\)/g
	)) {
		addSpecifiers(match[1] ?? "");
	}
	for (const match of content.matchAll(
		/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*["']electron["']\s*\)(?!\s*\.)/g
	)) {
		namespaces.add(match[1]!);
	}
	for (const match of content.matchAll(
		/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*["']electron["']\s*\)\s*\.\s*shell\b/g
	)) {
		shells.add(match[1]!);
	}
	for (const match of content.matchAll(/\bimport\s+([^;]*?)\s+from\s*["']electron["']/g)) {
		const clause = (match[1] ?? "").trim();
		const named = clause.match(/\{([^}]*)\}/);
		if (named) addSpecifiers(named[1] ?? "");
		if (clause.startsWith("*")) {
			const alias = clause.match(/^\*\s*as\s+([A-Za-z_$][\w$]*)/);
			if (alias) namespaces.add(alias[1]!);
		} else if (!clause.startsWith("{")) {
			const alias = clause.match(/^([A-Za-z_$][\w$]*)/);
			if (alias) namespaces.add(alias[1]!);
		}
	}

	return { namespaces, shells };
}

/** Identifier ending at `end`, or null when the text there is not a name. */
function identifierBefore(content: string, end: number): { name: string; start: number } | null {
	let start = end;
	while (start > 0 && /[\w$]/.test(content[start - 1]!)) start--;
	if (start === end) return null;
	return { name: content.slice(start, end), start };
}

/**
 * Start of the callee chain when the `openExternal` call at `index` roots at
 * the Electron shell, or null otherwise. Bare `shell`, a known shell alias,
 * and `namespace.shell` for a known Electron module alias all qualify.
 * Wrappers such as `this.shell`/`SafeShell` are local APIs that may validate
 * the URL first, so they are left alone.
 */
function electronShellCallStart(
	content: string,
	index: number,
	aliases: ElectronShellAliases
): number | null {
	let cursor = index;
	while (cursor > 0 && /\s/.test(content[cursor - 1]!)) cursor--;
	if (cursor === 0 || content[cursor - 1] !== ".") return null;
	cursor--;
	while (cursor > 0 && /\s/.test(content[cursor - 1]!)) cursor--;

	const identifier = identifierBefore(content, cursor);
	if (!identifier) return null;

	const { name, start } = identifier;
	let objectEnd = start;
	while (objectEnd > 0 && /\s/.test(content[objectEnd - 1]!)) objectEnd--;
	const qualified = objectEnd > 0 && content[objectEnd - 1] === ".";

	if (!qualified) return name === "shell" || aliases.shells.has(name) ? start : null;

	const object = identifierBefore(content, objectEnd - 1);
	return object !== null && aliases.namespaces.has(object.name) ? object.start : null;
}

/** Electron's second argument is an options object or undefined. */
function isOptionsArgument(argument: string | undefined): boolean {
	const value = (argument ?? "").trim();
	return value === "" || value === "undefined" || value === "void 0" || value.startsWith("{");
}

function openExternalHits(content: string): RuntimeHit[] {
	const hits: RuntimeHit[] = [];
	const aliases = electronShellAliases(content);
	for (const site of callSites(content, "openExternal")) {
		const start = electronShellCallStart(content, site.index, aliases);
		if (start === null) continue;
		const args = splitArguments(site.args);
		if (STATIC_STRING_RE.test(args[0] ?? "")) continue;
		if (!isOptionsArgument(args[1])) continue;
		hits.push({
			severity: "info",
			message: "shell.openExternal receives a non-literal URL — verify it is validated",
			evidence: evidence(content.slice(start, site.index + site.text.length))
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

/** Identifier or member expression: a channel a guard can name exactly. */
const SIMPLE_CHANNEL_RE = /^[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*$/;

/** How far before the call to look for an enclosing allowlist check. */
const CHANNEL_GUARD_WINDOW = 600;

/** True when a nearby guard validates this exact channel expression. */
function hasChannelGuard(content: string, index: number, channel: string): boolean {
	const escaped = escapeRegExp(channel);
	// Lookarounds instead of \b so `$`-prefixed identifiers are matched too, and
	// so `mychannel` cannot satisfy a guard written for `channel`.
	const left = "(?<![\\w$])";
	const right = "(?![\\w$])";
	const guard = new RegExp(
		`\\.(?:includes|indexOf|startsWith|endsWith|has)\\s*\\(\\s*${left}${escaped}${right}\\s*\\)` +
			`|\\bswitch\\s*\\(\\s*${left}${escaped}${right}\\s*\\)` +
			`|${left}${escaped}${right}\\s*(?:===|!==|==|!=)` +
			`|(?:===|!==|==|!=)\\s*${left}${escaped}${right}`
	);
	const start = Math.max(0, index - CHANNEL_GUARD_WINDOW);
	return guard.test(content.slice(start, index));
}

function forwardedChannelHits(content: string): RuntimeHit[] {
	const hits: RuntimeHit[] = [];
	let scopes: FunctionScope[] | null = null;
	for (const method of FORWARDED_IPC_METHODS) {
		for (const site of callSites(content, `ipcRenderer.${method}`)) {
			const channel = splitArguments(site.args)[0] ?? "";
			if (STATIC_STRING_RE.test(channel)) continue;
			if (SIMPLE_CHANNEL_RE.test(channel)) {
				// A validated channel is deliberate allowlisting, not blind forwarding.
				if (hasChannelGuard(content, site.index, channel)) continue;
				// Likewise a helper whose every call site passes a literal channel.
				scopes ??= functionScopes(content);
				if (isLiteralOnlyWrapper(content, scopes, site.index, channel)) continue;
			}
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

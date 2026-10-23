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
/** Large destructured parameter lists (Signal's settings factory) exceed 2 KB. */
const MAX_PARAM_LIST = 16_000;
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
		if (ch === "/" && content[i + 1] === "/") {
			while (i < end && content[i] !== "\n") i++;
		} else if (ch === "/" && content[i + 1] === "*") {
			i += 2;
			while (i < end && !(content[i] === "*" && content[i + 1] === "/")) i++;
			i++;
		} else if (ch === '"' || ch === "'" || ch === "`") quote = ch;
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
		if (ch === "/" && content[i + 1] === "/") {
			while (i < end && content[i] !== "\n") i++;
		} else if (ch === "/" && content[i + 1] === "*") {
			i += 2;
			while (i < end && !(content[i] === "*" && content[i + 1] === "/")) i++;
			i++;
		} else if (ch === '"' || ch === "'" || ch === "`") quote = ch;
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
		const params = balancedSlice(content, open, MAX_PARAM_LIST);
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
		const params = balancedSlice(content, open, MAX_PARAM_LIST);
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

/**
 * Named functions containing `index`, innermost first. Minified bundles often
 * put the `ipcRenderer` call in a small local helper that closes over the
 * channel parameter of an outer factory, so parameter lookup walks outward.
 */
function enclosingScopes(scopes: FunctionScope[], index: number): FunctionScope[] {
	return scopes
		.filter((scope) => scope.bodyStart <= index && scope.bodyEnd > index)
		.sort((a, b) => b.bodyStart - a.bodyStart);
}

/** Parameter position named `name`, ignoring `...` and default values. */
function parameterIndex(params: string, name: string): number {
	const parts = splitArguments(params);
	for (let i = 0; i < parts.length; i++) {
		const parameter = (parts[i] ?? "")
			.trim()
			.replace(/^\.\.\./, "")
			.split("=")[0]!
			.trim();
		if (parameter === name) return i;
	}
	return -1;
}

/** A parameter with a default value is never "absent" at a call site. */
function parameterHasDefault(params: string, position: number): boolean {
	return (splitArguments(params)[position] ?? "").includes("=");
}

interface ParameterOwner {
	scope: FunctionScope;
	position: number;
}

/** The scope whose parameter list names `name`, innermost first. */
function parameterOwner(
	scopes: FunctionScope[],
	index: number,
	name: string
): ParameterOwner | null {
	for (const scope of enclosingScopes(scopes, index)) {
		const position = parameterIndex(scope.params, name);
		if (position !== -1) return { scope, position };
	}
	return null;
}

const VALUE_CONTEXT_RE =
	/(?:^|[:(,=[!&|?;{}]|\breturn|\btypeof|\bnew|\bawait|\byield|\bcase|=>)\s*$/;
/** `.x` or `?.x`: a property, never this local binding. */
const PROPERTY_ACCESS_RE = /(?:\?\.|\.)\s*$/;
/** Call arguments may be longer than an argument list we merely inspect. */
const MAX_WRAPPER_CALL_ARGUMENTS = MAX_CALL_ARGUMENTS * 20;

function precedingText(content: string, at: number): string {
	return content.slice(Math.max(0, at - 16), at);
}

/**
 * Innermost open brace enclosing `at`, found by binary search over the sorted
 * open positions. Walking backwards skips scopes that already closed, which
 * yields the innermost enclosing scope because inner braces open later.
 */
function enclosingBrace(opens: number[], ends: Map<number, number>, at: number): number {
	let low = 0;
	let high = opens.length - 1;
	let found = -1;
	while (low <= high) {
		const middle = (low + high) >> 1;
		if (opens[middle]! <= at) {
			found = middle;
			low = middle + 1;
		} else {
			high = middle - 1;
		}
	}
	for (let index = found; index >= 0; index--) {
		const open = opens[index]!;
		if (ends.get(open)! > at) return open;
	}
	return -1;
}

/** Code offsets where `name` appears as a whole identifier. */
function nameOccurrences(content: string, name: string, mask: Uint8Array): number[] {
	const occurrences: number[] = [];
	const boundary = /[\w$]/;
	let at = content.indexOf(name);
	while (at !== -1) {
		const before = at === 0 ? "" : content[at - 1]!;
		const after = at + name.length < content.length ? content[at + name.length]! : "";
		if (mask[at] === 1 && !boundary.test(before) && !boundary.test(after)) {
			occurrences.push(at);
		}
		at = content.indexOf(name, at + 1);
	}
	return occurrences;
}

const DECLARATION_RE = /\b(?:function\s*\*?\s*|const\s+|let\s+|var\s+|class\s+)([A-Za-z_$][\w$]*)/g;

/** Split at top-level commas, keeping each part's offset. */
function splitTopLevel(value: string): Array<{ text: string; start: number }> {
	const parts: Array<{ text: string; start: number }> = [];
	let depth = 0;
	let quote = "";
	let start = 0;
	for (let i = 0; i < value.length; i++) {
		const ch = value[i]!;
		if (quote) {
			if (ch === "\\") i++;
			else if (ch === quote) quote = "";
			continue;
		}
		if (ch === '"' || ch === "'" || ch === "`") {
			quote = ch;
			continue;
		}
		if (ch === "{" || ch === "[" || ch === "(") depth++;
		else if (ch === "}" || ch === "]" || ch === ")") depth--;
		else if (ch === "," && depth === 0) {
			parts.push({ text: value.slice(start, i), start });
			start = i + 1;
		}
	}
	parts.push({ text: value.slice(start), start });
	return parts;
}

/** Index of the first `:` at depth 0, or -1. */
function topLevelColon(value: string): number {
	let depth = 0;
	let quote = "";
	for (let i = 0; i < value.length; i++) {
		const ch = value[i]!;
		if (quote) {
			if (ch === "\\") i++;
			else if (ch === quote) quote = "";
			continue;
		}
		if (ch === '"' || ch === "'" || ch === "`") quote = ch;
		else if (ch === "{" || ch === "[" || ch === "(") depth++;
		else if (ch === "}" || ch === "]" || ch === ")") depth--;
		else if (ch === ":" && depth === 0) return i;
	}
	return -1;
}

/** Index of the first assignment `=` at depth 0, or -1. */
function topLevelDefault(value: string): number {
	let depth = 0;
	let quote = "";
	for (let i = 0; i < value.length; i++) {
		const ch = value[i]!;
		if (quote) {
			if (ch === "\\") i++;
			else if (ch === quote) quote = "";
			continue;
		}
		if (ch === '"' || ch === "'" || ch === "`") quote = ch;
		else if (ch === "{" || ch === "[" || ch === "(") depth++;
		else if (ch === "}" || ch === "]" || ch === ")") depth--;
		else if (ch === "=" && depth === 0) {
			const before = value[i - 1] ?? "";
			if (value[i + 1] === "=" || "=!<>".includes(before)) continue;
			return i;
		}
	}
	return -1;
}

/** The balanced `{...}`/`[...]` at the start of `value`, ignoring a default. */
function leadingPattern(value: string): string | null {
	if (value[0] !== "{" && value[0] !== "[") return null;
	let depth = 0;
	let quote = "";
	for (let i = 0; i < value.length; i++) {
		const ch = value[i]!;
		if (quote) {
			if (ch === "\\") i++;
			else if (ch === quote) quote = "";
			continue;
		}
		if (ch === '"' || ch === "'" || ch === "`") {
			quote = ch;
			continue;
		}
		if (ch === "{" || ch === "[" || ch === "(") depth++;
		else if (ch === "}" || ch === "]" || ch === ")") {
			depth--;
			if (depth === 0) return value.slice(0, i + 1);
		}
	}
	return null;
}

/**
 * Positions of `name` bound by a destructuring pattern, relative to `base`.
 * Property keys are skipped: in `{ helper: name }` only `name` is bound, while
 * `{ name }` and `[name]` bind `name` itself.
 */
function collectPatternBindings(pattern: string, name: string, base: number, out: number[]): void {
	const inner = pattern.slice(1, -1);
	for (const part of splitTopLevel(inner)) {
		collectBindingTarget(part.text, name, base + 1 + part.start, out);
	}
}

function collectBindingTarget(segment: string, name: string, base: number, out: number[]): void {
	const trimmed = segment.trim();
	const offset = base + (segment.length - segment.trimStart().length);
	if (trimmed === "") return;

	if (trimmed.startsWith("...")) {
		collectBindingTarget(trimmed.slice(3), name, offset + 3, out);
		return;
	}
	if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
		const pattern = leadingPattern(trimmed);
		if (pattern !== null) collectPatternBindings(pattern, name, offset, out);
		return;
	}

	const colon = topLevelColon(trimmed);
	if (colon !== -1) {
		const target = trimmed.slice(colon + 1);
		collectBindingTarget(target, name, offset + colon + 1, out);
		return;
	}

	const fallback = topLevelDefault(trimmed);
	const identifier = (fallback === -1 ? trimmed : trimmed.slice(0, fallback)).trim();
	if (identifier === name) out.push(offset);
}

/**
 * Binding positions of `name` inside a function's parameter list. Destructured
 * parameters (Signal's settings factory) shadow the name before the body's
 * opening brace, so they need their own attribution entry.
 */
function parameterBindings(
	content: string,
	scope: FunctionScope,
	name: string,
	mask: Uint8Array
): Binding[] {
	const paramsStart = content.indexOf(scope.params, scope.headerStart);
	if (paramsStart === -1) return [];

	const bindings: Binding[] = [];
	let searchFrom = 0;
	for (const segment of splitArguments(scope.params)) {
		const segmentStart = scope.params.indexOf(segment, searchFrom);
		if (segmentStart === -1) continue;
		searchFrom = segmentStart + segment.length;

		const positions: number[] = [];
		collectBindingTarget(segment, name, paramsStart + segmentStart, positions);
		for (const pos of positions) {
			if (mask[pos] === 1) bindings.push({ pos, end: scope.bodyEnd });
		}
	}
	return bindings;
}

/**
 * Every binding of `name` that can shadow the helper, with the end of its
 * enclosing scope. Minified bundles reuse short names in unrelated modules, so
 * a call site only belongs to this helper when the nearest preceding binding
 * that covers it is this helper's own declaration.
 *
 * Covers plain declarations, comma-continued declarators (`var a, it = ...`),
 * destructuring targets and parameters. Destructuring patterns of parameters
 * are handled by the caller through `functionScopes`, whose params mention the
 * name. Over-collecting is safe: an unattributed call keeps the warning.
 */
function bindingPositions(
	content: string,
	name: string,
	mask: Uint8Array,
	scopeEnd: (at: number) => number
): Binding[] {
	const bindings: Binding[] = [];
	const add = (pos: number, end: number): void => {
		if (mask[pos] === 1) bindings.push({ pos, end });
	};

	for (const match of content.matchAll(DECLARATION_RE)) {
		if (match[1] !== name) continue;
		const pos = (match.index ?? 0) + match[0].length - name.length;
		add(pos, scopeEnd(pos));
	}

	// Comma-continued declarators: `var a, NAME = ...`.
	const comma = new RegExp(`,\\s*${escapeRegExp(name)}(?=\\s*=)`, "g");
	for (const match of content.matchAll(comma)) {
		const pos = (match.index ?? 0) + match[0].length - name.length;
		add(pos, scopeEnd(pos));
	}

	// Destructuring targets: `const { a: NAME } = ...`, `[NAME] = ...`.
	for (const match of content.matchAll(/\{([^{}]*)\}\s*=/g)) {
		const start = match.index ?? 0;
		const end = scopeEnd(Math.max(0, start - 1));
		const positions: number[] = [];
		collectPatternBindings(match[0].replace(/\s*=$/, ""), name, start, positions);
		for (const pos of positions) add(pos, end);
	}
	for (const match of content.matchAll(/\[([^[\]]*)\]\s*=/g)) {
		const start = match.index ?? 0;
		// `obj[NAME] = ...` is a member write, not an array pattern.
		const previous = content[start - 1];
		if (previous !== undefined && /[\w$)\]}'"`.]/.test(previous)) continue;
		const end = scopeEnd(Math.max(0, start - 1));
		const positions: number[] = [];
		collectPatternBindings(match[0].replace(/\s*=$/, ""), name, start, positions);
		for (const pos of positions) add(pos, end);
	}

	bindings.sort((a, b) => a.pos - b.pos);
	return bindings;
}

/** Innermost binding whose scope covers `at`. */
function nearestBinding(bindings: Binding[], at: number): Binding | null {
	let low = 0;
	let high = bindings.length - 1;
	let found = -1;
	while (low <= high) {
		const middle = (low + high) >> 1;
		if (bindings[middle]!.pos <= at) {
			found = middle;
			low = middle + 1;
		} else {
			high = middle - 1;
		}
	}
	for (let index = found; index >= 0; index--) {
		const binding = bindings[index]!;
		if (binding.end > at) return binding;
	}
	return null;
}

/**
 * Every direct call to `scope.name` must pass a static value for each of the
 * given parameter positions. Using the name as a value anywhere (for example
 * handing the helper to `exposeInMainWorld`) keeps the flag, as there is then
 * no bound on the channels it can receive.
 *
 * An omitted argument is `undefined` — not attacker-controlled — so it is
 * accepted unless the parameter has a default that would supply something else.
 * Spread arguments can shift any position, so they always keep the flag.
 *
 * Minified bundles reuse short names, so an occurrence only counts when the
 * nearest binding covering it is this helper's declaration.
 */
function staticWrapperCalls(
	content: string,
	scope: FunctionScope,
	positions: number[],
	values: StaticValues
): boolean {
	const index = values.wrapperIndex(scope.name);
	const occurrences = index.occurrences.filter(
		(at) => at < scope.headerStart || at >= scope.bodyStart
	);
	const bindings = index.bindings;
	const ours = bindings.find(
		(binding) => binding.pos >= scope.headerStart && binding.pos < scope.bodyStart
	);
	if (ours === undefined) return false;

	let calls = 0;
	for (const at of occurrences) {
		const nearest = nearestBinding(bindings, at);
		if (nearest === null) {
			// Only hoisted uses before the declaration can be this helper; once its
			// scope has ended the name belongs to another binding.
			if (at > ours.pos && ours.end <= at) continue;
		} else if (nearest.pos !== ours.pos) {
			// A different binding says nothing about the channels this helper takes.
			continue;
		}

		// `other.it(...)` is a property, not this binding.
		if (PROPERTY_ACCESS_RE.test(precedingText(content, at))) continue;

		let open = at + scope.name.length;
		while (open < content.length && /\s/.test(content[open]!)) open++;
		if (content[open] !== "(") {
			// A property key (`{ it: ... }`) and plain prose are not uses. A ternary
			// consequence (`cond ? it : other`) is a value use.
			if (content[open] === ":") {
				if (/[{,]\s*$/.test(precedingText(content, at))) continue;
				return false;
			}
			if (VALUE_CONTEXT_RE.test(precedingText(content, at))) return false;
			continue;
		}
		const args = balancedSlice(content, open, MAX_WRAPPER_CALL_ARGUMENTS);
		if (args === null) return false;
		const parts = splitArguments(args);
		if (parts.some((part) => part.startsWith("..."))) return false;
		calls++;
		for (const position of positions) {
			const argument = (parts[position] ?? "").trim();
			if (argument === "") {
				if (parameterHasDefault(scope.params, position)) return false;
				continue;
			}
			if (!values.isStatic(argument)) return false;
		}
	}
	return calls > 0;
}

function isStaticOnlyWrapper(
	content: string,
	scopes: FunctionScope[],
	index: number,
	channel: string,
	values: StaticValues
): boolean {
	const owner = parameterOwner(scopes, index, channel.trim());
	if (!owner) return false;
	return staticWrapperCalls(content, owner.scope, [owner.position], values);
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

interface Binding {
	pos: number;
	/** Offset just past the binding's enclosing scope. */
	end: number;
}

interface WrapperIndex {
	/** Code occurrences of the name, including declarations. */
	occurrences: number[];
	/** Declarations, destructured bindings, parameters and shadowing ranges. */
	bindings: Binding[];
}

/** True when a channel expression is provably a fixed string. */
interface StaticValues {
	isStatic(expression: string): boolean;
	/** Per-name call-site index, built once because bundle names repeat. */
	wrapperIndex(name: string): WrapperIndex;
}

const REGEX_PRECEDING_KEYWORDS = new Set([
	"return",
	"typeof",
	"instanceof",
	"in",
	"of",
	"new",
	"delete",
	"void",
	"case",
	"do",
	"else",
	"yield",
	"await",
	"throw"
]);

/** A `/` starts a regex literal unless it follows a value (division). */
function regexAllowedAt(content: string, index: number): boolean {
	let cursor = index - 1;
	while (cursor >= 0 && /\s/.test(content[cursor]!)) cursor--;
	if (cursor < 0) return true;
	const ch = content[cursor]!;
	if ("([{,;:=!&|?+-*%<>~^".includes(ch)) return true;
	if (!/[\w$]/.test(ch)) return false;
	let start = cursor;
	while (start > 0 && /[\w$]/.test(content[start - 1]!)) start--;
	return REGEX_PRECEDING_KEYWORDS.has(content.slice(start, cursor + 1));
}

/** Code-only mask plus brace/paren matching, from one quote-aware pass. */
interface CodeStructure {
	/** 1 for code characters, 0 inside strings, templates, comments and regexes. */
	mask: Uint8Array;
	/** Closing brace offset for every open brace. */
	braceEnds: Map<number, number>;
	/** Opening paren offset for every closing paren. */
	parenOpens: Map<number, number>;
}

function scanStructure(content: string): CodeStructure {
	const mask = new Uint8Array(content.length);
	const braceEnds = new Map<number, number>();
	const parenOpens = new Map<number, number>();
	const braces: number[] = [];
	const parens: number[] = [];
	let quote = "";
	let i = 0;
	while (i < content.length) {
		const ch = content[i]!;
		if (quote) {
			if (ch === "\\") i += 2;
			else if (ch === quote) {
				quote = "";
				i++;
			} else i++;
			continue;
		}
		if (ch === '"' || ch === "'" || ch === "`") {
			quote = ch;
			i++;
			continue;
		}
		if (ch === "/" && content[i + 1] === "/") {
			i += 2;
			while (i < content.length && content[i] !== "\n") i++;
			continue;
		}
		if (ch === "/" && content[i + 1] === "*") {
			i += 2;
			while (i < content.length && !(content[i] === "*" && content[i + 1] === "/")) i++;
			i += 2;
			continue;
		}
		if (ch === "/" && regexAllowedAt(content, i)) {
			i++;
			let inClass = false;
			while (i < content.length) {
				const inner = content[i]!;
				if (inner === "\\") i += 2;
				else if (inner === "[") {
					inClass = true;
					i++;
				} else if (inner === "]") {
					inClass = false;
					i++;
				} else if (inner === "/" && !inClass) {
					i++;
					break;
				} else if (inner === "\n") break;
				else i++;
			}
			while (i < content.length && /[a-z]/i.test(content[i]!)) i++;
			continue;
		}

		mask[i] = 1;
		if (ch === "{") braces.push(i);
		else if (ch === "}") {
			const open = braces.pop();
			if (open !== undefined) braceEnds.set(open, i);
		} else if (ch === "(") parens.push(i);
		else if (ch === ")") {
			const open = parens.pop();
			if (open !== undefined) parenOpens.set(i, open);
		}
		i++;
	}
	return { mask, braceEnds, parenOpens };
}

const IDENTIFIER_RE = /^[A-Za-z_$][\w$]*$/;
const CONST_DECLARATION_RE = /\bconst\s+([A-Za-z_$][\w$]*)\s*=/g;
const BINDING_RE = /\b(?:function\s*\*?\s*|class\s+|const\s+|let\s+|var\s+)([A-Za-z_$][\w$]*)/g;
const STRING_LITERAL_AT_RE = /^(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`[^`$]*`)/;
const MEMBER_RE =
	/^([A-Za-z_$][\w$]*)\s*(?:\.\s*([A-Za-z_$][\w$]*)|\[\s*(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')\s*\])$/;
const OBJECT_PROPERTY_RE =
	/^(?:([A-Za-z_$][\w$]*)|"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')\s*:\s*([\s\S]+)$/;
const METHOD_HEADER_RE =
	/(?:^|[{,};\n])\s*(?:static\s+)?(?:async\s+)?(?:get\s+|set\s+)?\*?\s*([A-Za-z_$][\w$]*)\s*\(/g;
const SINGLE_ARROW_PARAM_RE = /([A-Za-z_$][\w$]*)\s*=>/g;
const DESTRUCTURING_RE = /(?:const|let|var)\s*([{[][^;]{0,500}?[}\]])\s*=/g;
const IMPORT_CLAUSE_RE = /\bimport\s+([^;]+?)\s+from\b/g;
const MEMBER_WRITE_RE =
	/\b([A-Za-z_$][\w$]*)\s*(?:(?:\.\s*[A-Za-z_$][\w$]*)|(?:\[[^\]]*\]))\s*(?:\*\*|&&|\|\||\?\?|[+\-*/%&|^])?=(?!=)/g;
const OBJECT_MUTATOR_RE = /\bObject\s*\.\s*(?:assign|defineProperty)\s*\(\s*([A-Za-z_$][\w$]*)/g;
const METHOD_KEYWORDS = new Set([
	"if",
	"for",
	"while",
	"switch",
	"catch",
	"with",
	"return",
	"typeof",
	"function",
	"class",
	"const",
	"let",
	"var",
	"do",
	"else",
	"try",
	"finally",
	"throw",
	"delete",
	"void",
	"in",
	"of",
	"instanceof",
	"new"
]);
const MAX_STATIC_OBJECT = 20_000;
const MAX_STATIC_STRING = 512;

function unescapeKey(value: string): string {
	return value.replace(/\\(.)/g, "$1");
}

/**
 * Flat object literal with every property a fixed string. One dynamic value
 * taints the whole object: a partially known enum proves nothing about the
 * keys that are not known.
 */
function staticObject(literal: string): Set<string> | null {
	const keys = new Set<string>();
	for (const raw of splitArguments(literal.slice(1, -1))) {
		const property = raw.trim();
		if (property === "") continue;
		const match = OBJECT_PROPERTY_RE.exec(property);
		if (!match) return null;
		if (!STATIC_STRING_RE.test((match[4] ?? "").trim())) return null;
		keys.add(match[1] ?? unescapeKey(match[2] ?? match[3] ?? ""));
	}
	return keys;
}

type StaticInitializer = { kind: "string" } | { kind: "object"; keys: Set<string> };

/** Fixed string or flat object at `start`, for `const NAME = <initializer>`. */
function parseStaticInitializer(content: string, start: number): StaticInitializer | null {
	if (/^Object\.freeze\s*\(/.test(content.slice(start, start + 32))) {
		const open = content.indexOf("(", start);
		if (open === -1) return null;
		const inner = balancedSlice(content, open, MAX_STATIC_OBJECT);
		if (inner === null) return null;
		const value = inner.trim();
		if (!value.startsWith("{") || !value.endsWith("}")) return null;
		const keys = staticObject(value);
		return keys === null ? null : { kind: "object", keys };
	}
	if (content[start] === "{") {
		const literal = balancedBraces(content, start, MAX_STATIC_OBJECT);
		if (literal === null) return null;
		const keys = staticObject(`{${literal}}`);
		return keys === null ? null : { kind: "object", keys };
	}

	const first = content[start];
	if (first !== '"' && first !== "'" && first !== "`") return null;
	const literal = STRING_LITERAL_AT_RE.exec(content.slice(start, start + MAX_STATIC_STRING));
	if (literal === null) return null;

	// A concatenation such as `"settings:" + key` is not a fixed channel, so the
	// literal must be the whole initializer.
	let end = start + literal[0].length;
	while (end < content.length && (content[end] === " " || content[end] === "\t")) end++;
	const terminator = content[end];
	if (terminator !== undefined && !";,\n\r)}]".includes(terminator)) return null;
	return { kind: "string" };
}

/**
 * File-local constants that prove a channel is fixed. Deliberately shallow:
 * only `const` string literals and flat string-only objects, and only when the
 * name has a single binding and is never a parameter, destructured binding or
 * mutation target — minified bundles reuse short names across scopes, and
 * proving the wrong binding would hide a real forwarder.
 */
function staticValues(content: string, scopes: FunctionScope[]): StaticValues {
	const counts = new Map<string, number>();
	for (const match of content.matchAll(BINDING_RE)) {
		const name = match[1]!;
		counts.set(name, (counts.get(name) ?? 0) + 1);
	}

	const structure = scanStructure(content);
	const { mask, braceEnds, parenOpens } = structure;
	const braceOpens = [...braceEnds.keys()].sort((a, b) => a - b);

	// Names bound anywhere other than a `const` initializer: parameters,
	// destructuring, imports and method shorthand. A const of the same name is
	// shadowed often enough in minified bundles that it proves nothing.
	const otherBindings = new Set<string>();
	const addBindings = (value: string | undefined): void => {
		for (const identifier of (value ?? "").matchAll(/[A-Za-z_$][\w$]*/g)) {
			otherBindings.add(identifier[0]!);
		}
	};
	// Balanced, quote-aware parameter lists: a default like `f(a = "(")` must
	// not truncate the list and hide a shadowing parameter.
	for (const pattern of [/\bfunction\b\s*\*?\s*(?:[A-Za-z_$][\w$]*)?\s*\(/g, /\bcatch\s*\(/g]) {
		for (const match of content.matchAll(pattern)) {
			const open = (match.index ?? 0) + match[0].length - 1;
			const params = balancedSlice(content, open, MAX_PARAM_LIST);
			if (params !== null) addBindings(params);
		}
	}
	for (const match of content.matchAll(METHOD_HEADER_RE)) {
		if (METHOD_KEYWORDS.has(match[1]!)) continue;
		const open = (match.index ?? 0) + match[0].length - 1;
		const params = balancedSlice(content, open, MAX_PARAM_LIST);
		if (params === null) continue;
		let cursor = open + params.length + 2;
		while (cursor < content.length && /\s/.test(content[cursor]!)) cursor++;
		if (content[cursor] === "{") addBindings(params);
	}
	for (const match of content.matchAll(/\)\s*=>/g)) {
		const close = match.index ?? 0;
		const open = parenOpens.get(close);
		if (open !== undefined) addBindings(content.slice(open + 1, close));
	}
	for (const match of content.matchAll(SINGLE_ARROW_PARAM_RE)) {
		const at = match.index ?? 0;
		if (at > 0 && /[\w$.]/.test(content[at - 1]!)) continue;
		otherBindings.add(match[1]!);
	}
	for (const match of content.matchAll(DESTRUCTURING_RE)) addBindings(match[1]);
	for (const match of content.matchAll(IMPORT_CLAUSE_RE)) addBindings(match[1]);

	const mutated = new Set<string>();
	for (const match of content.matchAll(MEMBER_WRITE_RE)) mutated.add(match[1]!);
	for (const match of content.matchAll(OBJECT_MUTATOR_RE)) mutated.add(match[1]!);

	const strings = new Set<string>();
	const tables = new Map<string, Set<string>>();
	for (const match of content.matchAll(CONST_DECLARATION_RE)) {
		const name = match[1]!;
		if (strings.has(name) || tables.has(name)) continue;
		let start = (match.index ?? 0) + match[0].length;
		while (start < content.length && /\s/.test(content[start]!)) start++;
		const parsed = parseStaticInitializer(content, start);
		if (parsed === null) continue;
		if (parsed.kind === "string") strings.add(name);
		else tables.set(name, parsed.keys);
	}

	const safe = (name: string): boolean =>
		counts.get(name) === 1 && !otherBindings.has(name) && !mutated.has(name);

	const wrapperIndexes = new Map<string, WrapperIndex>();
	const scopeEnd = (at: number): number => {
		const open = enclosingBrace(braceOpens, braceEnds, at);
		return open === -1 ? content.length : (braceEnds.get(open) ?? content.length);
	};

	return {
		isStatic(expression: string): boolean {
			const value = expression.trim();
			if (STATIC_STRING_RE.test(value)) return true;
			if (IDENTIFIER_RE.test(value)) return safe(value) && strings.has(value);

			const member = MEMBER_RE.exec(value);
			if (!member || !safe(member[1]!)) return false;
			const table = tables.get(member[1]!);
			if (!table) return false;
			const key = member[2] ?? unescapeKey(member[3] ?? member[4] ?? "");
			return table.has(key);
		},
		wrapperIndex(name: string): WrapperIndex {
			const cached = wrapperIndexes.get(name);
			if (cached) return cached;

			const occurrences = nameOccurrences(content, name, mask);
			const bindings = bindingPositions(content, name, mask, scopeEnd);
			// A parameter binding shadows the name for the whole function body.
			const word = new RegExp(`(?<![\\w$])${escapeRegExp(name)}(?![\\w$])`);
			for (const scope of scopes) {
				if (!word.test(scope.params)) continue;
				if (mask[scope.bodyStart] !== 1) continue;
				const parameters = parameterBindings(content, scope, name, mask);
				if (parameters.length === 0) continue;
				bindings.push(...parameters);
				bindings.push({ pos: scope.bodyStart, end: scope.bodyEnd });
			}
			bindings.sort((a, b) => a.pos - b.pos);

			const index: WrapperIndex = { occurrences, bindings };
			wrapperIndexes.set(name, index);
			return index;
		}
	};
}

/** `${...}` expressions of a single template literal, or null if unparseable. */
function staticTemplateParts(channel: string): string[] | null {
	const template = channel.trim();
	if (!template.startsWith("`") || !template.endsWith("`") || template.length < 2) {
		return null;
	}
	const body = template.slice(1, -1);
	const parts: string[] = [];
	for (let i = 0; i < body.length; i++) {
		const ch = body[i]!;
		if (ch === "\\") {
			i++;
			continue;
		}
		if (ch === "`") return null;
		if (ch !== "$" || body[i + 1] !== "{") continue;

		let depth = 1;
		let quote = "";
		let end = i + 2;
		for (; end < body.length; end++) {
			const inner = body[end]!;
			if (quote) {
				if (inner === "\\") end++;
				else if (inner === quote) quote = "";
				continue;
			}
			if (inner === '"' || inner === "'" || inner === "`") quote = inner;
			else if (inner === "{") depth++;
			else if (inner === "}" && --depth === 0) break;
		}
		if (depth !== 0) return null;
		parts.push(body.slice(i + 2, end));
		i = end;
	}
	return parts;
}

/**
 * A fixed-prefix template channel is static when every `${...}` part is a
 * known constant or a parameter whose every call site is static.
 */
function isStaticTemplateWrapper(
	content: string,
	scopes: FunctionScope[],
	index: number,
	channel: string,
	values: StaticValues
): boolean {
	const parts = staticTemplateParts(channel);
	if (!parts || parts.length === 0) return false;

	const owners = new Map<FunctionScope, Set<number>>();
	for (const part of parts) {
		const expression = part.trim();
		if (!SIMPLE_CHANNEL_RE.test(expression)) return false;
		if (values.isStatic(expression)) continue;
		const owner = parameterOwner(scopes, index, expression);
		if (!owner) return false;
		const positions = owners.get(owner.scope) ?? new Set<number>();
		positions.add(owner.position);
		owners.set(owner.scope, positions);
	}
	// Every part is a known constant: the channel is static by construction.
	if (owners.size === 0) return true;
	for (const [scope, positions] of owners) {
		if (!staticWrapperCalls(content, scope, [...positions], values)) return false;
	}
	return true;
}

function forwardedChannelHits(content: string): RuntimeHit[] {
	const hits: RuntimeHit[] = [];
	let scopes: FunctionScope[] | null = null;
	let values: StaticValues | null = null;
	const analysis = (): { scopes: FunctionScope[]; values: StaticValues } => {
		scopes ??= functionScopes(content);
		values ??= staticValues(content, scopes);
		return { scopes, values };
	};
	for (const method of FORWARDED_IPC_METHODS) {
		for (const site of callSites(content, `ipcRenderer.${method}`)) {
			const channel = splitArguments(site.args)[0] ?? "";
			if (STATIC_STRING_RE.test(channel)) continue;
			const known = analysis();
			if (known.values.isStatic(channel)) continue;

			if (SIMPLE_CHANNEL_RE.test(channel)) {
				// A validated channel is deliberate allowlisting, not blind forwarding.
				if (hasChannelGuard(content, site.index, channel)) continue;
				// Likewise a helper whose every call site passes a static channel.
				if (isStaticOnlyWrapper(content, known.scopes, site.index, channel, known.values)) {
					continue;
				}
			} else if (
				isStaticTemplateWrapper(content, known.scopes, site.index, channel, known.values)
			) {
				continue;
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

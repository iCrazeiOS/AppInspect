/**
 * Pure resolver for cross-tab navigation targets referenced by Security
 * findings. No DOM access, so the routing rules stay unit-testable.
 */

import type { SecurityFinding } from "../../shared/types";
import type { NavigationTarget } from "../navigation";

export interface SecurityReferenceContext {
	/** Container binaries in selector order (overview.ipa.binaries). */
	binaries: Array<{ name: string; type: string }>;
	/** Index of the binary whose findings are currently shown. */
	currentBinaryIndex: number;
	/** True when the result has an Electron tab (result.electron != null). */
	hasElectron: boolean;
	/** Fuse names from result.electron.fuses (empty when no Electron data). */
	fuseNames: string[];
}

export type ReferenceField = "functionName" | "source" | "location" | "evidence";

const OFFSET_RE = /offset=0x([0-9a-f]+)/i;
const FUSE_RE = /^([A-Za-z0-9_]+)=(enabled|disabled|removed)$/;
const ELECTRON_ASAR_PREFIX = "app.asar/";
const ELECTRON_UNPACKED_PREFIX = "app.asar.unpacked/";
const SYMBOL_CATEGORIES = new Set(["weak-crypto", "unsafe-api", "dangerous-api"]);

function normalisePath(path: string): string {
	return path.replaceAll("\\", "/").replace(/\/+$/, "");
}

function baseName(path: string): string {
	const normalised = normalisePath(path);
	return normalised.split("/").pop() ?? normalised;
}

/** Parse the offset out of a `offset=0x…` finding location. */
export function parseLocationOffset(location: string | undefined): number | null {
	if (!location) return null;
	const match = OFFSET_RE.exec(location);
	if (!match?.[1]) return null;
	const value = Number.parseInt(match[1], 16);
	return Number.isFinite(value) ? value : null;
}

/** Index of the container binary a finding `source` names, or null. */
export function matchBinaryName(source: string, ctx: SecurityReferenceContext): number | null {
	const target = normalisePath(source);
	const targetBase = baseName(target);
	for (let i = 0; i < ctx.binaries.length; i++) {
		const binary = ctx.binaries[i];
		if (!binary) continue;
		const name = normalisePath(binary.name);
		if (target === name || target.endsWith(`/${name}`) || targetBase === baseName(name)) {
			return i;
		}
	}
	return null;
}

/** Flatten a file tree into its entry paths. */
export function collectTreePaths<T extends { path: string; children?: T[] }>(
	entries: T[]
): string[] {
	const paths: string[] = [];
	const walk = (nodes: T[]): void => {
		for (const node of nodes) {
			paths.push(node.path);
			if (node.children) walk(node.children);
		}
	};
	walk(entries);
	return paths;
}

/**
 * Resolve a bundle-root-relative path against absolute tree paths. Returns null
 * when the path is missing or ambiguous.
 */
export function matchTreePath(paths: string[], raw: string): string | null {
	if (!raw) return null;
	const target = normalisePath(raw);

	const exact = paths.find((path) => normalisePath(path) === target);
	if (exact) return exact;

	const suffix = paths.filter((path) => normalisePath(path).endsWith(`/${target}`));
	if (suffix.length === 1) return suffix[0]!;
	if (suffix.length > 1) return null;

	const targetBase = baseName(target);
	const byBase = paths.filter((path) => baseName(path) === targetBase);
	return byBase.length === 1 ? byBase[0]! : null;
}

/** Map a binary-hardening finding message onto the matching Overview row key. */
export function resolveHardeningTarget(finding: SecurityFinding): NavigationTarget | null {
	if (finding.category !== "binary-hardening") return null;
	const message = finding.message.toLowerCase();
	let key: "pie" | "arc" | "stackCanaries" | "rpath" | undefined;
	if (message.includes("pie")) key = "pie";
	else if (message.includes("stack canar")) key = "stackCanaries";
	else if (message.includes("arc")) key = "arc";
	else if (message.includes("rpath")) key = "rpath";
	return { sectionTab: "overview", kind: "hardening", ...(key ? { key } : {}) };
}

function electronFileTarget(path: string): NavigationTarget {
	return { sectionTab: "electron", kind: "electron", view: "files", path };
}

/** Resolve one reference field of a finding into a navigation target. */
export function resolveReference(
	finding: SecurityFinding,
	field: ReferenceField,
	ctx: SecurityReferenceContext
): NavigationTarget | null {
	switch (field) {
		case "location": {
			const offset = parseLocationOffset(finding.location);
			return offset === null ? null : { sectionTab: "strings", kind: "string", offset };
		}
		case "functionName": {
			const name = finding.functionName?.trim();
			return name ? { sectionTab: "symbols", kind: "symbol", name } : null;
		}
		case "evidence": {
			if (finding.category === "electron-fuses") {
				const match = FUSE_RE.exec(finding.evidence.trim());
				if (!match?.[1] || !ctx.hasElectron) return null;
				if (!ctx.fuseNames.includes(match[1])) return null;
				return {
					sectionTab: "electron",
					kind: "electron",
					view: "package",
					fuse: match[1]
				};
			}
			if (SYMBOL_CATEGORIES.has(finding.category)) {
				const name = finding.evidence.trim();
				return name ? { sectionTab: "symbols", kind: "symbol", name } : null;
			}
			return null;
		}
		case "source": {
			const source = finding.source?.trim();
			if (!source) return null;

			if (finding.category.startsWith("electron-")) {
				if (!ctx.hasElectron) return null;
				if (source === "app.asar") {
					if (/source map/i.test(finding.message)) {
						const first = finding.evidence.split(",")[0]?.trim();
						return {
							sectionTab: "electron",
							kind: "electron",
							view: "package",
							...(first ? { sourceMap: first } : {})
						};
					}
					return { sectionTab: "electron", kind: "electron", view: "package" };
				}
				if (source.startsWith(ELECTRON_ASAR_PREFIX)) {
					return electronFileTarget(source.slice(ELECTRON_ASAR_PREFIX.length));
				}
				if (source.startsWith(ELECTRON_UNPACKED_PREFIX)) {
					return electronFileTarget(source.slice(ELECTRON_UNPACKED_PREFIX.length));
				}
				return null;
			}

			// Another binary's finding: navigating would need a binary switch first.
			if (matchBinaryName(source, ctx) !== null) return null;
			return { sectionTab: "files", kind: "file", path: source };
		}
	}
}

/** Resolve every navigable reference field of a finding in one pass. */
export function resolveFindingTargets(
	finding: SecurityFinding,
	ctx: SecurityReferenceContext
): Partial<Record<ReferenceField, NavigationTarget>> {
	const fields: ReferenceField[] = ["functionName", "source", "location", "evidence"];
	const targets: Partial<Record<ReferenceField, NavigationTarget>> = {};
	for (const field of fields) {
		const target = resolveReference(finding, field, ctx);
		if (target) targets[field] = target;
	}
	return targets;
}

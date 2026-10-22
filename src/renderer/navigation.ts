/**
 * Cross-tab navigation for Security findings: typed targets, a pending-target
 * store consumed by the destination tab at render time, and the host callback
 * that index.ts registers to drive section-tab switching.
 */

/** Section tab ids exactly as used by `data-tab` in index.html. */
export type NavigationTarget =
	| { sectionTab: "strings"; kind: "string"; offset?: number; value?: string }
	| { sectionTab: "symbols"; kind: "symbol"; name: string }
	| { sectionTab: "files"; kind: "file"; path: string }
	| {
			sectionTab: "electron";
			kind: "electron";
			view: "files" | "package";
			path?: string;
			fuse?: string;
			sourceMap?: string;
	  }
	| { sectionTab: "entitlements"; kind: "entitlement"; key: string }
	| {
			sectionTab: "overview";
			kind: "hardening";
			key?: "pie" | "arc" | "stackCanaries" | "stripped" | "rpath";
	  }
	| { sectionTab: "hex"; kind: "hex"; offset: number };

type NavigationHost = (sessionId: string, target: NavigationTarget) => void;

let host: NavigationHost | null = null;

/** Called once from index.ts. Keeps the DOM/index.ts knowledge out of this module. */
export function registerNavigationHost(fn: NavigationHost): void {
	host = fn;
}

const pending = new Map<string, NavigationTarget>();
const key = (sessionId: string, tab: string): string => `${sessionId}:${tab}`;

/** Queue a target and ask the host to show its section tab. Last click wins. */
export function navigateTo(sessionId: string, target: NavigationTarget): void {
	if (!host) return;
	pending.set(key(sessionId, target.sectionTab), target);
	host(sessionId, target);
}

/** Remove and return the pending target for a tab (called by the tab renderer). */
export function takePendingTarget(sessionId: string, tab: string): NavigationTarget | undefined {
	const k = key(sessionId, tab);
	const target = pending.get(k);
	pending.delete(k);
	return target;
}

export function clearPendingTargets(sessionId: string): void {
	const prefix = `${sessionId}:`;
	for (const k of pending.keys()) {
		if (k.startsWith(prefix)) pending.delete(k);
	}
}

/** Screen-reader-only status updates; no-op outside a DOM. */
export function announce(message: string): void {
	if (typeof document === "undefined") return;
	let el = document.getElementById("nav-announcer");
	if (!el) {
		el = document.createElement("div");
		el.id = "nav-announcer";
		el.className = "sr-only";
		el.setAttribute("aria-live", "polite");
		document.body.appendChild(el);
	}
	el.textContent = message;
}

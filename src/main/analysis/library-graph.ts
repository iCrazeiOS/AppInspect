/**
 * Library dependency graph helpers.
 *
 * Classification and naming utilities for building the inter-binary
 * dependency graph displayed in the Libraries tab graph view.
 */

export function classifyLib(name: string): "system" | "framework" | "swift" | "embedded" {
	if (name.startsWith("/usr/lib/swift") || name.includes("libswift")) return "swift";
	if (name.includes(".framework/")) return "framework";
	if (name.startsWith("/") || name.startsWith("@rpath/libswift")) return "system";
	return "embedded";
}

export function libBasename(fullPath: string): string {
	const parts = fullPath.split("/");
	let name = parts[parts.length - 1] ?? fullPath;
	if (fullPath.includes(".framework")) {
		const pre = fullPath.split(".framework")[0]!.split("/");
		name = pre[pre.length - 1] ?? name;
	}
	return name;
}

/** Hooking framework library names that indicate a jailbreak tweak */
const TWEAK_DEPS = ["substrate", "ellekit", "libhooker", "substitute"];

export function isTweakDep(libName: string): boolean {
	const lower = libName.toLowerCase();
	return TWEAK_DEPS.some((d) => lower.includes(d));
}

/** Shared Mach-O decoding constants and helpers. */

import {
	CPU_SUBTYPE_ARM64_V8,
	CPU_SUBTYPE_ARM64E,
	CPU_SUBTYPE_ARM64E_X1,
	CPU_SUBTYPE_X86_64_H,
	CPU_TYPE_ARM,
	CPU_TYPE_ARM64,
	CPU_TYPE_X86,
	CPU_TYPE_X86_64
} from "../../shared/arch";

export const CPU_TYPE_NAMES: Record<number, string> = {
	[CPU_TYPE_X86]: "x86",
	[CPU_TYPE_ARM]: "ARM",
	[CPU_TYPE_X86_64]: "x86_64",
	[CPU_TYPE_ARM64]: "ARM64"
};

/** LC_BUILD_VERSION platform constants */
export const PLATFORM_NAMES: Record<number, string> = {
	1: "macOS",
	2: "iOS",
	3: "tvOS",
	4: "watchOS",
	5: "bridgeOS",
	6: "Mac Catalyst",
	7: "iOS Simulator",
	8: "tvOS Simulator",
	9: "watchOS Simulator",
	10: "DriverKit",
	11: "visionOS",
	12: "visionOS Simulator"
};

export function decodePlatform(platform: number): string {
	return PLATFORM_NAMES[platform] ?? `Unknown (${platform})`;
}

/** Returns true if the platform is macOS or Mac Catalyst */
export function isMacOSPlatform(platform: number): boolean {
	return platform === 1 || platform === 6;
}

export const FILE_TYPE_NAMES: Record<number, string> = {
	1: "MH_OBJECT",
	2: "MH_EXECUTE",
	5: "MH_CORE",
	6: "MH_DYLIB",
	7: "MH_DYLINKER",
	8: "MH_BUNDLE",
	9: "MH_DYLIB_STUB",
	10: "MH_DSYM",
	11: "MH_KEXT_BUNDLE"
};

export function decodeCpuType(cputype: number): string {
	return CPU_TYPE_NAMES[cputype] ?? `Unknown (${cputype})`;
}

/** Returns a human-readable name for a CPU subtype, or null if unknown. */
export function cpuSubtypeName(cputype: number, cpusubtype: number): string | null {
	const sub = cpusubtype & 0x00ffffff;
	if (cputype === CPU_TYPE_ARM) {
		// ARM
		if (sub === 6) return "ARMv6";
		if (sub === 9) return "ARMv7";
		if (sub === 11) return "ARMv7s";
		if (sub === 12) return "ARMv7k";
	}
	if (cputype === CPU_TYPE_ARM64) {
		// ARM64
		if (sub === CPU_SUBTYPE_ARM64_V8) return "ARM64v8";
		if (sub === CPU_SUBTYPE_ARM64E) return "ARM64e";
		if (sub === CPU_SUBTYPE_ARM64E_X1) return "ARM64e.x1";
	}
	if (cputype === CPU_TYPE_X86_64) {
		// x86_64
		if (sub === CPU_SUBTYPE_X86_64_H) return "x86_64 (Haswell)";
	}
	return null;
}

export function decodeFileType(filetype: number): string {
	return FILE_TYPE_NAMES[filetype] ?? `Unknown (${filetype})`;
}

export function hexStr(n: number): string {
	return `0x${n.toString(16).toUpperCase().padStart(8, "0")}`;
}

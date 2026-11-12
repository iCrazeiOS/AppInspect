/**
 * CPU architecture naming helpers.
 *
 * Shared by the CLI, MCP server and analysis pipeline so a slice chosen by name
 * ("arm64", "x86_64h") resolves the same way everywhere.
 */

import type { FatArch } from "./types";

export const CPU_TYPE_X86 = 0x00000007;
export const CPU_TYPE_ARM = 0x0000000c;
export const CPU_TYPE_X86_64 = 0x01000007;
export const CPU_TYPE_ARM64 = 0x0100000c;

export const CPU_SUBTYPE_ARM64_V8 = 1;
export const CPU_SUBTYPE_ARM64E = 2;
export const CPU_SUBTYPE_ARM64E_X1 = 12;
export const CPU_SUBTYPE_X86_ALL = 3;
export const CPU_SUBTYPE_X86_64_ALL = 3;
export const CPU_SUBTYPE_X86_64_H = 8;

export interface ArchPreference {
	cpuType: number;
	/** Restrict to one CPU subtype; omit to accept any subtype of `cpuType`. */
	cpuSubtype?: number;
}

const CPU_TYPE_NAMES: Record<number, string> = {
	[CPU_TYPE_X86]: "x86",
	[CPU_TYPE_ARM]: "arm",
	[CPU_TYPE_X86_64]: "x86_64",
	[CPU_TYPE_ARM64]: "arm64"
};

const CPU_SUBTYPE_NAMES: Record<string, string> = {
	[`${CPU_TYPE_ARM}:6`]: "armv6",
	[`${CPU_TYPE_ARM}:9`]: "armv7",
	[`${CPU_TYPE_ARM}:11`]: "armv7s",
	[`${CPU_TYPE_ARM}:12`]: "armv7k",
	[`${CPU_TYPE_ARM64}:${CPU_SUBTYPE_ARM64_V8}`]: "arm64v8",
	[`${CPU_TYPE_ARM64}:${CPU_SUBTYPE_ARM64E}`]: "arm64e",
	[`${CPU_TYPE_ARM64}:${CPU_SUBTYPE_ARM64E_X1}`]: "arm64e.x1",
	[`${CPU_TYPE_X86_64}:${CPU_SUBTYPE_X86_64_H}`]: "x86_64h"
};

/** Architecture names accepted by the CLI `--arch` flag and MCP `arch` argument. */
export const ARCH_NAMES = [
	"x86",
	"armv6",
	"armv7",
	"armv7s",
	"armv7k",
	"x86_64",
	"x86_64h",
	"arm64",
	"arm64v8",
	"arm64e",
	"arm64e.x1"
] as const;

/** Aliases that resolve to one of the canonical names. */
const ARCH_ALIASES: Record<string, ArchPreference> = {
	i386: { cpuType: CPU_TYPE_X86 },
	amd64: { cpuType: CPU_TYPE_X86_64 },
	aarch64: { cpuType: CPU_TYPE_ARM64 }
};

const ARCH_BY_NAME: Record<string, ArchPreference> = {
	x86: { cpuType: CPU_TYPE_X86 },
	armv6: { cpuType: CPU_TYPE_ARM, cpuSubtype: 6 },
	armv7: { cpuType: CPU_TYPE_ARM, cpuSubtype: 9 },
	armv7s: { cpuType: CPU_TYPE_ARM, cpuSubtype: 11 },
	armv7k: { cpuType: CPU_TYPE_ARM, cpuSubtype: 12 },
	x86_64: { cpuType: CPU_TYPE_X86_64 },
	x86_64h: { cpuType: CPU_TYPE_X86_64, cpuSubtype: CPU_SUBTYPE_X86_64_H },
	arm64: { cpuType: CPU_TYPE_ARM64 },
	arm64v8: { cpuType: CPU_TYPE_ARM64, cpuSubtype: CPU_SUBTYPE_ARM64_V8 },
	arm64e: { cpuType: CPU_TYPE_ARM64, cpuSubtype: CPU_SUBTYPE_ARM64E },
	"arm64e.x1": { cpuType: CPU_TYPE_ARM64, cpuSubtype: CPU_SUBTYPE_ARM64E_X1 }
};

/** Parse an architecture name (case-insensitive). Returns null when unknown. */
export function parseArch(name: string): ArchPreference | null {
	const key = name.trim().toLowerCase();
	return ARCH_BY_NAME[key] ?? ARCH_ALIASES[key] ?? null;
}

/** Human-readable name for a CPU type/subtype pair, e.g. "arm64e", "x86_64". */
export function formatArch(cpuType: number, cpuSubtype?: number): string {
	if (cpuSubtype != null) {
		const sub = CPU_SUBTYPE_NAMES[`${cpuType}:${cpuSubtype & 0x00ffffff}`];
		if (sub) return sub;
	}
	return CPU_TYPE_NAMES[cpuType] ?? `cpu(0x${cpuType.toString(16)})`;
}

/**
 * Subtypes that count as the plain architecture when no subtype was requested.
 * ARM64e and arm64e.x1 are distinct ABIs, so a bare "arm64" must not select them.
 */
const GENERIC_SUBTYPES: Record<number, ReadonlySet<number>> = {
	[CPU_TYPE_ARM]: new Set([0]),
	[CPU_TYPE_ARM64]: new Set([0, CPU_SUBTYPE_ARM64_V8]),
	[CPU_TYPE_X86]: new Set([CPU_SUBTYPE_X86_ALL]),
	[CPU_TYPE_X86_64]: new Set([CPU_SUBTYPE_X86_64_ALL])
};

/** Whether a fat slice or Mach-O header matches an architecture preference. */
export function archMatches(
	arch: { cputype: number; cpusubtype: number },
	preference: ArchPreference
): boolean {
	if (arch.cputype !== preference.cpuType) return false;
	const sub = arch.cpusubtype & 0x00ffffff;
	if (preference.cpuSubtype != null) {
		// Callers (notably the renderer) pass the raw subtype, which may carry
		// capability bits; compare only the architecture subtype.
		return sub === (preference.cpuSubtype & 0x00ffffff);
	}
	const generic = GENERIC_SUBTYPES[preference.cpuType];
	return !generic || generic.has(sub);
}

/** Comma-separated names of the slices in a fat binary. */
export function describeArchs(archs: FatArch[]): string {
	return archs.map((a) => formatArch(a.cputype, a.cpusubtype)).join(", ");
}

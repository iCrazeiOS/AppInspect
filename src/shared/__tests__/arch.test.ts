import { describe, expect, it } from "bun:test";
import {
	archMatches,
	CPU_TYPE_ARM,
	CPU_TYPE_ARM64,
	CPU_TYPE_X86,
	CPU_TYPE_X86_64,
	describeArchs,
	formatArch,
	parseArch
} from "../arch";

describe("parseArch", () => {
	it("resolves common names case-insensitively", () => {
		expect(parseArch("arm64")).toEqual({ cpuType: CPU_TYPE_ARM64 });
		expect(parseArch(" ARM64 ")).toEqual({ cpuType: CPU_TYPE_ARM64 });
		expect(parseArch("x86_64")).toEqual({ cpuType: CPU_TYPE_X86_64 });
		expect(parseArch("armv7")).toEqual({ cpuType: CPU_TYPE_ARM, cpuSubtype: 9 });
	});

	it("resolves subtype names", () => {
		expect(parseArch("arm64e")).toEqual({ cpuType: CPU_TYPE_ARM64, cpuSubtype: 2 });
		expect(parseArch("x86_64h")).toEqual({ cpuType: CPU_TYPE_X86_64, cpuSubtype: 8 });
	});

	it("resolves arm64e.x1 checked-pointer-arithmetic slices", () => {
		expect(parseArch("arm64e.x1")).toEqual({ cpuType: CPU_TYPE_ARM64, cpuSubtype: 12 });
		expect(parseArch("ARM64E.X1")).toEqual({ cpuType: CPU_TYPE_ARM64, cpuSubtype: 12 });
	});

	it("accepts aliases", () => {
		expect(parseArch("aarch64")).toEqual({ cpuType: CPU_TYPE_ARM64 });
		expect(parseArch("amd64")).toEqual({ cpuType: CPU_TYPE_X86_64 });
		expect(parseArch("i386")).toEqual({ cpuType: CPU_TYPE_X86 });
	});

	it("returns null for unknown names", () => {
		expect(parseArch("riscv64")).toBeNull();
		expect(parseArch("")).toBeNull();
	});
});

describe("archMatches", () => {
	const arm64e = { cputype: CPU_TYPE_ARM64, cpusubtype: 2 };
	const arm64eWithCapability = { cputype: CPU_TYPE_ARM64, cpusubtype: 0x80000002 };

	it("matches a bare architecture name only for its generic subtypes", () => {
		expect(
			archMatches({ cputype: CPU_TYPE_ARM64, cpusubtype: 0 }, { cpuType: CPU_TYPE_ARM64 })
		).toBe(true);
		expect(
			archMatches({ cputype: CPU_TYPE_ARM64, cpusubtype: 1 }, { cpuType: CPU_TYPE_ARM64 })
		).toBe(true);
		expect(archMatches(arm64e, { cpuType: CPU_TYPE_ARM64 })).toBe(false);
	});

	it("matches the subtype when one is requested", () => {
		expect(archMatches(arm64e, { cpuType: CPU_TYPE_ARM64, cpuSubtype: 2 })).toBe(true);
		expect(archMatches(arm64e, { cpuType: CPU_TYPE_ARM64, cpuSubtype: 1 })).toBe(false);
	});

	it("masks capability bits in the subtype", () => {
		expect(archMatches(arm64eWithCapability, { cpuType: CPU_TYPE_ARM64, cpuSubtype: 2 })).toBe(
			true
		);
	});

	it("matches arm64e.x1 only when its subtype is requested", () => {
		const x1 = { cputype: CPU_TYPE_ARM64, cpusubtype: 12 };
		expect(archMatches(x1, { cpuType: CPU_TYPE_ARM64, cpuSubtype: 12 })).toBe(true);
		expect(archMatches(x1, { cpuType: CPU_TYPE_ARM64, cpuSubtype: 2 })).toBe(false);
		expect(archMatches(x1, { cpuType: CPU_TYPE_ARM64 })).toBe(false);
	});

	it("masks capability bits in the requested subtype", () => {
		const x1 = { cputype: CPU_TYPE_ARM64, cpusubtype: 0x8000000c };
		expect(archMatches(x1, { cpuType: CPU_TYPE_ARM64, cpuSubtype: 0x8000000c })).toBe(true);
		expect(archMatches(x1, { cpuType: CPU_TYPE_ARM64, cpuSubtype: 12 })).toBe(true);
	});
});

describe("formatArch", () => {
	it("names slices by type and subtype", () => {
		expect(formatArch(CPU_TYPE_ARM64, 0)).toBe("arm64");
		expect(formatArch(CPU_TYPE_ARM64, 2)).toBe("arm64e");
		expect(formatArch(CPU_TYPE_ARM64, 12)).toBe("arm64e.x1");
		expect(formatArch(CPU_TYPE_X86_64, 8)).toBe("x86_64h");
	});

	it("falls back to the CPU type for unknown subtypes", () => {
		expect(formatArch(CPU_TYPE_X86_64, 99)).toBe("x86_64");
	});
});

describe("describeArchs", () => {
	it("lists slice names in order", () => {
		expect(
			describeArchs([
				{ cputype: CPU_TYPE_ARM64, cpusubtype: 0, offset: 0, size: 0, align: 0 },
				{ cputype: CPU_TYPE_X86_64, cpusubtype: 3, offset: 0, size: 0, align: 0 }
			])
		).toBe("arm64, x86_64");
	});
});

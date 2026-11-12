import { describe, expect, it } from "bun:test";
import { CPU_TYPE_ARM64, CPU_TYPE_X86_64 } from "../../../shared/arch";
import { cpuSubtypeName, decodeCpuType } from "../macho";

describe("decodeCpuType", () => {
	it("names the supported CPU types", () => {
		expect(decodeCpuType(CPU_TYPE_ARM64)).toBe("ARM64");
		expect(decodeCpuType(CPU_TYPE_X86_64)).toBe("x86_64");
	});
});

describe("cpuSubtypeName", () => {
	it("names ARM64 subtypes including arm64e.x1", () => {
		expect(cpuSubtypeName(CPU_TYPE_ARM64, 1)).toBe("ARM64v8");
		expect(cpuSubtypeName(CPU_TYPE_ARM64, 2)).toBe("ARM64e");
		expect(cpuSubtypeName(CPU_TYPE_ARM64, 12)).toBe("ARM64e.x1");
	});

	it("masks capability bits before naming", () => {
		expect(cpuSubtypeName(CPU_TYPE_ARM64, 0x8000000c)).toBe("ARM64e.x1");
	});
});

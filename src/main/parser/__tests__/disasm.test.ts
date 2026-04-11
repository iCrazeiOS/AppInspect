import { beforeAll, describe, expect, it } from "bun:test";
import {
	classifyMnemonic,
	cpuTypeToArch,
	disassembleChunk,
	getAvgInstructionSize,
	initCapstone,
	isCapstoneReady
} from "../disasm";
import { CPU_TYPE_ARM, CPU_TYPE_ARM64, CPU_TYPE_X86, CPU_TYPE_X86_64 } from "../macho";

describe("disasm", () => {
	beforeAll(async () => {
		await initCapstone();
	});

	describe("initCapstone", () => {
		it("should initialize successfully", () => {
			expect(isCapstoneReady()).toBe(true);
		});
	});

	describe("cpuTypeToArch", () => {
		it("should map ARM64 CPU type", () => {
			expect(cpuTypeToArch(CPU_TYPE_ARM64)).toBe("arm64");
		});

		it("should map ARM CPU type", () => {
			expect(cpuTypeToArch(CPU_TYPE_ARM)).toBe("arm");
		});

		it("should map x86_64 CPU type", () => {
			expect(cpuTypeToArch(CPU_TYPE_X86_64)).toBe("x86_64");
		});

		it("should map x86 CPU type", () => {
			expect(cpuTypeToArch(CPU_TYPE_X86)).toBe("x86");
		});

		it("should return null for unknown CPU type", () => {
			expect(cpuTypeToArch(0x12345678)).toBe(null);
		});
	});

	describe("disassembleChunk - ARM64", () => {
		it("should disassemble ARM64 instructions", () => {
			// ARM64 instructions: sub sp, sp, #0x10; stp x29, x30, [sp]
			const bytes = new Uint8Array([0xff, 0x43, 0x00, 0xd1, 0xfd, 0x7b, 0x00, 0xa9]);
			const baseAddr = BigInt(0x100004000);
			const baseOffset = 0x4000;

			const result = disassembleChunk(bytes, baseAddr, "arm64", baseOffset);

			expect(result.length).toBe(2);

			// First instruction: sub sp, sp, #0x10
			expect(result[0]!.address).toBe(BigInt(0x100004000));
			expect(result[0]!.offset).toBe(0x4000);
			expect(result[0]!.mnemonic).toBe("sub");
			expect(result[0]!.size).toBe(4);
			expect(result[0]!.bytes).toEqual([0xff, 0x43, 0x00, 0xd1]);

			// Second instruction: stp x29, x30, [sp]
			expect(result[1]!.address).toBe(BigInt(0x100004004));
			expect(result[1]!.offset).toBe(0x4004);
			expect(result[1]!.mnemonic).toBe("stp");
			expect(result[1]!.size).toBe(4);
		});

		it("should handle empty input", () => {
			const result = disassembleChunk(new Uint8Array([]), BigInt(0), "arm64", 0);
			expect(result).toEqual([]);
		});
	});

	describe("disassembleChunk - x86_64", () => {
		it("should disassemble x86_64 instructions", () => {
			// x86_64: push rbp; mov rbp, rsp
			const bytes = new Uint8Array([0x55, 0x48, 0x89, 0xe5]);
			const baseAddr = BigInt(0x1000);
			const baseOffset = 0x1000;

			const result = disassembleChunk(bytes, baseAddr, "x86_64", baseOffset);

			expect(result.length).toBe(2);

			// First instruction: push rbp
			expect(result[0]!.mnemonic).toBe("push");
			expect(result[0]!.operands).toBe("rbp");
			expect(result[0]!.size).toBe(1);

			// Second instruction: mov rbp, rsp
			expect(result[1]!.mnemonic).toBe("mov");
			expect(result[1]!.size).toBe(3);
		});
	});

	describe("classifyMnemonic", () => {
		it("should classify branch instructions", () => {
			expect(classifyMnemonic("b")).toBe("branch");
			expect(classifyMnemonic("b.eq")).toBe("branch");
			expect(classifyMnemonic("cbz")).toBe("branch");
			expect(classifyMnemonic("jmp")).toBe("branch");
			expect(classifyMnemonic("jne")).toBe("branch");
		});

		it("should classify call instructions", () => {
			expect(classifyMnemonic("bl")).toBe("call");
			expect(classifyMnemonic("blr")).toBe("call");
			expect(classifyMnemonic("call")).toBe("call");
		});

		it("should classify return instructions", () => {
			expect(classifyMnemonic("ret")).toBe("ret");
			expect(classifyMnemonic("retaa")).toBe("ret");
		});

		it("should classify load instructions", () => {
			expect(classifyMnemonic("ldr")).toBe("load");
			expect(classifyMnemonic("ldp")).toBe("load");
			expect(classifyMnemonic("adrp")).toBe("load");
			expect(classifyMnemonic("mov")).toBe("load");
			expect(classifyMnemonic("lea")).toBe("load");
		});

		it("should classify store instructions", () => {
			expect(classifyMnemonic("str")).toBe("store");
			expect(classifyMnemonic("stp")).toBe("store");
			expect(classifyMnemonic("push")).toBe("store");
		});

		it("should classify other instructions", () => {
			expect(classifyMnemonic("add")).toBe("other");
			expect(classifyMnemonic("sub")).toBe("other");
			expect(classifyMnemonic("mul")).toBe("other");
		});
	});

	describe("getAvgInstructionSize", () => {
		it("should return 4 for ARM64", () => {
			expect(getAvgInstructionSize("arm64")).toBe(4);
		});

		it("should return 4 for ARM", () => {
			expect(getAvgInstructionSize("arm")).toBe(4);
		});

		it("should return 5 for x86_64", () => {
			expect(getAvgInstructionSize("x86_64")).toBe(5);
		});

		it("should return 5 for x86", () => {
			expect(getAvgInstructionSize("x86")).toBe(5);
		});
	});
});

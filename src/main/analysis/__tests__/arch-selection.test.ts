import { afterAll, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { CPU_SUBTYPE_ARM64E_X1, CPU_TYPE_ARM64, CPU_TYPE_X86_64 } from "../../../shared/arch";
import { analyseBinaryFile } from "../binary-pipeline";

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "appinspect-arch-"));
const ARM_OFFSET = 4096;
const X86_OFFSET = 8192;
const X1_OFFSET = 12288;
const SLICE_SIZE = 32;

/** A minimal three-slice fat binary: arm64, x86_64 and arm64e.x1. */
function writeFatBinary(): string {
	const buf = Buffer.alloc(X1_OFFSET + SLICE_SIZE);
	buf.writeUInt32BE(0xcafebabe, 0);
	buf.writeUInt32BE(3, 4);
	buf.writeUInt32BE(CPU_TYPE_ARM64, 8);
	buf.writeUInt32BE(0, 12);
	buf.writeUInt32BE(ARM_OFFSET, 16);
	buf.writeUInt32BE(SLICE_SIZE, 20);
	buf.writeUInt32BE(12, 24);
	buf.writeUInt32BE(CPU_TYPE_X86_64, 28);
	buf.writeUInt32BE(3, 32);
	buf.writeUInt32BE(X86_OFFSET, 36);
	buf.writeUInt32BE(SLICE_SIZE, 40);
	buf.writeUInt32BE(12, 44);
	buf.writeUInt32BE(CPU_TYPE_ARM64, 48);
	buf.writeUInt32BE(CPU_SUBTYPE_ARM64E_X1, 52);
	buf.writeUInt32BE(X1_OFFSET, 56);
	buf.writeUInt32BE(SLICE_SIZE, 60);
	buf.writeUInt32BE(12, 64);

	for (const [offset, cpuType, cpuSubtype] of [
		[ARM_OFFSET, CPU_TYPE_ARM64, 0],
		[X86_OFFSET, CPU_TYPE_X86_64, 3],
		[X1_OFFSET, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E_X1]
	] as const) {
		buf.writeUInt32LE(0xfeedfacf, offset);
		buf.writeUInt32LE(cpuType, offset + 4);
		buf.writeUInt32LE(cpuSubtype, offset + 8);
		buf.writeUInt32LE(2, offset + 12);
		buf.writeUInt32LE(0, offset + 16);
		buf.writeUInt32LE(0, offset + 20);
		buf.writeUInt32LE(0, offset + 24);
		buf.writeUInt32LE(0, offset + 28);
	}

	const filePath = path.join(dir, "fat.bin");
	fs.writeFileSync(filePath, buf);
	return filePath;
}

const fatPath = writeFatBinary();

afterAll(() => {
	fs.rmSync(dir, { recursive: true, force: true });
});

describe("analyseBinaryFile architecture selection", () => {
	it("defaults to the arm64 slice", async () => {
		const result = await analyseBinaryFile(fatPath, () => {}, 0);
		expect(result.header.cputype).toBe(CPU_TYPE_ARM64);
		expect(result.fatSliceOffset).toBe(ARM_OFFSET);
	});

	it("selects the requested slice and reports its offset", async () => {
		const result = await analyseBinaryFile(fatPath, () => {}, 0, CPU_TYPE_X86_64);
		expect(result.header.cputype).toBe(CPU_TYPE_X86_64);
		expect(result.fatSliceOffset).toBe(X86_OFFSET);
	});

	it("selects the arm64e.x1 checked-pointer-arithmetic slice", async () => {
		const result = await analyseBinaryFile(fatPath, () => {}, 0, CPU_TYPE_ARM64, 12);
		expect(result.header.cputype).toBe(CPU_TYPE_ARM64);
		expect(result.header.cpusubtype).toBe(CPU_SUBTYPE_ARM64E_X1);
		expect(result.fatSliceOffset).toBe(X1_OFFSET);
	});

	it("throws instead of falling back when the slice is absent", async () => {
		await expect(analyseBinaryFile(fatPath, () => {}, 0, CPU_TYPE_ARM64, 2)).rejects.toThrow(
			"Requested architecture arm64e not present; available: arm64, x86_64, arm64e.x1"
		);
	});
});

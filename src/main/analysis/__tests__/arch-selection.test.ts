import { afterAll, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { CPU_TYPE_ARM64, CPU_TYPE_X86_64 } from "../../../shared/arch";
import { analyseBinaryFile } from "../binary-pipeline";

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "appinspect-arch-"));
const ARM_OFFSET = 4096;
const X86_OFFSET = 8192;
const SLICE_SIZE = 32;

/** A minimal two-slice fat binary: arm64 at 4096, x86_64 at 8192. */
function writeFatBinary(): string {
	const buf = Buffer.alloc(X86_OFFSET + SLICE_SIZE);
	buf.writeUInt32BE(0xcafebabe, 0);
	buf.writeUInt32BE(2, 4);
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

	for (const [offset, cpuType, cpuSubtype] of [
		[ARM_OFFSET, CPU_TYPE_ARM64, 0],
		[X86_OFFSET, CPU_TYPE_X86_64, 3]
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

	it("throws instead of falling back when the slice is absent", async () => {
		await expect(analyseBinaryFile(fatPath, () => {}, 0, CPU_TYPE_ARM64, 2)).rejects.toThrow(
			"Requested architecture arm64e not present; available: arm64, x86_64"
		);
	});
});

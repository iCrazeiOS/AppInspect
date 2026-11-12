import { describe, expect, it } from "bun:test";
import { vmaddrToFileBackedOffset, vmaddrToFileOffset } from "../address";
import type { Segment64 } from "../load-commands";

const data: Segment64 = {
	cmd: 0x19,
	cmdsize: 72,
	segname: "__DATA",
	vmaddr: 0x4000n,
	vmsize: 0x2000n,
	fileoff: 0x1000n,
	filesize: 0x800n,
	maxprot: 3,
	initprot: 3,
	nsects: 0,
	flags: 0,
	sections: []
};

describe("vmaddrToFileBackedOffset", () => {
	it("translates addresses inside the segment's file data", () => {
		expect(vmaddrToFileBackedOffset(0x4010n, [data])).toBe(0x1010);
	});

	it("returns null for zerofill storage past the file data", () => {
		expect(vmaddrToFileOffset(0x4900n, [data])).toBe(0x1900);
		expect(vmaddrToFileBackedOffset(0x4900n, [data])).toBeNull();
	});

	it("returns null outside every segment", () => {
		expect(vmaddrToFileBackedOffset(0x9000n, [data])).toBeNull();
	});
});

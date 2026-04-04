/**
 * Tests for Mach-O string extraction (strings.ts).
 */

import { describe, expect, it } from "bun:test";
import { extractStrings, vmaddrToFileOffset, type StringEntry } from "../strings";
import type { Section64, Segment64 } from "../load-commands";

// ── Fixture Helpers ──────────────────────────────────────────────────

/** Create a minimal Section64 with sensible defaults. */
function makeSection(
  segname: string,
  sectname: string,
  offset: number,
  size: number,
): Section64 {
  return {
    sectname,
    segname,
    addr: BigInt(offset + 0x100000000),
    size: BigInt(size),
    offset,
    align: 0,
    reloff: 0,
    nreloc: 0,
    flags: 0,
    reserved1: 0,
    reserved2: 0,
    reserved3: 0,
  };
}

/** Create a minimal Segment64 containing the given sections. */
function makeSegment(
  segname: string,
  vmaddr: bigint,
  vmsize: bigint,
  fileoff: bigint,
  filesize: bigint,
  sections: Section64[] = [],
): Segment64 {
  return {
    cmd: 0x19,
    cmdsize: 72 + sections.length * 80,
    segname,
    vmaddr,
    vmsize,
    fileoff,
    filesize,
    maxprot: 7,
    initprot: 5,
    nsects: sections.length,
    flags: 0,
    sections,
  };
}

/** Write a null-terminated UTF-8 string into a Uint8Array at offset. Returns bytes written (including null). */
function writeCString(arr: Uint8Array, offset: number, str: string): number {
  const encoder = new TextEncoder();
  const encoded = encoder.encode(str);
  arr.set(encoded, offset);
  arr[offset + encoded.length] = 0;
  return encoded.length + 1;
}

/** Write a UTF-16LE string into a DataView at offset, followed by 0x0000. Returns bytes written. */
function writeUTF16LE(view: DataView, offset: number, str: string): number {
  for (let i = 0; i < str.length; i++) {
    view.setUint16(offset + i * 2, str.charCodeAt(i), true);
  }
  view.setUint16(offset + str.length * 2, 0, true);
  return (str.length + 1) * 2;
}

// ── Tests ────────────────────────────────────────────────────────────

describe("strings", () => {
  describe("vmaddrToFileOffset", () => {
    it("converts a vmaddr inside a segment to a file offset", () => {
      const seg = makeSegment("__TEXT", 0x100000000n, 0x10000n, 0n, 0x10000n);
      const result = vmaddrToFileOffset(0x100000100n, [seg]);
      expect(result).toBe(0x100);
    });

    it("returns null for a vmaddr outside all segments", () => {
      const seg = makeSegment("__TEXT", 0x100000000n, 0x10000n, 0n, 0x10000n);
      expect(vmaddrToFileOffset(0x200000000n, [seg])).toBeNull();
    });
  });

  describe("__cstring extraction", () => {
    it("extracts null-terminated strings >= 4 chars", () => {
      const sectionOffset = 100;
      const bufSize = 1024;
      const buf = new ArrayBuffer(bufSize);
      const arr = new Uint8Array(buf);

      let pos = sectionOffset;
      pos += writeCString(arr, pos, "Hello, World!");
      pos += writeCString(arr, pos, "test");
      pos += writeCString(arr, pos, "ok"); // too short, should be excluded

      const sectionSize = pos - sectionOffset;
      const sect = makeSection("__TEXT", "__cstring", sectionOffset, sectionSize);
      const seg = makeSegment("__TEXT", 0x100000000n, BigInt(bufSize), 0n, BigInt(bufSize), [sect]);

      const result = extractStrings(buf, [sect], [seg], new Map(), true);

      const values = result.map((e) => e.value);
      expect(values).toContain("Hello, World!");
      expect(values).toContain("test");
      expect(values).not.toContain("ok");
    });
  });

  describe("minimum length filter", () => {
    it("excludes strings shorter than 4 characters", () => {
      const sectionOffset = 50;
      const bufSize = 512;
      const buf = new ArrayBuffer(bufSize);
      const arr = new Uint8Array(buf);

      let pos = sectionOffset;
      pos += writeCString(arr, pos, "a");
      pos += writeCString(arr, pos, "ab");
      pos += writeCString(arr, pos, "abc");
      pos += writeCString(arr, pos, "abcd"); // exactly 4 — should be included

      const sectionSize = pos - sectionOffset;
      const sect = makeSection("__TEXT", "__cstring", sectionOffset, sectionSize);
      const seg = makeSegment("__TEXT", 0x100000000n, BigInt(bufSize), 0n, BigInt(bufSize), [sect]);

      const result = extractStrings(buf, [sect], [seg], new Map(), true);
      expect(result).toHaveLength(1);
      expect(result[0]!.value).toBe("abcd");
    });
  });

  describe("__cfstring resolution with rebaseMap", () => {
    it("resolves a CFString struct via chained fixup rebase", () => {
      // Layout:
      //   offset 0..255: __TEXT segment (contains the actual string data)
      //   offset 256..511: __DATA segment (contains __cfstring structs)
      const bufSize = 1024;
      const buf = new ArrayBuffer(bufSize);
      const view = new DataView(buf);
      const arr = new Uint8Array(buf);

      // Put the actual string at file offset 100, in __TEXT segment
      const strValue = "CFStringTest";
      const encoder = new TextEncoder();
      const encoded = encoder.encode(strValue);
      arr.set(encoded, 100);

      // __TEXT segment: vmaddr 0x100000000, fileoff 0, size 256
      const textSeg = makeSegment("__TEXT", 0x100000000n, 256n, 0n, 256n);

      // __DATA segment: vmaddr 0x100000100, fileoff 256, size 256
      const cfstringSectionOffset = 256;
      const cfstringSection = makeSection("__DATA", "__cfstring", cfstringSectionOffset, 32);
      const dataSeg = makeSegment("__DATA", 0x100000100n, 256n, 256n, 256n, [cfstringSection]);

      // Write the CFString struct at offset 256:
      //   isa (8 bytes) — don't care
      //   flags (8 bytes) — don't care
      //   data_ptr (8 bytes) at offset 256+16 = 272 — will be resolved via rebaseMap
      //   length (8 bytes) at offset 256+24 = 280
      view.setBigUint64(280, BigInt(strValue.length), true); // length

      // The string is at file offset 100, which maps to vmaddr 0x100000064
      const stringVmaddr = 0x100000000n + 100n; // = 0x100000064
      const rebaseMap = new Map<number, bigint>();
      rebaseMap.set(272, stringVmaddr); // data_ptr field offset -> resolved vmaddr

      const result = extractStrings(buf, [cfstringSection], [textSeg, dataSeg], rebaseMap, true);

      expect(result).toHaveLength(1);
      expect(result[0]!.value).toBe("CFStringTest");
      expect(result[0]!.sources).toContain("__cfstring");
    });
  });

  describe("__ustring (UTF-16) extraction", () => {
    it("extracts UTF-16LE encoded strings", () => {
      const sectionOffset = 64;
      const bufSize = 512;
      const buf = new ArrayBuffer(bufSize);
      const view = new DataView(buf);

      const str1 = "Unicode\u00AE";
      let pos = sectionOffset;
      pos += writeUTF16LE(view, pos, str1);

      const sectionSize = pos - sectionOffset;
      const sect = makeSection("__TEXT", "__ustring", sectionOffset, sectionSize);
      const seg = makeSegment("__TEXT", 0x100000000n, BigInt(bufSize), 0n, BigInt(bufSize), [sect]);

      const result = extractStrings(buf, [sect], [seg], new Map(), true);

      expect(result).toHaveLength(1);
      expect(result[0]!.value).toBe("Unicode\u00AE");
      expect(result[0]!.sources).toContain("__ustring");
    });

    it("filters out short UTF-16 strings", () => {
      const sectionOffset = 64;
      const bufSize = 512;
      const buf = new ArrayBuffer(bufSize);
      const view = new DataView(buf);

      let pos = sectionOffset;
      pos += writeUTF16LE(view, pos, "ab"); // too short
      pos += writeUTF16LE(view, pos, "longstring"); // ok

      const sectionSize = pos - sectionOffset;
      const sect = makeSection("__TEXT", "__ustring", sectionOffset, sectionSize);
      const seg = makeSegment("__TEXT", 0x100000000n, BigInt(bufSize), 0n, BigInt(bufSize), [sect]);

      const result = extractStrings(buf, [sect], [seg], new Map(), true);

      expect(result).toHaveLength(1);
      expect(result[0]!.value).toBe("longstring");
    });
  });

  describe("empty section", () => {
    it("returns empty array when section has zero size", () => {
      const bufSize = 256;
      const buf = new ArrayBuffer(bufSize);
      const sect = makeSection("__TEXT", "__cstring", 0, 0);
      const seg = makeSegment("__TEXT", 0x100000000n, BigInt(bufSize), 0n, BigInt(bufSize), [sect]);

      const result = extractStrings(buf, [sect], [seg], new Map(), true);
      expect(result).toEqual([]);
    });
  });

  describe("deduplication", () => {
    it("deduplicates the same string from __cstring and __cfstring into one entry with both sources", () => {
      const bufSize = 2048;
      const buf = new ArrayBuffer(bufSize);
      const arr = new Uint8Array(buf);
      const view = new DataView(buf);

      const sharedStr = "SharedString";
      const encoder = new TextEncoder();
      const encoded = encoder.encode(sharedStr);

      // __cstring section at offset 100 with the string
      const cstringOffset = 100;
      arr.set(encoded, cstringOffset);
      arr[cstringOffset + encoded.length] = 0;
      const cstringSize = encoded.length + 1;
      const cstringSect = makeSection("__TEXT", "__cstring", cstringOffset, cstringSize);

      // __TEXT segment covers offsets 0..511
      const textSeg = makeSegment("__TEXT", 0x100000000n, 512n, 0n, 512n, [cstringSect]);

      // __cfstring section at offset 512 (in __DATA)
      const cfstringOffset = 512;
      const cfstringSect = makeSection("__DATA", "__cfstring", cfstringOffset, 32);
      const dataSeg = makeSegment("__DATA", 0x100000200n, 512n, 512n, 512n, [cfstringSect]);

      // CFString struct: data_ptr at 512+16=528, length at 512+24=536
      view.setBigUint64(536, BigInt(sharedStr.length), true);

      // String data at file offset 100 -> vmaddr 0x100000064
      const rebaseMap = new Map<number, bigint>();
      rebaseMap.set(528, 0x100000000n + BigInt(cstringOffset));

      const result = extractStrings(buf, [cstringSect, cfstringSect], [textSeg, dataSeg], rebaseMap, true);

      // Should have only one entry for "SharedString"
      const matches = result.filter((e) => e.value === "SharedString");
      expect(matches).toHaveLength(1);
      expect(matches[0]!.sources).toContain("__cstring");
      expect(matches[0]!.sources).toContain("__cfstring");
    });
  });

  describe("__objc_methname extraction", () => {
    it("extracts ObjC method name strings", () => {
      const sectionOffset = 200;
      const bufSize = 1024;
      const buf = new ArrayBuffer(bufSize);
      const arr = new Uint8Array(buf);

      let pos = sectionOffset;
      pos += writeCString(arr, pos, "viewDidLoad");
      pos += writeCString(arr, pos, "initWithFrame:");

      const sectionSize = pos - sectionOffset;
      const sect = makeSection("__TEXT", "__objc_methname", sectionOffset, sectionSize);
      const seg = makeSegment("__TEXT", 0x100000000n, BigInt(bufSize), 0n, BigInt(bufSize), [sect]);

      const result = extractStrings(buf, [sect], [seg], new Map(), true);

      const values = result.map((e) => e.value);
      expect(values).toContain("viewDidLoad");
      expect(values).toContain("initWithFrame:");
      expect(result[0]!.sources).toContain("__objc_methname");
    });
  });
});

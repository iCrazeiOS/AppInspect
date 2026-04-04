/**
 * Tests for the chained fixups resolver (LC_DYLD_CHAINED_FIXUPS).
 */

import { describe, expect, it } from "bun:test";
import {
  buildFixupMap,
  DYLD_CHAINED_PTR_64_OFFSET,
  DYLD_CHAINED_PTR_START_NONE,
  type ChainedFixupsResult,
} from "../chained-fixups";
import type { Segment64 } from "../load-commands";

// ── Fixture Helpers ──────────────────────────────────────────────────

/** Write a null-terminated C string into a DataView. */
function writeCString(view: DataView, offset: number, str: string): void {
  for (let i = 0; i < str.length; i++) {
    view.setUint8(offset + i, str.charCodeAt(i));
  }
  view.setUint8(offset + str.length, 0);
}

/**
 * Encode a DYLD_CHAINED_PTR_64_OFFSET rebase entry as a BigInt.
 * Layout: target(36) | high8(8) | reserved(7) | next(12) | bind(1)
 *   bits 0-35 = target, bits 36-43 = high8, bits 51-62 = next, bit 63 = 0
 */
function encodeRebase(target: bigint, high8: bigint, next: number): bigint {
  return (
    (target & 0xFFFFFFFFFn) |
    ((high8 & 0xFFn) << 36n) |
    (BigInt(next & 0xfff) << 51n)
  );
}

/**
 * Encode a DYLD_CHAINED_PTR_64_OFFSET bind entry as a BigInt.
 * Layout: ordinal(24) | addend_sign(1) | addend(18) | reserved(9) | next(12) | bind(1)
 *   bits 0-23 = ordinal, bit 24 = sign, bits 25-42 = addend, bits 51-62 = next, bit 63 = 1
 */
function encodeBind(ordinal: number, addend: bigint, next: number): bigint {
  // Per Apple spec: addend is 8-bit unsigned (bits 24-31)
  return (
    (1n << 63n) |
    (BigInt(ordinal) & 0xFFFFFFn) |
    ((addend & 0xFFn) << 24n) |
    (BigInt(next & 0xfff) << 51n)
  );
}

/** A dummy segment for tests. */
function dummySegment(segname: string, fileoff: bigint): Segment64 {
  return {
    cmd: 0x19,
    cmdsize: 72,
    segname,
    vmaddr: fileoff,
    vmsize: 0x4000n,
    fileoff,
    filesize: 0x4000n,
    maxprot: 7,
    initprot: 3,
    nsects: 0,
    flags: 0,
    sections: [],
  };
}

/**
 * Build a complete chained fixups data blob in an ArrayBuffer.
 *
 * Layout (all at dataOffset within the returned buffer):
 *   - dyld_chained_fixups_header (28 bytes)
 *   - dyld_chained_starts_in_image (4 + segCount*4 bytes)
 *   - dyld_chained_starts_in_segment (22 + pageCount*2 bytes) for each segment with fixups
 *   - imports table
 *   - symbols table
 *   - page data with fixup chains (placed at segment_offset within the buffer)
 */
interface FixupFixtureOpts {
  /** File offset where the fixups header lives. */
  dataOffset: number;
  /** Segments with fixups. */
  segmentFixups: Array<{
    segmentOffset: number; // file offset of the segment
    pageSize: number;
    pages: Array<{
      /** Offset within page of the first fixup, or DYLD_CHAINED_PTR_START_NONE */
      startOffset: number;
      /** Chain of raw 8-byte values at the fixup locations (if not NONE) */
      entries?: bigint[];
    }>;
  }>;
  /** Total number of segment slots in starts_in_image (some may be empty). */
  totalSegCount: number;
  /** Which slot index each segmentFixups entry maps to. */
  segSlots: number[];
  /** Imports to encode. */
  imports?: Array<{ lib_ordinal: number; weak: boolean; symbolName: string }>;
}

function buildFixupFixture(opts: FixupFixtureOpts): ArrayBuffer {
  const {
    dataOffset,
    segmentFixups,
    totalSegCount,
    segSlots,
    imports = [],
  } = opts;

  // We'll allocate a large-enough buffer and fill it in.
  const bufSize = 32768;
  const buf = new ArrayBuffer(bufSize);
  const view = new DataView(buf);
  const le = true;

  // ── Layout calculation ──

  // Header at dataOffset (28 bytes)
  const headerSize = 28;

  // starts_in_image right after header
  const startsInImageRelOffset = headerSize; // offset from header start
  const startsInImageAbs = dataOffset + startsInImageRelOffset;
  const startsInImageSize = 4 + totalSegCount * 4;

  // starts_in_segment blocks follow
  let nextStartsInSeg = startsInImageAbs + startsInImageSize;
  const startsInSegAbsOffsets: number[] = []; // absolute offsets for each segmentFixups entry

  for (const sf of segmentFixups) {
    startsInSegAbsOffsets.push(nextStartsInSeg);
    const startsInSegSize = 22 + sf.pages.length * 2;
    nextStartsInSeg += startsInSegSize;
  }

  // Imports table follows
  const importsAbsOffset = nextStartsInSeg;
  const importsRelOffset = importsAbsOffset - dataOffset;
  const importsTableSize = imports.length * 4;

  // Symbols table follows imports
  const symbolsAbsOffset = importsAbsOffset + importsTableSize;
  const symbolsRelOffset = symbolsAbsOffset - dataOffset;

  // Build symbols blob
  let symbolsBlobSize = 0;
  const symbolNameOffsets: number[] = [];
  for (const imp of imports) {
    symbolNameOffsets.push(symbolsBlobSize);
    symbolsBlobSize += imp.symbolName.length + 1; // null terminated
  }

  const totalHeaderDataSize = symbolsRelOffset + symbolsBlobSize;

  // ── Write header ──
  view.setUint32(dataOffset, 0, le); // fixups_version = 0
  view.setUint32(dataOffset + 4, startsInImageRelOffset, le); // starts_offset
  view.setUint32(dataOffset + 8, importsRelOffset, le); // imports_offset
  view.setUint32(dataOffset + 12, symbolsRelOffset, le); // symbols_offset
  view.setUint32(dataOffset + 16, imports.length, le); // imports_count
  view.setUint32(dataOffset + 20, 1, le); // imports_format (DYLD_CHAINED_IMPORT)
  view.setUint32(dataOffset + 24, 0, le); // symbols_format

  // ── Write starts_in_image ──
  view.setUint32(startsInImageAbs, totalSegCount, le); // seg_count
  // Zero all seg_info_offsets first
  for (let i = 0; i < totalSegCount; i++) {
    view.setUint32(startsInImageAbs + 4 + i * 4, 0, le);
  }
  // Fill in non-zero entries
  for (let i = 0; i < segmentFixups.length; i++) {
    const slot = segSlots[i];
    const relOff = startsInSegAbsOffsets[i] - startsInImageAbs;
    view.setUint32(startsInImageAbs + 4 + slot * 4, relOff, le);
  }

  // ── Write starts_in_segment blocks ──
  for (let i = 0; i < segmentFixups.length; i++) {
    const sf = segmentFixups[i];
    const abs = startsInSegAbsOffsets[i];
    const startsInSegSize = 22 + sf.pages.length * 2;

    view.setUint32(abs, startsInSegSize, le); // size
    view.setUint16(abs + 4, sf.pageSize, le); // page_size
    view.setUint16(abs + 6, DYLD_CHAINED_PTR_64_OFFSET, le); // pointer_format
    view.setBigUint64(abs + 8, BigInt(sf.segmentOffset), le); // segment_offset
    view.setUint32(abs + 16, 0, le); // max_valid_pointer
    view.setUint16(abs + 20, sf.pages.length, le); // page_count

    for (let p = 0; p < sf.pages.length; p++) {
      view.setUint16(abs + 22 + p * 2, sf.pages[p].startOffset, le);
    }
  }

  // ── Write page data (fixup chains) ──
  for (const sf of segmentFixups) {
    for (let p = 0; p < sf.pages.length; p++) {
      const page = sf.pages[p];
      if (page.startOffset === DYLD_CHAINED_PTR_START_NONE || !page.entries) {
        continue;
      }

      // First entry at segment_offset + page_index * page_size + page_start
      let entryOffset = sf.segmentOffset + p * sf.pageSize + page.startOffset;
      for (let e = 0; e < page.entries.length; e++) {
        view.setBigUint64(entryOffset, page.entries[e], le);
        // Calculate next delta from the entry itself to advance
        const raw = page.entries[e];
        const next = Number((raw >> 51n) & 0xFFFn);
        if (next === 0) break;
        entryOffset += next * 4;
      }
    }
  }

  // ── Write imports table ──
  for (let i = 0; i < imports.length; i++) {
    const imp = imports[i];
    const raw =
      (imp.lib_ordinal & 0xff) |
      ((imp.weak ? 1 : 0) << 8) |
      ((symbolNameOffsets[i] & 0x7fffff) << 9);
    view.setUint32(importsAbsOffset + i * 4, raw, le);
  }

  // ── Write symbols table ──
  for (let i = 0; i < imports.length; i++) {
    writeCString(view, symbolsAbsOffset + symbolNameOffsets[i], imports[i].symbolName);
  }

  return buf;
}

// ── Tests ────────────────────────────────────────────────────────────

describe("chained-fixups", () => {
  describe("buildFixupMap", () => {
    it("returns empty maps when chainedFixupsOffset is 0", () => {
      const buf = new ArrayBuffer(64);
      const result = buildFixupMap(buf, 0, 0, [], true);
      expect(result.rebaseMap.size).toBe(0);
      expect(result.bindMap.size).toBe(0);
    });

    it("returns empty maps when chainedFixupsSize is too small", () => {
      const buf = new ArrayBuffer(256);
      const result = buildFixupMap(buf, 0, 10, [], true);
      expect(result.rebaseMap.size).toBe(0);
      expect(result.bindMap.size).toBe(0);
    });

    it("returns empty maps when data extends beyond buffer", () => {
      const buf = new ArrayBuffer(64);
      const result = buildFixupMap(buf, 50, 100, [], true);
      expect(result.rebaseMap.size).toBe(0);
      expect(result.bindMap.size).toBe(0);
    });

    it("resolves a single rebase entry correctly", () => {
      const segOffset = 4096;
      const pageSize = 4096;
      const targetValue = 0x123456789n;
      const entry = encodeRebase(targetValue, 0n, 0); // next=0, single entry

      const buf = buildFixupFixture({
        dataOffset: 256,
        segmentFixups: [
          {
            segmentOffset: segOffset,
            pageSize,
            pages: [{ startOffset: 16, entries: [entry] }],
          },
        ],
        totalSegCount: 2,
        segSlots: [1],
      });

      const segments = [dummySegment("__TEXT", 0n), dummySegment("__DATA", BigInt(segOffset))];
      const result = buildFixupMap(buf, 256, 512, segments, true);

      expect(result.rebaseMap.size).toBe(1);
      const expectedOffset = segOffset + 0 * pageSize + 16;
      expect(result.rebaseMap.has(expectedOffset)).toBe(true);
      expect(result.rebaseMap.get(expectedOffset)).toBe(targetValue);
    });

    it("resolves rebase with high8 bits correctly", () => {
      const segOffset = 4096;
      const pageSize = 4096;
      const target = 0xABCDEn;
      const high8 = 0x42n;
      const entry = encodeRebase(target, high8, 0);

      const buf = buildFixupFixture({
        dataOffset: 256,
        segmentFixups: [
          {
            segmentOffset: segOffset,
            pageSize,
            pages: [{ startOffset: 0, entries: [entry] }],
          },
        ],
        totalSegCount: 1,
        segSlots: [0],
      });

      const segments = [dummySegment("__DATA", BigInt(segOffset))];
      const result = buildFixupMap(buf, 256, 512, segments, true);

      expect(result.rebaseMap.size).toBe(1);
      const resolved = result.rebaseMap.get(segOffset)!;
      // resolved = target | (high8 << 56)
      expect(resolved).toBe(target | (high8 << 56n));
    });

    it("walks a chain with multiple rebase entries following next deltas", () => {
      const segOffset = 4096;
      const pageSize = 4096;

      // Chain: entry1 (next=2) -> entry2 (next=3) -> entry3 (next=0)
      // Stride = 4, so:
      //   entry1 at startOffset=8
      //   entry2 at 8 + 2*4 = 16
      //   entry3 at 16 + 3*4 = 28
      const entry1 = encodeRebase(0x1000n, 0n, 2);
      const entry2 = encodeRebase(0x2000n, 0n, 3);
      const entry3 = encodeRebase(0x3000n, 0n, 0);

      const buf = buildFixupFixture({
        dataOffset: 256,
        segmentFixups: [
          {
            segmentOffset: segOffset,
            pageSize,
            pages: [{ startOffset: 8, entries: [entry1, entry2, entry3] }],
          },
        ],
        totalSegCount: 1,
        segSlots: [0],
      });

      const segments = [dummySegment("__DATA", BigInt(segOffset))];
      const result = buildFixupMap(buf, 256, 512, segments, true);

      expect(result.rebaseMap.size).toBe(3);
      expect(result.rebaseMap.get(segOffset + 8)).toBe(0x1000n);
      expect(result.rebaseMap.get(segOffset + 16)).toBe(0x2000n);
      expect(result.rebaseMap.get(segOffset + 28)).toBe(0x3000n);
    });

    it("records bind entries with ordinal and symbol name", () => {
      const segOffset = 4096;
      const pageSize = 4096;
      const bindEntry = encodeBind(0, 0n, 0);

      const buf = buildFixupFixture({
        dataOffset: 256,
        segmentFixups: [
          {
            segmentOffset: segOffset,
            pageSize,
            pages: [{ startOffset: 0, entries: [bindEntry] }],
          },
        ],
        totalSegCount: 1,
        segSlots: [0],
        imports: [
          { lib_ordinal: 1, weak: false, symbolName: "_objc_msgSend" },
        ],
      });

      const segments = [dummySegment("__DATA", BigInt(segOffset))];
      const result = buildFixupMap(buf, 256, 512, segments, true);

      expect(result.bindMap.size).toBe(1);
      const bind = result.bindMap.get(segOffset)!;
      expect(bind).toBeDefined();
      expect(bind.ordinal).toBe(0);
      expect(bind.symbolName).toBe("_objc_msgSend");
      expect(bind.addend).toBe(0n);
    });

    it("records bind entry with non-zero addend", () => {
      const segOffset = 4096;
      const pageSize = 4096;
      const bindEntry = encodeBind(1, 11n, 0);

      const buf = buildFixupFixture({
        dataOffset: 256,
        segmentFixups: [
          {
            segmentOffset: segOffset,
            pageSize,
            pages: [{ startOffset: 0, entries: [bindEntry] }],
          },
        ],
        totalSegCount: 1,
        segSlots: [0],
        imports: [
          { lib_ordinal: 1, weak: false, symbolName: "_foo" },
          { lib_ordinal: 2, weak: true, symbolName: "_bar" },
        ],
      });

      const segments = [dummySegment("__DATA", BigInt(segOffset))];
      const result = buildFixupMap(buf, 256, 512, segments, true);

      const bind = result.bindMap.get(segOffset)!;
      expect(bind.ordinal).toBe(1);
      expect(bind.symbolName).toBe("_bar");
      expect(bind.addend).toBe(11n);
    });

    it("skips pages with DYLD_CHAINED_PTR_START_NONE", () => {
      const segOffset = 4096;
      const pageSize = 4096;
      const entry = encodeRebase(0xAAAAn, 0n, 0);

      const buf = buildFixupFixture({
        dataOffset: 256,
        segmentFixups: [
          {
            segmentOffset: segOffset,
            pageSize,
            pages: [
              { startOffset: DYLD_CHAINED_PTR_START_NONE }, // page 0: skipped
              { startOffset: 0, entries: [entry] },          // page 1: has fixup
              { startOffset: DYLD_CHAINED_PTR_START_NONE }, // page 2: skipped
            ],
          },
        ],
        totalSegCount: 1,
        segSlots: [0],
      });

      const segments = [dummySegment("__DATA", BigInt(segOffset))];
      const result = buildFixupMap(buf, 256, 512, segments, true);

      expect(result.rebaseMap.size).toBe(1);
      // Entry is on page 1: segOffset + 1 * pageSize + 0
      const expectedOffset = segOffset + pageSize;
      expect(result.rebaseMap.has(expectedOffset)).toBe(true);
      expect(result.rebaseMap.get(expectedOffset)).toBe(0xAAAAn);
    });

    it("skips segments with zero seg_info_offset", () => {
      const segOffset = 4096;
      const pageSize = 4096;
      const entry = encodeRebase(0xBBBBn, 0n, 0);

      // totalSegCount=3, but only slot 2 has fixups
      const buf = buildFixupFixture({
        dataOffset: 256,
        segmentFixups: [
          {
            segmentOffset: segOffset,
            pageSize,
            pages: [{ startOffset: 0, entries: [entry] }],
          },
        ],
        totalSegCount: 3,
        segSlots: [2],
      });

      const segments = [
        dummySegment("__TEXT", 0n),
        dummySegment("__LINKEDIT", 0x8000n),
        dummySegment("__DATA", BigInt(segOffset)),
      ];
      const result = buildFixupMap(buf, 256, 512, segments, true);

      expect(result.rebaseMap.size).toBe(1);
      expect(result.rebaseMap.get(segOffset)).toBe(0xBBBBn);
    });

    it("handles mixed rebase and bind entries in a chain", () => {
      const segOffset = 4096;
      const pageSize = 4096;

      // Chain: rebase (next=2) -> bind (next=2) -> rebase (next=0)
      const entry1 = encodeRebase(0x5000n, 0n, 2);
      const entry2 = encodeBind(0, 0n, 2);
      const entry3 = encodeRebase(0x6000n, 0n, 0);

      const buf = buildFixupFixture({
        dataOffset: 256,
        segmentFixups: [
          {
            segmentOffset: segOffset,
            pageSize,
            pages: [{ startOffset: 0, entries: [entry1, entry2, entry3] }],
          },
        ],
        totalSegCount: 1,
        segSlots: [0],
        imports: [{ lib_ordinal: 1, weak: false, symbolName: "_malloc" }],
      });

      const segments = [dummySegment("__DATA", BigInt(segOffset))];
      const result = buildFixupMap(buf, 256, 512, segments, true);

      // 2 rebases + 1 bind
      expect(result.rebaseMap.size).toBe(2);
      expect(result.bindMap.size).toBe(1);

      expect(result.rebaseMap.get(segOffset + 0)).toBe(0x5000n);
      expect(result.rebaseMap.get(segOffset + 16)).toBe(0x6000n);
      expect(result.bindMap.get(segOffset + 8)!.symbolName).toBe("_malloc");
    });

    it("returns empty maps gracefully for malformed data (bad version)", () => {
      const buf = new ArrayBuffer(512);
      const view = new DataView(buf);

      // Write a header with version != 0
      view.setUint32(0, 99, true); // fixups_version = 99

      const result = buildFixupMap(buf, 0, 256, [], true);
      expect(result.rebaseMap.size).toBe(0);
      expect(result.bindMap.size).toBe(0);
    });
  });
});

/**
 * String Extraction from Mach-O Sections
 *
 * Extracts strings from multiple well-known section types:
 * - __TEXT.__cstring, __TEXT.__objc_methname, __TEXT.__objc_classname,
 *   __TEXT.__objc_methtype, __TEXT.__swift5_reflstr, __TEXT.__oslogstring
 *   (null-terminated C strings)
 * - __TEXT.__ustring (UTF-16 encoded strings)
 * - __DATA.__cfstring / __DATA_CONST.__cfstring (CFString struct resolution
 *   via chained fixups rebaseMap)
 *
 * Does NOT classify or filter strings by content — that is left to
 * downstream consumers (e.g. security scan).
 */

import type { Section64, Segment64 } from "./load-commands";

// ── Types ─────────────────────────────────────────────────────────────

export interface StringEntry {
  /** The decoded string value. */
  value: string;
  /** Section(s) where this string was found (e.g. "__cstring"). */
  sources: string[];
  /** File offset of the first occurrence. */
  offset: number;
}

// ── Null-terminated section names (segname -> sectname) ─────────────

const NULL_TERM_SECTIONS: Array<{ segname: string; sectname: string }> = [
  { segname: "__TEXT", sectname: "__cstring" },
  { segname: "__TEXT", sectname: "__objc_methname" },
  { segname: "__TEXT", sectname: "__objc_classname" },
  { segname: "__TEXT", sectname: "__objc_methtype" },
  { segname: "__TEXT", sectname: "__swift5_reflstr" },
  { segname: "__TEXT", sectname: "__oslogstring" },
];

const CFSTRING_SEGMENTS = ["__DATA", "__DATA_CONST"];

// ── Helpers ──────────────────────────────────────────────────────────

/**
 * Convert a virtual memory address to a file offset using the segment list.
 * Returns null if no segment contains the given vmaddr.
 */
export function vmaddrToFileOffset(
  vmaddr: bigint,
  segments: Segment64[],
): number | null {
  for (const seg of segments) {
    if (vmaddr >= seg.vmaddr && vmaddr < seg.vmaddr + seg.vmsize) {
      return Number(vmaddr - seg.vmaddr) + Number(seg.fileoff);
    }
  }
  return null;
}

/**
 * Find a section by trimmed segname and sectname across all segments.
 */
function findSections(
  segments: Segment64[],
  segname: string,
  sectname: string,
): Section64[] {
  const results: Section64[] = [];
  for (const seg of segments) {
    for (const sect of seg.sections) {
      if (
        sect.segname.trim() === segname &&
        sect.sectname.trim() === sectname
      ) {
        results.push(sect);
      }
    }
  }
  return results;
}

/**
 * Parse null-terminated C strings from a region of the buffer.
 * Returns strings of length >= minLen.
 */
function parseNullTerminatedStrings(
  bytes: Uint8Array,
  sectionOffset: number,
  sectionSize: number,
  minLen: number,
): Array<{ value: string; offset: number }> {
  const results: Array<{ value: string; offset: number }> = [];
  const decoder = new TextDecoder("utf-8", { fatal: false });
  const end = sectionOffset + sectionSize;

  let start = sectionOffset;
  for (let i = sectionOffset; i < end; i++) {
    if (bytes[i] === 0) {
      const len = i - start;
      if (len >= minLen) {
        const slice = bytes.subarray(start, i);
        const value = decoder.decode(slice);
        results.push({ value, offset: start });
      }
      start = i + 1;
    }
  }
  // Handle case where section doesn't end with a null byte
  if (start < end) {
    const len = end - start;
    if (len >= minLen) {
      const slice = bytes.subarray(start, end);
      const value = decoder.decode(slice);
      results.push({ value, offset: start });
    }
  }

  return results;
}

/**
 * Parse UTF-16 strings from __TEXT.__ustring.
 * Reads 2-byte code units (LE) until a 0x0000 terminator.
 */
function parseUTF16Strings(
  view: DataView,
  sectionOffset: number,
  sectionSize: number,
  littleEndian: boolean,
  minLen: number,
): Array<{ value: string; offset: number }> {
  const results: Array<{ value: string; offset: number }> = [];
  const end = sectionOffset + sectionSize;

  let start = sectionOffset;
  const codes: number[] = [];

  for (let i = sectionOffset; i + 1 < end; i += 2) {
    const codeUnit = view.getUint16(i, littleEndian);
    if (codeUnit === 0) {
      if (codes.length >= minLen) {
        results.push({
          value: String.fromCharCode(...codes),
          offset: start,
        });
      }
      codes.length = 0;
      start = i + 2;
    } else {
      codes.push(codeUnit);
    }
  }
  // Trailing non-terminated string
  if (codes.length >= minLen) {
    results.push({
      value: String.fromCharCode(...codes),
      offset: start,
    });
  }

  return results;
}

/**
 * Parse CFString structs from __DATA.__cfstring or __DATA_CONST.__cfstring.
 *
 * Each entry is 32 bytes:
 *   isa (8) + flags (8) + data_ptr (8) + length (8)
 *
 * data_ptr may be a chained fixup pointer — check rebaseMap for its file offset.
 * If the resolved vmaddr is found, convert to file offset and read `length` bytes.
 */
function parseCFStrings(
  buffer: ArrayBuffer,
  section: Section64,
  segments: Segment64[],
  rebaseMap: Map<number, bigint>,
  littleEndian: boolean,
  minLen: number,
): Array<{ value: string; offset: number }> {
  const results: Array<{ value: string; offset: number }> = [];
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);
  const decoder = new TextDecoder("utf-8", { fatal: false });
  const le = littleEndian;

  const sectionEnd = section.offset + Number(section.size);
  const CFSTRING_STRUCT_SIZE = 32;

  for (
    let structOff = section.offset;
    structOff + CFSTRING_STRUCT_SIZE <= sectionEnd;
    structOff += CFSTRING_STRUCT_SIZE
  ) {
    const dataPtrFieldOffset = structOff + 16;
    const lengthFieldOffset = structOff + 24;

    // Read the length field
    if (lengthFieldOffset + 8 > buffer.byteLength) break;
    const length = Number(view.getBigUint64(lengthFieldOffset, le));

    if (length < minLen || length > 0x100000) continue; // sanity cap at 1MB

    // Try to resolve data_ptr via rebaseMap first
    let fileOffset: number | null = null;

    const rebasedVmaddr = rebaseMap.get(dataPtrFieldOffset);
    if (rebasedVmaddr !== undefined) {
      fileOffset = vmaddrToFileOffset(rebasedVmaddr, segments);
    }

    // Fallback: read the raw pointer value and try to interpret as vmaddr
    if (fileOffset === null && dataPtrFieldOffset + 8 <= buffer.byteLength) {
      const rawPtr = view.getBigUint64(dataPtrFieldOffset, le);
      if (rawPtr > 0n) {
        fileOffset = vmaddrToFileOffset(rawPtr, segments);
      }
    }

    if (fileOffset === null) continue;
    if (fileOffset < 0 || fileOffset + length > buffer.byteLength) continue;

    const slice = bytes.subarray(fileOffset, fileOffset + length);
    const value = decoder.decode(slice);

    if (value.length >= minLen) {
      results.push({ value, offset: structOff });
    }
  }

  return results;
}

// ── Main Entry Point ─────────────────────────────────────────────────

/**
 * Extract strings from well-known Mach-O sections.
 *
 * @param buffer       The full Mach-O file buffer
 * @param sections     Flattened array of Section64 (convenience, but we also
 *                     look inside segments[].sections[])
 * @param segments     Parsed LC_SEGMENT_64 entries
 * @param rebaseMap    Chained fixups rebase map (file offset -> resolved vmaddr)
 * @param littleEndian Byte order
 * @returns Deduplicated array of StringEntry
 */
export function extractStrings(
  buffer: ArrayBuffer,
  sections: Section64[],
  segments: Segment64[],
  rebaseMap: Map<number, bigint>,
  littleEndian: boolean,
): StringEntry[] {
  const bytes = new Uint8Array(buffer);
  const view = new DataView(buffer);
  const MIN_LEN = 4;

  // Map from string value -> StringEntry (for deduplication)
  const dedup = new Map<string, StringEntry>();

  function addEntries(
    entries: Array<{ value: string; offset: number }>,
    source: string,
  ): void {
    for (const entry of entries) {
      const existing = dedup.get(entry.value);
      if (existing) {
        if (!existing.sources.includes(source)) {
          existing.sources.push(source);
        }
      } else {
        dedup.set(entry.value, {
          value: entry.value,
          sources: [source],
          offset: entry.offset,
        });
      }
    }
  }

  // 1. Null-terminated string sections
  for (const { segname, sectname } of NULL_TERM_SECTIONS) {
    const matched = findSections(segments, segname, sectname);
    for (const sect of matched) {
      const size = Number(sect.size);
      if (size === 0) continue;
      if (sect.offset + size > buffer.byteLength) continue;

      const entries = parseNullTerminatedStrings(
        bytes,
        sect.offset,
        size,
        MIN_LEN,
      );
      addEntries(entries, sectname);
    }
  }

  // 2. UTF-16 __ustring
  const ustringMatched = findSections(segments, "__TEXT", "__ustring");
  for (const sect of ustringMatched) {
    const size = Number(sect.size);
    if (size === 0) continue;
    if (sect.offset + size > buffer.byteLength) continue;

    const entries = parseUTF16Strings(view, sect.offset, size, littleEndian, MIN_LEN);
    addEntries(entries, "__ustring");
  }

  // 3. CFString sections (__DATA/__DATA_CONST)
  for (const segname of CFSTRING_SEGMENTS) {
    const matched = findSections(segments, segname, "__cfstring");
    for (const sect of matched) {
      const size = Number(sect.size);
      if (size === 0) continue;
      if (sect.offset + size > buffer.byteLength) continue;

      const entries = parseCFStrings(
        buffer,
        sect,
        segments,
        rebaseMap,
        littleEndian,
        MIN_LEN,
      );
      addEntries(entries, "__cfstring");
    }
  }

  return Array.from(dedup.values());
}

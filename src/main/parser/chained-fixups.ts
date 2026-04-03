/**
 * Chained Fixups Resolver (LC_DYLD_CHAINED_FIXUPS)
 *
 * Parses the dyld chained fixups data structure to resolve rebased pointers
 * and bind entries in __DATA segments. Only supports DYLD_CHAINED_PTR_64_OFFSET
 * (pointer_format 6).
 *
 * Reference: <mach-o/fixup-chains.h> in the macOS SDK.
 */

import type { Segment64 } from "./load-commands";
import { readCString } from "./load-commands";

// ── Constants ────────────────────────────────────────────────────────

/** Pointer format: DYLD_CHAINED_PTR_64_OFFSET */
export const DYLD_CHAINED_PTR_64_OFFSET = 6;

/** Sentinel: no fixups in this page */
export const DYLD_CHAINED_PTR_START_NONE = 0xffff;

/** Stride for DYLD_CHAINED_PTR_64_OFFSET */
const STRIDE_64_OFFSET = 4;

// ── Types ────────────────────────────────────────────────────────────

export interface ChainedFixupsHeader {
  fixups_version: number;
  starts_offset: number;
  imports_offset: number;
  symbols_offset: number;
  imports_count: number;
  imports_format: number;
  symbols_format: number;
}

export interface ChainedStartsInSegment {
  size: number;
  page_size: number;
  pointer_format: number;
  segment_offset: bigint;
  max_valid_pointer: number;
  page_count: number;
  page_starts: number[];
}

export interface ChainedImport {
  lib_ordinal: number;
  weak_import: boolean;
  name_offset: number;
  symbolName: string;
}

export interface ChainedFixupsResult {
  rebaseMap: Map<number, bigint>;
  bindMap: Map<number, { ordinal: number; symbolName: string; addend: bigint }>;
}

// ── Parser ───────────────────────────────────────────────────────────

/**
 * Parse the dyld_chained_fixups_header at the given offset.
 */
function parseFixupsHeader(
  view: DataView,
  offset: number,
  le: boolean,
): ChainedFixupsHeader {
  return {
    fixups_version: view.getUint32(offset, le),
    starts_offset: view.getUint32(offset + 4, le),
    imports_offset: view.getUint32(offset + 8, le),
    symbols_offset: view.getUint32(offset + 12, le),
    imports_count: view.getUint32(offset + 16, le),
    imports_format: view.getUint32(offset + 20, le),
    symbols_format: view.getUint32(offset + 24, le),
  };
}

/**
 * Parse dyld_chained_starts_in_segment at the given offset.
 */
function parseStartsInSegment(
  view: DataView,
  offset: number,
  le: boolean,
): ChainedStartsInSegment {
  const size = view.getUint32(offset, le);
  const page_size = view.getUint16(offset + 4, le);
  const pointer_format = view.getUint16(offset + 6, le);
  const segment_offset = view.getBigUint64(offset + 8, le);
  const max_valid_pointer = view.getUint32(offset + 16, le);
  const page_count = view.getUint16(offset + 20, le);

  const page_starts: number[] = [];
  for (let i = 0; i < page_count; i++) {
    page_starts.push(view.getUint16(offset + 22 + i * 2, le));
  }

  return {
    size,
    page_size,
    pointer_format,
    segment_offset,
    max_valid_pointer,
    page_count,
    page_starts,
  };
}

/**
 * Parse the imports table and resolve symbol names.
 */
function parseImports(
  view: DataView,
  headerOffset: number,
  importsOffset: number,
  symbolsOffset: number,
  importsCount: number,
  le: boolean,
): ChainedImport[] {
  const imports: ChainedImport[] = [];
  const absImportsOffset = headerOffset + importsOffset;
  const absSymbolsOffset = headerOffset + symbolsOffset;

  for (let i = 0; i < importsCount; i++) {
    const raw = view.getUint32(absImportsOffset + i * 4, le);
    const lib_ordinal = raw & 0xff; // bits 0-7
    const weak_import = ((raw >> 8) & 1) === 1; // bit 8
    const name_offset = (raw >>> 9) & 0x7fffff; // bits 9-31

    // Read null-terminated symbol name
    const maxLen = view.byteLength - (absSymbolsOffset + name_offset);
    const symbolName =
      maxLen > 0
        ? readCString(view, absSymbolsOffset + name_offset, Math.min(maxLen, 4096))
        : "";

    imports.push({ lib_ordinal, weak_import, name_offset, symbolName });
  }

  return imports;
}

/**
 * Walk a fixup chain starting at the given file offset.
 * Processes DYLD_CHAINED_PTR_64_OFFSET entries (8 bytes each).
 */
function walkChain(
  view: DataView,
  startOffset: number,
  le: boolean,
  imports: ChainedImport[],
  rebaseMap: Map<number, bigint>,
  bindMap: Map<number, { ordinal: number; symbolName: string; addend: bigint }>,
): void {
  let currentOffset = startOffset;

  // Safety limit to prevent infinite loops on malformed data
  const maxIterations = 1_000_000;
  let iterations = 0;

  while (iterations < maxIterations) {
    iterations++;

    // Bounds check
    if (currentOffset + 8 > view.byteLength) {
      break;
    }

    const raw = view.getBigUint64(currentOffset, le);
    const bind = (raw >> 63n) & 1n;

    if (bind === 0n) {
      // Rebase entry (dyld_chained_ptr_64_rebase)
      //   target: bits 0-35  (36 bits)
      //   high8:  bits 36-43 (8 bits)
      //   reserved: bits 44-50 (7 bits)
      //   next:   bits 51-62 (12 bits)
      //   bind:   bit 63
      const target = raw & 0xFFFFFFFFFn; // bits 0-35
      const high8 = (raw >> 36n) & 0xFFn; // bits 36-43
      const next = Number((raw >> 51n) & 0xFFFn); // bits 51-62

      // Resolved value: target | (high8 << 56) for DYLD_CHAINED_PTR_64_OFFSET
      const resolved = target | (high8 << 56n);
      rebaseMap.set(currentOffset, resolved);

      if (next === 0) break;
      currentOffset += next * STRIDE_64_OFFSET;
    } else {
      // Bind entry (dyld_chained_ptr_64_bind)
      //   ordinal: bits 0-23 (24 bits)
      //   addend:  bits 24-31 (8 bits)
      //   reserved: bits 32-50 (19 bits)
      //   next:   bits 51-62 (12 bits)
      //   bind:   bit 63
      const ordinal = Number(raw & 0xFFFFFFn); // bits 0-23
      const addendSign = (raw >> 24n) & 1n; // bit 24
      const addendRaw = (raw >> 25n) & 0x3FFFFn; // bits 25-42 (18 bits)
      const next = Number((raw >> 51n) & 0xFFFn); // bits 51-62

      const addend = addendSign === 1n ? -addendRaw : addendRaw;

      const symbolName =
        ordinal < imports.length ? imports[ordinal].symbolName : `<unknown_ordinal_${ordinal}>`;

      bindMap.set(currentOffset, { ordinal, symbolName, addend });

      if (next === 0) break;
      currentOffset += next * STRIDE_64_OFFSET;
    }
  }
}

/**
 * Build fixup maps from the LC_DYLD_CHAINED_FIXUPS data.
 *
 * @param buffer               The full Mach-O file buffer
 * @param chainedFixupsOffset  File offset of the chained fixups data (from linkedit_data_command.dataoff)
 * @param chainedFixupsSize    Size of the chained fixups data
 * @param segments             Parsed LC_SEGMENT_64 entries
 * @param littleEndian         Byte order
 * @returns Maps of rebase and bind fixups keyed by file offset
 */
export function buildFixupMap(
  buffer: ArrayBuffer,
  chainedFixupsOffset: number,
  chainedFixupsSize: number,
  segments: Segment64[],
  littleEndian: boolean,
): ChainedFixupsResult {
  const emptyResult: ChainedFixupsResult = {
    rebaseMap: new Map(),
    bindMap: new Map(),
  };

  // Guard: no fixups data
  if (!chainedFixupsOffset || !chainedFixupsSize || chainedFixupsSize < 28) {
    return emptyResult;
  }

  // Guard: data extends beyond buffer
  if (chainedFixupsOffset + chainedFixupsSize > buffer.byteLength) {
    return emptyResult;
  }

  const view = new DataView(buffer);
  const le = littleEndian;
  const headerOffset = chainedFixupsOffset;

  // 1. Parse the fixups header
  const header = parseFixupsHeader(view, headerOffset, le);

  // Validate version
  if (header.fixups_version !== 0) {
    return emptyResult;
  }

  // 2. Parse imports table
  const imports = parseImports(
    view,
    headerOffset,
    header.imports_offset,
    header.symbols_offset,
    header.imports_count,
    le,
  );

  // 3. Parse starts_in_image
  const startsInImageOffset = headerOffset + header.starts_offset;
  const segCount = view.getUint32(startsInImageOffset, le);

  // Read seg_info_offset array
  const segInfoOffsets: number[] = [];
  for (let i = 0; i < segCount; i++) {
    segInfoOffsets.push(view.getUint32(startsInImageOffset + 4 + i * 4, le));
  }

  const rebaseMap = new Map<number, bigint>();
  const bindMap = new Map<number, { ordinal: number; symbolName: string; addend: bigint }>();

  // 4. For each segment with fixups, walk the chains
  for (let segIdx = 0; segIdx < segCount; segIdx++) {
    const segInfoOff = segInfoOffsets[segIdx];
    if (segInfoOff === 0) continue; // No fixups in this segment

    const startsInSegOffset = startsInImageOffset + segInfoOff;

    // Bounds check
    if (startsInSegOffset + 22 > buffer.byteLength) continue;

    const startsInSeg = parseStartsInSegment(view, startsInSegOffset, le);

    // Only support DYLD_CHAINED_PTR_64_OFFSET (format 6)
    if (startsInSeg.pointer_format !== DYLD_CHAINED_PTR_64_OFFSET) {
      continue;
    }

    for (let pageIdx = 0; pageIdx < startsInSeg.page_count; pageIdx++) {
      const pageStart = startsInSeg.page_starts[pageIdx];

      // Skip pages with no fixups
      if (pageStart === DYLD_CHAINED_PTR_START_NONE) continue;

      // Calculate file offset of the first fixup in this page
      const segFileOffset = Number(startsInSeg.segment_offset);
      const firstFixupOffset =
        segFileOffset + pageIdx * startsInSeg.page_size + pageStart;

      walkChain(view, firstFixupOffset, le, imports, rebaseMap, bindMap);
    }
  }

  return { rebaseMap, bindMap };
}

/**
 * Cross-reference analysis for Mach-O binaries
 *
 * Parses LC_FUNCTION_STARTS to build function address ranges, then scans
 * arm64 code (__TEXT.__text) for ADRP+ADD instruction pairs that reference
 * addresses in string sections. This maps string file offsets to the
 * function(s) that reference them.
 */

import type { Segment64, Section64 } from "./load-commands";
import type { Symbol } from "./symbols";
import { vmaddrToFileOffset } from "./strings";

// ── Function starts parsing ──────────────────────────────────────────

/**
 * Decode the ULEB128-encoded function start deltas from LC_FUNCTION_STARTS.
 * Returns an array of virtual memory addresses for each function entry point.
 */
export function parseFunctionStarts(
  buffer: ArrayBuffer,
  dataoff: number,
  datasize: number,
  textSegmentVmaddr: bigint,
): bigint[] {
  const bytes = new Uint8Array(buffer);
  const end = dataoff + datasize;
  const addrs: bigint[] = [];
  let addr = textSegmentVmaddr;

  let pos = dataoff;
  while (pos < end) {
    // Read ULEB128 delta
    let delta = 0n;
    let shift = 0n;
    let byte: number;
    do {
      if (pos >= end) break;
      byte = bytes[pos++]!;
      delta |= BigInt(byte & 0x7f) << shift;
      shift += 7n;
    } while (byte & 0x80);

    if (delta === 0n) break; // terminator
    addr += delta;
    addrs.push(addr);
  }

  return addrs;
}

// ── Function range building ──────────────────────────────────────────

interface FunctionRange {
  start: bigint;  // vmaddr
  end: bigint;    // vmaddr of next function (exclusive)
  name: string;
}

/**
 * Build named function ranges from function starts and symbol table.
 * If functionStarts is empty, falls back to deriving ranges from symbol
 * addresses in the __text section (common for stripped frameworks that
 * lack LC_FUNCTION_STARTS).
 */
function buildFunctionRanges(
  functionStarts: bigint[],
  symbols: Symbol[],
  textSectionStart: bigint,
  textSectionEnd: bigint,
): FunctionRange[] {
  // Build address → name map from non-imported symbols
  const addrToName = new Map<bigint, string>();
  for (const sym of symbols) {
    if (sym.type === "imported") continue;
    const existing = addrToName.get(sym.address);
    if (!existing || (existing.startsWith("sub_") && !sym.name.startsWith("sub_"))) {
      addrToName.set(sym.address, sym.name);
    }
  }

  // Use function starts if available; otherwise derive from symbol addresses
  let sortedAddrs: bigint[];
  if (functionStarts.length > 0) {
    sortedAddrs = functionStarts;
  } else {
    // Collect symbol addresses that fall within the __text section
    const textSymAddrs = new Set<bigint>();
    for (const sym of symbols) {
      if (sym.type === "imported") continue;
      if (sym.address >= textSectionStart && sym.address < textSectionEnd) {
        textSymAddrs.add(sym.address);
      }
    }
    if (textSymAddrs.size === 0) return [];
    sortedAddrs = [...textSymAddrs].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  }

  const ranges: FunctionRange[] = [];
  for (let i = 0; i < sortedAddrs.length; i++) {
    const start = sortedAddrs[i]!;
    const end = i + 1 < sortedAddrs.length ? sortedAddrs[i + 1]! : textSectionEnd;
    const name = addrToName.get(start) ?? `sub_${start.toString(16)}`;
    ranges.push({ start, end, name });
  }

  return ranges;
}

/**
 * Find the function containing a given vmaddr using binary search.
 */
function findContainingFunction(
  vmaddr: bigint,
  ranges: FunctionRange[],
): string | null {
  let lo = 0;
  let hi = ranges.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    const r = ranges[mid]!;
    if (vmaddr < r.start) {
      hi = mid - 1;
    } else if (vmaddr >= r.end) {
      lo = mid + 1;
    } else {
      return r.name;
    }
  }
  return null;
}

// ── ARM64 instruction decoding ───────────────────────────────────────

/**
 * Decode an ADRP instruction.
 * Returns { rd, targetPage } or null if not ADRP.
 *
 * ADRP: bit[31]=1, bits[28:24]=10000
 *   immlo = bits[30:29], immhi = bits[23:5]
 *   immediate = SignExtend(immhi:immlo, 21) << 12
 *   result = (PC & ~0xFFF) + immediate
 */
function decodeADRP(
  insn: number,
  pc: bigint,
): { rd: number; target: bigint } | null {
  // Check opcode: bit31=1, bits[28:24]=10000
  // Use >>> 0 to force unsigned comparison (JS bitwise ops return signed Int32)
  if (((insn & 0x9f000000) >>> 0) !== 0x90000000) return null;

  const rd = insn & 0x1f;
  const immlo = (insn >>> 29) & 0x3;
  const immhi = (insn >>> 5) & 0x7ffff;
  // Combine: 21-bit value = immhi:immlo
  let imm21 = (immhi << 2) | immlo;
  // Sign-extend from 21 bits
  if (imm21 & (1 << 20)) {
    imm21 |= ~((1 << 21) - 1); // sign extend to 32 bits
  }
  const immediate = BigInt(imm21) << 12n;
  const pageBase = pc & ~0xfffn;
  return { rd, target: pageBase + immediate };
}

/**
 * Decode an ADD immediate instruction.
 * Returns { rd, rn, imm } or null if not ADD imm.
 *
 * ADD (imm): sf=1, bits[30:24]=0010001, sh, imm12, Rn, Rd
 */
function decodeADDImm(
  insn: number,
): { rd: number; rn: number; imm: number } | null {
  // Check: bit31=1 (64-bit), bits[30:24]=0010001
  if (((insn & 0xff000000) >>> 0) !== 0x91000000) return null;

  const rd = insn & 0x1f;
  const rn = (insn >>> 5) & 0x1f;
  const imm12 = (insn >>> 10) & 0xfff;
  const sh = (insn >>> 22) & 0x1;
  const imm = sh ? imm12 << 12 : imm12;

  return { rd, rn, imm };
}

/**
 * Decode an ADR instruction (PC-relative address within +/-1MB).
 * Returns { rd, target } or null if not ADR.
 *
 * ADR: bit[31]=0, bits[28:24]=10000
 *   immlo = bits[30:29], immhi = bits[23:5]
 *   immediate = SignExtend(immhi:immlo, 21)
 *   result = PC + immediate
 */
function decodeADR(
  insn: number,
  pc: bigint,
): { rd: number; target: bigint } | null {
  // Check opcode: bit31=0, bits[28:24]=10000
  if (((insn & 0x9f000000) >>> 0) !== 0x10000000) return null;

  const rd = insn & 0x1f;
  const immlo = (insn >>> 29) & 0x3;
  const immhi = (insn >>> 5) & 0x7ffff;
  let imm21 = (immhi << 2) | immlo;
  // Sign-extend from 21 bits
  if (imm21 & (1 << 20)) {
    imm21 |= ~((1 << 21) - 1);
  }
  return { rd, target: pc + BigInt(imm21) };
}

/**
 * Decode an LDR (unsigned offset, 64-bit) instruction.
 * Returns { rt, rn, offset } or null.
 *
 * LDR Xt, [Xn, #imm]: size=11, V=0, opc=01
 * Encoding: 1111 1001 01 [imm12] [Rn] [Rt]
 * offset = imm12 << 3
 */
function decodeLDR64(
  insn: number,
): { rt: number; rn: number; offset: number } | null {
  if (((insn & 0xffc00000) >>> 0) !== 0xf9400000) return null;
  const rt = insn & 0x1f;
  const rn = (insn >>> 5) & 0x1f;
  const imm12 = (insn >>> 10) & 0xfff;
  return { rt, rn, offset: imm12 << 3 };
}

// ── String section range helpers ─────────────────────────────────────

interface VmRange {
  vmStart: bigint;
  vmEnd: bigint;
  fileStart: number;
  isCFString: boolean;
}

function buildStringSectionRanges(
  segments: Segment64[],
): VmRange[] {
  const STRING_SECTIONS = [
    "__cstring", "__objc_methname", "__objc_classname",
    "__objc_methtype", "__swift5_reflstr", "__oslogstring",
    "__ustring",
  ];

  const ranges: VmRange[] = [];
  for (const seg of segments) {
    for (const sect of seg.sections) {
      const name = sect.sectname.trim();
      if (STRING_SECTIONS.includes(name)) {
        ranges.push({
          vmStart: sect.addr,
          vmEnd: sect.addr + sect.size,
          fileStart: sect.offset,
          isCFString: false,
        });
      } else if (name === "__cfstring") {
        ranges.push({
          vmStart: sect.addr,
          vmEnd: sect.addr + sect.size,
          fileStart: sect.offset,
          isCFString: true,
        });
      }
    }
  }
  return ranges;
}

/**
 * Check if a vmaddr falls in a string section and return the file offset.
 * Also indicates whether the hit is in a CFString section.
 */
function vmaddrToStringFileOffset(
  vmaddr: bigint,
  strRanges: VmRange[],
): { fileOffset: number; isCFString: boolean } | null {
  for (const r of strRanges) {
    if (vmaddr >= r.vmStart && vmaddr < r.vmEnd) {
      return {
        fileOffset: r.fileStart + Number(vmaddr - r.vmStart),
        isCFString: r.isCFString,
      };
    }
  }
  return null;
}

const CFSTRING_STRUCT_SIZE = 32;

/**
 * For a CFString struct at a given file offset, resolve the data_ptr field
 * to get the file offset of the actual string character data.
 * This handles the deduplication mismatch: code references the CFString struct,
 * but the StringEntry may use the __cstring data offset.
 */
function resolveCFStringDataOffset(
  structFileOffset: number,
  buffer: ArrayBuffer,
  segments: Segment64[],
  rebaseMap: Map<number, bigint>,
  littleEndian: boolean,
): number | null {
  const view = new DataView(buffer);
  const dataPtrFieldOffset = structFileOffset + 16;

  if (dataPtrFieldOffset + 8 > buffer.byteLength) return null;

  // Try rebaseMap first (chained fixups)
  const rebasedVmaddr = rebaseMap.get(dataPtrFieldOffset);
  if (rebasedVmaddr !== undefined) {
    return vmaddrToFileOffset(rebasedVmaddr, segments);
  }

  // Fallback: raw pointer value
  const rawPtr = view.getBigUint64(dataPtrFieldOffset, littleEndian);
  if (rawPtr > 0n) {
    return vmaddrToFileOffset(rawPtr, segments);
  }

  return null;
}

// ── Main xref builder ────────────────────────────────────────────────

/**
 * Build a map from string file offset to the function name(s) that reference it.
 *
 * Scans the __TEXT.__text section for arm64 instructions that reference
 * addresses in string sections:
 *   - ADRP + ADD  (most common: page + offset)
 *   - ADRP + LDR  (pointer loads from data sections / CFString structs)
 *   - ADR          (single-instruction, PC-relative within +/-1MB)
 */
export function buildStringXrefMap(
  buffer: ArrayBuffer,
  segments: Segment64[],
  functionStarts: bigint[],
  symbols: Symbol[],
  littleEndian: boolean,
  rebaseMap: Map<number, bigint>,
): Map<number, string[]> {
  const xrefMap = new Map<number, string[]>();

  // Find __TEXT.__text section
  let textSection: Section64 | null = null;
  let textSegment: Segment64 | null = null;
  for (const seg of segments) {
    if (seg.segname.trim() === "__TEXT") {
      textSegment = seg;
      for (const sect of seg.sections) {
        if (sect.sectname.trim() === "__text") {
          textSection = sect;
          break;
        }
      }
      break;
    }
  }

  if (!textSection || !textSegment) return xrefMap;

  // Build function ranges (uses function starts if available, else symbol addresses)
  const textStart = textSection.addr;
  const textEnd = textSection.addr + textSection.size;
  const funcRanges = buildFunctionRanges(functionStarts, symbols, textStart, textEnd);
  if (funcRanges.length === 0) return xrefMap;

  // Build string section vmaddr ranges (includes __cstring, __cfstring, etc.)
  const strRanges = buildStringSectionRanges(segments);
  if (strRanges.length === 0) return xrefMap;

  // Build indirect pointer map: for strings referenced through data tables
  // (e.g., __DATA_CONST.__const), the rebaseMap tells us which data locations
  // contain pointers to string sections. We map:
  //   data pointer vmaddr → string file offset
  // So when code does ADRP+ADD/LDR to a data section address, we can check
  // if that address (or nearby) holds a pointer to a string.
  const indirectPtrMap = new Map<number, number>(); // data file offset → string file offset
  for (const [ptrFileOff, targetVmaddr] of rebaseMap) {
    for (const r of strRanges) {
      if (targetVmaddr >= r.vmStart && targetVmaddr < r.vmEnd) {
        const strFileOff = r.fileStart + Number(targetVmaddr - r.vmStart);
        indirectPtrMap.set(ptrFileOff, strFileOff);
        break;
      }
    }
  }

  // Convert indirect pointer file offsets → vmaddrs for matching against code targets
  const indirectVmaddrMap = new Map<bigint, number>(); // data vmaddr → string file offset
  for (const [ptrFileOff, strFileOff] of indirectPtrMap) {
    for (const seg of segments) {
      const segFileOff = Number(seg.fileoff);
      const segFileEnd = segFileOff + Number(seg.filesize);
      if (ptrFileOff >= segFileOff && ptrFileOff < segFileEnd) {
        const vmaddr = seg.vmaddr + BigInt(ptrFileOff - segFileOff);
        indirectVmaddrMap.set(vmaddr, strFileOff);
        break;
      }
    }
  }

  const view = new DataView(buffer);
  const sectionOffset = textSection.offset;
  const sectionSize = Number(textSection.size);
  const sectionVmaddr = textSection.addr;

  // Limit scan to avoid excessive time on very large binaries
  const MAX_INSTRUCTIONS = 20_000_000; // ~80MB of arm64 code
  const instrCount = Math.min(sectionSize >>> 2, MAX_INSTRUCTIONS);

  // Helper to record a xref for a given file offset + function
  function addXref(fileOffset: number, funcName: string): void {
    const existing = xrefMap.get(fileOffset);
    if (existing) {
      if (!existing.includes(funcName)) existing.push(funcName);
    } else {
      xrefMap.set(fileOffset, [funcName]);
    }
  }

  /**
   * Record a xref for a resolved target vmaddr.
   * Checks: direct string section hit, CFString data_ptr resolution,
   * and indirect pointers through data tables.
   */
  function recordXrefForTarget(targetVmaddr: bigint, pc: bigint): void {
    // 1. Direct hit in a string/CFString section
    const directHit = vmaddrToStringFileOffset(targetVmaddr, strRanges);
    if (directHit) {
      const funcName = findContainingFunction(pc, funcRanges);
      if (!funcName) return;

      addXref(directHit.fileOffset, funcName);

      // For CFString, also resolve data_ptr to the actual __cstring offset
      if (directHit.isCFString) {
        const dataOffset = resolveCFStringDataOffset(
          directHit.fileOffset, buffer, segments, rebaseMap, littleEndian,
        );
        if (dataOffset !== null && dataOffset !== directHit.fileOffset) {
          addXref(dataOffset, funcName);
        }
      }
      return;
    }

    // 2. Indirect: target is a data location that holds a pointer to a string
    const indirectStrOff = indirectVmaddrMap.get(targetVmaddr);
    if (indirectStrOff !== undefined) {
      const funcName = findContainingFunction(pc, funcRanges);
      if (funcName) addXref(indirectStrOff, funcName);
      return;
    }

    // 3. Check nearby aligned addresses for indirect pointers (array access patterns)
    // Code often does ADRP+ADD to get the base of an array, then LDR with index.
    // Check if the target is within 256 bytes of a known indirect pointer.
    for (let delta = 0n; delta < 256n; delta += 8n) {
      const nearby = indirectVmaddrMap.get(targetVmaddr + delta);
      if (nearby !== undefined) {
        const funcName = findContainingFunction(pc, funcRanges);
        if (funcName) addXref(nearby, funcName);
        return;
      }
    }
  }

  // Track register values: register → { computed address, instruction index }
  // Updated by ADRP (page address) and ADD (base + offset).
  // Used by ADD (to record string refs) and LDR (to follow data pointers).
  const regCache = new Map<number, { addr: bigint; instrIdx: number }>();
  const MAX_GAP = 8; // allow up to 8 instructions between ADRP and use

  for (let i = 0; i < instrCount; i++) {
    const off = sectionOffset + (i << 2);
    if (off + 4 > buffer.byteLength) break;

    const insn = view.getUint32(off, littleEndian);
    const pc = sectionVmaddr + BigInt(i << 2);

    // ── Try ADRP ──
    const adrp = decodeADRP(insn, pc);
    if (adrp) {
      regCache.set(adrp.rd, { addr: adrp.target, instrIdx: i });
      continue;
    }

    // ── Try ADR (single-instruction PC-relative) ──
    const adr = decodeADR(insn, pc);
    if (adr) {
      regCache.set(adr.rd, { addr: adr.target, instrIdx: i });
      recordXrefForTarget(adr.target, pc);
      continue;
    }

    // ── Try ADD immediate (ADRP + ADD pattern) ──
    const add = decodeADDImm(insn);
    if (add) {
      const cached = regCache.get(add.rn);
      if (cached && (i - cached.instrIdx) <= MAX_GAP) {
        const target = cached.addr + BigInt(add.imm);
        recordXrefForTarget(target, pc);
        // Update register with computed address (for subsequent LDR)
        regCache.set(add.rd, { addr: target, instrIdx: i });
      } else if (add.rd !== add.rn) {
        // Overwrites a register we don't have context for — clear it
        regCache.delete(add.rd);
      }
      continue;
    }

    // ── Try LDR 64-bit unsigned offset (ADRP+LDR or ADRP+ADD+LDR) ──
    const ldr = decodeLDR64(insn);
    if (ldr) {
      const cached = regCache.get(ldr.rn);
      if (cached && (i - cached.instrIdx) <= MAX_GAP) {
        const target = cached.addr + BigInt(ldr.offset);
        recordXrefForTarget(target, pc);
      }
    }
  }

  return xrefMap;
}

// ── Convenience: format function name for display ────────────────────

/**
 * Clean up a raw symbol name for display.
 * ObjC methods like "-[ClassName method:]" are already readable.
 * C functions start with "_" which we strip.
 */
export function formatFunctionName(raw: string): string {
  // ObjC method: already in nice form
  if (raw.startsWith("-[") || raw.startsWith("+[")) {
    return raw;
  }
  // Strip leading underscore from C symbols
  if (raw.startsWith("_")) {
    return raw.slice(1);
  }
  return raw;
}

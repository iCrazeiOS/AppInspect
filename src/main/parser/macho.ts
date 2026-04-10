/**
 * Fat Binary + Mach-O Header Parser
 *
 * Parses fat (universal) binary headers and Mach-O 64-bit headers from
 * raw ArrayBuffer input. Uses DataView for all binary reads, respecting
 * endianness detected from magic values.
 *
 * Does NOT parse load commands or read files from disk.
 */

import * as fs from "fs";

// ── Constants ──────────────────────────────────────────────────────────

export const MH_MAGIC_64 = 0xfeedfacf; // 64-bit Mach-O, native endian
export const MH_CIGAM_64 = 0xcffaedfe; // 64-bit Mach-O, swapped endian
export const MH_MAGIC = 0xfeedface; // 32-bit Mach-O, native endian
export const MH_CIGAM = 0xcefaedfe; // 32-bit Mach-O, swapped endian

export const FAT_MAGIC = 0xcafebabe; // Fat binary, big-endian
export const FAT_CIGAM = 0xbebafeca; // Fat binary, little-endian (rare)

export const CPU_TYPE_ARM64 = 0x0100000c;
export const CPU_TYPE_X86_64 = 0x01000007;
export const CPU_TYPE_ARM = 0x0000000c;
export const CPU_TYPE_X86 = 0x00000007;

export const MH_EXECUTE = 2;
export const MH_DYLIB = 6;

export const MH_PIE = 0x200000;

/** Set of all known Mach-O / fat binary magic values. */
export const MACHO_MAGICS = new Set([
  MH_MAGIC,     // 0xfeedface — 32-bit
  MH_CIGAM,     // 0xcefaedfe — 32-bit swapped
  MH_MAGIC_64,  // 0xfeedfacf — 64-bit
  MH_CIGAM_64,  // 0xcffaedfe — 64-bit swapped
  FAT_MAGIC,    // 0xcafebabe — fat binary
  FAT_CIGAM,    // 0xbebafeca — fat binary swapped
]);

// Struct sizes
const FAT_HEADER_SIZE = 8; // magic(4) + nfat_arch(4)
const FAT_ARCH_SIZE = 20; // cputype(4) + cpusubtype(4) + offset(4) + size(4) + align(4)
const MACH_HEADER_32_SIZE = 28; // magic(4) + cputype(4) + cpusubtype(4) + filetype(4) + ncmds(4) + sizeofcmds(4) + flags(4)
const MACH_HEADER_64_SIZE = 32; // magic(4) + cputype(4) + cpusubtype(4) + filetype(4) + ncmds(4) + sizeofcmds(4) + flags(4) + reserved(4)

// ── Types ──────────────────────────────────────────────────────────────

export interface FatArch {
  cputype: number;
  cpusubtype: number;
  offset: number;
  size: number;
  align: number;
}

export interface MachOHeader {
  magic: number;
  cputype: number;
  cpusubtype: number;
  filetype: number;
  ncmds: number;
  sizeofcmds: number;
  flags: number;
  reserved: number;
}

export interface MachOFile {
  header: MachOHeader;
  offset: number;
  littleEndian: boolean;
  is64Bit: boolean;
}

export type Result<T> =
  | { ok: true; data: T }
  | { ok: false; error: string };

// ── Fat Header Parsing ─────────────────────────────────────────────────

/**
 * Parse a fat (universal) binary header. If the buffer is not a fat binary,
 * returns a single slice descriptor covering the entire buffer.
 */
export function parseFatHeader(buffer: ArrayBuffer): Result<FatArch[]> {
  if (buffer.byteLength < 4) {
    return { ok: false, error: "Buffer too small to read magic (need at least 4 bytes)" };
  }

  const view = new DataView(buffer);
  const magic = view.getUint32(0, false); // read as big-endian first

  // Fat headers are ALWAYS big-endian
  if (magic === FAT_MAGIC || magic === FAT_CIGAM) {
    // FAT_CIGAM means the file stores the fat header in little-endian,
    // but by convention fat headers are big-endian. FAT_CIGAM indicates
    // we read big-endian and got the swapped value, so the file is LE.
    const fatLE = magic === FAT_CIGAM;

    if (buffer.byteLength < FAT_HEADER_SIZE) {
      return { ok: false, error: "Buffer too small for fat header (need at least 8 bytes)" };
    }

    const nfat_arch = view.getUint32(4, fatLE);

    const requiredSize = FAT_HEADER_SIZE + nfat_arch * FAT_ARCH_SIZE;
    if (buffer.byteLength < requiredSize) {
      return {
        ok: false,
        error: `Buffer too small for ${nfat_arch} fat_arch entries (need ${requiredSize} bytes, have ${buffer.byteLength})`,
      };
    }

    const arches: FatArch[] = [];
    for (let i = 0; i < nfat_arch; i++) {
      const base = FAT_HEADER_SIZE + i * FAT_ARCH_SIZE;
      arches.push({
        cputype: view.getUint32(base, fatLE),
        cpusubtype: view.getUint32(base + 4, fatLE),
        offset: view.getUint32(base + 8, fatLE),
        size: view.getUint32(base + 12, fatLE),
        align: view.getUint32(base + 16, fatLE),
      });
    }

    return { ok: true, data: arches };
  }

  // Not a fat binary — return a single slice covering the entire buffer
  return {
    ok: true,
    data: [
      {
        cputype: 0,
        cpusubtype: 0,
        offset: 0,
        size: buffer.byteLength,
        align: 0,
      },
    ],
  };
}

// ── Mach-O Header Parsing ──────────────────────────────────────────────

/**
 * Parse a mach_header or mach_header_64 at the given byte offset within the buffer.
 * Detects endianness and bitness from the magic value.
 */
export function parseMachOHeader(
  buffer: ArrayBuffer,
  offset: number = 0,
): Result<MachOFile> {
  if (buffer.byteLength < offset + 4) {
    return {
      ok: false,
      error: `Buffer too small to read magic at offset ${offset} (need ${offset + 4} bytes, have ${buffer.byteLength})`,
    };
  }

  const view = new DataView(buffer);
  const rawMagicBE = view.getUint32(offset, false); // read big-endian first
  const rawMagicLE = view.getUint32(offset, true);  // also try little-endian

  // Determine bitness and endianness from magic
  let littleEndian: boolean;
  let is64Bit: boolean;

  if (rawMagicBE === MH_MAGIC_64) {
    // Read as big-endian and got 64-bit native magic → file is big-endian
    littleEndian = false;
    is64Bit = true;
  } else if (rawMagicBE === MH_CIGAM_64) {
    // Read as big-endian and got 64-bit swapped magic → file is little-endian
    littleEndian = true;
    is64Bit = true;
  } else if (rawMagicBE === MH_MAGIC) {
    // 32-bit native magic, big-endian
    littleEndian = false;
    is64Bit = false;
  } else if (rawMagicBE === MH_CIGAM) {
    // 32-bit swapped magic, little-endian
    littleEndian = true;
    is64Bit = false;
  } else if (rawMagicLE === MH_MAGIC_64) {
    // Little-endian read got 64-bit magic
    littleEndian = true;
    is64Bit = true;
  } else if (rawMagicLE === MH_MAGIC) {
    // Little-endian read got 32-bit magic
    littleEndian = true;
    is64Bit = false;
  } else {
    return {
      ok: false,
      error: `Invalid Mach-O magic: 0x${rawMagicBE.toString(16).padStart(8, "0")}`,
    };
  }

  const headerSize = is64Bit ? MACH_HEADER_64_SIZE : MACH_HEADER_32_SIZE;
  if (buffer.byteLength < offset + headerSize) {
    return {
      ok: false,
      error: `Buffer too small for mach_header${is64Bit ? "_64" : ""} at offset ${offset} (need ${offset + headerSize} bytes, have ${buffer.byteLength})`,
    };
  }

  const header: MachOHeader = {
    magic: view.getUint32(offset, littleEndian),
    cputype: view.getUint32(offset + 4, littleEndian),
    cpusubtype: view.getUint32(offset + 8, littleEndian),
    filetype: view.getUint32(offset + 12, littleEndian),
    ncmds: view.getUint32(offset + 16, littleEndian),
    sizeofcmds: view.getUint32(offset + 20, littleEndian),
    flags: view.getUint32(offset + 24, littleEndian),
    reserved: is64Bit ? view.getUint32(offset + 28, littleEndian) : 0,
  };

  return {
    ok: true,
    data: {
      header,
      offset,
      littleEndian,
      is64Bit,
    },
  };
}

// ── File-Level Detection ──────────────────────────────────────────────

/**
 * Check if a file looks like a Mach-O (or fat) binary by reading its magic bytes.
 */
export function isMachOFile(filePath: string): boolean {
  try {
    const fd = fs.openSync(filePath, "r");
    const buf = Buffer.alloc(4);
    fs.readSync(fd, buf, 0, 4, 0);
    fs.closeSync(fd);
    const magic = buf.readUInt32BE(0);
    const magicLE = buf.readUInt32LE(0);
    return MACHO_MAGICS.has(magic) || MACHO_MAGICS.has(magicLE);
  } catch {
    return false;
  }
}

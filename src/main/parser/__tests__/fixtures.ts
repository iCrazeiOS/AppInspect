/**
 * Test fixtures: helpers to build minimal Mach-O byte arrays in memory.
 * All values are known constants for easy assertion.
 */

import {
  MH_MAGIC_64,
  MH_MAGIC,
  FAT_MAGIC,
  CPU_TYPE_ARM64,
  CPU_TYPE_X86_64,
  MH_EXECUTE,
  MH_DYLIB,
  MH_PIE,
} from "../macho";

// ── mach_header_64 builder ─────────────────────────────────────────────

export interface MachHeader64Options {
  magic?: number;
  cputype?: number;
  cpusubtype?: number;
  filetype?: number;
  ncmds?: number;
  sizeofcmds?: number;
  flags?: number;
  reserved?: number;
  littleEndian?: boolean;
}

/**
 * Build a 32-byte mach_header_64 buffer with configurable fields.
 * Defaults to a valid ARM64 executable header in little-endian.
 */
export function buildMachHeader64(opts: MachHeader64Options = {}): ArrayBuffer {
  const le = opts.littleEndian ?? true;
  const buf = new ArrayBuffer(32);
  const view = new DataView(buf);

  view.setUint32(0, opts.magic ?? MH_MAGIC_64, le);
  view.setUint32(4, opts.cputype ?? CPU_TYPE_ARM64, le);
  view.setUint32(8, opts.cpusubtype ?? 0x00000000, le);
  view.setUint32(12, opts.filetype ?? MH_EXECUTE, le);
  view.setUint32(16, opts.ncmds ?? 15, le);
  view.setUint32(20, opts.sizeofcmds ?? 1200, le);
  view.setUint32(24, opts.flags ?? MH_PIE, le);
  view.setUint32(28, opts.reserved ?? 0, le);

  return buf;
}

// ── 32-bit mach_header builder ─────────────────────────────────────────

/**
 * Build a 28-byte mach_header (32-bit) buffer.
 */
export function buildMachHeader32(littleEndian: boolean = true): ArrayBuffer {
  const buf = new ArrayBuffer(28);
  const view = new DataView(buf);
  view.setUint32(0, MH_MAGIC, littleEndian);
  view.setUint32(4, 0x0000000c, littleEndian); // CPU_TYPE_ARM
  view.setUint32(8, 0x00000000, littleEndian);
  view.setUint32(12, MH_EXECUTE, littleEndian);
  view.setUint32(16, 5, littleEndian);
  view.setUint32(20, 400, littleEndian);
  view.setUint32(24, 0, littleEndian);
  return buf;
}

// ── Fat binary builder ─────────────────────────────────────────────────

export interface FatArchEntry {
  cputype: number;
  cpusubtype: number;
  offset: number;
  size: number;
  align: number;
}

/**
 * Build a fat header with the given arch entries.
 * Fat headers are ALWAYS big-endian.
 * Returns buffer containing fat_header + fat_arch entries (no actual slice data).
 */
export function buildFatHeader(arches: FatArchEntry[]): ArrayBuffer {
  const headerSize = 8 + arches.length * 20;
  const buf = new ArrayBuffer(headerSize);
  const view = new DataView(buf);

  // fat_header: always big-endian
  view.setUint32(0, FAT_MAGIC, false);
  view.setUint32(4, arches.length, false);

  for (let i = 0; i < arches.length; i++) {
    const base = 8 + i * 20;
    const arch = arches[i]!;
    view.setUint32(base, arch.cputype, false);
    view.setUint32(base + 4, arch.cpusubtype, false);
    view.setUint32(base + 8, arch.offset, false);
    view.setUint32(base + 12, arch.size, false);
    view.setUint32(base + 16, arch.align, false);
  }

  return buf;
}

// ── Pre-built fixtures with known values ───────────────────────────────

/** A standard ARM64 executable header (little-endian) */
export const ARM64_EXEC_HEADER = buildMachHeader64({
  cputype: CPU_TYPE_ARM64,
  filetype: MH_EXECUTE,
  ncmds: 15,
  sizeofcmds: 1200,
  flags: MH_PIE,
  littleEndian: true,
});

/** An x86_64 dylib header (little-endian) */
export const X86_64_DYLIB_HEADER = buildMachHeader64({
  cputype: CPU_TYPE_X86_64,
  filetype: MH_DYLIB,
  ncmds: 22,
  sizeofcmds: 2048,
  flags: 0x00000085,
  littleEndian: true,
});

/** A big-endian ARM64 header (unusual but valid) */
export const BE_ARM64_HEADER = buildMachHeader64({
  cputype: CPU_TYPE_ARM64,
  filetype: MH_EXECUTE,
  ncmds: 10,
  sizeofcmds: 800,
  flags: MH_PIE,
  littleEndian: false,
});

/** A fat binary with ARM64 + x86_64 slices */
export const FAT_DUAL_ARCH = buildFatHeader([
  { cputype: CPU_TYPE_ARM64, cpusubtype: 0, offset: 16384, size: 50000, align: 14 },
  { cputype: CPU_TYPE_X86_64, cpusubtype: 3, offset: 70000, size: 45000, align: 14 },
]);

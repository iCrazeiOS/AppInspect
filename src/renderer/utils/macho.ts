/** Shared Mach-O decoding constants and helpers. */

export const CPU_TYPE_NAMES: Record<number, string> = {
  7: "x86",
  12: "ARM",
  0x01000007: "x86_64",
  0x0100000c: "ARM64",
};

export const FILE_TYPE_NAMES: Record<number, string> = {
  1: "MH_OBJECT",
  2: "MH_EXECUTE",
  5: "MH_CORE",
  6: "MH_DYLIB",
  7: "MH_DYLINKER",
  8: "MH_BUNDLE",
  9: "MH_DYLIB_STUB",
  10: "MH_DSYM",
  11: "MH_KEXT_BUNDLE",
};

export function decodeCpuType(cputype: number): string {
  return CPU_TYPE_NAMES[cputype] ?? `Unknown (${cputype})`;
}

export function decodeFileType(filetype: number): string {
  return FILE_TYPE_NAMES[filetype] ?? `Unknown (${filetype})`;
}

export function hexStr(n: number): string {
  return "0x" + n.toString(16).toUpperCase().padStart(8, "0");
}

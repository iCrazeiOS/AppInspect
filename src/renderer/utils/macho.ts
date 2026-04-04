/** Shared Mach-O decoding constants and helpers. */

export const CPU_TYPE_NAMES: Record<number, string> = {
  7: "x86",
  12: "ARM",
  0x01000007: "x86_64",
  0x0100000c: "ARM64",
};

/** LC_BUILD_VERSION platform constants */
export const PLATFORM_NAMES: Record<number, string> = {
  1: "macOS",
  2: "iOS",
  3: "tvOS",
  4: "watchOS",
  5: "bridgeOS",
  6: "Mac Catalyst",
  7: "iOS Simulator",
  8: "tvOS Simulator",
  9: "watchOS Simulator",
  10: "DriverKit",
  11: "visionOS",
  12: "visionOS Simulator",
};

export function decodePlatform(platform: number): string {
  return PLATFORM_NAMES[platform] ?? `Unknown (${platform})`;
}

/** Returns true if the platform is macOS or Mac Catalyst */
export function isMacOSPlatform(platform: number): boolean {
  return platform === 1 || platform === 6;
}

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

/**
 * Type conversion helpers.
 *
 * Converts internal parser types (with bigint addresses, nested structures)
 * to the shared types used in AnalysisResult for IPC serialisation.
 */

import type {
  LinkedLibrary,
  Symbol as SymbolEntry,
  StringEntry,
  Entitlement,
  PlistValue,
  Section,
  Segment,
  LoadCommand as SharedLoadCommand,
} from "../../shared/types";
import type { LoadCommandsResult, Segment64, Section64 } from "../parser/load-commands";
import type { Symbol as ParserSymbol } from "../parser/symbols";
import type { StringEntry as ParserStringEntry } from "../parser/strings";
import { buildMethodSignature } from "../parser/objc";

// Complete LC_* mapping from Apple XNU mach-o/loader.h
const LC_NAMES: Record<number, string> = {
  0x1: "LC_SEGMENT",
  0x2: "LC_SYMTAB",
  0x3: "LC_SYMSEG",
  0x4: "LC_THREAD",
  0x5: "LC_UNIXTHREAD",
  0x6: "LC_LOADFVMLIB",
  0x7: "LC_IDFVMLIB",
  0x8: "LC_IDENT",
  0x9: "LC_FVMFILE",
  0xa: "LC_PREPAGE",
  0xb: "LC_DYSYMTAB",
  0xc: "LC_LOAD_DYLIB",
  0xd: "LC_ID_DYLIB",
  0xe: "LC_LOAD_DYLINKER",
  0xf: "LC_ID_DYLINKER",
  0x10: "LC_PREBOUND_DYLIB",
  0x11: "LC_ROUTINES",
  0x12: "LC_SUB_FRAMEWORK",
  0x13: "LC_SUB_UMBRELLA",
  0x14: "LC_SUB_CLIENT",
  0x15: "LC_SUB_LIBRARY",
  0x16: "LC_TWOLEVEL_HINTS",
  0x17: "LC_PREBIND_CKSUM",
  0x19: "LC_SEGMENT_64",
  0x1a: "LC_ROUTINES_64",
  0x1b: "LC_UUID",
  0x1d: "LC_CODE_SIGNATURE",
  0x1e: "LC_SEGMENT_SPLIT_INFO",
  0x20: "LC_LAZY_LOAD_DYLIB",
  0x21: "LC_ENCRYPTION_INFO",
  0x22: "LC_DYLD_INFO",
  0x24: "LC_VERSION_MIN_MACOSX",
  0x25: "LC_VERSION_MIN_IPHONEOS",
  0x26: "LC_FUNCTION_STARTS",
  0x27: "LC_DYLD_ENVIRONMENT",
  0x29: "LC_DATA_IN_CODE",
  0x2a: "LC_SOURCE_VERSION",
  0x2b: "LC_DYLIB_CODE_SIGN_DRS",
  0x2c: "LC_ENCRYPTION_INFO_64",
  0x2d: "LC_LINKER_OPTION",
  0x2e: "LC_LINKER_OPTIMIZATION_HINT",
  0x2f: "LC_VERSION_MIN_TVOS",
  0x30: "LC_VERSION_MIN_WATCHOS",
  0x31: "LC_NOTE",
  0x32: "LC_BUILD_VERSION",
  // LC_REQ_DYLD (0x80000000) variants
  0x80000018: "LC_LOAD_WEAK_DYLIB",
  0x8000001c: "LC_RPATH",
  0x8000001f: "LC_REEXPORT_DYLIB",
  0x80000022: "LC_DYLD_INFO_ONLY",
  0x80000023: "LC_LOAD_UPWARD_DYLIB",
  0x80000028: "LC_MAIN",
  0x80000033: "LC_DYLD_EXPORTS_TRIE",
  0x80000034: "LC_DYLD_CHAINED_FIXUPS",
  0x80000035: "LC_FILESET_ENTRY",
};

function decodeLCName(cmd: number): string {
  return LC_NAMES[cmd] ?? `LC_UNKNOWN(0x${cmd.toString(16)})`;
}

/** Build signature from prefix (-/+), selector, and raw type encoding using the full ObjC type parser. */
export function buildMethodSignatureFromParts(prefix: string, selector: string, typeEncoding: string): string {
  if (!typeEncoding) return `${prefix}${selector}`;
  return buildMethodSignature(selector, typeEncoding, prefix === "-");
}

export function convertSection(s: Section64): Section {
  return {
    sectname: s.sectname,
    segname: s.segname,
    addr: s.addr,
    size: s.size,
    offset: s.offset,
    align: s.align,
    reloff: s.reloff,
    nreloc: s.nreloc,
    flags: s.flags,
    reserved1: s.reserved1,
    reserved2: s.reserved2,
    reserved3: s.reserved3,
  };
}

export function convertSegment(s: Segment64): Segment {
  return {
    name: s.segname,
    vmaddr: s.vmaddr,
    vmsize: s.vmsize,
    fileoff: Number(s.fileoff),
    filesize: Number(s.filesize),
    sections: s.sections.map(convertSection),
    maxprot: s.maxprot,
    initprot: s.initprot,
    flags: s.flags,
  };
}

/**
 * Convert internal parser load commands to the shared LoadCommand type
 * used in the AnalysisResult. Strips bigint values.
 */
export function convertLoadCommands(lcResult: LoadCommandsResult): SharedLoadCommand[] {
  const result: SharedLoadCommand[] = [];

  for (const seg of lcResult.segments) {
    result.push({
      type: "segment",
      cmd: seg.cmd,
      cmdsize: seg.cmdsize,
      segment: convertSegment(seg),
    });
  }

  for (const lib of lcResult.libraries) {
    result.push({
      type: "dylib",
      cmd: lib.cmd,
      cmdsize: lib.cmdsize,
      library: {
        name: lib.name,
        currentVersion: lib.currentVersion,
        compatVersion: lib.compatVersion,
        weak: lib.weak,
      },
    });
  }

  if (lcResult.symtabInfo) {
    result.push({
      type: "symtab",
      cmd: lcResult.symtabInfo.cmd,
      cmdsize: lcResult.symtabInfo.cmdsize,
      symtab: {
        symoff: lcResult.symtabInfo.symoff,
        nsyms: lcResult.symtabInfo.nsyms,
        stroff: lcResult.symtabInfo.stroff,
        strsize: lcResult.symtabInfo.strsize,
      },
    });
  }

  if (lcResult.encryption) {
    result.push({
      type: "encryption_info",
      cmd: lcResult.encryption.cmd,
      cmdsize: lcResult.encryption.cmdsize,
      encryption: {
        cryptoff: lcResult.encryption.cryptoff,
        cryptsize: lcResult.encryption.cryptsize,
        cryptid: lcResult.encryption.cryptid,
      },
    });
  }

  if (lcResult.buildVersion) {
    result.push({
      type: "build_version",
      cmd: lcResult.buildVersion.cmd,
      cmdsize: lcResult.buildVersion.cmdsize,
      buildVersion: {
        platform: lcResult.buildVersion.platform,
        minos: lcResult.buildVersion.minos,
        sdk: lcResult.buildVersion.sdk,
        ntools: lcResult.buildVersion.ntools,
      },
    });
  }

  // Add remaining generic load commands that weren't already covered
  for (const lc of lcResult.loadCommands) {
    const cmd = lc.cmd;
    // Skip commands we already converted above
    if ("segname" in lc || "name" in lc || "symoff" in lc || "cryptoff" in lc || "platform" in lc) {
      continue;
    }
    result.push({
      type: "generic",
      cmd,
      cmdsize: lc.cmdsize,
      cmdName: decodeLCName(cmd),
    });
  }

  return result;
}

export function convertSymbols(symbols: ParserSymbol[]): SymbolEntry[] {
  return symbols.map((s) => ({
    name: s.name,
    address: s.address,
    type: s.type,
    sectionIndex: s.sectionIndex,
  }));
}

export function convertStrings(strings: ParserStringEntry[]): StringEntry[] {
  return strings.map((s) => ({
    value: s.value,
    sectionSource: s.sources.join(", "),
    offset: s.offset,
  }));
}

export function convertEntitlements(
  raw: Record<string, unknown> | null
): Entitlement[] {
  if (!raw) return [];
  return Object.entries(raw).map(([key, value]) => ({
    key,
    value: value as PlistValue,
  }));
}

export function convertLibraries(lcResult: LoadCommandsResult): LinkedLibrary[] {
  return lcResult.libraries.map((lib) => ({
    name: lib.name,
    currentVersion: lib.currentVersion,
    compatVersion: lib.compatVersion,
    weak: lib.weak,
  }));
}

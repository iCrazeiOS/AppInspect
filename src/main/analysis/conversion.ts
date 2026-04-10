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
import { decodeLCName } from "../../shared/macho";

/**
 * Decode LC_SOURCE_VERSION packed version number.
 * Format: A.B.C.D.E where A is 24 bits, B/C/D/E are 10 bits each.
 */
function decodeSourceVersion(version: bigint): string {
  const a = Number((version >> 40n) & 0xFFFFFFn);
  const b = Number((version >> 30n) & 0x3FFn);
  const c = Number((version >> 20n) & 0x3FFn);
  const d = Number((version >> 10n) & 0x3FFn);
  const e = Number(version & 0x3FFn);
  // Omit trailing zeros for cleaner display
  if (e !== 0) return `${a}.${b}.${c}.${d}.${e}`;
  if (d !== 0) return `${a}.${b}.${c}.${d}`;
  if (c !== 0) return `${a}.${b}.${c}`;
  if (b !== 0) return `${a}.${b}`;
  return `${a}`;
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

  // Add remaining load commands - handle specific types before falling through to generic
  for (const lc of lcResult.loadCommands) {
    const cmd = lc.cmd;
    // Skip commands we already converted above
    if ("segname" in lc || "name" in lc || "symoff" in lc || "cryptoff" in lc || "platform" in lc) {
      continue;
    }

    // LC_UUID
    if ("uuid" in lc && typeof lc.uuid === "string") {
      result.push({
        type: "uuid",
        cmd,
        cmdsize: lc.cmdsize,
        uuid: lc.uuid,
      });
      continue;
    }

    // LC_MAIN
    if ("entryoff" in lc && typeof lc.entryoff === "bigint") {
      result.push({
        type: "main",
        cmd,
        cmdsize: lc.cmdsize,
        entryoff: Number(lc.entryoff),
        stacksize: Number(lc.stacksize),
      });
      continue;
    }

    // LC_RPATH
    if ("path" in lc && typeof lc.path === "string") {
      result.push({
        type: "rpath",
        cmd,
        cmdsize: lc.cmdsize,
        path: lc.path,
      });
      continue;
    }

    // LC_SOURCE_VERSION
    if ("version" in lc && typeof lc.version === "bigint") {
      result.push({
        type: "source_version",
        cmd,
        cmdsize: lc.cmdsize,
        version: decodeSourceVersion(lc.version),
      });
      continue;
    }

    // LC_DYLD_INFO / LC_DYLD_INFO_ONLY
    if ("exportSize" in lc && typeof lc.exportSize === "number") {
      result.push({
        type: "dyld_info",
        cmd,
        cmdsize: lc.cmdsize,
        exportSize: lc.exportSize,
        bindSize: lc.bindSize,
        rebaseSize: lc.rebaseSize,
      });
      continue;
    }

    // LC_ID_DYLIB (dylib identifying itself - has name but wasn't added to libraries)
    if ("name" in lc && "currentVersion" in lc && "compatVersion" in lc && cmd === 0xd) {
      result.push({
        type: "id_dylib",
        cmd,
        cmdsize: lc.cmdsize,
        name: lc.name as string,
        currentVersion: lc.currentVersion as string,
        compatVersion: lc.compatVersion as string,
      });
      continue;
    }

    // Generic fallback
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

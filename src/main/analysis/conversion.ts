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
      cmdName: `LC_0x${cmd.toString(16)}`,
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

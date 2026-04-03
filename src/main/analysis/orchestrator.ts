/**
 * Analysis Orchestrator
 *
 * Sequences all parser modules to produce a full AnalysisResult from an IPA file.
 * Reports progress via a callback. Gracefully continues when individual parsers fail.
 */

import * as fs from "fs";
import * as path from "path";
import * as os from "os";

import type {
  AnalysisResult,
  FileEntry,
  MachOHeader,
  FatArch,
  BuildVersion,
  EncryptionInfo,
  BinaryHardening,
  LinkedLibrary,
  Symbol as SymbolEntry,
  ObjCClass,
  Entitlement,
  StringEntry,
  SecurityFinding,
  LoadCommand as SharedLoadCommand,
  PlistValue,
  Section,
  Segment,
} from "../../shared/types";

import {
  extractIPA,
  discoverAppBundle,
  discoverBinaries,
} from "../ipa/extractor";
import type { BinaryInfo } from "../ipa/extractor";
import { parseFatHeader, parseMachOHeader, CPU_TYPE_ARM64 } from "../parser/macho";
import type { MachOFile } from "../parser/macho";
import { parseLoadCommands } from "../parser/load-commands";
import type { LoadCommandsResult, Segment64, Section64 } from "../parser/load-commands";
import { buildFixupMap } from "../parser/chained-fixups";
import { extractStrings } from "../parser/strings";
import type { StringEntry as ParserStringEntry } from "../parser/strings";
import { parseSymbolTable, parseExportTrie } from "../parser/symbols";
import type { Symbol as ParserSymbol } from "../parser/symbols";
import { extractObjCMetadata } from "../parser/objc";
import { parseCodeSignature, extractEntitlements } from "../parser/codesign";
import { parseInfoPlist, parseMobileprovision } from "../parser/plist";
import { runSecurityScan, getBinaryHardening } from "./security";

// ── BigInt serialization helpers ────────────────────────────────────

/**
 * Convert bigint values to numbers (or strings for very large values)
 * so the result can be JSON-serialized over IPC.
 */
function bigintToNumber(val: bigint): number {
  if (val <= BigInt(Number.MAX_SAFE_INTEGER) && val >= BigInt(Number.MIN_SAFE_INTEGER)) {
    return Number(val);
  }
  return Number(val);
}

// ── Cached state ────────────────────────────────────────────────────

let cachedResult: AnalysisResult | null = null;
let cachedExtractedDir: string | null = null;
let cachedAppBundlePath: string | null = null;
let cachedBinaries: BinaryInfo[] = [];
let cachedInfoPlist: Record<string, unknown> = {};

export function getCachedResult(): AnalysisResult | null {
  return cachedResult;
}

// ── File tree builder ───────────────────────────────────────────────

export function buildFileTree(dirPath: string): FileEntry[] {
  try {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    const result: FileEntry[] = [];

    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      let size = 0;

      try {
        const stat = fs.statSync(fullPath);
        size = stat.size;
      } catch {
        // skip entries we can't stat
        continue;
      }

      if (entry.isDirectory()) {
        const children = buildFileTree(fullPath);
        result.push({
          name: entry.name,
          path: fullPath,
          size,
          isDirectory: true,
          children,
        });
      } else {
        result.push({
          name: entry.name,
          path: fullPath,
          size,
          isDirectory: false,
        });
      }
    }

    return result.sort((a, b) => {
      // Directories first, then alphabetical
      if (a.isDirectory && !b.isDirectory) return -1;
      if (!a.isDirectory && b.isDirectory) return 1;
      return a.name.localeCompare(b.name);
    });
  } catch {
    return [];
  }
}

// ── Section / Segment conversion helpers ────────────────────────────

function convertSection(s: Section64): Section {
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

function convertSegment(s: Segment64): Segment {
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
function convertLoadCommands(lcResult: LoadCommandsResult): SharedLoadCommand[] {
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

function convertSymbols(symbols: ParserSymbol[]): SymbolEntry[] {
  return symbols.map((s) => ({
    name: s.name,
    address: s.address,
    type: s.type,
    sectionIndex: s.sectionIndex,
  }));
}

function convertStrings(strings: ParserStringEntry[]): StringEntry[] {
  return strings.map((s) => ({
    value: s.value,
    sectionSource: s.sources.join(", "),
    offset: s.offset,
  }));
}

function convertEntitlements(
  raw: Record<string, unknown> | null
): Entitlement[] {
  if (!raw) return [];
  return Object.entries(raw).map(([key, value]) => ({
    key,
    value: value as PlistValue,
  }));
}

// ── Binary analysis (steps 4-12) ────────────────────────────────────

interface BinaryAnalysisResult {
  header: MachOHeader;
  fatArchs: FatArch[];
  loadCommands: SharedLoadCommand[];
  libraries: LinkedLibrary[];
  buildVersion: BuildVersion | null;
  encryptionInfo: EncryptionInfo | null;
  strings: StringEntry[];
  symbols: SymbolEntry[];
  classes: ObjCClass[];
  protocols: string[];
  entitlements: Entitlement[];
  uuid: string | null;
  teamId: string | null;
  security: { findings: SecurityFinding[]; hardening: BinaryHardening };
  errors: string[];
}

async function analyzeBinaryFile(
  binaryPath: string,
  progressCallback: (phase: string, percent: number) => void,
  basePercent: number,
): Promise<BinaryAnalysisResult> {
  const errors: string[] = [];

  // Defaults
  let header: MachOHeader = {
    magic: 0, cputype: 0, cpusubtype: 0, filetype: 0,
    ncmds: 0, sizeofcmds: 0, flags: 0, reserved: 0,
  };
  let fatArchs: FatArch[] = [];
  let sharedLoadCommands: SharedLoadCommand[] = [];
  let libraries: LinkedLibrary[] = [];
  let buildVersion: BuildVersion | null = null;
  let encryptionInfo: EncryptionInfo | null = null;
  let strings: StringEntry[] = [];
  let symbols: SymbolEntry[] = [];
  let classes: ObjCClass[] = [];
  let protocols: string[] = [];
  let entitlements: Entitlement[] = [];
  let uuid: string | null = null;
  let teamId: string | null = null;
  let findings: SecurityFinding[] = [];
  let hardening: BinaryHardening = {
    pie: false, arc: false, stackCanaries: false, encrypted: false, stripped: true,
  };

  // Step 4: Read binary
  progressCallback("Reading binary...", basePercent);
  let buffer: ArrayBuffer;
  try {
    const fileBuf = fs.readFileSync(binaryPath);
    buffer = fileBuf.buffer.slice(
      fileBuf.byteOffset,
      fileBuf.byteOffset + fileBuf.byteLength,
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`Failed to read binary: ${msg}`);
    return {
      header, fatArchs, loadCommands: sharedLoadCommands, libraries,
      buildVersion, encryptionInfo, strings, symbols, classes, protocols, entitlements,
      uuid, teamId, security: { findings, hardening }, errors,
    };
  }

  // Step 5: Parse fat header / select arm64 slice / parse Mach-O header
  progressCallback("Parsing Mach-O header...", basePercent + 5);
  let machoFile: MachOFile | null = null;

  try {
    const fatResult = parseFatHeader(buffer);
    if (fatResult.ok) {
      fatArchs = fatResult.data;

      // Prefer arm64 slice
      const arm64Arch = fatArchs.find((a) => a.cputype === CPU_TYPE_ARM64);
      const selectedArch = arm64Arch ?? fatArchs[0];

      if (selectedArch) {
        const headerResult = parseMachOHeader(buffer, selectedArch.offset);
        if (headerResult.ok) {
          machoFile = headerResult.data;
          header = machoFile.header;
        } else {
          errors.push(`Mach-O header parse: ${headerResult.error}`);
        }
      }
    } else {
      errors.push(`Fat header parse: ${fatResult.error}`);
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`Header parse error: ${msg}`);
  }

  if (!machoFile) {
    return {
      header, fatArchs, loadCommands: sharedLoadCommands, libraries,
      buildVersion, encryptionInfo, strings, symbols, classes, protocols, entitlements,
      uuid, teamId, security: { findings, hardening }, errors,
    };
  }

  // Step 6: Parse load commands
  progressCallback("Parsing load commands...", basePercent + 10);
  let lcResult: LoadCommandsResult | null = null;
  try {
    const lcOffset = machoFile.offset + 32; // mach_header_64 = 32 bytes
    lcResult = parseLoadCommands(
      buffer,
      lcOffset,
      header.ncmds,
      header.sizeofcmds,
      machoFile.littleEndian,
    );
    sharedLoadCommands = convertLoadCommands(lcResult);

    libraries = lcResult.libraries.map((lib) => ({
      name: lib.name,
      currentVersion: lib.currentVersion,
      compatVersion: lib.compatVersion,
      weak: lib.weak,
    }));

    if (lcResult.buildVersion) {
      buildVersion = {
        platform: lcResult.buildVersion.platform,
        minos: lcResult.buildVersion.minos,
        sdk: lcResult.buildVersion.sdk,
        ntools: lcResult.buildVersion.ntools,
      };
    }

    if (lcResult.uuid) {
      uuid = lcResult.uuid;
    }

    if (lcResult.encryption) {
      encryptionInfo = {
        cryptoff: lcResult.encryption.cryptoff,
        cryptsize: lcResult.encryption.cryptsize,
        cryptid: lcResult.encryption.cryptid,
      };
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`Load commands parse error: ${msg}`);
  }

  if (!lcResult) {
    return {
      header, fatArchs, loadCommands: sharedLoadCommands, libraries,
      buildVersion, encryptionInfo, strings, symbols, classes, protocols, entitlements,
      uuid, teamId, security: { findings, hardening }, errors,
    };
  }

  // Step 7: Build chained fixup map
  progressCallback("Building fixup map...", basePercent + 20);
  let rebaseMap = new Map<number, bigint>();
  try {
    if (lcResult.chainedFixupsInfo) {
      const fixups = buildFixupMap(
        buffer,
        lcResult.chainedFixupsInfo.offset,
        lcResult.chainedFixupsInfo.size,
        lcResult.segments,
        machoFile.littleEndian,
      );
      rebaseMap = fixups.rebaseMap;
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`Chained fixups error: ${msg}`);
  }

  // Flatten all sections for convenience
  const allSections: Section64[] = lcResult.segments.flatMap((seg) => seg.sections);

  // Step 8: Extract strings
  progressCallback("Extracting strings...", basePercent + 25);
  try {
    const rawStrings = extractStrings(
      buffer,
      allSections,
      lcResult.segments,
      rebaseMap,
      machoFile.littleEndian,
    );
    strings = convertStrings(rawStrings);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`String extraction error: ${msg}`);
  }

  // Step 9: Parse symbols
  progressCallback("Parsing symbols...", basePercent + 35);
  let rawSymbols: ParserSymbol[] = [];
  try {
    rawSymbols = parseSymbolTable(
      buffer,
      lcResult.symtabInfo
        ? {
            symoff: lcResult.symtabInfo.symoff,
            nsyms: lcResult.symtabInfo.nsyms,
            stroff: lcResult.symtabInfo.stroff,
            strsize: lcResult.symtabInfo.strsize,
          }
        : null,
      machoFile.littleEndian,
    );
    symbols = convertSymbols(rawSymbols);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`Symbol table parse error: ${msg}`);
  }

  // Step 10: Extract ObjC metadata
  progressCallback("Extracting ObjC metadata...", basePercent + 40);
  try {
    const objcMeta = extractObjCMetadata(
      buffer,
      allSections,
      lcResult.segments,
      rebaseMap,
      machoFile.littleEndian,
    );
    classes = objcMeta.classes;
    protocols = objcMeta.protocols;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`ObjC metadata error: ${msg}`);
  }

  // Step 11: Parse code signature + entitlements
  progressCallback("Parsing code signature...", basePercent + 50);
  try {
    if (lcResult.codeSignatureInfo) {
      const csResult = parseCodeSignature(
        buffer,
        lcResult.codeSignatureInfo.offset,
        lcResult.codeSignatureInfo.size,
      );
      if (csResult?.entitlements) {
        entitlements = convertEntitlements(csResult.entitlements);
      }
      if (csResult?.codeDirectory?.teamID) {
        teamId = csResult.codeDirectory.teamID;
      }
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`Code signature parse error: ${msg}`);
  }

  // Step 12: Run security scan
  progressCallback("Running security scan...", basePercent + 55);
  try {
    // Convert strings back to the format security.ts expects
    const securityStrings = strings.map((s) => ({
      value: s.value,
      sectionSource: s.sectionSource,
      offset: s.offset,
    }));

    // Convert symbols to the format expected by security (with bigint address)
    const securitySymbols = rawSymbols.map((s) => ({
      name: s.name,
      type: s.type as "exported" | "imported" | "local",
      address: s.address,
      sectionIndex: s.sectionIndex,
    }));

    findings = runSecurityScan({
      strings: securityStrings,
      symbols: securitySymbols,
      headerFlags: header.flags,
      encryption: encryptionInfo,
      loadCommands: lcResult.loadCommands.map((lc) => ({ cmd: lc.cmd })),
    });

    hardening = getBinaryHardening({
      symbols: securitySymbols,
      headerFlags: header.flags,
      encryption: encryptionInfo,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`Security scan error: ${msg}`);
  }

  return {
    header,
    fatArchs,
    loadCommands: sharedLoadCommands,
    libraries,
    buildVersion,
    encryptionInfo,
    strings,
    symbols,
    classes,
    entitlements,
    security: { findings, hardening },
    errors,
  };
}

// ── Main orchestrator ───────────────────────────────────────────────

export async function analyzeIPA(
  ipaPath: string,
  progressCallback: (phase: string, percent: number) => void,
): Promise<AnalysisResult> {
  const errors: string[] = [];

  // Step 1: Extract IPA
  progressCallback("Extracting IPA...", 0);
  const tempDir = path.join(os.tmpdir(), `disect-${Date.now()}`);
  const extraction = extractIPA(ipaPath, tempDir);

  if (!extraction.success) {
    throw new Error((extraction as { success: false; error: string }).error);
  }

  cachedExtractedDir = tempDir;

  // Step 2: Discover app bundle and binaries
  progressCallback("Discovering binaries...", 15);
  const appBundlePath = discoverAppBundle(tempDir);
  if (!appBundlePath) {
    throw new Error("No .app bundle found in IPA Payload directory");
  }
  cachedAppBundlePath = appBundlePath;

  const binaries = discoverBinaries(appBundlePath);
  cachedBinaries = binaries;

  if (binaries.length === 0) {
    throw new Error("No binaries found in app bundle");
  }

  // Step 3: Parse Info.plist + mobileprovision
  progressCallback("Parsing plists...", 20);
  let infoPlistData: Record<string, PlistValue> = {};
  try {
    const plistResult = parseInfoPlist(appBundlePath);
    if (plistResult && plistResult.ok) {
      infoPlistData = plistResult.data.raw as Record<string, PlistValue>;
    } else if (plistResult && !plistResult.ok) {
      errors.push(`Info.plist: ${plistResult.error}`);
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`Info.plist error: ${msg}`);
  }
  cachedInfoPlist = infoPlistData;

  // Mobileprovision entitlements (supplementary)
  try {
    const mpResult = parseMobileprovision(appBundlePath);
    if (mpResult && mpResult.ok && mpResult.data.Entitlements) {
      // These will be merged if code-signature entitlements are empty
    }
  } catch {
    // Non-critical
  }

  // Steps 4-12: Analyze main binary (index 0)
  progressCallback("Reading binary...", 25);
  const mainBinary = binaries[0]!;
  const binaryResult = await analyzeBinaryFile(mainBinary.path, progressCallback, 25);

  // If code-signature entitlements were empty, try mobileprovision
  let finalEntitlements = binaryResult.entitlements;
  if (finalEntitlements.length === 0) {
    try {
      const mpResult = parseMobileprovision(appBundlePath);
      if (mpResult && mpResult.ok && mpResult.data.Entitlements) {
        finalEntitlements = convertEntitlements(mpResult.data.Entitlements);
      }
    } catch {
      // Non-critical
    }
  }

  // Step 13: Build file tree (start from the .app bundle directly)
  progressCallback("Building file tree...", 95);
  const files = buildFileTree(appBundlePath);

  // Assemble final result
  const appName = path.basename(appBundlePath, ".app");
  const result: AnalysisResult = {
    overview: {
      ipa: {
        bundlePath: appBundlePath,
        appName,
        binaries: binaries.map((b) => ({
          name: b.name,
          path: b.path,
          type: b.type,
          size: (() => {
            try { return fs.statSync(b.path).size; } catch { return 0; }
          })(),
        })),
      },
      header: binaryResult.header,
      fatArchs: binaryResult.fatArchs,
      buildVersion: binaryResult.buildVersion,
      encryptionInfo: binaryResult.encryptionInfo,
      hardening: binaryResult.security.hardening,
      uuid: binaryResult.uuid ?? undefined,
      teamId: binaryResult.teamId ?? undefined,
      infoPlist: infoPlistData,
    },
    strings: binaryResult.strings,
    headers: {
      machO: binaryResult.header,
      fatArchs: binaryResult.fatArchs,
      loadCommands: binaryResult.loadCommands,
    },
    libraries: binaryResult.libraries,
    symbols: binaryResult.symbols,
    classes: binaryResult.classes,
    protocols: binaryResult.protocols,
    entitlements: finalEntitlements,
    infoPlist: infoPlistData,
    security: binaryResult.security,
    files,
  };

  cachedResult = result;
  progressCallback("Analysis complete", 100);
  return result;
}

// ── Re-analyze a different binary ───────────────────────────────────

export async function analyzeBinary(
  binaryIndex: number,
  progressCallback: (phase: string, percent: number) => void,
): Promise<AnalysisResult> {
  if (!cachedResult || !cachedAppBundlePath) {
    throw new Error("No previous analysis. Run analyzeIPA first.");
  }

  if (binaryIndex < 0 || binaryIndex >= cachedBinaries.length) {
    throw new Error(`Binary index ${binaryIndex} out of range (0-${cachedBinaries.length - 1})`);
  }

  const binary = cachedBinaries[binaryIndex]!;
  const binaryResult = await analyzeBinaryFile(binary.path, progressCallback, 0);

  // Rebuild the result with the new binary data but keep IPA-level info
  const result: AnalysisResult = {
    ...cachedResult,
    overview: {
      ...cachedResult.overview,
      header: binaryResult.header,
      fatArchs: binaryResult.fatArchs,
      buildVersion: binaryResult.buildVersion,
      encryptionInfo: binaryResult.encryptionInfo,
      hardening: binaryResult.security.hardening,
      uuid: binaryResult.uuid ?? undefined,
      teamId: binaryResult.teamId ?? cachedResult.overview.teamId,
    },
    strings: binaryResult.strings,
    headers: {
      machO: binaryResult.header,
      fatArchs: binaryResult.fatArchs,
      loadCommands: binaryResult.loadCommands,
    },
    libraries: binaryResult.libraries,
    symbols: binaryResult.symbols,
    classes: binaryResult.classes,
    protocols: binaryResult.protocols,
    entitlements: binaryResult.entitlements.length > 0
      ? binaryResult.entitlements
      : cachedResult.entitlements,
    security: binaryResult.security,
  };

  cachedResult = result;
  return result;
}

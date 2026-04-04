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
  LocalisationString,
  SecurityFinding,
  LoadCommand as SharedLoadCommand,
  PlistValue,
  Section,
  Segment,
  SourceType,
  HookInfo,
} from "../../shared/types";

import {
  extractIPA,
  discoverAppBundle,
  discoverBinaries,
  isMacOSAppBundle,
  discoverMacOSBinaries,
} from "../ipa/extractor";
import type { BinaryInfo } from "../ipa/extractor";
import { parseFatHeader, parseMachOHeader, CPU_TYPE_ARM64 } from "../parser/macho";
import type { MachOFile } from "../parser/macho";
import { parseLoadCommands } from "../parser/load-commands";
import type { LoadCommandsResult, Segment64, Section64 } from "../parser/load-commands";
import { buildFixupMap } from "../parser/chained-fixups";
import { extractStrings } from "../parser/strings";
import type { StringEntry as ParserStringEntry } from "../parser/strings";
import { parseSymbolTable } from "../parser/symbols";
import type { Symbol as ParserSymbol } from "../parser/symbols";
import { extractObjCMetadata, buildMethodSignature } from "../parser/objc";
import { parseCodeSignature } from "../parser/codesign";
import { parseInfoPlist, parseMobileprovision } from "../parser/plist";
import { runSecurityScan, getBinaryHardening, scanBundleFileContents, isScannableExtension } from "./security";
import type { BundleFileEntry } from "./security";
import { loadSettings } from "../settings";
import { parseFunctionStarts, buildStringXrefMap, formatFunctionName } from "../parser/xrefs";
import bplist from "bplist-parser";
import plist from "plist";
import { extractDEB } from "../deb/extractor";
import type { DEBBinaryInfo } from "../deb/extractor";
import {
  MH_MAGIC_64,
  MH_CIGAM_64,
  MH_MAGIC,
  MH_CIGAM,
  FAT_MAGIC,
  FAT_CIGAM,
} from "../parser/macho";

// ── Event loop yield ───────────────────────────────────────────────

/** Yield to the event loop so the UI stays responsive during heavy parsing. */
const yieldToEventLoop = (): Promise<void> =>
  new Promise((resolve) => setImmediate(resolve));

// ── Cached state ────────────────────────────────────────────────────

let cachedResult: AnalysisResult | null = null;
let cachedExtractedDir: string | null = null;
let cachedAppBundlePath: string | null = null;
let cachedBinaries: BinaryInfo[] = [];
let cachedInfoPlist: Record<string, unknown> = {};
let cachedSourceType: SourceType = "ipa";
let cachedFilePath: string = "";
let cachedActiveBinaryName: string = "";
// Per-binary lightweight index for cross-binary search
interface BinarySearchIndex {
  classes: string[];
  strings: string[];
  symbols: string[];
}
let cachedSearchIndex: Map<number, BinarySearchIndex> | null = null;

export type SearchableTab = "classes" | "strings" | "symbols";

export function getCachedResult(): AnalysisResult | null {
  return cachedResult;
}

export function getActiveBinaryName(): string {
  return cachedActiveBinaryName;
}

export function getCachedBinariesCount(): number {
  return cachedBinaries.length;
}

// ── Cross-binary search (classes, strings, symbols) ────────────────

async function ensureSearchIndex(
  progressCallback: (phase: string, percent: number) => void,
): Promise<Map<number, BinarySearchIndex>> {
  if (cachedSearchIndex) return cachedSearchIndex;

  cachedSearchIndex = new Map();
  for (let i = 0; i < cachedBinaries.length; i++) {
    const bin = cachedBinaries[i]!;
    progressCallback(
      `Indexing ${bin.name}...`,
      Math.round((i / cachedBinaries.length) * 100),
    );
    await yieldToEventLoop();
    try {
      const result = await analyseBinaryFile(bin.path, () => {}, 0);
      cachedSearchIndex.set(i, {
        classes: result.classes.map((c) => c.name),
        strings: result.strings.map((s) => s.value),
        symbols: result.symbols.map((s) => s.name),
      });
    } catch {
      cachedSearchIndex.set(i, { classes: [], strings: [], symbols: [] });
    }
  }
  return cachedSearchIndex;
}

export interface CrossBinarySearchResult {
  binaryIndex: number;
  binaryName: string;
  binaryType: string;
  match: string;
}

export async function searchAllBinaries(
  query: string,
  tab: SearchableTab,
  progressCallback: (phase: string, percent: number) => void,
): Promise<CrossBinarySearchResult[]> {
  if (cachedBinaries.length === 0 || !query) return [];

  const index = await ensureSearchIndex(progressCallback);
  const lowerQuery = query.toLowerCase();
  const results: CrossBinarySearchResult[] = [];

  for (const [binaryIndex, entry] of index) {
    const bin = cachedBinaries[binaryIndex];
    if (!bin) continue;
    for (const value of entry[tab]) {
      if (value.toLowerCase().includes(lowerQuery)) {
        results.push({
          binaryIndex,
          binaryName: bin.name,
          binaryType: bin.type,
          match: value,
        });
      }
    }
  }

  return results;
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

/** Build signature from prefix (-/+), selector, and raw type encoding using the full ObjC type parser. */
function buildMethodSignatureFromParts(prefix: string, selector: string, typeEncoding: string): string {
  if (!typeEncoding) return `${prefix}${selector}`;
  return buildMethodSignature(selector, typeEncoding, prefix === "-");
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

// ── Hook detection ─────────────────────────────────────────────────

/** Known hook framework symbols → framework name */
const HOOK_SYMBOLS: Record<string, string> = {
  "_MSHookMessageEx": "Substrate",
  "_MSHookFunction": "Substrate",
  "_MSHookClassPair": "Substrate",
  "_MSGetImageByName": "Substrate",
  "_MSFindSymbol": "Substrate",
  "_LHHookMessageEx": "Libhooker",
  "_LHHookFunction": "Libhooker",
  "_LHOpenImage": "Libhooker",
  "_LBHookMessage": "Libhooker",
  "_rebind_symbols": "fishhook",
  "_rebind_symbols_image": "fishhook",
  "_substitute_hook_functions": "Substitute",
  "_SubHookMessageEx": "Substitute",
  // ObjC runtime swizzling APIs (used by compiled Logos/Theos tweaks)
  "_class_replaceMethod": "ObjC Runtime",
  "_method_setImplementation": "ObjC Runtime",
  "_method_exchangeImplementations": "ObjC Runtime",
};

/** System class prefixes (unlikely to be defined by a tweak) */
const SYSTEM_CLASS_PREFIXES = [
  "UI", "NS", "CA", "CK", "AV", "MF", "WK", "SK", "SB", "SF",
  "MP", "PH", "CL", "MK", "SC", "GK", "HK", "CN", "EK", "AS",
  "CT", "NW", "ST", "TI", "AB", "MB", "LS", "BS", "FBS", "RBS",
  "CSP", "SSB", "SFL", "SPT", "NCN", "BLT", "WiFi", "CarPlay",
  "Spring", "Web", "WAK", "DOM",
];

function detectHooks(
  symbols: SymbolEntry[],
  classes: ObjCClass[],
  strings: StringEntry[],
): HookInfo {
  const frameworks = new Set<string>();
  const hookSymbols: string[] = [];
  const hookedClasses = new Set<string>();

  // 1. Check imported symbols for hook framework functions
  for (const sym of symbols) {
    if (sym.type !== "imported") continue;
    const framework = HOOK_SYMBOLS[sym.name];
    if (framework) {
      frameworks.add(framework);
      hookSymbols.push(sym.name);
    }
  }

  // 2. Find system classes referenced by the binary.
  //    Only when a hook framework is present — regular apps also reference
  //    system classes via objc_getClass for normal usage.
  if (frameworks.size > 0) {
    const tweakClassNames = new Set(classes.map((c) => c.name));

    for (const str of strings) {
      const val = str.value;
      if (val.length < 3 || val.length > 80 || !/^[A-Z]/.test(val)) continue;
      if (/[\s@#$%^&*(){}[\]|\\<>,]/.test(val)) continue;
      if (tweakClassNames.has(val)) continue;

      for (const prefix of SYSTEM_CLASS_PREFIXES) {
        if (val.startsWith(prefix) && val.length > prefix.length && /^[A-Z]/.test(val[prefix.length]!)) {
          hookedClasses.add(val);
          break;
        }
      }
    }
  }

  return {
    frameworks: [...frameworks],
    targetBundles: [],
    hookedClasses: [...hookedClasses].sort(),
    hookSymbols,
  };
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
  hooks: HookInfo;
  errors: string[];
}

async function analyseBinaryFile(
  binaryPath: string,
  progressCallback: (phase: string, percent: number) => void,
  basePercent: number,
  preferredCpuType?: number,
  preferredCpuSubtype?: number,
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
  let hooks: HookInfo = { frameworks: [], targetBundles: [], hookedClasses: [], hookSymbols: [] };
  let hardening: BinaryHardening = {
    pie: false, arc: false, stackCanaries: false, encrypted: false, stripped: true,
  };

  // Step 4: Read binary
  progressCallback("Reading binary...", basePercent);
  await yieldToEventLoop();
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
      uuid, teamId, security: { findings, hardening }, hooks, errors,
    };
  }

  // Step 5: Parse fat header / select arm64 slice / parse Mach-O header
  progressCallback("Parsing Mach-O header...", basePercent + 5);
  await yieldToEventLoop();
  let machoFile: MachOFile | null = null;

  try {
    const fatResult = parseFatHeader(buffer);
    if (fatResult.ok) {
      fatArchs = fatResult.data;

      // Select preferred arch, or default to arm64, or first available
      const preferredArch = preferredCpuType != null
        ? fatArchs.find((a) =>
            a.cputype === preferredCpuType &&
            (preferredCpuSubtype == null || a.cpusubtype === preferredCpuSubtype)
          )
        : undefined;
      const arm64Arch = fatArchs.find((a) => a.cputype === CPU_TYPE_ARM64);
      const selectedArch = preferredArch ?? arm64Arch ?? fatArchs[0];

      if (selectedArch) {
        // Slice the buffer to the selected architecture so all internal
        // offsets (symoff, stroff, section offsets, etc.) are correct.
        // For thin binaries (offset=0, size=full), this is a no-op.
        if (selectedArch.offset > 0) {
          buffer = buffer.slice(selectedArch.offset, selectedArch.offset + selectedArch.size);
        }

        const headerResult = parseMachOHeader(buffer, 0);
        if (headerResult.ok) {
          machoFile = headerResult.data;
          header = machoFile.header;
        } else {
          errors.push(`Mach-O header parse: ${headerResult.error}`);
        }
      }
    } else {
      // Not a fat binary — try parsing as a thin Mach-O directly
      const headerResult = parseMachOHeader(buffer, 0);
      if (headerResult.ok) {
        machoFile = headerResult.data;
        header = machoFile.header;
      } else {
        errors.push(`Mach-O header parse: ${headerResult.error}`);
      }
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`Header parse error: ${msg}`);
  }

  if (!machoFile) {
    return {
      header, fatArchs, loadCommands: sharedLoadCommands, libraries,
      buildVersion, encryptionInfo, strings, symbols, classes, protocols, entitlements,
      uuid, teamId, security: { findings, hardening }, hooks, errors,
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
      uuid, teamId, security: { findings, hardening }, hooks, errors,
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
  await yieldToEventLoop();
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
  await yieldToEventLoop();
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
  await yieldToEventLoop();
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

  // Step 10b: Enrich classes with methods from symbol table when method
  // selector names couldn't be resolved (common with dyld_shared_cache
  // extracted binaries where relative method offsets point outside the file).
  // The method list may have type encodings but empty selectors — we merge
  // symbol table names with those type encodings by index.
  {
    const classesNeedingEnrichment = classes.filter(
      (c) => c.methods.length > 0 && c.methods.some((m) => m.selector === "")
    );
    const classesWithNoMethods = classes.filter((c) => c.methods.length === 0);

    if ((classesNeedingEnrichment.length > 0 || classesWithNoMethods.length > 0) && rawSymbols.length > 0) {
      // Build map: className → ordered methods from ObjC symbols like -[Class method:]
      const symMethodMap = new Map<string, { selector: string; prefix: string }[]>();
      for (const sym of rawSymbols) {
        const m = sym.name.match(/^([+-])\[(\S+)\s+(.+)\]$/);
        if (!m) continue;
        const className = m[2]!;
        if (!symMethodMap.has(className)) symMethodMap.set(className, []);
        symMethodMap.get(className)!.push({
          selector: m[3]!,
          prefix: m[1]!,
        });
      }

      // Merge: fill in selector names from symbols, keep type encodings from method list.
      // Method list and symbol table may be in different orders, so match by
      // argument count (colons in selector == arg types in encoding).
      for (const cls of classesNeedingEnrichment) {
        const symMethods = symMethodMap.get(cls.name);
        if (!symMethods) continue;

        const symInstanceMethods = symMethods.filter((m) => m.prefix === "-");
        const symClassMethods = symMethods.filter((m) => m.prefix === "+");

        // Group unnamed method entries by arg count (from type encoding)
        // Type encoding args = total decoded types - 3 (return, self, _cmd)
        const skipNested = (enc: string, pos: number, open: string, close: string): number => {
          let depth = 1;
          let i = pos + 1;
          while (i < enc.length && depth > 0) {
            if (enc[i] === open) depth++;
            else if (enc[i] === close) depth--;
            i++;
          }
          return i;
        };
        const countArgsFromEncoding = (enc: string): number => {
          let count = 0;
          let pos = 0;
          while (pos < enc.length) {
            const ch = enc[pos]!;
            // Skip offset digits
            if ((ch >= "0" && ch <= "9") || ch === "-") { pos++; continue; }
            // Skip qualifiers
            if ("rnNoORV".includes(ch)) { pos++; continue; }
            // Count a type
            if (ch === "{") { pos = skipNested(enc, pos, "{", "}"); }
            else if (ch === "(") { pos = skipNested(enc, pos, "(", ")"); }
            else if (ch === "[") { pos = skipNested(enc, pos, "[", "]"); }
            else if (ch === "@" && pos + 1 < enc.length && enc[pos + 1] === "?") { pos += 2; }
            else if (ch === "@" && pos + 1 < enc.length && enc[pos + 1] === '"') {
              const c = enc.indexOf('"', pos + 2); pos = c !== -1 ? c + 1 : pos + 1;
            }
            else if (ch === "^") { pos++; continue; } // pointer prefix, next char is the type
            else { pos++; }
            count++;
          }
          return Math.max(0, count - 3); // subtract return, self, _cmd
        };

        // Match unnamed method entries against symbols by arg count.
        // Process instance and class methods separately using the _isClassMethod flag.
        const matchMethodGroup = (
          symGroup: typeof symInstanceMethods,
          isClassMethod: boolean,
        ) => {
          const byArgCount = new Map<number, { method: typeof cls.methods[0]; enc: string }[]>();
          for (const method of cls.methods) {
            if (method.selector !== "") continue;
            if (isClassMethod !== !!method._isClassMethod) continue;
            const enc = method.signature; // raw type encoding stored when name was empty
            const argc = countArgsFromEncoding(enc);
            if (!byArgCount.has(argc)) byArgCount.set(argc, []);
            byArgCount.get(argc)!.push({ method, enc });
          }

          const usedSymbols = new Set<number>();
          for (const [argc, entries] of byArgCount) {
            const matchingSyms = symGroup
              .map((s, i) => ({ s, i }))
              .filter(({ s, i }) => !usedSymbols.has(i) && (s.selector.match(/:/g) || []).length === argc);

            const limit = Math.min(entries.length, matchingSyms.length);
            for (let j = 0; j < limit; j++) {
              const { method, enc } = entries[j]!;
              const { s, i } = matchingSyms[j]!;
              method.selector = s.selector;
              method.signature = buildMethodSignatureFromParts(s.prefix, s.selector, enc);
              usedSymbols.add(i);
            }
          }

          // Assign any remaining unmatched symbols to remaining unnamed methods in this group
          const remainingSyms = symGroup.filter((_, i) => !usedSymbols.has(i));
          const remainingMethods = cls.methods.filter(
            (m) => m.selector === "" && isClassMethod === !!m._isClassMethod,
          );
          for (let j = 0; j < Math.min(remainingMethods.length, remainingSyms.length); j++) {
            remainingMethods[j]!.selector = remainingSyms[j]!.selector;
            remainingMethods[j]!.signature = `${remainingSyms[j]!.prefix}${remainingSyms[j]!.selector}`;
          }

          return usedSymbols;
        };

        matchMethodGroup(symInstanceMethods, false);
        matchMethodGroup(symClassMethods, true);

        // Add class methods (+) not already matched to a metaclass entry
        for (const cm of symClassMethods) {
          if (!cls.methods.some((m) => m.selector === cm.selector)) {
            cls.methods.push({ selector: cm.selector, signature: `+${cm.selector}` });
          }
        }

        // Remove any remaining unnamed methods
        cls.methods = cls.methods.filter((m) => m.selector !== "");
      }

      // Classes with no methods at all — populate entirely from symbols
      for (const cls of classesWithNoMethods) {
        const symMethods = symMethodMap.get(cls.name);
        if (symMethods) {
          cls.methods = symMethods.map((m) => ({
            selector: m.selector,
            signature: `${m.prefix}${m.selector}`,
          }));
        }
      }
    }
  }

  // Step 11: Parse code signature + entitlements
  progressCallback("Parsing code signature...", basePercent + 50);
  await yieldToEventLoop();
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

  // Step 12: Run security scan (first pass — without xrefs)
  progressCallback("Running security scan...", basePercent + 52);
  await yieldToEventLoop();
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

  // Step 12b: Enrich findings with function names (only if there are
  // string-based findings that benefit from attribution)
  const stringFindings = findings.filter((f) =>
    f.category === "credential-leak" || f.category === "jailbreak-detection"
  );
  if (stringFindings.length > 0) {
    progressCallback("Resolving function references...", basePercent + 57);
    await yieldToEventLoop();
    try {
      const textSeg = lcResult.segments.find((s) => s.segname.trim() === "__TEXT");
      if (textSeg) {
        let funcStarts: bigint[] = [];
        if (lcResult.functionStartsInfo) {
          funcStarts = parseFunctionStarts(
            buffer,
            lcResult.functionStartsInfo.offset,
            lcResult.functionStartsInfo.size,
            textSeg.vmaddr,
          );
        }
        const stringXrefs = buildStringXrefMap(
          buffer,
          lcResult.segments,
          funcStarts,
          rawSymbols,
          machoFile.littleEndian,
          rebaseMap,
        );

        // Annotate findings with function names
        for (const finding of stringFindings) {
          if (finding.location) {
            const match = finding.location.match(/offset=0x([0-9a-f]+)/);
            if (match) {
              const offset = parseInt(match[1]!, 16);
              const names = stringXrefs.get(offset);
              if (names && names.length > 0) {
                finding.functionName = formatFunctionName(names[0]!);
              }
            }
          }
        }
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      errors.push(`Cross-reference analysis error: ${msg}`);
    }
  }

  // Step 13: Detect hooks
  hooks = detectHooks(symbols, classes, strings);

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
    protocols,
    entitlements,
    uuid,
    teamId,
    security: { findings, hardening },
    hooks,
    errors,
  };
}

// ── App framework detection ────────────────────────────────────────

function detectAppFrameworks(appBundlePath: string, linkedLibs: string[] = []): string[] {
  const frameworksDir = path.join(appBundlePath, "Frameworks");
  const detected: string[] = [];

  const hasFramework = (name: string): boolean => {
    try {
      return fs.existsSync(path.join(frameworksDir, name));
    } catch {
      return false;
    }
  };

  const hasFile = (relPath: string): boolean => {
    try {
      return fs.existsSync(path.join(appBundlePath, relPath));
    } catch {
      return false;
    }
  };

  const hasAnyFramework = (...names: string[]): boolean =>
    names.some(hasFramework);

  /** Check if the binary links against a system framework by name */
  const linksFramework = (name: string): boolean =>
    linkedLibs.some((lib) => lib.includes(`/${name}.framework/`));

  // ── Cross-platform frameworks ──

  // React Native
  if (
    hasFile("main.jsbundle") ||
    hasAnyFramework("hermes.framework", "React.framework", "ReactNative.framework")
  ) {
    detected.push("React Native");
  }

  // Expo (built on React Native)
  if (hasAnyFramework("ExpoModulesCore.framework", "Expo.framework")) {
    detected.push("Expo");
  }

  // Flutter (iOS uses Flutter.framework, macOS uses FlutterMacOS.framework)
  if (hasAnyFramework("Flutter.framework", "FlutterMacOS.framework")) {
    detected.push("Flutter");
  }

  // Cordova
  if (hasFile("www/index.html") && !hasFramework("Capacitor.framework")) {
    detected.push("Cordova");
  }

  // Capacitor
  if (hasFramework("Capacitor.framework") || hasFramework("CapacitorBridge.framework")) {
    detected.push("Capacitor");
  }

  // .NET MAUI / Xamarin
  if (hasAnyFramework("Xamarin.iOS.framework", "Mono.framework")) {
    detected.push("Xamarin/.NET MAUI");
  }

  // Kotlin Multiplatform
  if (hasAnyFramework("shared.framework") && hasFramework("KotlinRuntime.framework")) {
    detected.push("Kotlin Multiplatform");
  }

  // NativeScript
  if (hasAnyFramework("NativeScript.framework", "TNSRuntime.framework")) {
    detected.push("NativeScript");
  }

  // Titanium / Appcelerator
  if (hasAnyFramework("TitaniumKit.framework", "Titanium.framework")) {
    detected.push("Titanium");
  }

  // Qt
  if (hasAnyFramework("QtCore.framework", "Qt.framework")) {
    detected.push("Qt");
  }

  // Electron (very rare on iOS, but included for completeness)
  if (hasFramework("Electron Framework.framework")) {
    detected.push("Electron");
  }

  // ── Game engines ──

  // Unity
  if (hasFramework("UnityFramework.framework")) {
    detected.push("Unity");
  }

  // Unreal Engine
  if (hasAnyFramework("UE4.framework", "UnrealEngine.framework") || hasFile("UE4CommandLine.txt") || hasFile("uecommandline.txt")) {
    detected.push("Unreal Engine");
  }

  // Godot
  if (hasFile("godot_ios.pck")) {
    detected.push("Godot");
  }

  // Cocos2d
  if (hasAnyFramework("cocos2d.framework", "cocos2d_libs.framework")) {
    detected.push("Cocos2d");
  }

  // GameMaker
  if (hasFile("game.ios") || hasFile("data.win")) {
    detected.push("GameMaker");
  }

  // Corona / Solar2D
  if (hasAnyFramework("CoronaKit.framework", "Corona.framework")) {
    detected.push("Solar2D");
  }

  // ── Linked system frameworks (not bundled, detected via load commands) ──

  const systemFrameworks: string[] = [
    // UI layer
    "SwiftUI", "UIKit", "AppKit",
    // Graphics & games
    "RealityKit", "ARKit", "SceneKit", "SpriteKit", "Metal", "GameKit"
  ];

  for (const framework of systemFrameworks) {
    if (linksFramework(framework)) {
      detected.push(framework);
    }
  }

  return detected;
}

// ── Bundle file reading for security scanning ─────────────────────

function getBundleSizeLimits(): { maxTotal: number; maxSingle: number } {
  const settings = loadSettings();
  return {
    maxTotal: settings.maxBundleSizeMB * 1024 * 1024,
    maxSingle: settings.maxFileSizeMB * 1024 * 1024,
  };
}

/**
 * Try to parse a binary plist or compiled .strings file into a JSON text
 * representation so it can be scanned for secrets. Returns null if the
 * file isn't a binary plist or can't be parsed.
 */
function tryParseBinaryPlist(buf: Buffer): string | null {
  // Check for bplist magic
  if (buf.length < 6 || buf.toString("ascii", 0, 6) !== "bplist") {
    return null;
  }
  try {
    const parsed = bplist.parseBuffer(buf);
    if (parsed && parsed.length > 0) {
      return JSON.stringify(parsed[0], null, 2);
    }
  } catch {
    // Fall through
  }
  return null;
}

/**
 * Check if a file appears to be binary (has null bytes in the first 512 bytes).
 * Binary plists are handled separately via tryParseBinaryPlist.
 */
function hasBinaryContent(buf: Buffer): boolean {
  const checkLen = Math.min(buf.length, 512);
  for (let i = 0; i < checkLen; i++) {
    if (buf[i] === 0) return true;
  }
  return false;
}

function readBundleFiles(appBundlePath: string): BundleFileEntry[] {
  const files: BundleFileEntry[] = [];
  let totalSize = 0;
  const { maxTotal, maxSingle } = getBundleSizeLimits();

  function walk(dir: string): void {
    if (totalSize >= maxTotal) return;

    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (totalSize >= maxTotal) break;
      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        // Skip known binary-only directories
        if (entry.name === "Frameworks" || entry.name === "PlugIns" || entry.name === "_CodeSignature") {
          continue;
        }
        walk(fullPath);
        continue;
      }

      if (!entry.isFile()) continue;

      const ext = path.extname(entry.name);
      if (!isScannableExtension(ext)) continue;

      try {
        const stat = fs.statSync(fullPath);
        if (stat.size === 0 || stat.size > maxSingle) continue;

        const rawBuf = fs.readFileSync(fullPath);
        let content: string;

        // Try parsing binary plists (.plist, .strings can be binary plist format)
        const plistText = tryParseBinaryPlist(rawBuf);
        if (plistText !== null) {
          content = plistText;
        } else if (hasBinaryContent(rawBuf)) {
          // Skip other binary files (compiled nibs embedded with wrong extension, etc.)
          continue;
        } else {
          content = rawBuf.toString("utf-8");
        }

        const relativePath = path.relative(appBundlePath, fullPath).replace(/\\/g, "/");
        files.push({ relativePath, content });
        totalSize += stat.size;
      } catch {
        // Skip unreadable files
      }
    }
  }

  walk(appBundlePath);
  return files;
}

// ── Localisation string extraction ──────────────────────────────────

/**
 * Parse a .strings file content (Apple old-style plist or XML plist format)
 * into key-value pairs. Handles both text and binary plist .strings files.
 */
function parseStringsFile(buf: Buffer): Record<string, string> {
  const result: Record<string, string> = {};

  // Try binary plist first
  if (buf.length >= 6 && buf.toString("ascii", 0, 6) === "bplist") {
    try {
      const parsed = bplist.parseBuffer(buf);
      if (parsed && parsed.length > 0 && typeof parsed[0] === "object") {
        for (const [k, v] of Object.entries(parsed[0] as Record<string, unknown>)) {
          if (typeof v === "string") result[k] = v;
        }
      }
      return result;
    } catch {
      return result;
    }
  }

  // Try XML plist
  const text = buf.toString("utf-8");
  if (text.trimStart().startsWith("<?xml") || text.trimStart().startsWith("<!DOCTYPE")) {
    try {
      const parsed = plist.parse(text) as Record<string, unknown>;
      if (typeof parsed === "object" && parsed !== null) {
        for (const [k, v] of Object.entries(parsed)) {
          if (typeof v === "string") result[k] = v;
        }
      }
      return result;
    } catch {
      // Fall through to old-style format
    }
  }

  // Old-style .strings format: "key" = "value";
  const regex = /"((?:[^"\\]|\\.)*)"\s*=\s*"((?:[^"\\]|\\.)*)"\s*;/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(text)) !== null) {
    const key = match[1]!.replace(/\\"/g, '"').replace(/\\n/g, "\n").replace(/\\\\/g, "\\");
    const value = match[2]!.replace(/\\"/g, '"').replace(/\\n/g, "\n").replace(/\\\\/g, "\\");
    result[key] = value;
  }

  return result;
}

/**
 * Walk the app bundle for .lproj directories and extract localisation strings
 * from all .strings files within them.
 */
function extractLocalisationStrings(rootPath: string): LocalisationString[] {
  const results: LocalisationString[] = [];
  const { maxTotal, maxSingle } = getBundleSizeLimits();
  let totalSize = 0;

  function readStringsFile(fullPath: string, language: string): void {
    try {
      const stat = fs.statSync(fullPath);
      if (stat.size === 0 || stat.size > maxSingle) return;

      const buf = fs.readFileSync(fullPath);
      totalSize += stat.size;

      const pairs = parseStringsFile(buf);
      const relativePath = path.relative(rootPath, fullPath).replace(/\\/g, "/");

      for (const [key, value] of Object.entries(pairs)) {
        results.push({ key, value, file: relativePath, language });
      }
    } catch {
      // Skip unreadable files
    }
  }

  function walk(dir: string): void {
    if (totalSize >= maxTotal) return;

    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (totalSize >= maxTotal) break;
      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        // Skip heavy binary-only dirs
        if (entry.name === "_CodeSignature") continue;

        if (entry.name.endsWith(".lproj")) {
          // Process all .strings files in this lproj
          const language = entry.name.replace(/\.lproj$/, "");
          let files: fs.Dirent[];
          try {
            files = fs.readdirSync(fullPath, { withFileTypes: true });
          } catch {
            continue;
          }
          for (const file of files) {
            if (file.isFile() && file.name.endsWith(".strings")) {
              readStringsFile(path.join(fullPath, file.name), language);
            }
          }
        } else {
          walk(fullPath);
        }
        continue;
      }

      // Standalone .strings files outside .lproj (no language)
      if (entry.isFile() && entry.name.endsWith(".strings")) {
        readStringsFile(fullPath, "");
      }
    }
  }

  walk(rootPath);
  return results;
}

// ── Main orchestrator ───────────────────────────────────────────────

export async function analyseIPA(
  ipaPath: string,
  progressCallback: (phase: string, percent: number) => void,
): Promise<AnalysisResult> {
  const errors: string[] = [];

  // Step 1: Extract IPA
  progressCallback("Extracting IPA...", 0);
  const tempDir = path.join(os.tmpdir(), `appinspect-${Date.now()}`);
  const extraction = await extractIPA(ipaPath, tempDir);

  if (!extraction.success) {
    throw new Error((extraction as { success: false; error: string }).error);
  }

  cachedExtractedDir = tempDir;
  cachedSourceType = "ipa";
  cachedFilePath = ipaPath;

  // Step 2: Discover app bundle and binaries
  progressCallback("Discovering binaries...", 15);
  await yieldToEventLoop();
  const appBundlePath = discoverAppBundle(tempDir);
  if (!appBundlePath) {
    throw new Error("No .app bundle found in IPA Payload directory");
  }
  cachedAppBundlePath = appBundlePath;

  const binaries = discoverBinaries(appBundlePath);
  cachedBinaries = binaries;
  cachedSearchIndex = null;

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

  // Steps 4-12: Analyse main binary (index 0)
  progressCallback("Reading binary...", 25);
  const mainBinary = binaries[0]!;
  cachedActiveBinaryName = mainBinary.name;
  const binaryResult = await analyseBinaryFile(mainBinary.path, progressCallback, 25);

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

  // Step 13: Detect app frameworks
  const libNames = binaryResult.libraries.map((l) => l.name);
  const appFrameworks = detectAppFrameworks(appBundlePath, libNames);

  // Step 14: Scan bundle files for secrets (JS bundles, configs, etc.)
  progressCallback("Scanning bundle files...", 80);
  await yieldToEventLoop();
  let bundleFindings: SecurityFinding[] = [];
  try {
    const bundleFiles = readBundleFiles(appBundlePath);
    if (bundleFiles.length > 0) {
      bundleFindings = scanBundleFileContents(bundleFiles);
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`Bundle file scan error: ${msg}`);
  }

  // Step 14b: Extract localisation strings from .lproj directories
  let localisationStrings: LocalisationString[] = [];
  try {
    localisationStrings = extractLocalisationStrings(appBundlePath);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`Localisation extraction error: ${msg}`);
  }

  // Step 15: Scan additional binaries if setting enabled
  let extraBinaryFindings: SecurityFinding[] = [];
  const settings = loadSettings();
  if (settings.scanAllBinaries && binaries.length > 1) {
    progressCallback("Scanning additional binaries...", 85);
    await yieldToEventLoop();
    for (let i = 1; i < binaries.length; i++) {
      try {
        const extraResult = await analyseBinaryFile(
          binaries[i]!.path,
          () => {}, // silent progress
          0,
        );
        // Tag findings with source binary name
        for (const finding of extraResult.security.findings) {
          extraBinaryFindings.push({
            ...finding,
            source: binaries[i]!.name,
          });
        }
      } catch {
        // Non-critical: skip binaries that fail
      }
    }
  }

  // Merge all security findings
  const mergedSecurity = {
    findings: [
      ...binaryResult.security.findings,
      ...bundleFindings,
      ...extraBinaryFindings,
    ],
    hardening: binaryResult.security.hardening,
  };

  // Step 16: Build file tree (start from the .app bundle directly)
  progressCallback("Building file tree...", 95);
  await yieldToEventLoop();
  const files = buildFileTree(appBundlePath);

  // Assemble final result
  const appName = path.basename(appBundlePath, ".app");
  const result: AnalysisResult = {
    overview: {
      sourceType: "ipa",
      filePath: ipaPath,
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
      appFrameworks: appFrameworks.length > 0 ? appFrameworks : undefined,
    },
    strings: binaryResult.strings,
    localisationStrings,
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
    security: mergedSecurity,
    hooks: binaryResult.hooks,
    files,
  };

  cachedResult = result;
  progressCallback("Analysis complete", 100);
  return result;
}

// ── Re-analyse a different binary ───────────────────────────────────

export async function analyseBinary(
  binaryIndex: number,
  progressCallback: (phase: string, percent: number) => void,
  cpuType?: number,
  cpuSubtype?: number,
): Promise<AnalysisResult> {
  if (!cachedResult) {
    throw new Error("No previous analysis. Run analyseFile first.");
  }

  if (binaryIndex < 0 || binaryIndex >= cachedBinaries.length) {
    throw new Error(`Binary index ${binaryIndex} out of range (0-${cachedBinaries.length - 1})`);
  }

  const binary = cachedBinaries[binaryIndex]!;
  cachedActiveBinaryName = binary.name;
  const binaryResult = await analyseBinaryFile(binary.path, progressCallback, 0, cpuType, cpuSubtype);

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
    // localisationStrings kept from cachedResult via spread
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
    hooks: binaryResult.hooks,
  };

  cachedResult = result;
  return result;
}

// ── File type detection ────────────────────────────────────────────

const MACHO_MAGICS = new Set([
  MH_MAGIC_64,  // 0xfeedfacf
  MH_CIGAM_64,  // 0xcffaedfe
  MH_MAGIC,     // 0xfeedface
  MH_CIGAM,     // 0xcefaedfe
  FAT_MAGIC,    // 0xcafebabe
  FAT_CIGAM,    // 0xbebafeca
]);

export function detectFileType(filePath: string): SourceType {
  // Handle directories: .app bundles are valid, anything else is not
  if (fs.statSync(filePath).isDirectory()) {
    if (filePath.endsWith(".app")) return "ipa";
    throw new Error("The selected folder is not a valid .app bundle or supported file.");
  }

  const fd = fs.openSync(filePath, "r");
  const buf = Buffer.alloc(8);
  fs.readSync(fd, buf, 0, 8, 0);
  fs.closeSync(fd);

  // DEB: ar archive magic "!<arch>\n"
  if (buf.toString("ascii", 0, 8) === "!<arch>\n") {
    return "deb";
  }

  // Mach-O: check 4-byte magic
  const magic = buf.readUInt32BE(0);
  const magicLE = buf.readUInt32LE(0);
  if (MACHO_MAGICS.has(magic) || MACHO_MAGICS.has(magicLE)) {
    return "macho";
  }

  // IPA: ZIP file (PK\x03\x04) or assume IPA by extension
  if (buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04) {
    return "ipa";
  }

  // Fallback: check extension
  const ext = path.extname(filePath).toLowerCase();
  if (ext === ".ipa") return "ipa";
  if (ext === ".deb") return "deb";
  if (ext === ".dylib" || ext === ".a") return "macho";

  // Default to macho for extensionless files (common for executables)
  return "macho";
}

// ── Analyse bare Mach-O / dylib ────────────────────────────────────

export async function analyseMachO(
  filePath: string,
  progressCallback: (phase: string, percent: number) => void,
): Promise<AnalysisResult> {
  cachedSourceType = "macho";
  cachedFilePath = filePath;
  cachedAppBundlePath = null;
  cachedInfoPlist = {};

  const fileName = path.basename(filePath);
  let fileSize = 0;
  try {
    fileSize = fs.statSync(filePath).size;
  } catch { /* ignore */ }

  // Set up single-binary list for binary switching
  cachedBinaries = [{
    name: fileName,
    path: filePath,
    type: "main",
  }];
  cachedSearchIndex = null;
  cachedActiveBinaryName = fileName;

  progressCallback("Analysing binary...", 10);
  const binaryResult = await analyseBinaryFile(filePath, progressCallback, 10);

  const result: AnalysisResult = {
    overview: {
      sourceType: "macho",
      filePath,
      ipa: {
        bundlePath: path.dirname(filePath),
        appName: fileName,
        binaries: [{
          name: fileName,
          path: filePath,
          type: "main",
          size: fileSize,
        }],
      },
      header: binaryResult.header,
      fatArchs: binaryResult.fatArchs,
      buildVersion: binaryResult.buildVersion,
      encryptionInfo: binaryResult.encryptionInfo,
      hardening: binaryResult.security.hardening,
      uuid: binaryResult.uuid ?? undefined,
      teamId: binaryResult.teamId ?? undefined,
    },
    strings: binaryResult.strings,
    localisationStrings: [],
    headers: {
      machO: binaryResult.header,
      fatArchs: binaryResult.fatArchs,
      loadCommands: binaryResult.loadCommands,
    },
    libraries: binaryResult.libraries,
    symbols: binaryResult.symbols,
    classes: binaryResult.classes,
    protocols: binaryResult.protocols,
    entitlements: binaryResult.entitlements,
    infoPlist: {},
    security: binaryResult.security,
    hooks: binaryResult.hooks,
    files: [],
  };

  cachedResult = result;
  progressCallback("Analysis complete", 100);
  return result;
}

// ── Analyse DEB package ────────────────────────────────────────────

export async function analyseDEB(
  debPath: string,
  progressCallback: (phase: string, percent: number) => void,
): Promise<AnalysisResult> {
  cachedSourceType = "deb";
  cachedFilePath = debPath;
  cachedInfoPlist = {};

  // Step 1: Extract DEB
  progressCallback("Extracting DEB package...", 0);
  const extraction = await extractDEB(debPath);

  if (!extraction.success) {
    throw new Error(extraction.error);
  }

  cachedExtractedDir = extraction.extractedDir;
  cachedAppBundlePath = extraction.dataDir;

  // Convert DEB binaries to BinaryInfo for the binary selector
  cachedBinaries = extraction.binaries.map((b: DEBBinaryInfo) => ({
    name: b.name,
    path: b.path,
    type: b.type === "tweak" ? "main" as const : "framework" as const,
  }));
  cachedSearchIndex = null;

  if (cachedBinaries.length === 0) {
    throw new Error("No Mach-O binaries found in .deb package");
  }

  // Step 2: Analyse main binary
  progressCallback("Analysing binary...", 20);
  const mainBinary = cachedBinaries[0]!;
  cachedActiveBinaryName = mainBinary.name;
  const binaryResult = await analyseBinaryFile(mainBinary.path, progressCallback, 20);

  // Step 3: Scan additional binaries if setting enabled
  let debExtraFindings: SecurityFinding[] = [];
  const debSettings = loadSettings();
  if (debSettings.scanAllBinaries && cachedBinaries.length > 1) {
    progressCallback("Scanning additional binaries...", 80);
    await yieldToEventLoop();
    for (let i = 1; i < cachedBinaries.length; i++) {
      try {
        const extraResult = await analyseBinaryFile(
          cachedBinaries[i]!.path,
          () => {},
          0,
        );
        for (const finding of extraResult.security.findings) {
          debExtraFindings.push({ ...finding, source: cachedBinaries[i]!.name });
        }
      } catch {
        // Non-critical
      }
    }
  }

  const debMergedSecurity = {
    findings: [...binaryResult.security.findings, ...debExtraFindings],
    hardening: binaryResult.security.hardening,
  };

  // Step 3b: Extract localisation strings
  let localisationStrings: LocalisationString[] = [];
  try {
    localisationStrings = extractLocalisationStrings(extraction.dataDir);
  } catch {
    // Non-critical
  }

  // Step 4: Build file tree from extracted data
  progressCallback("Building file tree...", 90);
  const files = buildFileTree(extraction.dataDir);

  const result: AnalysisResult = {
    overview: {
      sourceType: "deb",
      filePath: debPath,
      debControl: extraction.control,
      ipa: {
        bundlePath: extraction.dataDir,
        appName: extraction.control.name || path.basename(debPath, ".deb"),
        binaries: cachedBinaries.map((b) => ({
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
    },
    strings: binaryResult.strings,
    localisationStrings,
    headers: {
      machO: binaryResult.header,
      fatArchs: binaryResult.fatArchs,
      loadCommands: binaryResult.loadCommands,
    },
    libraries: binaryResult.libraries,
    symbols: binaryResult.symbols,
    classes: binaryResult.classes,
    protocols: binaryResult.protocols,
    entitlements: binaryResult.entitlements,
    infoPlist: {},
    security: debMergedSecurity,
    hooks: binaryResult.hooks,
    files,
  };

  // Enrich hooks with tweak filter plist data (target bundles)
  try {
    const mainBinaryName = path.basename(mainBinary.path, ".dylib");
    // Look for filter plist next to the dylib
    const filterPlistPath = path.join(path.dirname(mainBinary.path), mainBinaryName + ".plist");
    if (fs.existsSync(filterPlistPath)) {
      const plistContent = fs.readFileSync(filterPlistPath, "utf-8");
      // Simple XML plist extraction for Filter > Bundles
      const bundleMatches = plistContent.match(/<string>([^<]+)<\/string>/g);
      if (bundleMatches) {
        const bundles = bundleMatches.map((m) => m.replace(/<\/?string>/g, ""));
        // Only add bundles that are within the Filter dict context
        if (plistContent.includes("<key>Filter</key>") || plistContent.includes("<key>Bundles</key>")) {
          result.hooks.targetBundles = bundles;
        }
      }
    }
  } catch {
    // Non-critical
  }

  cachedResult = result;
  progressCallback("Analysis complete", 100);
  return result;
}

// ── Analyse macOS .app bundle ─────────────────────────────────────

export async function analyseApp(
  appPath: string,
  progressCallback: (phase: string, percent: number) => void,
): Promise<AnalysisResult> {
  cachedSourceType = "app";
  cachedFilePath = appPath;

  // macOS .app bundles use Contents/ structure
  const isMacOS = isMacOSAppBundle(appPath);
  cachedAppBundlePath = appPath;

  // Step 1: Discover binaries
  progressCallback("Discovering binaries...", 5);
  await yieldToEventLoop();

  const binaries = isMacOS
    ? discoverMacOSBinaries(appPath)
    : discoverBinaries(appPath);
  cachedBinaries = binaries;
  cachedSearchIndex = null;

  if (binaries.length === 0) {
    throw new Error("No binaries found in .app bundle");
  }

  // Step 2: Parse Info.plist
  progressCallback("Parsing plists...", 10);
  let infoPlistData: Record<string, PlistValue> = {};
  const plistDir = isMacOS ? path.join(appPath, "Contents") : appPath;
  try {
    const plistResult = parseInfoPlist(plistDir);
    if (plistResult && plistResult.ok) {
      infoPlistData = plistResult.data.raw as Record<string, PlistValue>;
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    // Try the .app root as fallback
    try {
      const plistResult = parseInfoPlist(appPath);
      if (plistResult && plistResult.ok) {
        infoPlistData = plistResult.data.raw as Record<string, PlistValue>;
      }
    } catch {
      // Non-critical
    }
  }
  cachedInfoPlist = infoPlistData;

  // Steps 3-12: Analyse main binary
  progressCallback("Reading binary...", 15);
  const mainBinary = binaries[0]!;
  cachedActiveBinaryName = mainBinary.name;
  const binaryResult = await analyseBinaryFile(mainBinary.path, progressCallback, 15);

  // Entitlements from code signature
  let finalEntitlements = binaryResult.entitlements;

  // Detect app frameworks
  const bundleRoot = isMacOS ? path.join(appPath, "Contents") : appPath;
  const libNames = binaryResult.libraries.map((l) => l.name);
  const appFrameworks = detectAppFrameworks(bundleRoot, libNames);

  // Scan bundle files for secrets
  progressCallback("Scanning bundle files...", 80);
  await yieldToEventLoop();
  let bundleFindings: SecurityFinding[] = [];
  try {
    const bundleFiles = readBundleFiles(bundleRoot);
    if (bundleFiles.length > 0) {
      bundleFindings = scanBundleFileContents(bundleFiles);
    }
  } catch {
    // Non-critical
  }

  // Extract localisation strings from .lproj directories
  let localisationStrings: LocalisationString[] = [];
  try {
    localisationStrings = extractLocalisationStrings(bundleRoot);
  } catch {
    // Non-critical
  }

  // Scan additional binaries if enabled
  let extraBinaryFindings: SecurityFinding[] = [];
  const settings = loadSettings();
  if (settings.scanAllBinaries && binaries.length > 1) {
    progressCallback("Scanning additional binaries...", 85);
    await yieldToEventLoop();
    for (let i = 1; i < binaries.length; i++) {
      try {
        const extraResult = await analyseBinaryFile(binaries[i]!.path, () => {}, 0);
        for (const finding of extraResult.security.findings) {
          extraBinaryFindings.push({ ...finding, source: binaries[i]!.name });
        }
      } catch {
        // Non-critical
      }
    }
  }

  const mergedSecurity = {
    findings: [...binaryResult.security.findings, ...bundleFindings, ...extraBinaryFindings],
    hardening: binaryResult.security.hardening,
  };

  // Build file tree — for macOS apps where the only top-level entry is
  // "Contents", promote its children to root so users see the useful stuff
  progressCallback("Building file tree...", 95);
  await yieldToEventLoop();
  let files = buildFileTree(appPath);
  if (
    isMacOS &&
    files.length === 1 &&
    files[0]!.isDirectory &&
    files[0]!.name === "Contents" &&
    files[0]!.children
  ) {
    files = files[0]!.children;
  }

  const appName = path.basename(appPath, ".app");
  const result: AnalysisResult = {
    overview: {
      sourceType: "app",
      filePath: appPath,
      ipa: {
        bundlePath: appPath,
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
      appFrameworks: appFrameworks.length > 0 ? appFrameworks : undefined,
    },
    strings: binaryResult.strings,
    localisationStrings,
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
    security: mergedSecurity,
    hooks: binaryResult.hooks,
    files,
  };

  cachedResult = result;
  progressCallback("Analysis complete", 100);
  return result;
}

// ── Unified file analysis entry point ──────────────────────────────

export async function analyseFile(
  filePath: string,
  progressCallback: (phase: string, percent: number) => void,
): Promise<AnalysisResult> {
  // Check if it's a .app directory
  try {
    const stat = fs.statSync(filePath);
    if (stat.isDirectory() && filePath.endsWith(".app")) {
      return analyseApp(filePath, progressCallback);
    }
  } catch {
    // Not a directory — continue with file-based detection
  }

  const fileType = detectFileType(filePath);

  switch (fileType) {
    case "ipa":
      return analyseIPA(filePath, progressCallback);
    case "macho":
      return analyseMachO(filePath, progressCallback);
    case "deb":
      return analyseDEB(filePath, progressCallback);
    case "app":
      return analyseApp(filePath, progressCallback);
  }
}

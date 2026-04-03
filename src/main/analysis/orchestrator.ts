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
  SourceType,
  HookInfo,
  HookMethod,
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
import { extractObjCMetadata, buildMethodSignature } from "../parser/objc";
import { parseCodeSignature, extractEntitlements } from "../parser/codesign";
import { parseInfoPlist, parseMobileprovision } from "../parser/plist";
import { runSecurityScan, getBinaryHardening } from "./security";
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
let cachedSourceType: SourceType = "ipa";
let cachedFilePath: string = "";

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
  const methods: HookMethod[] = [];
  const seenMethods = new Set<string>(); // "ClassName.selector" dedup key

  // 1. Check imported symbols for hook framework functions
  for (const sym of symbols) {
    if (sym.type === "imported") {
      const framework = HOOK_SYMBOLS[sym.name];
      if (framework) {
        frameworks.add(framework);
        hookSymbols.push(sym.name);
      }
    }

    // Logos-generated symbols encode exact class+method pairs:
    //   _logos_method$group$ClassName$selector$  (instance method)
    //   _logos_meta_method$group$ClassName$selector$  (class method)
    if (sym.name.startsWith("_logos_method$") || sym.name.startsWith("_logos_meta_method$")) {
      frameworks.add("Logos");
      hookSymbols.push(sym.name);

      const parts = sym.name.split("$");
      // parts: ["_logos_method", group, ClassName, selector_part1, selector_part2, ...]
      if (parts.length >= 4) {
        const className = parts[2]!;
        // Logos encodes selector components separated by $, with : replaced
        // e.g., _logos_method$_ungrouped$UIView$setFrame$  → setFrame:
        // e.g., _logos_method$_ungrouped$UIView$hitTest$withEvent$  → hitTest:withEvent:
        const selectorParts = parts.slice(3).filter((p) => p !== "");
        const selector = selectorParts.length > 0
          ? selectorParts.map((p) => p + ":").join("")
          : "";

        if (className && selector) {
          hookedClasses.add(className);
          const key = `${className}.${selector}`;
          if (!seenMethods.has(key)) {
            seenMethods.add(key);
            methods.push({ className, selector, source: "logos" });
          }
        } else if (className) {
          hookedClasses.add(className);
        }
      }
    }

    if (sym.name.startsWith("_logos_register")) {
      frameworks.add("Logos");
      hookSymbols.push(sym.name);
    }

    // _logos_orig$ patterns also encode class names
    if (sym.name.startsWith("_logos_orig$")) {
      const parts = sym.name.split("$");
      if (parts.length >= 3) {
        hookedClasses.add(parts[2]!);
      }
    }
  }

  // 2. Find system classes referenced by the binary
  const tweakClassNames = new Set(classes.map((c) => c.name));

  // Only look for hooked system classes when a hook framework is actually present.
  // Regular apps also import objc_getClass and reference system classes — that's normal usage, not hooking.
  if (frameworks.size > 0) {
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

  // Note: For Substrate/Libhooker hooks (non-Logos), we cannot reliably determine
  // which specific methods are hooked without ARM64 disassembly and backward register
  // tracing (as TweakInspect does). The selectors in __objc_methname include both
  // hooked methods AND regular API calls, so we only report exact matches from Logos
  // symbols and list the hooked classes without guessing methods.

  // Sort methods alphabetically
  methods.sort((a, b) => {
    const cmp = a.className.localeCompare(b.className);
    return cmp !== 0 ? cmp : a.selector.localeCompare(b.selector);
  });

  return {
    frameworks: [...frameworks],
    targetBundles: [],
    hookedClasses: [...hookedClasses].sort(),
    hookSymbols,
    methods,
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

async function analyzeBinaryFile(
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
  let hooks: HookInfo = { frameworks: [], targetBundles: [], hookedClasses: [], hookSymbols: [], methods: [] };
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
      uuid, teamId, security: { findings, hardening }, hooks, errors,
    };
  }

  // Step 5: Parse fat header / select arm64 slice / parse Mach-O header
  progressCallback("Parsing Mach-O header...", basePercent + 5);
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

        // Group unnamed method entries by arg count (from type encoding)
        // Type encoding args = total decoded types - 3 (return, self, _cmd)
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
            if (ch === "{") { const c = enc.indexOf("}", pos); pos = c !== -1 ? c + 1 : pos + 1; }
            else if (ch === "(") { const c = enc.indexOf(")", pos); pos = c !== -1 ? c + 1 : pos + 1; }
            else if (ch === "[") { const c = enc.indexOf("]", pos); pos = c !== -1 ? c + 1 : pos + 1; }
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

        // Build map: argCount → list of unnamed method entries with their type encoding
        const byArgCount = new Map<number, { method: typeof cls.methods[0]; enc: string }[]>();
        for (const method of cls.methods) {
          if (method.selector !== "") continue;
          const enc = method.signature; // raw type encoding stored when name was empty
          const argc = countArgsFromEncoding(enc);
          if (!byArgCount.has(argc)) byArgCount.set(argc, []);
          byArgCount.get(argc)!.push({ method, enc });
        }

        // Match symbols to method entries by arg count
        const usedSymbols = new Set<number>();
        for (const [argc, entries] of byArgCount) {
          const matchingSyms = symInstanceMethods
            .map((s, i) => ({ s, i }))
            .filter(({ s, i }) => !usedSymbols.has(i) && (s.selector.match(/:/g) || []).length === argc);

          if (matchingSyms.length === entries.length) {
            // Unique match — pair them with full type info
            for (let j = 0; j < entries.length; j++) {
              const { method, enc } = entries[j]!;
              const { s, i } = matchingSyms[j]!;
              method.selector = s.selector;
              method.signature = buildMethodSignatureFromParts(s.prefix, s.selector, enc);
              usedSymbols.add(i);
            }
          } else {
            // Ambiguous — more entries than symbols or vice versa.
            // Assign names and try type info (may be wrong for some).
            for (let j = 0; j < Math.min(entries.length, matchingSyms.length); j++) {
              const { method, enc } = entries[j]!;
              const { s, i } = matchingSyms[j]!;
              method.selector = s.selector;
              method.signature = buildMethodSignatureFromParts(s.prefix, s.selector, enc);
              usedSymbols.add(i);
            }
          }
        }

        // Assign any remaining unmatched symbols to remaining unnamed methods
        const remainingSyms = symInstanceMethods.filter((_, i) => !usedSymbols.has(i));
        const remainingMethods = cls.methods.filter((m) => m.selector === "");
        for (let j = 0; j < Math.min(remainingMethods.length, remainingSyms.length); j++) {
          remainingMethods[j]!.selector = remainingSyms[j]!.selector;
          remainingMethods[j]!.signature = `${remainingSyms[j]!.prefix}${remainingSyms[j]!.selector}`;
        }

        // Add class methods (+) not in the instance method list
        const symClassMethods = symMethods.filter((m) => m.prefix === "+");
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

// ── Main orchestrator ───────────────────────────────────────────────

export async function analyzeIPA(
  ipaPath: string,
  progressCallback: (phase: string, percent: number) => void,
): Promise<AnalysisResult> {
  const errors: string[] = [];

  // Step 1: Extract IPA
  progressCallback("Extracting IPA...", 0);
  const tempDir = path.join(os.tmpdir(), `appinspect-${Date.now()}`);
  const extraction = extractIPA(ipaPath, tempDir);

  if (!extraction.success) {
    throw new Error((extraction as { success: false; error: string }).error);
  }

  cachedExtractedDir = tempDir;
  cachedSourceType = "ipa";
  cachedFilePath = ipaPath;

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
    hooks: binaryResult.hooks,
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
  cpuType?: number,
  cpuSubtype?: number,
): Promise<AnalysisResult> {
  if (!cachedResult) {
    throw new Error("No previous analysis. Run analyzeFile first.");
  }

  if (binaryIndex < 0 || binaryIndex >= cachedBinaries.length) {
    throw new Error(`Binary index ${binaryIndex} out of range (0-${cachedBinaries.length - 1})`);
  }

  const binary = cachedBinaries[binaryIndex]!;
  const binaryResult = await analyzeBinaryFile(binary.path, progressCallback, 0, cpuType, cpuSubtype);

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

// ── Analyze bare Mach-O / dylib ────────────────────────────────────

export async function analyzeMachO(
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

  progressCallback("Analyzing binary...", 10);
  const binaryResult = await analyzeBinaryFile(filePath, progressCallback, 10);

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

// ── Analyze DEB package ────────────────────────────────────────────

export async function analyzeDEB(
  debPath: string,
  progressCallback: (phase: string, percent: number) => void,
): Promise<AnalysisResult> {
  cachedSourceType = "deb";
  cachedFilePath = debPath;
  cachedInfoPlist = {};

  // Step 1: Extract DEB
  progressCallback("Extracting DEB package...", 0);
  const extraction = extractDEB(debPath);

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

  if (cachedBinaries.length === 0) {
    throw new Error("No Mach-O binaries found in .deb package");
  }

  // Step 2: Analyze main binary
  progressCallback("Analyzing binary...", 20);
  const mainBinary = cachedBinaries[0]!;
  const binaryResult = await analyzeBinaryFile(mainBinary.path, progressCallback, 20);

  // Step 3: Build file tree from extracted data
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

// ── Unified file analysis entry point ──────────────────────────────

export async function analyzeFile(
  filePath: string,
  progressCallback: (phase: string, percent: number) => void,
): Promise<AnalysisResult> {
  const fileType = detectFileType(filePath);

  switch (fileType) {
    case "ipa":
      return analyzeIPA(filePath, progressCallback);
    case "macho":
      return analyzeMachO(filePath, progressCallback);
    case "deb":
      return analyzeDEB(filePath, progressCallback);
  }
}

/**
 * Analysis Orchestrator
 *
 * Sequences all parser modules to produce a full AnalysisResult from an IPA file.
 * Reports progress via a callback. Gracefully continues when individual parsers fail.
 */

import * as fs from "fs";
import * as path from "path";

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
  SourceType,
  HookInfo,
  LibraryGraphData,
  LibraryGraphNode,
  LibraryGraphEdge,
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
import type { LoadCommandsResult, Section64 } from "../parser/load-commands";
import { buildFixupMap } from "../parser/chained-fixups";
import { extractStrings } from "../parser/strings";
import type { StringEntry as ParserStringEntry } from "../parser/strings";
import { parseSymbolTable } from "../parser/symbols";
import type { Symbol as ParserSymbol } from "../parser/symbols";
import { extractObjCMetadata } from "../parser/objc";
import { parseCodeSignature } from "../parser/codesign";
import { parseInfoPlist, parseMobileprovision, parsePlistBuffer } from "../parser/plist";
import { runSecurityScan, getBinaryHardening, scanBundleFileContents } from "./security";
import { loadSettings } from "../settings";
import { parseFunctionStarts, buildStringXrefMap, formatFunctionName } from "../parser/xrefs";
import { extractDEB } from "../deb/extractor";
import type { DEBBinaryInfo } from "../deb/extractor";
import { MACHO_MAGICS } from "../parser/macho";

// ── Extracted modules ─────────────────────────────────────────────
import { getCacheDir, isCacheValid, pruneCache } from "./cache";
import { detectHooks } from "./hook-detection";
import { detectAppFrameworks } from "./framework-detection";
import { readBundleFiles, extractLocalisationStrings } from "./bundle-files";
import {
  buildMethodSignatureFromParts,
  convertLoadCommands,
  convertSymbols,
  convertStrings,
  convertEntitlements,
  convertLibraries,
} from "./conversion";
import { classifyLib, libBasename, isTweakDep } from "./library-graph";

// Re-export for external consumers (main/index.ts, mcp/server.ts, handlers.ts)
export { pruneCache };

// ── Event loop yield ───────────────────────────────────────────────

/** Yield to the event loop so the UI stays responsive during heavy parsing. */
const yieldToEventLoop = (): Promise<void> =>
  new Promise((resolve) => setImmediate(resolve));

// ── Per-binary search index type ───────────────────────────────────

interface BinarySearchIndex {
  classes: string[];
  strings: string[];
  symbols: string[];
  symbolTypes: string[];
  libraries: string[];
}

export type SearchableTab = "classes" | "strings" | "symbols" | "libraries";

export interface CrossBinarySearchResult {
  binaryIndex: number;
  binaryName: string;
  binaryType: string;
  match: string;
  symbolType?: string;
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
    libraries = convertLibraries(lcResult);

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
      platform: buildVersion?.platform,
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

// ── Analysis session ───────────────────────────────────────────────

/**
 * Isolated analysis session.
 *
 * Each instance holds its own state (parsed result, extracted directory,
 * discovered binaries, search index, etc.) so multiple analyses can run
 * concurrently without interfering with each other.
 */
export class AnalysisSession {
  // ── State ──────────────────────────────────────────────────────────
  private result: AnalysisResult | null = null;
  private extractedDir: string | null = null;
  private appBundlePath: string | null = null;
  private binaries: BinaryInfo[] = [];
  private infoPlist: Record<string, unknown> = {};
  private sourceType: SourceType = "ipa";
  private filePath: string = "";
  private activeBinaryName: string = "";
  private searchIndex: Map<number, BinarySearchIndex> | null = null;

  // ── Getters ────────────────────────────────────────────────────────

  /** Return the cached analysis result, or null if no file has been analysed. */
  getResult(): AnalysisResult | null {
    return this.result;
  }

  /** Return the name of the currently active binary (e.g. the main executable). */
  getActiveBinaryName(): string {
    return this.activeBinaryName;
  }

  /** Return how many binaries were discovered in the loaded container. */
  getBinariesCount(): number {
    return this.binaries.length;
  }

  // ── Library dependency graph ────────────────────────────────────────

  /**
   * Build a dependency graph across all binaries in the container.
   * For each binary, parses only its load commands (lightweight) to
   * extract linked libraries, then merges into a single graph.
   */
  async getLibraryGraph(): Promise<LibraryGraphData> {
    const nodes = new Map<string, LibraryGraphNode>();
    const edges: LibraryGraphEdge[] = [];

    // If no binaries discovered (plain Mach-O), use the cached result directly
    if (this.binaries.length === 0 && this.result) {
      const rootId = this.activeBinaryName || "Binary";
      nodes.set(rootId, { id: rootId, label: rootId, type: "binary", binaryType: "main" });
      for (const lib of this.result.libraries) {
        const cat = classifyLib(lib.name);
        if (!nodes.has(lib.name)) {
          nodes.set(lib.name, {
            id: lib.name, label: libBasename(lib.name), type: "library",
            category: cat, weak: lib.weak, version: lib.currentVersion,
          });
        }
        edges.push({ source: rootId, target: lib.name, weak: lib.weak });
      }
      return { nodes: Array.from(nodes.values()), edges };
    }

    // For containers with multiple binaries, scan each one
    for (let i = 0; i < this.binaries.length; i++) {
      const bin = this.binaries[i]!;
      const binId = bin.name;

      let libs: LinkedLibrary[] = [];
      if (bin.name === this.activeBinaryName && this.result) {
        libs = this.result.libraries;
      } else {
        libs = this.parseLibrariesOnly(bin.path);
      }

      // Detect if this binary is a tweak (links a hooking framework)
      const isTweak = bin.type !== "main" && libs.some((l) => isTweakDep(l.name));
      const binaryType = isTweak ? "tweak" as const : bin.type;
      nodes.set(binId, { id: binId, label: bin.name, type: "binary", binaryType });

      for (const lib of libs) {
        const matchedBinary = this.binaries.find(
          (b) => b.name !== bin.name && lib.name.includes(b.name)
        );

        if (matchedBinary) {
          edges.push({ source: binId, target: matchedBinary.name, weak: lib.weak });
        } else {
          const cat = classifyLib(lib.name);
          if (!nodes.has(lib.name)) {
            nodes.set(lib.name, {
              id: lib.name, label: libBasename(lib.name), type: "library",
              category: cat, weak: lib.weak, version: lib.currentVersion,
            });
          }
          edges.push({ source: binId, target: lib.name, weak: lib.weak });
        }
      }
    }

    return { nodes: Array.from(nodes.values()), edges };
  }

  /**
   * Lightweight: read a binary and parse only its load commands to extract
   * linked libraries. Skips strings, symbols, ObjC, signatures, etc.
   */
  private parseLibrariesOnly(binaryPath: string): LinkedLibrary[] {
    try {
      const fileBuf = fs.readFileSync(binaryPath);
      let buffer = fileBuf.buffer.slice(
        fileBuf.byteOffset,
        fileBuf.byteOffset + fileBuf.byteLength,
      );

      // Handle fat binary — select arm64 or first arch
      const fatResult = parseFatHeader(buffer);
      let headerOffset = 0;
      if (fatResult.ok) {
        const arm64 = fatResult.data.find((a) => a.cputype === CPU_TYPE_ARM64);
        const arch = arm64 ?? fatResult.data[0];
        if (arch && arch.offset > 0) {
          buffer = buffer.slice(arch.offset, arch.offset + arch.size);
        }
      }

      const headerResult = parseMachOHeader(buffer, headerOffset);
      if (!headerResult.ok) return [];

      const machO = headerResult.data;
      const lcOffset = machO.offset + 32;
      const lcResult = parseLoadCommands(
        buffer, lcOffset, machO.header.ncmds, machO.header.sizeofcmds, machO.littleEndian,
      );

      return lcResult.libraries.map((lib) => ({
        name: lib.name,
        currentVersion: lib.currentVersion,
        compatVersion: lib.compatVersion,
        weak: lib.weak,
      }));
    } catch {
      return [];
    }
  }

  // ── Cross-binary search ────────────────────────────────────────────

  /** Build (or return cached) lightweight per-binary search index. */
  private async ensureSearchIndex(
    progressCallback: (phase: string, percent: number) => void,
  ): Promise<Map<number, BinarySearchIndex>> {
    if (this.searchIndex) return this.searchIndex;

    this.searchIndex = new Map();
    for (let i = 0; i < this.binaries.length; i++) {
      const bin = this.binaries[i]!;
      progressCallback(
        `Indexing ${bin.name}...`,
        Math.round((i / this.binaries.length) * 100),
      );
      await yieldToEventLoop();
      try {
        const result = await analyseBinaryFile(bin.path, () => {}, 0);
        this.searchIndex.set(i, {
          classes: result.classes.map((c) => c.name),
          strings: result.strings.map((s) => s.value),
          symbols: result.symbols.map((s) => s.name),
          symbolTypes: result.symbols.map((s) => s.type),
          libraries: result.libraries.map((l) => l.name),
        });
      } catch {
        this.searchIndex.set(i, { classes: [], strings: [], symbols: [], symbolTypes: [], libraries: [] });
      }
    }
    return this.searchIndex;
  }

  /** Search across all binaries in the container for a query string. */
  async searchAllBinaries(
    query: string,
    tab: SearchableTab,
    progressCallback: (phase: string, percent: number) => void,
    isRegex?: boolean,
    caseSensitive?: boolean,
  ): Promise<CrossBinarySearchResult[]> {
    if (this.binaries.length === 0 || !query) return [];

    const index = await this.ensureSearchIndex(progressCallback);
    const results: CrossBinarySearchResult[] = [];

    let matcher: (value: string) => boolean;
    if (isRegex) {
      const flags = caseSensitive ? "" : "i";
      const re = new RegExp(query, flags);
      matcher = (value) => re.test(value);
    } else if (caseSensitive) {
      matcher = (value) => value.includes(query);
    } else {
      const lowerQuery = query.toLowerCase();
      matcher = (value) => value.toLowerCase().includes(lowerQuery);
    }

    for (const [binaryIndex, entry] of index) {
      const bin = this.binaries[binaryIndex];
      if (!bin) continue;
      const values = entry[tab];
      for (let i = 0; i < values.length; i++) {
        const value = values[i]!;
        if (matcher(value)) {
          const result: CrossBinarySearchResult = {
            binaryIndex,
            binaryName: bin.name,
            binaryType: bin.type,
            match: value,
          };
          if (tab === "symbols") result.symbolType = entry.symbolTypes[i];
          results.push(result);
        }
      }
    }

    return results;
  }

  // ── Main orchestrator ─────────────────────────────────────────────

  /** Analyse an IPA archive — extract, discover binaries, and parse the main executable. */
  async analyseIPA(
    ipaPath: string,
    progressCallback: (phase: string, percent: number) => void,
  ): Promise<AnalysisResult> {
    const errors: string[] = [];

    // Step 1: Extract IPA (skip if a valid cache exists)
    const cacheDir = getCacheDir(ipaPath);
    if (isCacheValid(cacheDir)) {
      progressCallback("Using cached extraction...", 5);
    } else {
      progressCallback("Extracting IPA...", 0);
      const extraction = await extractIPA(ipaPath, cacheDir);
      if (!extraction.success) {
        throw new Error((extraction as { success: false; error: string }).error);
      }
    }

    this.extractedDir = cacheDir;
    this.sourceType = "ipa";
    this.filePath = ipaPath;

    // Step 2: Discover app bundle and binaries
    progressCallback("Discovering binaries...", 15);
    await yieldToEventLoop();
    const appBundlePath = discoverAppBundle(cacheDir);
    if (!appBundlePath) {
      throw new Error("No .app bundle found in IPA Payload directory");
    }
    this.appBundlePath = appBundlePath;

    const binaries = discoverBinaries(appBundlePath);
    this.binaries = binaries;
    this.searchIndex = null;

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
    this.infoPlist = infoPlistData;

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
    this.activeBinaryName = mainBinary.name;
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

    this.result = result;
    progressCallback("Analysis complete", 100);
    return result;
  }

  // ── Re-analyse a different binary ─────────────────────────────────

  /** Switch to a different binary within the loaded container and re-analyse it. */
  async analyseBinary(
    binaryIndex: number,
    progressCallback: (phase: string, percent: number) => void,
    cpuType?: number,
    cpuSubtype?: number,
  ): Promise<AnalysisResult> {
    if (!this.result) {
      throw new Error("No previous analysis. Run analyseFile first.");
    }

    if (binaryIndex < 0 || binaryIndex >= this.binaries.length) {
      throw new Error(`Binary index ${binaryIndex} out of range (0-${this.binaries.length - 1})`);
    }

    const binary = this.binaries[binaryIndex]!;
    this.activeBinaryName = binary.name;
    const binaryResult = await analyseBinaryFile(binary.path, progressCallback, 0, cpuType, cpuSubtype);

    // Rebuild the result with the new binary data but keep IPA-level info
    const result: AnalysisResult = {
      ...this.result,
      overview: {
        ...this.result.overview,
        header: binaryResult.header,
        fatArchs: binaryResult.fatArchs,
        buildVersion: binaryResult.buildVersion,
        encryptionInfo: binaryResult.encryptionInfo,
        hardening: binaryResult.security.hardening,
        uuid: binaryResult.uuid ?? undefined,
        teamId: binaryResult.teamId ?? this.result.overview.teamId,
      },
      strings: binaryResult.strings,
      // localisationStrings kept from this.result via spread
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
        : this.result.entitlements,
      security: binaryResult.security,
      hooks: binaryResult.hooks,
    };

    this.result = result;
    return result;
  }

  // ── Analyse bare Mach-O / dylib ──────────────────────────────────

  /** Analyse a bare Mach-O executable or dylib (no container). */
  async analyseMachO(
    filePath: string,
    progressCallback: (phase: string, percent: number) => void,
  ): Promise<AnalysisResult> {
    this.sourceType = "macho";
    this.filePath = filePath;
    this.appBundlePath = null;
    this.infoPlist = {};

    const fileName = path.basename(filePath);
    let fileSize = 0;
    try {
      fileSize = fs.statSync(filePath).size;
    } catch { /* ignore */ }

    // Set up single-binary list for binary switching
    this.binaries = [{
      name: fileName,
      path: filePath,
      type: "main",
    }];
    this.searchIndex = null;
    this.activeBinaryName = fileName;

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

    this.result = result;
    progressCallback("Analysis complete", 100);
    return result;
  }

  // ── Analyse DEB package ──────────────────────────────────────────

  /** Analyse a DEB package — extract, parse control metadata, and analyse binaries. */
  async analyseDEB(
    debPath: string,
    progressCallback: (phase: string, percent: number) => void,
  ): Promise<AnalysisResult> {
    this.sourceType = "deb";
    this.filePath = debPath;
    this.infoPlist = {};

    // Step 1: Extract DEB (extractor skips if cache dir already has content)
    const cacheDir = getCacheDir(debPath);
    progressCallback("Extracting DEB package...", 0);
    const extraction = await extractDEB(debPath, cacheDir);

    if (!extraction.success) {
      throw new Error(extraction.error);
    }

    this.extractedDir = cacheDir;
    this.appBundlePath = extraction.dataDir;

    // Convert DEB binaries to BinaryInfo for the binary selector
    this.binaries = extraction.binaries.map((b: DEBBinaryInfo) => ({
      name: b.name,
      path: b.path,
      type: b.type === "tweak" ? "main" as const : "framework" as const,
    }));
    this.searchIndex = null;

    if (this.binaries.length === 0) {
      throw new Error("No Mach-O binaries found in .deb package");
    }

    // Step 2: Analyse main binary
    progressCallback("Analysing binary...", 20);
    const mainBinary = this.binaries[0]!;
    this.activeBinaryName = mainBinary.name;
    const binaryResult = await analyseBinaryFile(mainBinary.path, progressCallback, 20);

    // Step 3: Scan additional binaries if setting enabled
    let debExtraFindings: SecurityFinding[] = [];
    const debSettings = loadSettings();
    if (debSettings.scanAllBinaries && this.binaries.length > 1) {
      progressCallback("Scanning additional binaries...", 80);
      await yieldToEventLoop();
      for (let i = 1; i < this.binaries.length; i++) {
        try {
          const extraResult = await analyseBinaryFile(
            this.binaries[i]!.path,
            () => {},
            0,
          );
          for (const finding of extraResult.security.findings) {
            debExtraFindings.push({ ...finding, source: this.binaries[i]!.name });
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
          binaries: this.binaries.map((b) => ({
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
        const filterBuf = fs.readFileSync(filterPlistPath);
        try {
          const filterDict = parsePlistBuffer(filterBuf);
          const filter = filterDict.Filter as Record<string, unknown> | undefined;
          const bundles = filter?.Bundles as string[] | undefined;
          if (bundles && bundles.length > 0) {
            result.hooks.targetBundles = bundles;
          }
        } catch {
          // Non-critical — skip if filter plist can't be parsed
        }
      }
    } catch {
      // Non-critical
    }

    this.result = result;
    progressCallback("Analysis complete", 100);
    return result;
  }

  // ── Analyse macOS .app bundle ───────────────────────────────────

  /** Analyse a macOS .app bundle — discover binaries and parse the main executable. */
  async analyseApp(
    appPath: string,
    progressCallback: (phase: string, percent: number) => void,
  ): Promise<AnalysisResult> {
    this.sourceType = "app";
    this.filePath = appPath;

    // macOS .app bundles use Contents/ structure
    const isMacOS = isMacOSAppBundle(appPath);
    this.appBundlePath = appPath;

    // Step 1: Discover binaries
    progressCallback("Discovering binaries...", 5);
    await yieldToEventLoop();

    const binaries = isMacOS
      ? discoverMacOSBinaries(appPath)
      : discoverBinaries(appPath);
    this.binaries = binaries;
    this.searchIndex = null;

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
    this.infoPlist = infoPlistData;

    // Steps 3-12: Analyse main binary
    progressCallback("Reading binary...", 15);
    const mainBinary = binaries[0]!;
    this.activeBinaryName = mainBinary.name;
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

    this.result = result;
    progressCallback("Analysis complete", 100);
    return result;
  }

  // ── Unified file analysis entry point ────────────────────────────

  /** Analyse any supported file — auto-detects type and dispatches to the right method. */
  async analyseFile(
    filePath: string,
    progressCallback: (phase: string, percent: number) => void,
  ): Promise<AnalysisResult> {
    // Check if it's a .app directory
    try {
      const stat = fs.statSync(filePath);
      if (stat.isDirectory() && filePath.endsWith(".app")) {
        return this.analyseApp(filePath, progressCallback);
      }
    } catch {
      // Not a directory — continue with file-based detection
    }

    const fileType = detectFileType(filePath);

    switch (fileType) {
      case "ipa":
        return this.analyseIPA(filePath, progressCallback);
      case "macho":
        return this.analyseMachO(filePath, progressCallback);
      case "deb":
        return this.analyseDEB(filePath, progressCallback);
      case "app":
        return this.analyseApp(filePath, progressCallback);
    }
  }
}

// ── File type detection ────────────────────────────────────────────

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

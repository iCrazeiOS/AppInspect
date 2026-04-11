/**
 * Analysis Orchestrator
 *
 * Sequences all parser modules to produce a full AnalysisResult from an IPA file.
 * Reports progress via a callback. Gracefully continues when individual parsers fail.
 */

import * as fs from "node:fs";
import * as path from "node:path";

import type {
	AnalysisResult,
	BinaryHardening,
	BuildVersion,
	DisasmInstruction,
	DisasmSection,
	EncryptionInfo,
	Entitlement,
	FatArch,
	FileEntry,
	HookInfo,
	LibraryGraphData,
	LibraryGraphEdge,
	LibraryGraphNode,
	LinkedLibrary,
	LocalisationString,
	MachOHeader,
	ObjCClass,
	ObjCProtocol,
	PlistValue,
	SecurityFinding,
	LoadCommand as SharedLoadCommand,
	SourceType,
	StringEntry,
	SymbolEntry
} from "../../shared/types";
import type { DEBBinaryInfo } from "../deb/extractor";
import { extractDEB } from "../deb/extractor";
import type { BinaryInfo } from "../ipa/extractor";
import {
	discoverAppBundle,
	discoverBinaries,
	discoverMacOSBinaries,
	extractIPA,
	isMacOSAppBundle
} from "../ipa/extractor";
import { buildFixupMap } from "../parser/chained-fixups";
import { parseCodeSignature } from "../parser/codesign";
import { cpuTypeToArch, disassembleChunk, initCapstone, isCapstoneReady } from "../parser/disasm";
import type { LoadCommandsResult, Section64 } from "../parser/load-commands";
import { parseLoadCommands } from "../parser/load-commands";
import type { MachOFile } from "../parser/macho";
import { CPU_TYPE_ARM64, MACHO_MAGICS, parseFatHeader, parseMachOHeader } from "../parser/macho";
import { extractObjCMetadata } from "../parser/objc";
import { parseInfoPlist, parseMobileprovision, parsePlistBuffer } from "../parser/plist";
import type { StringEntry as ParserStringEntry } from "../parser/strings";
import { extractStrings } from "../parser/strings";
import type { SymbolEntry as ParserSymbol } from "../parser/symbols";
import { parseSymbolTable } from "../parser/symbols";
import { buildStringXrefMap, formatFunctionName, parseFunctionStarts } from "../parser/xrefs";
import { loadSettings } from "../settings";
import { extractLocalisationStrings, readBundleFiles } from "./bundle-files";

// ── Extracted modules ─────────────────────────────────────────────
import { extractToCache, getCacheDir, pruneCache } from "./cache";
import {
	buildMethodSignatureFromParts,
	convertEntitlements,
	convertLibraries,
	convertLoadCommands,
	convertStrings,
	convertSymbols
} from "./conversion";
import { detectAppFrameworks } from "./framework-detection";
import { detectHooks } from "./hook-detection";
import { classifyLib, isTweakDep, libBasename } from "./library-graph";
import { getBinaryHardening, runSecurityScan, scanBundleFileContents } from "./security";

// Re-export for external consumers (main/index.ts, mcp/server.ts, handlers.ts)
export { pruneCache };

// ── Event loop yield ───────────────────────────────────────────────

/** Yield to the event loop so the UI stays responsive during heavy parsing. */
const yieldToEventLoop = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

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
					children
				});
			} else {
				result.push({
					name: entry.name,
					path: fullPath,
					size,
					isDirectory: false
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
	protocolDetails: ObjCProtocol[];
	entitlements: Entitlement[];
	uuid: string | null;
	teamId: string | null;
	security: { findings: SecurityFinding[]; hardening: BinaryHardening };
	hooks: HookInfo;
	errors: string[];
	fatSliceOffset: number;
}

async function analyseBinaryFile(
	binaryPath: string,
	progressCallback: (phase: string, percent: number) => void,
	basePercent: number,
	preferredCpuType?: number,
	preferredCpuSubtype?: number
): Promise<BinaryAnalysisResult> {
	const errors: string[] = [];

	// Defaults
	let header: MachOHeader = {
		magic: 0,
		cputype: 0,
		cpusubtype: 0,
		filetype: 0,
		ncmds: 0,
		sizeofcmds: 0,
		flags: 0,
		reserved: 0
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
	let protocolDetails: ObjCProtocol[] = [];
	let entitlements: Entitlement[] = [];
	let uuid: string | null = null;
	let teamId: string | null = null;
	let findings: SecurityFinding[] = [];
	let hooks: HookInfo = { frameworks: [], targetBundles: [], hookedClasses: [], hookSymbols: [] };
	let hardening: BinaryHardening = {
		pie: false,
		arc: false,
		stackCanaries: false,
		encrypted: false,
		stripped: true
	};
	let fatSliceOffset = 0;

	// Step 4: Read binary
	progressCallback("Reading binary...", basePercent);
	await yieldToEventLoop();
	let buffer: ArrayBuffer;
	try {
		const fileBuf = fs.readFileSync(binaryPath);
		buffer = fileBuf.buffer.slice(fileBuf.byteOffset, fileBuf.byteOffset + fileBuf.byteLength);
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		errors.push(`Failed to read binary: ${msg}`);
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
			protocolDetails,
			entitlements,
			uuid,
			teamId,
			security: { findings, hardening },
			hooks,
			errors,
			fatSliceOffset
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
			const preferredArch =
				preferredCpuType != null
					? fatArchs.find(
							(a) =>
								a.cputype === preferredCpuType &&
								(preferredCpuSubtype == null ||
									a.cpusubtype === preferredCpuSubtype)
						)
					: undefined;
			const arm64Arch = fatArchs.find((a) => a.cputype === CPU_TYPE_ARM64);
			const selectedArch = preferredArch ?? arm64Arch ?? fatArchs[0];

			if (selectedArch) {
				// Slice the buffer to the selected architecture so all internal
				// offsets (symoff, stroff, section offsets, etc.) are correct.
				// For thin binaries (offset=0, size=full), this is a no-op.
				fatSliceOffset = selectedArch.offset;
				if (selectedArch.offset > 0) {
					buffer = buffer.slice(
						selectedArch.offset,
						selectedArch.offset + selectedArch.size
					);
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
			protocolDetails,
			entitlements,
			uuid,
			teamId,
			security: { findings, hardening },
			hooks,
			errors,
			fatSliceOffset
		};
	}

	// Step 6: Parse load commands
	progressCallback("Parsing load commands...", basePercent + 10);
	let lcResult: LoadCommandsResult | null = null;
	try {
		const headerSize = machoFile.is64Bit ? 32 : 28;
		const lcOffset = machoFile.offset + headerSize;
		lcResult = parseLoadCommands(
			buffer,
			lcOffset,
			header.ncmds,
			header.sizeofcmds,
			machoFile.littleEndian,
			machoFile.is64Bit
		);
		sharedLoadCommands = convertLoadCommands(lcResult);
		libraries = convertLibraries(lcResult);

		if (lcResult.buildVersion) {
			buildVersion = {
				platform: lcResult.buildVersion.platform,
				minos: lcResult.buildVersion.minos,
				sdk: lcResult.buildVersion.sdk,
				ntools: lcResult.buildVersion.ntools
			};
		}

		if (lcResult.uuid) {
			uuid = lcResult.uuid;
		}

		if (lcResult.encryption) {
			encryptionInfo = {
				cryptoff: lcResult.encryption.cryptoff,
				cryptsize: lcResult.encryption.cryptsize,
				cryptid: lcResult.encryption.cryptid
			};
		}
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		errors.push(`Load commands parse error: ${msg}`);
	}

	if (!lcResult) {
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
			protocolDetails,
			entitlements,
			uuid,
			teamId,
			security: { findings, hardening },
			hooks,
			errors,
			fatSliceOffset
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
				machoFile.littleEndian
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
			machoFile.is64Bit
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
						strsize: lcResult.symtabInfo.strsize
					}
				: null,
			machoFile.littleEndian,
			machoFile.is64Bit
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
			machoFile.is64Bit
		);
		classes = objcMeta.classes;
		protocols = objcMeta.protocols;
		protocolDetails = objcMeta.protocolDetails;
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

		if (
			(classesNeedingEnrichment.length > 0 || classesWithNoMethods.length > 0) &&
			rawSymbols.length > 0
		) {
			// Build map: className → ordered methods from ObjC symbols like -[Class method:]
			const symMethodMap = new Map<string, { selector: string; prefix: string }[]>();
			for (const sym of rawSymbols) {
				const m = sym.name.match(/^([+-])\[(\S+)\s+(.+)\]$/);
				if (!m) continue;
				const className = m[2]!;
				if (!symMethodMap.has(className)) symMethodMap.set(className, []);
				symMethodMap.get(className)!.push({
					selector: m[3]!,
					prefix: m[1]!
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
				const skipNested = (
					enc: string,
					pos: number,
					open: string,
					close: string
				): number => {
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
						if ((ch >= "0" && ch <= "9") || ch === "-") {
							pos++;
							continue;
						}
						// Skip qualifiers
						if ("rnNoORV".includes(ch)) {
							pos++;
							continue;
						}
						// Count a type
						if (ch === "{") {
							pos = skipNested(enc, pos, "{", "}");
						} else if (ch === "(") {
							pos = skipNested(enc, pos, "(", ")");
						} else if (ch === "[") {
							pos = skipNested(enc, pos, "[", "]");
						} else if (ch === "@" && pos + 1 < enc.length && enc[pos + 1] === "?") {
							pos += 2;
						} else if (ch === "@" && pos + 1 < enc.length && enc[pos + 1] === '"') {
							const c = enc.indexOf('"', pos + 2);
							pos = c !== -1 ? c + 1 : pos + 1;
						} else if (ch === "^") {
							pos++;
							continue;
						} // pointer prefix, next char is the type
						else {
							pos++;
						}
						count++;
					}
					return Math.max(0, count - 3); // subtract return, self, _cmd
				};

				// Match unnamed method entries against symbols by arg count.
				// Process instance and class methods separately using the _isClassMethod flag.
				const matchMethodGroup = (
					symGroup: typeof symInstanceMethods,
					isClassMethod: boolean
				) => {
					const byArgCount = new Map<
						number,
						{ method: (typeof cls.methods)[0]; enc: string }[]
					>();
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
							.filter(
								({ s, i }) =>
									!usedSymbols.has(i) &&
									(s.selector.match(/:/g) || []).length === argc
							);

						const limit = Math.min(entries.length, matchingSyms.length);
						for (let j = 0; j < limit; j++) {
							const { method, enc } = entries[j]!;
							const { s, i } = matchingSyms[j]!;
							method.selector = s.selector;
							method.signature = buildMethodSignatureFromParts(
								s.prefix,
								s.selector,
								enc
							);
							usedSymbols.add(i);
						}
					}

					// Assign any remaining unmatched symbols to remaining unnamed methods in this group
					const remainingSyms = symGroup.filter((_, i) => !usedSymbols.has(i));
					const remainingMethods = cls.methods.filter(
						(m) => m.selector === "" && isClassMethod === !!m._isClassMethod
					);
					for (
						let j = 0;
						j < Math.min(remainingMethods.length, remainingSyms.length);
						j++
					) {
						remainingMethods[j]!.selector = remainingSyms[j]!.selector;
						remainingMethods[j]!.signature =
							`${remainingSyms[j]!.prefix}${remainingSyms[j]!.selector}`;
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
						signature: `${m.prefix}${m.selector}`
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
				lcResult.codeSignatureInfo.size
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
			offset: s.offset
		}));

		// Convert symbols to the format expected by security (with bigint address)
		const securitySymbols = rawSymbols.map((s) => ({
			name: s.name,
			type: s.type as "exported" | "imported" | "local",
			address: s.address,
			sectionIndex: s.sectionIndex
		}));

		findings = runSecurityScan({
			strings: securityStrings,
			symbols: securitySymbols,
			headerFlags: header.flags,
			encryption: encryptionInfo,
			loadCommands: lcResult.loadCommands.map((lc) => ({ cmd: lc.cmd })),
			platform: buildVersion?.platform
		});

		hardening = getBinaryHardening({
			symbols: securitySymbols,
			headerFlags: header.flags,
			encryption: encryptionInfo
		});
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		errors.push(`Security scan error: ${msg}`);
	}

	// Step 12b: Enrich findings with function names (only if there are
	// string-based findings that benefit from attribution)
	const stringFindings = findings.filter(
		(f) => f.category === "credential-leak" || f.category === "jailbreak-detection"
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
						textSeg.vmaddr
					);
				}
				const stringXrefs = buildStringXrefMap(
					buffer,
					lcResult.segments,
					funcStarts,
					rawSymbols,
					machoFile.littleEndian,
					rebaseMap,
					machoFile.header.cputype,
					machoFile.is64Bit
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
		protocolDetails,
		entitlements,
		uuid,
		teamId,
		security: { findings, hardening },
		hooks,
		errors,
		fatSliceOffset
	};
}

// ── Result builder ────────────────────────────────────────────────

/** Common overview fields that come directly from a BinaryAnalysisResult. */
function binaryOverviewFields(br: BinaryAnalysisResult) {
	return {
		header: br.header,
		fatArchs: br.fatArchs,
		buildVersion: br.buildVersion,
		encryptionInfo: br.encryptionInfo,
		hardening: br.security.hardening,
		uuid: br.uuid ?? undefined,
		teamId: br.teamId ?? undefined
	};
}

/**
 * Assemble an AnalysisResult from a BinaryAnalysisResult plus overview and
 * optional overrides. Eliminates the repeated result-construction pattern
 * across analyseIPA / analyseMachO / analyseDEB / analyseApp.
 */
function buildAnalysisResult(
	br: BinaryAnalysisResult,
	overview: AnalysisResult["overview"],
	opts: {
		localisationStrings?: LocalisationString[];
		entitlements?: Entitlement[];
		infoPlist?: Record<string, PlistValue>;
		security?: AnalysisResult["security"];
		files?: FileEntry[];
	} = {}
): AnalysisResult {
	return {
		overview,
		strings: br.strings,
		localisationStrings: opts.localisationStrings ?? [],
		headers: {
			machO: br.header,
			fatArchs: br.fatArchs,
			loadCommands: br.loadCommands
		},
		libraries: br.libraries,
		symbols: br.symbols,
		classes: br.classes,
		protocols: br.protocols,
		protocolDetails: br.protocolDetails,
		entitlements: opts.entitlements ?? br.entitlements,
		infoPlist: opts.infoPlist ?? {},
		security: opts.security ?? br.security,
		hooks: br.hooks,
		files: opts.files ?? []
	};
}

// ── Analysis session ───────────────────────────────────────────────

// ── Hexdump formatter ─────────────────────────────────────────────

/** Format raw bytes as a classic hexdump string (16 bytes per line). */
export function formatHexdump(data: number[], offset: number): string {
	const lines: string[] = [];
	for (let i = 0; i < data.length; i += 16) {
		const rowBytes = data.slice(i, i + 16);
		const addr = (offset + i).toString(16).padStart(8, "0").toUpperCase();
		const hexParts: string[] = [];
		for (let j = 0; j < 16; j++) {
			if (j < rowBytes.length) {
				hexParts.push(rowBytes[j]!.toString(16).padStart(2, "0").toUpperCase());
			} else {
				hexParts.push("  ");
			}
		}
		const hexLeft = hexParts.slice(0, 8).join(" ");
		const hexRight = hexParts.slice(8).join(" ");
		const ascii = rowBytes
			.map((b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : "."))
			.join("");
		lines.push(`${addr}  ${hexLeft}  ${hexRight}  |${ascii}|`);
	}
	return lines.join("\n");
}

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
	private fatSliceOffset: number = 0;
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

	/** Return the file path of the currently active binary. */
	getActiveBinaryPath(): string | null {
		if (this.binaries.length === 0) return this.filePath || null;
		const active = this.binaries.find((b) => b.name === this.activeBinaryName);
		return active?.path ?? this.binaries[0]?.path ?? null;
	}

	// ── Hex read ──────────────────────────────────────────────────────

	/** Read raw bytes from the active binary for hex display. */
	readHex(
		offset: number,
		length: number
	): { offset: number; length: number; data: number[]; fileSize: number } | null {
		const binaryPath = this.getActiveBinaryPath();
		if (!binaryPath) return null;

		const MAX_LEN = 65536;
		const safeLength = Math.min(Math.max(0, length), MAX_LEN);

		const fd = fs.openSync(binaryPath, "r");
		try {
			const stat = fs.fstatSync(fd);
			const fileSize = stat.size;
			const absOffset = this.fatSliceOffset + offset;

			// Compute the logical binary slice size
			const sliceSize =
				this.fatSliceOffset > 0
					? Math.min(fileSize - this.fatSliceOffset, fileSize)
					: fileSize;

			if (absOffset >= fileSize) {
				return { offset, length: 0, data: [], fileSize: sliceSize };
			}
			const readLen = Math.min(safeLength, fileSize - absOffset);
			const buf = Buffer.alloc(readLen);
			fs.readSync(fd, buf, 0, readLen, absOffset);

			return { offset, length: readLen, data: Array.from(buf), fileSize: sliceSize };
		} finally {
			fs.closeSync(fd);
		}
	}

	/** Search for a byte pattern within a region of the active binary. */
	searchHex(
		regionOffset: number,
		regionSize: number,
		pattern: number[],
		caseInsensitive = false
	): { matches: number[] } | null {
		const binaryPath = this.getActiveBinaryPath();
		if (!binaryPath || pattern.length === 0) return null;

		const MAX_MATCHES = 10000;
		const CHUNK_SIZE = 65536;
		const matches: number[] = [];

		const fd = fs.openSync(binaryPath, "r");
		try {
			const stat = fs.fstatSync(fd);
			const fileSize = stat.size;
			const absStart = this.fatSliceOffset + regionOffset;
			const sliceSize =
				this.fatSliceOffset > 0
					? Math.min(fileSize - this.fatSliceOffset, fileSize)
					: fileSize;
			const safeRegionSize = Math.min(regionSize, sliceSize - regionOffset);

			if (absStart >= fileSize || safeRegionSize <= 0) {
				return { matches: [] };
			}

			// Read in chunks with overlap for cross-boundary matches
			const overlap = pattern.length - 1;
			let pos = 0;
			let carryover = Buffer.alloc(0);

			while (pos < safeRegionSize && matches.length < MAX_MATCHES) {
				const readStart = absStart + pos;
				const readLen = Math.min(CHUNK_SIZE, safeRegionSize - pos);
				const buf = Buffer.alloc(readLen);
				const bytesRead = fs.readSync(fd, buf, 0, readLen, readStart);
				if (bytesRead === 0) break;

				// Prepend carryover from previous chunk for cross-boundary matching
				const searchBuf =
					carryover.length > 0
						? Buffer.concat([carryover, buf.subarray(0, bytesRead)])
						: buf.subarray(0, bytesRead);
				const searchStart = carryover.length > 0 ? 0 : 0;
				const baseOffset = pos - carryover.length;

				for (let i = searchStart; i <= searchBuf.length - pattern.length; i++) {
					let found = true;
					for (let j = 0; j < pattern.length; j++) {
						let a = searchBuf[i + j]!;
						let b = pattern[j]!;
						if (caseInsensitive) {
							if (a >= 0x41 && a <= 0x5a) a |= 0x20;
							if (b >= 0x41 && b <= 0x5a) b |= 0x20;
						}
						if (a !== b) {
							found = false;
							break;
						}
					}
					if (found) {
						matches.push(regionOffset + baseOffset + i);
						if (matches.length >= MAX_MATCHES) break;
					}
				}

				pos += bytesRead;
				// Keep the last (pattern.length - 1) bytes as carryover
				if (overlap > 0 && bytesRead === readLen && pos < safeRegionSize) {
					carryover = Buffer.from(buf.subarray(bytesRead - overlap, bytesRead));
				} else {
					carryover = Buffer.alloc(0);
				}
			}

			return { matches };
		} finally {
			fs.closeSync(fd);
		}
	}

	// ── Disassembly ───────────────────────────────────────────────────────

	/** Get sections available for disassembly (typically __TEXT,__text). */
	getDisasmSections(): DisasmSection[] {
		if (!this.result) return [];

		const arch = cpuTypeToArch(this.result.headers.machO.cputype);
		if (!arch) return [];

		const sections: DisasmSection[] = [];

		for (const lc of this.result.headers.loadCommands) {
			if (lc.type !== "segment") continue;
			const seg = lc.segment;
			const segName = seg.name.trim();

			// Only look in __TEXT segment
			if (segName !== "__TEXT") continue;

			for (const sect of seg.sections) {
				const sectName = sect.sectname.trim();

				// Include __text section (main code) and __stubs/__stub_helper (PLT stubs)
				if (
					sectName === "__text" ||
					sectName === "__stubs" ||
					sectName === "__stub_helper"
				) {
					// Ensure section has data (size > 0 and valid offset)
					if (Number(sect.size) > 0 && sect.offset > 0) {
						sections.push({
							segname: sect.segname.trim(),
							sectname: sectName,
							virtualAddr: BigInt(sect.addr),
							fileOffset: sect.offset,
							size: Number(sect.size),
							arch
						});
					}
				}
			}
		}

		return sections;
	}

	/** Trim trailing instructions after the last return instruction. */
	private trimAfterReturn(instructions: DisasmInstruction[]): DisasmInstruction[] {
		for (let j = instructions.length - 1; j >= 0; j--) {
			const m = instructions[j]!.mnemonic.toLowerCase();
			if (
				m === "ret" ||
				m === "retaa" ||
				m === "retab" ||
				m === "eret" ||
				(m === "bx" && instructions[j]!.operands.trim() === "lr") ||
				(m === "pop" && instructions[j]!.operands.includes("pc"))
			) {
				return instructions.slice(0, j + 1);
			}
		}
		return instructions;
	}

	// Cache for row index per section
	private disasmRowIndexCache = new Map<
		number,
		{ totalVisualRows: number; entries: Array<{ byteOffset: number; cumulativeRow: number }> }
	>();

	/** Build a row index mapping visual rows to byte offsets for a section. */
	async buildDisasmRowIndex(sectionIndex: number): Promise<{
		totalVisualRows: number;
		entries: Array<{ byteOffset: number; cumulativeRow: number }>;
	}> {
		const cached = this.disasmRowIndexCache.get(sectionIndex);
		if (cached) return cached;

		const sections = this.getDisasmSections();
		const section = sections[sectionIndex];
		if (!section) return { totalVisualRows: 0, entries: [] };

		if (!isCapstoneReady()) {
			await initCapstone();
		}

		const funcStarts = this.getFunctionStarts();
		const labelMap = this.buildLabelMap();
		const sectionStart = section.virtualAddr;
		const sectionEnd = section.virtualAddr + BigInt(section.size);

		// Get function boundaries within this section
		const boundaries: bigint[] = [];
		for (const addr of funcStarts) {
			if (addr >= sectionStart && addr < sectionEnd) {
				boundaries.push(addr);
			}
		}
		boundaries.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

		if (boundaries.length === 0) {
			boundaries.push(sectionStart);
		}

		// Disassemble each function, apply trimming, count visual rows (insns + labels)
		const entries: Array<{ byteOffset: number; cumulativeRow: number }> = [];
		let cumulativeRow = 0;

		for (let i = 0; i < boundaries.length; i++) {
			const funcAddr = boundaries[i]!;
			const nextAddr = i + 1 < boundaries.length ? boundaries[i + 1]! : sectionEnd;
			const funcSize = Number(nextAddr - funcAddr);
			const funcByteOffset = Number(funcAddr - sectionStart);
			const funcFileOffset = section.fileOffset + funcByteOffset;

			entries.push({ byteOffset: funcByteOffset, cumulativeRow });

			const hexResult = this.readHex(funcFileOffset, funcSize);
			if (!hexResult || hexResult.data.length === 0) continue;

			try {
				const bytes = new Uint8Array(hexResult.data);
				let instructions = disassembleChunk(bytes, funcAddr, section.arch, funcFileOffset);
				instructions = this.trimAfterReturn(instructions);

				for (const insn of instructions) {
					// Label row adds an extra visual row
					if (labelMap.has(insn.address)) cumulativeRow++;
					cumulativeRow++; // instruction row
				}
			} catch {
				// Skip functions that fail
			}
		}

		const result = { totalVisualRows: cumulativeRow, entries };
		this.disasmRowIndexCache.set(sectionIndex, result);
		return result;
	}

	/** Count total visual rows in a section (delegates to buildDisasmRowIndex). */
	async getDisasmInsnCount(sectionIndex: number): Promise<number> {
		const index = await this.buildDisasmRowIndex(sectionIndex);
		return index.totalVisualRows;
	}

	/** Disassemble a chunk of code from a section. */
	async readDisasm(
		sectionIndex: number,
		byteOffset: number,
		maxBytes: number
	): Promise<{
		instructions: DisasmInstruction[];
		bytesConsumed: number;
		instructionBytes: number;
	} | null> {
		const sections = this.getDisasmSections();
		const section = sections[sectionIndex];
		if (!section) return null;

		// Ensure Capstone is initialized
		if (!isCapstoneReady()) {
			await initCapstone();
		}

		// Cap read size
		const MAX_LEN = 65536;
		const safeMaxBytes = Math.min(Math.max(0, maxBytes), MAX_LEN);
		const safeOffset = Math.max(0, byteOffset);

		// Don't read past section end
		const remaining = section.size - safeOffset;
		if (remaining <= 0) {
			return { instructions: [], bytesConsumed: 0, instructionBytes: 0 };
		}
		const readLen = Math.min(safeMaxBytes, remaining);

		// Read bytes from file
		const hexResult = this.readHex(section.fileOffset + safeOffset, readLen);
		if (!hexResult || hexResult.data.length === 0) {
			return { instructions: [], bytesConsumed: 0, instructionBytes: 0 };
		}

		const bytes = new Uint8Array(hexResult.data);
		const baseAddr = section.virtualAddr + BigInt(safeOffset);
		const baseFileOffset = section.fileOffset + safeOffset;
		const endAddr = baseAddr + BigInt(readLen);

		const labelMap = this.buildLabelMap();

		// Get function boundaries within the requested range
		const funcStarts = this.getFunctionStarts();
		const rangeStarts: bigint[] = [];
		for (const addr of funcStarts) {
			if (addr >= baseAddr && addr < endAddr) {
				rangeStarts.push(addr);
			}
		}
		rangeStarts.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

		// If no function starts found, fall back to disassembling the whole chunk
		if (rangeStarts.length === 0) {
			// Include baseAddr as a starting point if it's the section start
			rangeStarts.push(baseAddr);
		}

		// Disassemble function-by-function to skip embedded data between functions
		const allInstructions: DisasmInstruction[] = [];

		for (let i = 0; i < rangeStarts.length; i++) {
			const funcAddr = rangeStarts[i]!;
			// Function ends at the next function start, or end of read range
			const nextFuncAddr = i + 1 < rangeStarts.length ? rangeStarts[i + 1]! : endAddr;
			const funcSize = Number(nextFuncAddr - funcAddr);
			const funcOffsetInBuf = Number(funcAddr - baseAddr);

			if (funcOffsetInBuf < 0 || funcOffsetInBuf >= bytes.length) continue;

			const funcBytes = bytes.subarray(funcOffsetInBuf, funcOffsetInBuf + funcSize);
			if (funcBytes.length === 0) continue;

			const funcFileOffset = baseFileOffset + funcOffsetInBuf;

			try {
				let instructions = disassembleChunk(
					funcBytes,
					funcAddr,
					section.arch,
					funcFileOffset
				);

				instructions = this.trimAfterReturn(instructions);

				for (const insn of instructions) {
					const label = labelMap.get(insn.address);
					if (label) {
						insn.label = label;
					}
					allInstructions.push(insn);
				}
			} catch {
				// Skip functions that fail to disassemble
			}
		}

		const instructionBytes = allInstructions.reduce((sum, insn) => sum + insn.size, 0);
		return { instructions: allInstructions, bytesConsumed: readLen, instructionBytes };
	}

	/** Search disassembled code for a query. */
	async searchDisasm(
		sectionIndex: number,
		query: string,
		isRegex = false,
		maxResults = 1000
	): Promise<{
		matches: Array<{ address: bigint; offset: number; preview: string }>;
		hasMore: boolean;
	}> {
		const sections = this.getDisasmSections();
		const section = sections[sectionIndex];
		if (!section || !query) {
			return { matches: [], hasMore: false };
		}

		// Ensure Capstone is initialized
		if (!isCapstoneReady()) {
			await initCapstone();
		}

		const matches: Array<{ address: bigint; offset: number; preview: string }> = [];
		const CHUNK_SIZE = 65536;

		// Build matcher
		let matcher: (mnemonic: string, operands: string, addrHex: string) => boolean;
		if (isRegex) {
			try {
				const re = new RegExp(query, "i");
				matcher = (m, o, a) => re.test(m) || re.test(o) || re.test(a);
			} catch {
				return { matches: [], hasMore: false };
			}
		} else {
			const lowerQuery = query.toLowerCase();
			matcher = (m, o, a) =>
				m.toLowerCase().includes(lowerQuery) ||
				o.toLowerCase().includes(lowerQuery) ||
				a.toLowerCase().includes(lowerQuery);
		}

		// Scan through section in chunks
		let offset = 0;
		while (offset < section.size && matches.length < maxResults) {
			const result = await this.readDisasm(sectionIndex, offset, CHUNK_SIZE);
			if (!result || result.instructions.length === 0) break;

			for (const insn of result.instructions) {
				const addrHex = insn.address.toString(16);
				if (matcher(insn.mnemonic, insn.operands, addrHex)) {
					matches.push({
						address: insn.address,
						offset: insn.offset,
						preview: `${insn.mnemonic} ${insn.operands}`.trim()
					});
					if (matches.length >= maxResults) break;
				}
			}

			offset += result.bytesConsumed;
			if (result.bytesConsumed === 0) break;

			// Yield to event loop periodically
			await yieldToEventLoop();
		}

		return {
			matches,
			hasMore: offset < section.size && matches.length >= maxResults
		};
	}

	/** Build a map of symbol addresses to names for labeling disassembly. */
	private buildSymbolMap(): Map<bigint, string> {
		const map = new Map<bigint, string>();
		if (!this.result) return map;

		for (const sym of this.result.symbols) {
			if (sym.address !== 0n && sym.name) {
				// Prefer exported/local symbols over imports for labels
				const existing = map.get(sym.address);
				if (!existing || sym.type !== "imported") {
					map.set(sym.address, sym.name);
				}
			}
		}

		return map;
	}

	/**
	 * Build a label map that includes both symbol names and sub_XXXX
	 * for function starts without a symbol name.
	 */
	private buildLabelMap(): Map<bigint, string> {
		const map = this.buildSymbolMap();
		const funcStarts = this.getFunctionStarts();

		for (const addr of funcStarts) {
			if (!map.has(addr)) {
				map.set(addr, `sub_${addr.toString(16).toUpperCase()}`);
			}
		}

		return map;
	}

	// Cache for function starts
	private functionStartsCache: bigint[] | null = null;

	/** Get function start addresses from LC_FUNCTION_STARTS. */
	getFunctionStarts(): bigint[] {
		if (this.functionStartsCache) return this.functionStartsCache;
		if (!this.result) return [];

		const binaryPath = this.getActiveBinaryPath();
		if (!binaryPath) return [];

		try {
			const fileBuf = fs.readFileSync(binaryPath);
			let buffer = fileBuf.buffer.slice(
				fileBuf.byteOffset,
				fileBuf.byteOffset + fileBuf.byteLength
			);

			// Handle fat binary — select the same arch we analyzed
			const fatResult = parseFatHeader(buffer);
			if (fatResult.ok) {
				const selectedArch =
					fatResult.data.find((a) => a.cputype === this.result!.headers.machO.cputype) ??
					fatResult.data[0];
				if (selectedArch && selectedArch.offset > 0) {
					buffer = buffer.slice(
						selectedArch.offset,
						selectedArch.offset + selectedArch.size
					);
				}
			}

			// Parse Mach-O header
			const headerResult = parseMachOHeader(buffer, 0);
			if (!headerResult.ok) return [];

			const machO = headerResult.data;
			const headerSize = machO.is64Bit ? 32 : 28;
			const lcOffset = machO.offset + headerSize;

			// Parse load commands to get functionStartsInfo
			const lcResult = parseLoadCommands(
				buffer,
				lcOffset,
				machO.header.ncmds,
				machO.header.sizeofcmds,
				machO.littleEndian,
				machO.is64Bit
			);

			if (lcResult.functionStartsInfo) {
				// Find __TEXT segment for base address
				const textSeg = lcResult.segments.find((s) => s.segname.trim() === "__TEXT");
				if (textSeg) {
					// Parse function starts
					const funcStarts = parseFunctionStarts(
						buffer,
						lcResult.functionStartsInfo.offset,
						lcResult.functionStartsInfo.size,
						textSeg.vmaddr
					);

					// Strip Thumb bit (bit 0) for ARM binaries so addresses match
					// the symbol table (which doesn't include the Thumb bit)
					const arch = cpuTypeToArch(machO.header.cputype);
					const cleaned = arch === "arm" ? funcStarts.map((a) => a & ~1n) : funcStarts;

					this.functionStartsCache = cleaned;
					return cleaned;
				}
			}

			// Fall back to symbol addresses for older binaries without LC_FUNCTION_STARTS
			return this.getFunctionStartsFromSymbols();
		} catch {
			// Fall back to symbols on any error
			return this.getFunctionStartsFromSymbols();
		}
	}

	/** Fall back: derive function addresses from symbol table (for older binaries). */
	private getFunctionStartsFromSymbols(): bigint[] {
		if (!this.result) return [];

		// Get __text section bounds
		let textStart = 0n;
		let textEnd = 0n;
		for (const lc of this.result.headers.loadCommands) {
			if (lc.type === "segment" && lc.segment.name.trim() === "__TEXT") {
				for (const sect of lc.segment.sections) {
					if (sect.sectname.trim() === "__text") {
						textStart = BigInt(sect.addr);
						textEnd = textStart + BigInt(sect.size);
						break;
					}
				}
			}
		}

		if (textEnd === 0n) return [];

		// Collect non-imported symbol addresses within __text section
		const addrs = new Set<bigint>();
		for (const sym of this.result.symbols) {
			if (sym.type === "imported") continue;
			if (sym.address >= textStart && sym.address < textEnd) {
				addrs.add(sym.address);
			}
		}

		const sorted = Array.from(addrs).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
		this.functionStartsCache = sorted;
		return sorted;
	}

	/** Get function starts for a specific disasm section as {address, name} pairs. */
	getDisasmFunctions(sectionIndex: number): Array<{ address: bigint; name: string }> {
		const sections = this.getDisasmSections();
		const section = sections[sectionIndex];
		if (!section) return [];

		const funcStarts = this.getFunctionStarts();
		const symbolMap = this.buildSymbolMap();

		const sectionStart = section.virtualAddr;
		const sectionEnd = section.virtualAddr + BigInt(section.size);

		const functions: Array<{ address: bigint; name: string }> = [];

		for (const addr of funcStarts) {
			if (addr >= sectionStart && addr < sectionEnd) {
				const symName = symbolMap.get(addr);
				functions.push({
					address: addr,
					name: symName ?? `sub_${addr.toString(16).toUpperCase()}`
				});
			}
		}

		return functions;
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
						id: lib.name,
						label: libBasename(lib.name),
						type: "library",
						category: cat,
						weak: lib.weak,
						version: lib.currentVersion
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
			const binaryType = isTweak ? ("tweak" as const) : bin.type;
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
							id: lib.name,
							label: libBasename(lib.name),
							type: "library",
							category: cat,
							weak: lib.weak,
							version: lib.currentVersion
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
				fileBuf.byteOffset + fileBuf.byteLength
			);

			// Handle fat binary — select arm64 or first arch
			const fatResult = parseFatHeader(buffer);
			const headerOffset = 0;
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
			const headerSize = machO.is64Bit ? 32 : 28;
			const lcOffset = machO.offset + headerSize;
			const lcResult = parseLoadCommands(
				buffer,
				lcOffset,
				machO.header.ncmds,
				machO.header.sizeofcmds,
				machO.littleEndian,
				machO.is64Bit
			);

			return lcResult.libraries.map((lib) => ({
				name: lib.name,
				currentVersion: lib.currentVersion,
				compatVersion: lib.compatVersion,
				weak: lib.weak
			}));
		} catch {
			return [];
		}
	}

	// ── Cross-binary search ────────────────────────────────────────────

	/** Build (or return cached) lightweight per-binary search index. */
	private async ensureSearchIndex(
		progressCallback: (phase: string, percent: number) => void
	): Promise<Map<number, BinarySearchIndex>> {
		if (this.searchIndex) return this.searchIndex;

		this.searchIndex = new Map();
		for (let i = 0; i < this.binaries.length; i++) {
			const bin = this.binaries[i]!;
			progressCallback(
				`Indexing ${bin.name}...`,
				Math.round((i / this.binaries.length) * 100)
			);
			await yieldToEventLoop();
			try {
				const result = await analyseBinaryFile(bin.path, () => {}, 0);
				this.searchIndex.set(i, {
					classes: result.classes.map((c) => c.name),
					strings: result.strings.map((s) => s.value),
					symbols: result.symbols.map((s) => s.name),
					symbolTypes: result.symbols.map((s) => s.type),
					libraries: result.libraries.map((l) => l.name)
				});
			} catch {
				this.searchIndex.set(i, {
					classes: [],
					strings: [],
					symbols: [],
					symbolTypes: [],
					libraries: []
				});
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
		caseSensitive?: boolean
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
						match: value
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
		progressCallback: (phase: string, percent: number) => void
	): Promise<AnalysisResult> {
		const errors: string[] = [];

		// Step 1: Extract IPA (skip if a valid cache exists)
		const cacheDir = getCacheDir(ipaPath);
		const ext = await extractToCache(cacheDir, (dest) => {
			progressCallback("Extracting IPA...", 0);
			return extractIPA(ipaPath, dest);
		});
		if (ext.cached) {
			progressCallback("Using cached extraction...", 5);
		} else if (!ext.result.success) {
			throw new Error((ext.result as { success: false; error: string }).error);
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
		this.fatSliceOffset = binaryResult.fatSliceOffset;

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
		const extraBinaryFindings: SecurityFinding[] = [];
		const settings = loadSettings();
		if (settings.scanAllBinaries && binaries.length > 1) {
			progressCallback("Scanning additional binaries...", 85);
			await yieldToEventLoop();
			for (let i = 1; i < binaries.length; i++) {
				try {
					const extraResult = await analyseBinaryFile(
						binaries[i]!.path,
						() => {}, // silent progress
						0
					);
					// Tag findings with source binary name
					for (const finding of extraResult.security.findings) {
						extraBinaryFindings.push({
							...finding,
							source: binaries[i]!.name
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
				...extraBinaryFindings
			],
			hardening: binaryResult.security.hardening
		};

		// Step 16: Build file tree (start from the .app bundle directly)
		progressCallback("Building file tree...", 95);
		await yieldToEventLoop();
		const files = buildFileTree(appBundlePath);

		// Assemble final result
		const appName = path.basename(appBundlePath, ".app");
		const result = buildAnalysisResult(
			binaryResult,
			{
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
							try {
								return fs.statSync(b.path).size;
							} catch {
								return 0;
							}
						})()
					}))
				},
				...binaryOverviewFields(binaryResult),
				infoPlist: infoPlistData,
				appFrameworks: appFrameworks.length > 0 ? appFrameworks : undefined
			},
			{
				localisationStrings,
				entitlements: finalEntitlements,
				infoPlist: infoPlistData,
				security: mergedSecurity,
				files
			}
		);

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
		cpuSubtype?: number
	): Promise<AnalysisResult> {
		if (!this.result) {
			throw new Error("No previous analysis. Run analyseFile first.");
		}

		if (binaryIndex < 0 || binaryIndex >= this.binaries.length) {
			throw new Error(
				`Binary index ${binaryIndex} out of range (0-${this.binaries.length - 1})`
			);
		}

		const binary = this.binaries[binaryIndex]!;
		this.activeBinaryName = binary.name;
		this.functionStartsCache = null; // Clear caches when switching binaries
		this.disasmRowIndexCache.clear();
		const binaryResult = await analyseBinaryFile(
			binary.path,
			progressCallback,
			0,
			cpuType,
			cpuSubtype
		);
		this.fatSliceOffset = binaryResult.fatSliceOffset;

		// Rebuild the result with the new binary data but keep IPA-level info
		const result = buildAnalysisResult(
			binaryResult,
			{
				...this.result.overview,
				...binaryOverviewFields(binaryResult),
				teamId: binaryResult.teamId ?? this.result.overview.teamId
			},
			{
				localisationStrings: this.result.localisationStrings,
				entitlements:
					binaryResult.entitlements.length > 0
						? binaryResult.entitlements
						: this.result.entitlements,
				infoPlist: this.result.infoPlist,
				files: this.result.files
			}
		);

		this.result = result;
		return result;
	}

	// ── Analyse bare Mach-O / dylib ──────────────────────────────────

	/** Analyse a bare Mach-O executable or dylib (no container). */
	async analyseMachO(
		filePath: string,
		progressCallback: (phase: string, percent: number) => void
	): Promise<AnalysisResult> {
		this.sourceType = "macho";
		this.filePath = filePath;
		this.appBundlePath = null;
		this.infoPlist = {};

		const fileName = path.basename(filePath);
		let fileSize = 0;
		try {
			fileSize = fs.statSync(filePath).size;
		} catch {
			/* ignore */
		}

		// Set up single-binary list for binary switching
		this.binaries = [
			{
				name: fileName,
				path: filePath,
				type: "main"
			}
		];
		this.searchIndex = null;
		this.activeBinaryName = fileName;

		progressCallback("Analysing binary...", 10);
		const binaryResult = await analyseBinaryFile(filePath, progressCallback, 10);
		this.fatSliceOffset = binaryResult.fatSliceOffset;

		const result = buildAnalysisResult(binaryResult, {
			sourceType: "macho",
			filePath,
			ipa: {
				bundlePath: path.dirname(filePath),
				appName: fileName,
				binaries: [
					{
						name: fileName,
						path: filePath,
						type: "main",
						size: fileSize
					}
				]
			},
			...binaryOverviewFields(binaryResult)
		});

		this.result = result;
		progressCallback("Analysis complete", 100);
		return result;
	}

	// ── Analyse DEB package ──────────────────────────────────────────

	/** Analyse a DEB package — extract, parse control metadata, and analyse binaries. */
	async analyseDEB(
		debPath: string,
		progressCallback: (phase: string, percent: number) => void
	): Promise<AnalysisResult> {
		this.sourceType = "deb";
		this.filePath = debPath;
		this.infoPlist = {};

		// Step 1: Extract DEB (skip if a valid cache exists)
		const cacheDir = getCacheDir(debPath);
		const ext = await extractToCache(cacheDir, (dest) => {
			progressCallback("Extracting DEB package...", 0);
			return extractDEB(debPath, dest);
		});

		if (!ext.cached && !ext.result.success) {
			throw new Error(ext.result.error);
		}

		// Re-derive metadata from the stable cache directory.
		// Data is already extracted so this just parses control + discovers binaries.
		const extraction = await extractDEB(debPath, cacheDir);
		if (!extraction.success) throw new Error(extraction.error);

		this.extractedDir = cacheDir;
		this.appBundlePath = extraction.dataDir;

		// Convert DEB binaries to BinaryInfo for the binary selector
		this.binaries = extraction.binaries.map((b: DEBBinaryInfo) => ({
			name: b.name,
			path: b.path,
			type: b.type === "tweak" ? ("main" as const) : ("framework" as const)
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
		this.fatSliceOffset = binaryResult.fatSliceOffset;

		// Step 3: Scan additional binaries if setting enabled
		const debExtraFindings: SecurityFinding[] = [];
		const debSettings = loadSettings();
		if (debSettings.scanAllBinaries && this.binaries.length > 1) {
			progressCallback("Scanning additional binaries...", 80);
			await yieldToEventLoop();
			for (let i = 1; i < this.binaries.length; i++) {
				try {
					const extraResult = await analyseBinaryFile(
						this.binaries[i]!.path,
						() => {},
						0
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
			hardening: binaryResult.security.hardening
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

		const result = buildAnalysisResult(
			binaryResult,
			{
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
							try {
								return fs.statSync(b.path).size;
							} catch {
								return 0;
							}
						})()
					}))
				},
				...binaryOverviewFields(binaryResult)
			},
			{
				localisationStrings,
				security: debMergedSecurity,
				files
			}
		);

		// Enrich hooks with tweak filter plist data (target bundles)
		try {
			const mainBinaryName = path.basename(mainBinary.path, ".dylib");
			// Look for filter plist next to the dylib
			const filterPlistPath = path.join(
				path.dirname(mainBinary.path),
				mainBinaryName + ".plist"
			);
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
		progressCallback: (phase: string, percent: number) => void
	): Promise<AnalysisResult> {
		this.sourceType = "app";
		this.filePath = appPath;

		// macOS .app bundles use Contents/ structure
		const isMacOS = isMacOSAppBundle(appPath);
		this.appBundlePath = appPath;

		// Step 1: Discover binaries
		progressCallback("Discovering binaries...", 5);
		await yieldToEventLoop();

		const binaries = isMacOS ? discoverMacOSBinaries(appPath) : discoverBinaries(appPath);
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
		this.fatSliceOffset = binaryResult.fatSliceOffset;

		// Entitlements from code signature
		const finalEntitlements = binaryResult.entitlements;

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
		const extraBinaryFindings: SecurityFinding[] = [];
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
			findings: [
				...binaryResult.security.findings,
				...bundleFindings,
				...extraBinaryFindings
			],
			hardening: binaryResult.security.hardening
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
		const result = buildAnalysisResult(
			binaryResult,
			{
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
							try {
								return fs.statSync(b.path).size;
							} catch {
								return 0;
							}
						})()
					}))
				},
				...binaryOverviewFields(binaryResult),
				infoPlist: infoPlistData,
				appFrameworks: appFrameworks.length > 0 ? appFrameworks : undefined
			},
			{
				localisationStrings,
				entitlements: finalEntitlements,
				infoPlist: infoPlistData,
				security: mergedSecurity,
				files
			}
		);

		this.result = result;
		progressCallback("Analysis complete", 100);
		return result;
	}

	// ── Unified file analysis entry point ────────────────────────────

	/** Analyse any supported file — auto-detects type and dispatches to the right method. */
	async analyseFile(
		filePath: string,
		progressCallback: (phase: string, percent: number) => void
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

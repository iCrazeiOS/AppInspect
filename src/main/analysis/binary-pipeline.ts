/**
 * Per-binary analysis pipeline.
 *
 * Sequences the parser modules (steps 4-13) to turn a single Mach-O file into a
 * BinaryAnalysisResult, then assembles it into a full AnalysisResult. Gracefully
 * continues when individual parsers fail.
 */

import * as fs from "node:fs";

import type {
	AnalysisResult,
	BinaryHardening,
	BuildVersion,
	EncryptionInfo,
	Entitlement,
	FatArch,
	FileEntry,
	HookInfo,
	LinkedLibrary,
	LocalisationString,
	MachOHeader,
	ObjCClass,
	ObjCProtocol,
	PlistValue,
	SecurityFinding,
	LoadCommand as SharedLoadCommand,
	StringEntry,
	SymbolEntry
} from "../../shared/types";
import { buildFixupMap } from "../parser/chained-fixups";
import { parseCodeSignature } from "../parser/codesign";
import type { LoadCommandsResult, Section64 } from "../parser/load-commands";
import { parseLoadCommands } from "../parser/load-commands";
import type { MachOFile } from "../parser/macho";
import { CPU_TYPE_ARM64, parseFatHeader, parseMachOHeader } from "../parser/macho";
import { enrichMethodsFromSymbols, extractObjCMetadata } from "../parser/objc";
import { extractStrings } from "../parser/strings";
import type { SymbolEntry as ParserSymbol } from "../parser/symbols";
import { parseSymbolTable } from "../parser/symbols";
import { buildStringXrefMap, formatFunctionName, parseFunctionStarts } from "../parser/xrefs";
import {
	convertEntitlements,
	convertLibraries,
	convertLoadCommands,
	convertStrings,
	convertSymbols
} from "./conversion";
import { detectHooks } from "./hook-detection";
import { getBinaryHardening, runSecurityScan } from "./security";

/** Yield to the event loop so the UI stays responsive during heavy parsing. */
export const yieldToEventLoop = (): Promise<void> =>
	new Promise((resolve) => setImmediate(resolve));

export interface BinaryAnalysisResult {
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

/**
 * Terminal analysis steps that produce standalone outputs and feed none of the
 * name sources (libraries, symbols, strings, classes). Set a flag to skip that
 * step and yield its empty default. Used by the search index, which keeps only
 * names — see `ensureSearchIndex`. Defaults to running everything.
 */
export interface ScanOptions {
	skipCodesign?: boolean; // code signature + entitlements + teamId
	skipSecurity?: boolean; // security findings + hardening
	skipHooks?: boolean; // hook detection
}

export async function analyseBinaryFile(
	binaryPath: string,
	progressCallback: (phase: string, percent: number) => void,
	basePercent: number,
	preferredCpuType?: number,
	preferredCpuSubtype?: number,
	options: ScanOptions = {}
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

	// Step 10b: Recover method selectors from the symbol table when the method
	// list left them empty (common with dyld_shared_cache extracted binaries).
	enrichMethodsFromSymbols(classes, rawSymbols);

	// Step 11: Parse code signature + entitlements
	progressCallback("Parsing code signature...", basePercent + 50);
	await yieldToEventLoop();
	if (!options.skipCodesign) {
		if (lcResult.codeSignatureInfo) {
			const csResult = parseCodeSignature(
				buffer,
				lcResult.codeSignatureInfo.offset,
				lcResult.codeSignatureInfo.size
			);
			if (csResult.ok) {
				if (csResult.data.entitlements) {
					entitlements = convertEntitlements(csResult.data.entitlements);
				}
				if (csResult.data.codeDirectory?.teamID) {
					teamId = csResult.data.codeDirectory.teamID;
				}
			} else {
				errors.push(`Code signature parse error: ${csResult.error}`);
			}
		}
	}

	// Step 12: Run security scan (first pass — without xrefs)
	progressCallback("Running security scan...", basePercent + 52);
	await yieldToEventLoop();
	if (!options.skipSecurity) {
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
	if (!options.skipHooks) {
		hooks = detectHooks(symbols, classes, strings);
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
export function binaryOverviewFields(br: BinaryAnalysisResult) {
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
export function buildAnalysisResult(
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

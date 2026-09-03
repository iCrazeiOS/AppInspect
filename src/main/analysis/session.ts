/**
 * Analysis session.
 *
 * Isolated, stateful driver for a single loaded container. Each instance holds
 * its own parsed result, extracted directory, discovered binaries, and search
 * index, so multiple analyses can run concurrently without interfering. Wraps
 * the free-function pipeline/hex/graph helpers with the session's state.
 */

import * as fs from "node:fs";
import * as path from "node:path";

import type {
	AnalysisResult,
	LibraryGraphData,
	LocalisationString,
	PlistValue,
	SecurityFinding,
	SourceType
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
import { parseInfoPlist, parseMobileprovision, parsePlistBuffer } from "../parser/plist";
import type { BinaryAnalysisResult } from "./binary-pipeline";
import {
	analyseBinaryFile,
	binaryOverviewFields,
	buildAnalysisResult,
	yieldToEventLoop
} from "./binary-pipeline";
import { extractLocalisationStrings, readBundleFiles } from "./bundle-files";
import { extractToCache, getCacheDir } from "./cache";
import { assembleBinaryList, scanAdditionalBinaries } from "./containers/shared";
import { convertEntitlements } from "./conversion";
import { buildFileTree } from "./file-tree";
import { detectFileType } from "./file-type";
import { detectAppFrameworks } from "./framework-detection";
import { type HexReadResult, readHexAt, searchHexInFile } from "./hex";
import { buildLibraryGraph } from "./library-graph";
import type { BinarySearchIndex, CrossBinarySearchResult, SearchableTab } from "./search-index";
import { scanBundleFileContents } from "./security";

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
	/** Lazily-computed results for non-active binaries, keyed by binary index. */
	private binaryCache = new Map<number, { result: AnalysisResult; fatSliceOffset: number }>();

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
	readHex(offset: number, length: number): HexReadResult | null {
		return readHexAt(this.getActiveBinaryPath(), this.fatSliceOffset, offset, length);
	}

	/** Read raw bytes from a specific binary without changing the active one. */
	async readHexForBinary(
		binaryIndex: number,
		offset: number,
		length: number
	): Promise<HexReadResult | null> {
		const { path, fatSliceOffset } = await this.resolveBinary(binaryIndex);
		return readHexAt(path, fatSliceOffset, offset, length);
	}

	/** Search for a byte pattern within a region of the active binary. */
	searchHex(
		regionOffset: number,
		regionSize: number,
		pattern: number[],
		caseInsensitive = false
	): { matches: number[] } | null {
		return searchHexInFile(
			this.getActiveBinaryPath(),
			this.fatSliceOffset,
			regionOffset,
			regionSize,
			pattern,
			caseInsensitive
		);
	}

	// ── Library dependency graph ────────────────────────────────────────

	/** Build a dependency graph across all binaries in the container. */
	async getLibraryGraph(): Promise<LibraryGraphData> {
		return buildLibraryGraph(this.binaries, this.result, this.activeBinaryName);
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
				// Index-only light path: the index keeps solely names, so skip the
				// terminal steps (codesign/security/hooks) that feed none of them.
				// Every other caller passes no options and gets the full result.
				const result = await analyseBinaryFile(
					bin.path,
					() => {},
					0,
					undefined,
					undefined,
					{
						skipCodesign: true,
						skipSecurity: true,
						skipHooks: true
					}
				);
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

	// ── Analyse IPA ───────────────────────────────────────────────────

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
		const extraBinaryFindings = await scanAdditionalBinaries(binaries, progressCallback, 85);

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
					binaries: assembleBinaryList(binaries)
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
		const binaryResult = await analyseBinaryFile(
			binary.path,
			progressCallback,
			0,
			cpuType,
			cpuSubtype
		);
		this.fatSliceOffset = binaryResult.fatSliceOffset;

		const result = this.composeBinaryResult(binaryResult);
		this.result = result;
		return result;
	}

	/**
	 * Resolve a binary's analysis result without changing the active binary.
	 * Returns the active result directly, otherwise lazily computes and caches it.
	 */
	async resolveBinary(
		binaryIndex: number
	): Promise<{ result: AnalysisResult; fatSliceOffset: number; path: string }> {
		if (!this.result) {
			throw new Error("No previous analysis. Run analyseFile first.");
		}
		if (binaryIndex < 0 || binaryIndex >= this.binaries.length) {
			throw new Error(
				`Binary index ${binaryIndex} out of range (0-${this.binaries.length - 1})`
			);
		}

		const binary = this.binaries[binaryIndex]!;
		if (binary.name === this.activeBinaryName) {
			return { result: this.result, fatSliceOffset: this.fatSliceOffset, path: binary.path };
		}

		let entry = this.binaryCache.get(binaryIndex);
		if (!entry) {
			const binaryResult = await analyseBinaryFile(binary.path, () => {}, 0);
			entry = {
				result: this.composeBinaryResult(binaryResult),
				fatSliceOffset: binaryResult.fatSliceOffset
			};
			this.binaryCache.set(binaryIndex, entry);
		}
		return { ...entry, path: binary.path };
	}

	/** Merge per-binary analysis with the container-level info held on the session. */
	private composeBinaryResult(binaryResult: BinaryAnalysisResult): AnalysisResult {
		const base = this.result!;
		return buildAnalysisResult(
			binaryResult,
			{
				...base.overview,
				...binaryOverviewFields(binaryResult),
				teamId: binaryResult.teamId ?? base.overview.teamId
			},
			{
				localisationStrings: base.localisationStrings,
				entitlements:
					binaryResult.entitlements.length > 0
						? binaryResult.entitlements
						: base.entitlements,
				infoPlist: base.infoPlist,
				files: base.files
			}
		);
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
		const debExtraFindings = await scanAdditionalBinaries(this.binaries, progressCallback, 80);

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
					binaries: assembleBinaryList(this.binaries)
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
		const extraBinaryFindings = await scanAdditionalBinaries(binaries, progressCallback, 85);

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
					binaries: assembleBinaryList(binaries)
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

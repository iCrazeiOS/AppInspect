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

import {
	FILE_PREVIEW_BYTES,
	FILE_PREVIEW_FULL_BYTES,
	FILE_PREVIEW_IMAGE_BYTES,
	imageMimeType
} from "../../shared/file-preview";
import { compileSafeRegex } from "../../shared/safe-regex";
import type {
	AnalysisResult,
	AsarEntry,
	ElectronInfo,
	FilePreviewContent,
	LibraryGraphData,
	LocalisationString,
	PlistValue,
	SecurityFinding,
	SizeTreeNode
} from "../../shared/types";
import type { DEBBinaryInfo } from "../deb/extractor";
import { extractDEB } from "../deb/extractor";
import type { AsarArchive } from "../electron/asar";
import { readAsarFile as readAsarArchiveFile, readAsarHeader } from "../electron/asar";
import { detectElectron } from "../electron/detect";
import { readAsarTextFiles, readAsarUnpackedHtmlFiles, scanElectron } from "../electron/scan";
import type { BinaryInfo } from "../ipa/extractor";
import {
	discoverAppBundle,
	discoverBinaries,
	discoverMacOSBinaries,
	extractIPA,
	isMacOSAppBundle
} from "../ipa/extractor";
import { parseInfoPlist, parseMobileprovision, parsePlistBuffer } from "../parser/plist";
import { discoverXCFramework, findXCFramework, isXCFrameworkPath } from "../xcframework/discovery";
import type { BinaryAnalysisResult } from "./binary-pipeline";
import {
	analyseBinaryFile,
	binaryOverviewFields,
	buildAnalysisResult,
	yieldToEventLoop
} from "./binary-pipeline";
import { extractLocalisationStrings, readBundleFiles } from "./bundle-files";
import { extractToCache, getCacheBase, getCacheDir } from "./cache";
import { assembleBinaryList, scanAdditionalBinaries } from "./containers/shared";
import { convertEntitlements } from "./conversion";
import { findBundleDebugArtifacts } from "./debug-artifacts";
import { buildFilePreview, readFilePreview } from "./file-preview";
import { buildFileTree } from "./file-tree";
import { detectFileType } from "./file-type";
import { discoverFolderBinaries } from "./folder";
import { detectAppFrameworks } from "./framework-detection";
import { type HexReadResult, readHexAt, searchHexInFile } from "./hex";
import { buildLibraryGraph } from "./library-graph";
import type { BinarySearchIndex, CrossBinarySearchResult, SearchableTab } from "./search-index";
import { scanBundleFileContents } from "./security";
import { buildSizeTree } from "./size-tree";

export class AnalysisSession {
	// ── State ──────────────────────────────────────────────────────────
	private result: AnalysisResult | null = null;
	private extractedDir: string | null = null;
	private appBundlePath: string | null = null;
	private binaries: BinaryInfo[] = [];
	private filePath: string = "";
	private activeBinaryName: string = "";
	private fatSliceOffset: number = 0;
	private searchIndex: Map<number, BinarySearchIndex> | null = null;
	private asarArchive: AsarArchive | null = null;
	private electronFindings: SecurityFinding[] = [];
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

	/** Absolute roots the UI may reveal/open: the input file plus extracted dirs. */
	getAllowedOpenRoots(): string[] {
		return [this.filePath, this.extractedDir, this.appBundlePath].filter(
			(p): p is string => typeof p === "string" && p.length > 0
		);
	}

	/** Cache entries this session reads from: its extraction and any extracted DEBs in a folder. */
	getCacheDirs(): string[] {
		const base = getCacheBase();
		const dirs = new Set<string>();
		if (this.extractedDir) dirs.add(this.extractedDir);
		for (const binary of this.binaries) {
			const rel = path.relative(base, binary.path);
			if (rel.startsWith("..") || path.isAbsolute(rel)) continue;
			const entry = rel.split(path.sep)[0];
			if (entry) dirs.add(path.join(base, entry));
		}
		return [...dirs];
	}

	/** False when a cache entry this session reads from was deleted (e.g. cache cleared). */
	isExtractionPresent(): boolean {
		return this.getCacheDirs().every((dir) => fs.existsSync(dir));
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

	/** Index of the active binary within the container's binary list. */
	getActiveBinaryIndex(): number {
		return Math.max(
			0,
			this.binaries.findIndex((b) => b.name === this.activeBinaryName)
		);
	}

	/**
	 * Search a specific binary for a byte pattern without changing the active one.
	 * `regionSize` defaults to the whole slice and is clamped to it.
	 */
	async searchHexForBinary(
		binaryIndex: number,
		regionOffset: number,
		regionSize: number | undefined,
		pattern: number[],
		caseInsensitive = false
	): Promise<{
		matches: number[];
		binaryName: string;
		regionOffset: number;
		regionSize: number;
	} | null> {
		const { path, fatSliceOffset } = await this.resolveBinary(binaryIndex);
		const sliceSize = readHexAt(path, fatSliceOffset, 0, 0)?.fileSize ?? 0;
		const size = Math.max(0, Math.min(regionSize ?? sliceSize, sliceSize - regionOffset));
		const found = searchHexInFile(
			path,
			fatSliceOffset,
			regionOffset,
			size,
			pattern,
			caseInsensitive
		);
		if (!found) return null;
		return {
			matches: found.matches,
			binaryName: this.binaries[binaryIndex]!.name,
			regionOffset,
			regionSize: size
		};
	}

	// ── Library dependency graph ────────────────────────────────────────

	/** Build a dependency graph across all binaries in the container. */
	async getLibraryGraph(): Promise<LibraryGraphData> {
		return buildLibraryGraph(this.binaries, this.result, this.activeBinaryName);
	}

	// ── Electron bundle ────────────────────────────────────────────────

	/** Archive entries as a tree; empty when the bundle ships no readable app.asar. */
	getAsarTree(): AsarEntry[] {
		return this.asarArchive?.entries ?? [];
	}

	/**
	 * Read one archive entry for preview. Text and other non-image entries are
	 * clamped to `maxBytes` (1..32 MB) and return text unless a NUL byte in the
	 * first 8 KB marks them binary. Images ignore `maxBytes`, read up to 4 MB,
	 * and embed a data URL only when `includeImage` is true and not truncated.
	 */
	readAsarFile(
		entryPath: string,
		maxBytes: number,
		includeImage = false
	): FilePreviewContent | null {
		if (!this.asarArchive) return null;
		const mime = imageMimeType(entryPath);
		const limit = mime
			? FILE_PREVIEW_IMAGE_BYTES
			: Math.min(
					FILE_PREVIEW_FULL_BYTES,
					Math.max(
						1,
						Number.isFinite(maxBytes) ? Math.floor(maxBytes) : FILE_PREVIEW_BYTES
					)
				);

		const result = readAsarArchiveFile(this.asarArchive, entryPath, limit);
		if (!result.ok) return null;

		const { data, truncated } = result.data;
		const record = this.asarArchive.files.get(entryPath);
		return buildFilePreview(
			entryPath,
			data,
			record?.size ?? data.length,
			truncated,
			includeImage
		);
	}

	/** Read a file from the loaded container for preview, confined to session roots. */
	readWorkspaceFile(
		filePath: string,
		maxBytes: number,
		includeImage = false
	): FilePreviewContent | null {
		return readFilePreview(filePath, this.getAllowedOpenRoots(), maxBytes, includeImage);
	}

	// ── Size treemap ────────────────────────────────────────────────────

	/**
	 * Bundle contents for the treemap, with the active binary split into its
	 * modules. XCFrameworks show the active slice's .framework as it would be
	 * embedded in an app (headers, modules and .tbd stubs excluded); bare
	 * Mach-O files show just the binary. An Electron app.asar is split into its
	 * packed contents.
	 */
	getSizeTree(): SizeTreeNode {
		if (!this.result) throw new Error("No previous analysis. Run analyseFile first.");
		const activePath = this.getActiveBinaryPath();
		if (!activePath) throw new Error("No active binary");

		let root: string;
		const sourceType = this.result.overview.sourceType;
		if (sourceType === "macho") {
			root = activePath;
		} else if (sourceType === "xcframework") {
			let dir = path.dirname(activePath);
			while (!dir.endsWith(".framework") && dir !== path.dirname(dir))
				dir = path.dirname(dir);
			root = dir.endsWith(".framework") ? dir : path.dirname(activePath);
		} else {
			root = this.appBundlePath ?? path.dirname(activePath);
		}

		// An XCFramework slice is a build input: show only what embedding it ships
		return buildSizeTree(
			root,
			{ path: activePath, breakdown: this.result.size },
			new Set(this.binaries.map((b) => path.resolve(b.path))),
			sourceType === "xcframework",
			this.asarArchive
				? { path: this.asarArchive.path, entries: this.asarArchive.entries }
				: undefined
		);
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
						skipHooks: true,
						skipSize: true
					}
				);
				this.searchIndex.set(i, {
					classes: result.classes.map((c) => c.name),
					strings: result.strings.map((s) => s.value),
					symbols: result.symbols.map((s) => s.demangled ?? s.name),
					symbolTypes: result.symbols.map((s) => s.type),
					libraries: result.libraries.map((l) => l.name),
					swift: result.swift.types.map((t) => t.fullName)
				});
			} catch {
				this.searchIndex.set(i, {
					classes: [],
					strings: [],
					symbols: [],
					symbolTypes: [],
					libraries: [],
					swift: []
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
			const re = compileSafeRegex(query, flags);
			if (!re) return [];
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
		this.filePath = ipaPath;

		// Step 2: Discover app bundle and binaries
		progressCallback("Discovering binaries...", 15);
		await yieldToEventLoop();
		const appBundlePath = discoverAppBundle(cacheDir);
		if (!appBundlePath) {
			// Zipped XCFrameworks (e.g. SwiftPM binary targets) share the ZIP magic
			const xcframeworkPath = findXCFramework(cacheDir);
			if (xcframeworkPath) {
				return this.analyseXCFramework(xcframeworkPath, progressCallback, ipaPath);
			}
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
			if (plistResult?.ok) {
				infoPlistData = plistResult.data.raw as Record<string, PlistValue>;
			} else if (plistResult && !plistResult.ok) {
				errors.push(`Info.plist: ${plistResult.error}`);
			}
		} catch (err) {
			const msg = err instanceof Error ? err.message : String(err);
			errors.push(`Info.plist error: ${msg}`);
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
				if (mpResult?.ok && mpResult.data.Entitlements) {
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

		// Step 14c: Flag leaked development artifacts shipped in the bundle
		let bundleArtifactFindings: SecurityFinding[] = [];
		try {
			bundleArtifactFindings = findBundleDebugArtifacts(appBundlePath);
		} catch (err) {
			const msg = err instanceof Error ? err.message : String(err);
			errors.push(`Debug artifact scan error: ${msg}`);
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
				...bundleArtifactFindings,
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
				files: base.files,
				electron: base.electron,
				security: {
					findings: [...binaryResult.security.findings, ...this.electronFindings],
					hardening: binaryResult.security.hardening
				}
			}
		);
	}

	// ── Analyse bare Mach-O / dylib ──────────────────────────────────

	/** Analyse a bare Mach-O executable or dylib (no container). */
	async analyseMachO(
		filePath: string,
		progressCallback: (phase: string, percent: number) => void
	): Promise<AnalysisResult> {
		this.filePath = filePath;
		this.appBundlePath = null;

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
		this.filePath = debPath;

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
				`${mainBinaryName}.plist`
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

	// ── Electron bundle ──────────────────────────────────────────────

	/**
	 * Detect an Electron bundle and scan its `app.asar`. Best-effort: a
	 * malformed archive never fails the container analysis.
	 */
	private async loadElectron(
		appRoot: string,
		isMacOS: boolean,
		progressCallback: (phase: string, percent: number) => void,
		percent: number
	): Promise<ElectronInfo | null> {
		this.asarArchive = null;
		this.electronFindings = [];
		let info: ElectronInfo | null = null;
		try {
			info = detectElectron(appRoot, isMacOS);
			if (!info?.asarPath) return info;

			progressCallback("Scanning Electron bundle...", percent);
			await yieldToEventLoop();
			const parsed = readAsarHeader(info.asarPath);
			if (!parsed.ok) {
				console.warn(`[electron] ${parsed.error} (at ${info.asarPath})`);
				return info;
			}
			this.asarArchive = parsed.data;
			const files = readAsarTextFiles(parsed.data);
			const unpackedHtml = readAsarUnpackedHtmlFiles(parsed.data);
			this.electronFindings = [
				...scanBundleFileContents(files),
				...scanElectron(info, [...files, ...unpackedHtml])
			];
		} catch (err) {
			const msg = err instanceof Error ? err.message : String(err);
			console.warn(`[electron] Electron scan failed: ${msg}`);
		}
		return info;
	}

	// ── Analyse macOS .app bundle ────────────────────────────────────

	/** Analyse a macOS .app bundle — discover binaries and parse the main executable. */
	async analyseApp(
		appPath: string,
		progressCallback: (phase: string, percent: number) => void
	): Promise<AnalysisResult> {
		this.filePath = appPath;
		this.asarArchive = null;

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
		// parseInfoPlist signals a malformed plist in-band as { ok: false } and a
		// missing one as null, so only a thrown error reaches the catch below.
		try {
			const plistResult = parseInfoPlist(plistDir);
			if (plistResult?.ok) {
				infoPlistData = plistResult.data.raw as Record<string, PlistValue>;
			} else if (plistResult && !plistResult.ok) {
				console.warn(`[plist] ${plistResult.error} (at ${plistDir})`);
			}
		} catch (err) {
			const msg = err instanceof Error ? err.message : String(err);
			console.warn(`[plist] Failed to read ${plistDir}: ${msg}`);
			// Try the .app root as fallback
			try {
				const plistResult = parseInfoPlist(appPath);
				if (plistResult?.ok) {
					infoPlistData = plistResult.data.raw as Record<string, PlistValue>;
				}
			} catch {
				// Non-critical
			}
		}

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

		// Detect an Electron bundle and scan app.asar.
		const electronInfo = await this.loadElectron(appPath, isMacOS, progressCallback, 82);

		// Flag leaked development artifacts shipped in the bundle
		let bundleArtifactFindings: SecurityFinding[] = [];
		try {
			bundleArtifactFindings = findBundleDebugArtifacts(bundleRoot);
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
				...this.electronFindings,
				...bundleArtifactFindings,
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
				files,
				electron: electronInfo
			}
		);

		this.result = result;
		progressCallback("Analysis complete", 100);
		return result;
	}

	// ── Analyse .xcframework ───────────────────────────────────────

	/**
	 * Analyse an .xcframework — enumerate its platform slices and parse the first
	 * dynamic one. `sourcePath` is the file the user opened when the framework
	 * was extracted from a ZIP.
	 */
	async analyseXCFramework(
		xcframeworkPath: string,
		progressCallback: (phase: string, percent: number) => void,
		sourcePath: string = xcframeworkPath
	): Promise<AnalysisResult> {
		this.filePath = sourcePath;
		this.appBundlePath = xcframeworkPath;

		// Step 1: Discover slices
		progressCallback("Discovering slices...", 5);
		await yieldToEventLoop();
		const { slices, binaries } = discoverXCFramework(xcframeworkPath);
		this.binaries = binaries;
		this.searchIndex = null;

		if (binaries.length === 0) {
			throw new Error(
				slices.length > 0
					? "XCFramework contains only static libraries, which are not supported"
					: "No binaries found in XCFramework"
			);
		}

		const mainBinary = binaries[0]!;
		const mainSlice = slices.find((s) => s.absoluteBinaryPath === mainBinary.path)!;
		const libraryDir = fs.statSync(mainSlice.libraryPath).isDirectory()
			? mainSlice.libraryPath
			: path.dirname(mainSlice.libraryPath);

		// Step 2: Parse the main slice's Info.plist (flat iOS or macOS Resources/ layout)
		progressCallback("Parsing plists...", 10);
		let infoPlistData: Record<string, PlistValue> = {};
		for (const dir of [libraryDir, path.join(libraryDir, "Resources")]) {
			try {
				const plistResult = parseInfoPlist(dir);
				if (!plistResult) continue;
				if (plistResult.ok) {
					infoPlistData = plistResult.data.raw as Record<string, PlistValue>;
				} else {
					console.warn(`[plist] ${plistResult.error} (at ${dir})`);
				}
				break;
			} catch {
				// Non-critical
			}
		}

		// Steps 3-12: Analyse main slice binary
		progressCallback("Reading binary...", 15);
		this.activeBinaryName = mainBinary.name;
		const binaryResult = await analyseBinaryFile(mainBinary.path, progressCallback, 15);
		this.fatSliceOffset = binaryResult.fatSliceOffset;

		// Scan the main slice's bundle files for secrets (other slices ship the same resources)
		progressCallback("Scanning bundle files...", 80);
		await yieldToEventLoop();
		let bundleFindings: SecurityFinding[] = [];
		try {
			const bundleFiles = readBundleFiles(libraryDir);
			if (bundleFiles.length > 0) {
				bundleFindings = scanBundleFileContents(bundleFiles);
			}
		} catch {
			// Non-critical
		}

		// Flag leaked development artifacts — walk the whole XCFramework, since
		// dSYMs sit beside the library in each slice directory
		let bundleArtifactFindings: SecurityFinding[] = [];
		try {
			bundleArtifactFindings = findBundleDebugArtifacts(xcframeworkPath);
		} catch {
			// Non-critical
		}

		let localisationStrings: LocalisationString[] = [];
		try {
			localisationStrings = extractLocalisationStrings(libraryDir);
		} catch {
			// Non-critical
		}

		const extraBinaryFindings = await scanAdditionalBinaries(binaries, progressCallback, 85);

		const mergedSecurity = {
			findings: [
				...binaryResult.security.findings,
				...bundleFindings,
				...bundleArtifactFindings,
				...extraBinaryFindings
			],
			hardening: binaryResult.security.hardening
		};

		progressCallback("Building file tree...", 95);
		await yieldToEventLoop();
		const files = buildFileTree(xcframeworkPath);

		const result = buildAnalysisResult(
			binaryResult,
			{
				sourceType: "xcframework",
				filePath: sourcePath,
				ipa: {
					bundlePath: xcframeworkPath,
					appName: path.basename(xcframeworkPath, path.extname(xcframeworkPath)),
					binaries: assembleBinaryList(binaries)
				},
				...binaryOverviewFields(binaryResult),
				infoPlist: infoPlistData,
				xcframeworkLibraries: slices.map(
					({ libraryPath: _l, absoluteBinaryPath: _b, ...lib }) => lib
				)
			},
			{
				localisationStrings,
				entitlements: binaryResult.entitlements,
				infoPlist: infoPlistData,
				security: mergedSecurity,
				files
			}
		);

		this.result = result;
		progressCallback("Analysis complete", 100);
		return result;
	}

	// ── Analyse a plain folder ───────────────────────────────────────

	/**
	 * Analyse a folder that is not an .app or .xcframework: scan it for Mach-O
	 * binaries (including .dylibs, framework executables and extracted .debs)
	 * and analyse the first one. Every discovered binary stays selectable.
	 */
	async analyseFolder(
		folderPath: string,
		progressCallback: (phase: string, percent: number) => void
	): Promise<AnalysisResult> {
		this.filePath = folderPath;
		this.appBundlePath = folderPath;

		const binaries = await discoverFolderBinaries(folderPath, progressCallback);
		this.binaries = binaries;
		this.searchIndex = null;

		if (binaries.length === 0) {
			throw new Error("No Mach-O binaries found in folder");
		}

		const mainBinary = binaries[0]!;
		this.activeBinaryName = mainBinary.name;
		const binaryResult = await analyseBinaryFile(mainBinary.path, progressCallback, 15);
		this.fatSliceOffset = binaryResult.fatSliceOffset;

		const electronInfo = await this.loadElectron(folderPath, false, progressCallback, 80);
		const extraBinaryFindings = await scanAdditionalBinaries(binaries, progressCallback, 85);
		const security = {
			findings: [
				...binaryResult.security.findings,
				...this.electronFindings,
				...extraBinaryFindings
			],
			hardening: binaryResult.security.hardening
		};

		let localisationStrings: LocalisationString[] = [];
		try {
			localisationStrings = extractLocalisationStrings(folderPath);
		} catch {
			// Non-critical
		}

		progressCallback("Building file tree...", 95);
		await yieldToEventLoop();
		const files = buildFileTree(folderPath);

		const result = buildAnalysisResult(
			binaryResult,
			{
				sourceType: "folder",
				filePath: folderPath,
				ipa: {
					bundlePath: folderPath,
					appName: path.basename(folderPath),
					binaries: assembleBinaryList(binaries)
				},
				...binaryOverviewFields(binaryResult)
			},
			{ localisationStrings, security, files, electron: electronInfo }
		);

		this.result = result;
		progressCallback("Analysis complete", 100);
		return result;
	}

	// ── Unified file analysis entry point ────────────────────────────

	/** Analyse any supported input — auto-detects type and dispatches to the right method. */
	async analyseFile(
		filePath: string,
		progressCallback: (phase: string, percent: number) => void
	): Promise<AnalysisResult> {
		try {
			if (fs.statSync(filePath).isDirectory()) {
				if (filePath.endsWith(".app")) return this.analyseApp(filePath, progressCallback);
				if (isXCFrameworkPath(filePath)) {
					return this.analyseXCFramework(filePath, progressCallback);
				}
				return this.analyseFolder(filePath, progressCallback);
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
			case "xcframework":
				return this.analyseXCFramework(filePath, progressCallback);
			case "folder":
				return this.analyseFolder(filePath, progressCallback);
		}
	}
}

// ── Shared analysis data types for AppInspect ──

/** What kind of input was loaded */
export type SourceType = "ipa" | "macho" | "deb" | "app" | "xcframework" | "folder";

/** One platform slice declared in an .xcframework's Info.plist (AvailableLibraries) */
export interface XCFrameworkLibrary {
	/** Slice directory name, e.g. "ios-arm64_x86_64-simulator" */
	identifier: string;
	/** e.g. "ios", "macos", "tvos" */
	platform: string;
	/** e.g. "simulator", "maccatalyst"; undefined for device builds */
	platformVariant?: string;
	architectures: string[];
	/** Path to the slice binary relative to the slice directory */
	binaryPath: string;
	/** False for static libraries, which are listed but not analysed */
	analysable: boolean;
}

/** DEB package control metadata */
export interface DEBControlInfo {
	package: string;
	name: string;
	version: string;
	architecture: string;
	description: string;
	author?: string;
	maintainer?: string;
	section?: string;
	depends?: string;
	installedSize?: number;
}

/** Top-level info extracted from the IPA container */
export interface IPAInfo {
	bundlePath: string;
	appName: string;
	binaries: BinaryInfo[];
}

/** Describes a single binary found inside the IPA */
export interface BinaryInfo {
	name: string;
	path: string;
	type: "main" | "framework" | "extension";
	size: number;
}

// ── Mach-O Header & Fat Binary ──

export interface MachOHeader {
	magic: number;
	cputype: number;
	cpusubtype: number;
	filetype: number;
	ncmds: number;
	sizeofcmds: number;
	flags: number;
	reserved: number;
}

export interface FatArch {
	cputype: number;
	cpusubtype: number;
	offset: number;
	size: number;
	align: number;
}

// ── Sections & Segments ──

export interface Section {
	sectname: string;
	segname: string;
	addr: bigint;
	size: bigint;
	offset: number;
	align: number;
	reloff: number;
	nreloc: number;
	flags: number;
	reserved1: number;
	reserved2: number;
	reserved3: number;
}

export interface Segment {
	name: string;
	vmaddr: bigint;
	vmsize: bigint;
	fileoff: number;
	filesize: number;
	sections: Section[];
	maxprot: number;
	initprot: number;
	flags: number;
}

// ── Load Commands (discriminated union) ──

export interface LCSegment {
	type: "segment";
	cmd: number;
	cmdsize: number;
	segment: Segment;
}

export interface LCDylib {
	type: "dylib";
	cmd: number;
	cmdsize: number;
	library: LinkedLibrary;
}

export interface LCSymtab {
	type: "symtab";
	cmd: number;
	cmdsize: number;
	symtab: SymtabInfo;
}

export interface LCEncryptionInfo {
	type: "encryption_info";
	cmd: number;
	cmdsize: number;
	encryption: EncryptionInfo;
}

export interface LCBuildVersion {
	type: "build_version";
	cmd: number;
	cmdsize: number;
	buildVersion: BuildVersion;
}

export interface LCGeneric {
	type: "generic";
	cmd: number;
	cmdsize: number;
	cmdName: string;
}

export interface LCUUID {
	type: "uuid";
	cmd: number;
	cmdsize: number;
	uuid: string;
}

export interface LCMain {
	type: "main";
	cmd: number;
	cmdsize: number;
	entryoff: number;
	stacksize: number;
}

export interface LCRpath {
	type: "rpath";
	cmd: number;
	cmdsize: number;
	path: string;
}

export interface LCSourceVersion {
	type: "source_version";
	cmd: number;
	cmdsize: number;
	version: string;
}

export interface LCDyldInfo {
	type: "dyld_info";
	cmd: number;
	cmdsize: number;
	exportSize: number;
	bindSize: number;
	rebaseSize: number;
}

export interface LCIdDylib {
	type: "id_dylib";
	cmd: number;
	cmdsize: number;
	name: string;
	currentVersion: string;
	compatVersion: string;
}

export type LoadCommand =
	| LCSegment
	| LCDylib
	| LCSymtab
	| LCEncryptionInfo
	| LCBuildVersion
	| LCUUID
	| LCMain
	| LCRpath
	| LCSourceVersion
	| LCDyldInfo
	| LCIdDylib
	| LCGeneric;

// ── Strings ──

export interface StringEntry {
	value: string;
	sectionSource: string;
	offset: number;
}

export interface LocalisationString {
	key: string;
	value: string;
	file: string;
	language: string;
}

// ── Linked Libraries ──

export interface LinkedLibrary {
	name: string;
	currentVersion: string;
	compatVersion: string;
	weak: boolean;
}

// ── Symbols ──

export interface SymbolEntry {
	name: string;
	/** Human-readable name for Swift/mangled symbols; undefined when not applicable. */
	demangled?: string;
	type: "exported" | "imported" | "local";
	address: bigint;
	sectionIndex: number;
}

// ── Objective-C Classes ──

export interface ObjCMethod {
	selector: string;
	signature: string;
	/** @internal Set for metaclass (class-level) methods during parsing; used by enrichment. */
	_isClassMethod?: boolean;
	/** @internal Implementation address; feeds size attribution, then stripped before results leave the pipeline. */
	_imp?: bigint;
}

export interface ObjCClass {
	name: string;
	superclass?: string;
	methods: ObjCMethod[];
	protocols?: string[];
}

export interface ObjCProtocol {
	name: string;
	instanceMethods: ObjCMethod[];
	classMethods: ObjCMethod[];
	optionalInstanceMethods: ObjCMethod[];
	optionalClassMethods: ObjCMethod[];
}

// ── Entitlements ──

/** Valid plist value types (recursive) */
export type PlistValue = string | number | boolean | PlistValue[] | { [key: string]: PlistValue };

export interface Entitlement {
	key: string;
	value: PlistValue;
}

// ── Security ──

export interface SecurityFinding {
	severity: "critical" | "warning" | "info";
	category: string;
	message: string;
	evidence: string;
	location?: string;
	functionName?: string;
	/** Source binary or file name (for multi-binary / bundle file scanning) */
	source?: string;
}

// ── App Settings ──

export interface AppSettings {
	/** When true, security scan runs on all binaries (frameworks, extensions), not just the main binary */
	scanAllBinaries: boolean;
	/** Maximum total size of bundle files to scan (MB) */
	maxBundleSizeMB: number;
	/** Maximum size of a single bundle file to scan (MB) */
	maxFileSizeMB: number;
}

export interface BinaryHardening {
	pie: boolean;
	arc: boolean;
	stackCanaries: boolean;
	encrypted: boolean;
	stripped: boolean;
}

// ── Build & Encryption ──

export interface EncryptionInfo {
	cryptoff: number;
	cryptsize: number;
	cryptid: number;
}

export interface BuildVersion {
	platform: number;
	minos: string;
	sdk: string;
	ntools: number;
}

// ── Symbol Table ──

export interface SymtabInfo {
	symoff: number;
	nsyms: number;
	stroff: number;
	strsize: number;
}

// ── File Tree ──

export interface FileEntry {
	name: string;
	path: string;
	size: number;
	isDirectory: boolean;
	children?: FileEntry[];
}

// ── Hooks (jailbreak tweaks) ──

export interface HookInfo {
	/** Hook framework detected (e.g. "Substrate", "Libhooker", "fishhook") */
	frameworks: string[];
	/** Target bundle filters from the tweak plist */
	targetBundles: string[];
	/** Hooked class names (system classes referenced via objc_getClass or classrefs) */
	hookedClasses: string[];
	/** Hook registration symbols found (e.g. _MSHookMessageEx) */
	hookSymbols: string[];
}

// ── Library Dependency Graph ──

export interface LibraryGraphNode {
	/** Unique identifier (binary path or library name) */
	id: string;
	/** Short display label */
	label: string;
	/** 'binary' = analysable binary in the container; 'library' = external dependency */
	type: "binary" | "library";
	/** Only for binary nodes */
	binaryType?: "main" | "framework" | "extension" | "tweak";
	/** Only for library nodes */
	category?: "system" | "framework" | "swift" | "embedded";
	weak?: boolean;
	version?: string;
}

export interface LibraryGraphEdge {
	/** Binary node that links this library */
	source: string;
	/** Library or binary node being linked */
	target: string;
	weak: boolean;
}

export interface LibraryGraphData {
	nodes: LibraryGraphNode[];
	edges: LibraryGraphEdge[];
}

// ── Size Breakdown ──

export interface SizeSection {
	name: string;
	/** Bytes on disk (0 for zero-fill sections) */
	size: number;
}

export interface SizeSegment {
	name: string;
	fileSize: number;
	vmSize: number;
	sections: SizeSection[];
}

export type SizeModuleKind = "swift" | "objc" | "cpp" | "c" | "kotlin" | "unattributed";

export interface SizeModule {
	/** Swift module, C++ namespace, ObjC class prefix, Kotlin package, or C library */
	name: string;
	kind: SizeModuleKind;
	/** Total bytes attributed to the module (code + data) */
	size: number;
	/** Bytes in executable sections */
	codeSize: number;
	/** Bytes of unnamed (stripped) code assigned because both neighbours belong to this module */
	inferredSize: number;
	symbolCount: number;
	/** Largest named functions (code only — data symbol extents are unknown), demangled */
	topFunctions: { name: string; size: number }[];
}

/** Where the bytes of the active binary (architecture slice) go. */
export interface SizeBreakdown {
	/** Size of the analysed slice on disk */
	binarySize: number;
	segments: SizeSegment[];
	/** Sorted by size, descending. Includes an "Unattributed" entry for section bytes no symbol covers. */
	modules: SizeModule[];
	/** Section bytes attributed to a named module (directly or inferred) */
	attributedSize: number;
	/** Total bytes across all non-zero-fill sections */
	sectionSize: number;
}

/**
 * - directory / file: bundle filesystem entries
 * - mlmodel: a Core ML model (.mlmodelc / .mlpackage / .mlmodel), kept whole
 * - binary: a Mach-O file; split into module / overhead children when it is the active binary
 * - module: bytes the size breakdown attributes to one module
 * - overhead: binary bytes no module owns (unattributed section data, link-edit, headers, other slices)
 * - asar: an Electron app.asar archive, split into its packed contents
 */
export type SizeTreeKind =
	| "directory"
	| "file"
	| "mlmodel"
	| "binary"
	| "module"
	| "overhead"
	| "asar";

/** Bundle contents for the treemap: files with the active binary split into its modules. */
export interface SizeTreeNode {
	name: string;
	size: number;
	kind: SizeTreeKind;
	/** Set on module nodes */
	moduleKind?: SizeModuleKind;
	/** Sorted by size, descending */
	children?: SizeTreeNode[];
	/** Root only: entries left out because they are not embedded in an app (paths relative to the root) */
	excluded?: { path: string; size: number }[];
}

// ── Swift Metadata ──

export type SwiftTypeKind = "class" | "struct" | "enum";

export interface SwiftField {
	name: string;
	/** Demangled Swift type (e.g. "Swift.String"), when the mangled name resolves. */
	type?: string;
	/** True for heap-boxed enum cases. */
	indirect?: boolean;
}

export interface SwiftType {
	name: string;
	/** Module-qualified name including any nesting (e.g. "Nationwide.Foo.Bar"). */
	fullName: string;
	module: string;
	kind: SwiftTypeKind;
	/** Demangled superclass for classes, when resolvable. */
	superclass?: string;
	/** Protocols this type conforms to, resolved from __swift5_proto. */
	protocols: string[];
	fields: SwiftField[];
	generic: boolean;
	/** Number of fields declared in the field descriptor (may exceed fields.length if truncated). */
	fieldCount: number;
}

export interface SwiftProtocol {
	name: string;
	fullName: string;
	module: string;
	/** Number of requirements declared in the protocol descriptor. */
	requirementCount: number;
	/** Full names of in-binary types that conform, resolved from __swift5_proto. */
	conformingTypes: string[];
}

export interface SwiftConformance {
	typeName: string;
	protocolName: string;
}

export interface SwiftMetadata {
	types: SwiftType[];
	protocols: SwiftProtocol[];
	conformances: SwiftConformance[];
	/** True when __swift5_types was present. */
	present: boolean;
	/** Conformance records whose protocol descriptor lives outside this binary. */
	unresolvedConformances: number;
}

// ── Electron ──

export type ElectronFuseState = "enabled" | "disabled" | "removed";

export interface ElectronFuse {
	name: string;
	state: ElectronFuseState;
}

export interface ElectronAsarIntegrity {
	algorithm: string;
	expected: string;
	actual: string;
	valid: boolean;
}

export interface AsarEntry {
	name: string;
	/** POSIX path relative to the archive root. */
	path: string;
	size: number;
	isDirectory: boolean;
	unpacked?: boolean;
	executable?: boolean;
	/** Symlink target, relative to the entry's directory. */
	link?: string;
	children?: AsarEntry[];
}

export interface ElectronInfo {
	electronVersion?: string;
	asarPath?: string;
	asarSize?: number;
	fileCount: number;
	unpackedCount: number;
	packageJson?: { [key: string]: PlistValue };
	integrity?: ElectronAsarIntegrity;
	fuses: ElectronFuse[];
	/** Archive-relative paths of shipped .map files. */
	sourceMaps: string[];
	/** Archive-relative paths of .node addons. */
	nativeAddons: string[];
}

export interface AsarFileContent {
	path: string;
	size: number;
	truncated: boolean;
	binary: boolean;
	/** Present only when `binary` is false. */
	text?: string;
}

// ── Top-level Analysis Result ──

export interface AnalysisResult {
	overview: {
		sourceType: SourceType;
		filePath: string;
		ipa: IPAInfo;
		header: MachOHeader;
		fatArchs: FatArch[];
		buildVersion: BuildVersion | null;
		encryptionInfo: EncryptionInfo | null;
		hardening: BinaryHardening;
		uuid?: string;
		teamId?: string;
		infoPlist?: { [key: string]: PlistValue };
		debControl?: DEBControlInfo;
		xcframeworkLibraries?: XCFrameworkLibrary[];
		/** Detected app frameworks (React Native, Flutter, etc.) — undefined means native */
		appFrameworks?: string[];
	};
	hooks: HookInfo;
	size: SizeBreakdown;
	strings: StringEntry[];
	localisationStrings: LocalisationString[];
	headers: {
		machO: MachOHeader;
		fatArchs: FatArch[];
		loadCommands: LoadCommand[];
	};
	libraries: LinkedLibrary[];
	symbols: SymbolEntry[];
	swift: SwiftMetadata;
	classes: ObjCClass[];
	protocols: string[];
	protocolDetails: ObjCProtocol[];
	entitlements: Entitlement[];
	infoPlist: { [key: string]: PlistValue };
	electron: ElectronInfo | null;
	security: {
		findings: SecurityFinding[];
		hardening: BinaryHardening;
	};
	files: FileEntry[];
}

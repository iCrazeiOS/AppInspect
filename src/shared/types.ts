// ── Shared analysis data types for AppInspect ──

/** What kind of file was loaded */
export type SourceType = 'ipa' | 'macho' | 'deb' | 'app';

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
  type: 'main' | 'framework' | 'extension';
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
  type: 'segment';
  cmd: number;
  cmdsize: number;
  segment: Segment;
}

export interface LCDylib {
  type: 'dylib';
  cmd: number;
  cmdsize: number;
  library: LinkedLibrary;
}

export interface LCSymtab {
  type: 'symtab';
  cmd: number;
  cmdsize: number;
  symtab: SymtabInfo;
}

export interface LCEncryptionInfo {
  type: 'encryption_info';
  cmd: number;
  cmdsize: number;
  encryption: EncryptionInfo;
}

export interface LCBuildVersion {
  type: 'build_version';
  cmd: number;
  cmdsize: number;
  buildVersion: BuildVersion;
}

export interface LCGeneric {
  type: 'generic';
  cmd: number;
  cmdsize: number;
  cmdName: string;
}

export interface LCUUID {
  type: 'uuid';
  cmd: number;
  cmdsize: number;
  uuid: string;
}

export interface LCMain {
  type: 'main';
  cmd: number;
  cmdsize: number;
  entryoff: number;
  stacksize: number;
}

export interface LCRpath {
  type: 'rpath';
  cmd: number;
  cmdsize: number;
  path: string;
}

export interface LCSourceVersion {
  type: 'source_version';
  cmd: number;
  cmdsize: number;
  version: string;
}

export interface LCDyldInfo {
  type: 'dyld_info';
  cmd: number;
  cmdsize: number;
  exportSize: number;
  bindSize: number;
  rebaseSize: number;
}

export interface LCIdDylib {
  type: 'id_dylib';
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

export interface Symbol {
  name: string;
  type: 'exported' | 'imported' | 'local';
  address: bigint;
  sectionIndex: number;
}

// ── Objective-C Classes ──

export interface ObjCMethod {
  selector: string;
  signature: string;
  /** @internal Set for metaclass (class-level) methods during parsing; used by enrichment. */
  _isClassMethod?: boolean;
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
export type PlistValue =
  | string
  | number
  | boolean
  | PlistValue[]
  | { [key: string]: PlistValue };

export interface Entitlement {
  key: string;
  value: PlistValue;
}

// ── Security ──

export interface SecurityFinding {
  severity: 'critical' | 'warning' | 'info';
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
  type: 'binary' | 'library';
  /** Only for binary nodes */
  binaryType?: 'main' | 'framework' | 'extension' | 'tweak';
  /** Only for library nodes */
  category?: 'system' | 'framework' | 'swift' | 'embedded';
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
    /** Detected app frameworks (React Native, Flutter, etc.) — undefined means native */
    appFrameworks?: string[];
  };
  hooks: HookInfo;
  strings: StringEntry[];
  localisationStrings: LocalisationString[];
  headers: {
    machO: MachOHeader;
    fatArchs: FatArch[];
    loadCommands: LoadCommand[];
  };
  libraries: LinkedLibrary[];
  symbols: Symbol[];
  classes: ObjCClass[];
  protocols: string[];
  protocolDetails: ObjCProtocol[];
  entitlements: Entitlement[];
  infoPlist: { [key: string]: PlistValue };
  security: {
    findings: SecurityFinding[];
    hardening: BinaryHardening;
  };
  files: FileEntry[];
}

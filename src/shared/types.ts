// ── Shared analysis data types for Disect ──

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

export type LoadCommand =
  | LCSegment
  | LCDylib
  | LCSymtab
  | LCEncryptionInfo
  | LCBuildVersion
  | LCGeneric;

// ── Strings ──

export interface StringEntry {
  value: string;
  sectionSource: string;
  offset: number;
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

export interface ObjCClass {
  name: string;
  superclass?: string;
  methods: string[];
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

// ── Top-level Analysis Result ──

export interface AnalysisResult {
  overview: {
    ipa: IPAInfo;
    header: MachOHeader;
    fatArchs: FatArch[];
    buildVersion: BuildVersion | null;
    encryptionInfo: EncryptionInfo | null;
    hardening: BinaryHardening;
  };
  strings: StringEntry[];
  headers: {
    machO: MachOHeader;
    fatArchs: FatArch[];
    loadCommands: LoadCommand[];
  };
  libraries: LinkedLibrary[];
  symbols: Symbol[];
  classes: ObjCClass[];
  entitlements: Entitlement[];
  infoPlist: { [key: string]: PlistValue };
  security: {
    findings: SecurityFinding[];
    hardening: BinaryHardening;
  };
  files: FileEntry[];
}

// ── IPC channel definitions and payload types for Disect ──

import type {
  AnalysisResult,
  StringEntry,
  MachOHeader,
  FatArch,
  LoadCommand,
  LinkedLibrary,
  Symbol,
  ObjCClass,
  Entitlement,
  SecurityFinding,
  BinaryHardening,
  FileEntry,
  PlistValue,
} from './types';

// ── Tab-specific return types ──

export interface OverviewTabData {
  tab: 'overview';
  data: AnalysisResult['overview'];
}

export interface StringsTabData {
  tab: 'strings';
  data: StringEntry[];
}

export interface HeadersTabData {
  tab: 'headers';
  data: {
    machO: MachOHeader;
    fatArchs: FatArch[];
    loadCommands: LoadCommand[];
  };
}

export interface LibrariesTabData {
  tab: 'libraries';
  data: LinkedLibrary[];
}

export interface SymbolsTabData {
  tab: 'symbols';
  data: Symbol[];
}

export interface ClassesTabData {
  tab: 'classes';
  data: ObjCClass[];
}

export interface EntitlementsTabData {
  tab: 'entitlements';
  data: Entitlement[];
}

export interface InfoPlistTabData {
  tab: 'infoPlist';
  data: { [key: string]: PlistValue };
}

export interface SecurityTabData {
  tab: 'security';
  data: {
    findings: SecurityFinding[];
    hardening: BinaryHardening;
  };
}

export interface FilesTabData {
  tab: 'files';
  data: FileEntry[];
}

export type TabData =
  | OverviewTabData
  | StringsTabData
  | HeadersTabData
  | LibrariesTabData
  | SymbolsTabData
  | ClassesTabData
  | EntitlementsTabData
  | InfoPlistTabData
  | SecurityTabData
  | FilesTabData;

export type TabName = TabData['tab'];

// ── Invoke channels (renderer -> main) ──

export type InvokeChannelMap = {
  'analyze-ipa': {
    params: { path: string };
    result: AnalysisResult;
  };
  'get-tab-data': {
    params: { tab: TabName; binaryIndex: number };
    result: TabData;
  };
  'export-json': {
    params: { tabs?: TabName[] };
    result: { success: boolean; path?: string };
  };
  'open-file-picker': {
    params: void;
    result: string | null;
  };
  'analyze-binary': {
    params: { binaryIndex: number };
    result: AnalysisResult;
  };
};

// ── Send channels (main -> renderer) ──

export interface ProgressPayload {
  phase: string;
  percent: number;
  message: string;
}

export interface AnalysisErrorPayload {
  message: string;
}

export type SendChannelMap = {
  'update-progress': ProgressPayload;
  'analysis-complete': void;
  'analysis-error': AnalysisErrorPayload;
};

// ── Helper types for typed IPC wrappers ──

export type InvokeChannel = keyof InvokeChannelMap;
export type SendChannel = keyof SendChannelMap;

export type InvokeParams<C extends InvokeChannel> = InvokeChannelMap[C]['params'];
export type InvokeResult<C extends InvokeChannel> = InvokeChannelMap[C]['result'];
export type SendPayload<C extends SendChannel> = SendChannelMap[C];

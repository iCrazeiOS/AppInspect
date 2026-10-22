// ── IPC channel definitions and payload types for AppInspect ──

import type {
	AnalysisResult,
	AppSettings,
	AsarEntry,
	BinaryHardening,
	ElectronInfo,
	FatArch,
	FileEntry,
	FilePreviewContent,
	HookInfo,
	LibraryGraphData,
	LinkedLibrary,
	LoadCommand,
	LocalisationString,
	MachOHeader,
	ObjCClass,
	ObjCProtocol,
	PlistValue,
	SecurityFinding,
	SizeBreakdown,
	SizeTreeNode,
	StringEntry,
	SwiftMetadata,
	SymbolEntry
} from "./types";

// ── Tab-specific return types ──

export interface OverviewTabData {
	tab: "overview";
	data: AnalysisResult["overview"] & { hooks: HookInfo; electron: ElectronInfo | null };
}

export interface StringsTabData {
	tab: "strings";
	data: {
		binary: StringEntry[];
		localisation: LocalisationString[];
	};
}

export interface HeadersTabData {
	tab: "headers";
	data: {
		machO: MachOHeader;
		fatArchs: FatArch[];
		loadCommands: LoadCommand[];
	};
}

export interface LibrariesTabData {
	tab: "libraries";
	data: LinkedLibrary[];
}

export interface SymbolsTabData {
	tab: "symbols";
	data: SymbolEntry[];
}

export interface ClassesTabData {
	tab: "classes";
	data: { classes: ObjCClass[]; protocols: string[]; protocolDetails: ObjCProtocol[] };
}

export interface SwiftTabData {
	tab: "swift";
	data: SwiftMetadata;
}

export interface EntitlementsTabData {
	tab: "entitlements";
	data: Record<string, unknown>;
}

export interface InfoPlistTabData {
	tab: "infoPlist";
	data: { [key: string]: PlistValue };
}

export interface ElectronTabData {
	tab: "electron";
	data: { info: ElectronInfo; files: AsarEntry[] };
}

export interface SecurityTabData {
	tab: "security";
	data: {
		findings: SecurityFinding[];
		hardening: BinaryHardening;
	};
}

export interface FilesTabData {
	tab: "files";
	data: FileEntry[];
}

export interface SizeTabData {
	tab: "size";
	data: SizeBreakdown;
}

export interface HooksTabData {
	tab: "hooks";
	data: HookInfo;
}

export type TabData =
	| OverviewTabData
	| StringsTabData
	| HeadersTabData
	| LibrariesTabData
	| SymbolsTabData
	| ClassesTabData
	| SwiftTabData
	| EntitlementsTabData
	| InfoPlistTabData
	| ElectronTabData
	| SecurityTabData
	| FilesTabData
	| HooksTabData
	| SizeTabData;

export interface CrossBinarySearchResult {
	binaryIndex: number;
	binaryName: string;
	binaryType: string;
	match: string;
	/** Symbol type (exported/imported/local) — only present for symbols tab results. */
	symbolType?: string;
}

export type SearchableTab = "classes" | "strings" | "symbols" | "libraries" | "swift";

export type TabName = TabData["tab"];

// ── Invoke channels (renderer -> main) ──

export type InvokeChannelMap = {
	"analyse-file": {
		params: { path: string };
		result: { sessionId: string; result: AnalysisResult };
	};
	"analyse-ipa": {
		params: { path: string };
		result: { sessionId: string; result: AnalysisResult };
	};
	"get-tab-data": {
		params: { sessionId: string; tab: TabName };
		result: TabData;
	};
	"save-png": {
		params: { defaultName: string; data: Uint8Array };
		result: { success: boolean; path?: string };
	};
	"export-json": {
		params: { sessionId: string; tabs?: TabName[] };
		result: { success: boolean; path?: string };
	};
	"open-file-picker": {
		params: { mode?: "file" | "folder" } | undefined;
		result: string | null;
	};
	"is-directory": {
		params: { path: string };
		result: boolean;
	};
	"analyse-binary": {
		params: { sessionId: string; binaryIndex: number; cpuType?: number; cpuSubtype?: number };
		result: AnalysisResult;
	};
	"search-all-binaries": {
		params: {
			sessionId: string;
			query: string;
			tab: SearchableTab;
			isRegex?: boolean;
			caseSensitive?: boolean;
		};
		result: CrossBinarySearchResult[];
	};
	"close-session": {
		params: { sessionId: string };
		result: undefined;
	};
	"get-library-graph": {
		params: { sessionId: string };
		result: LibraryGraphData;
	};
	"get-size-tree": {
		params: { sessionId: string };
		result: SizeTreeNode;
	};
	"get-settings": {
		params: undefined;
		result: AppSettings;
	};
	"set-settings": {
		params: AppSettings;
		result: undefined;
	};
	"get-cache-info": {
		params: undefined;
		result: {
			path: string;
			entryCount: number;
			totalBytes: number;
			/** Entries a clear would remove right now. */
			clearableEntries: number;
			keptInUse: number;
		};
	};
	"clear-cache": {
		params: undefined;
		result: {
			cleared: boolean;
			entryCount: number;
			removedEntries: number;
			removedBytes: number;
			keptInUse: number;
			keptRecentTemp: number;
			failed: number;
		};
	};
	"read-hex": {
		params: { sessionId: string; offset: number; length: number };
		result: { offset: number; length: number; data: number[]; fileSize: number } | null;
	};
	"read-asar-file": {
		params: { sessionId: string; path: string; maxBytes?: number; includeImage?: boolean };
		result: FilePreviewContent | null;
	};
	"read-file-preview": {
		params: { sessionId: string; path: string; maxBytes?: number; includeImage?: boolean };
		result: FilePreviewContent | null;
	};
	"search-hex": {
		params: {
			sessionId: string;
			regionOffset: number;
			regionSize: number;
			pattern: number[];
			caseInsensitive?: boolean;
		};
		result: { matches: number[] } | null;
	};
};

// ── Send channels (main -> renderer) ──

export interface ProgressPayload {
	sessionId: string;
	phase: string;
	percent: number;
	message: string;
}

export interface AnalysisCompletePayload {
	sessionId: string;
}

export interface AnalysisErrorPayload {
	sessionId: string;
	message: string;
}

export type SendChannelMap = {
	"update-progress": ProgressPayload;
	"analysis-complete": AnalysisCompletePayload;
	"analysis-error": AnalysisErrorPayload;
};

// ── Helper types for typed IPC wrappers ──

export type InvokeChannel = keyof InvokeChannelMap;
export type SendChannel = keyof SendChannelMap;

export type InvokeParams<C extends InvokeChannel> = InvokeChannelMap[C]["params"];
export type InvokeResult<C extends InvokeChannel> = InvokeChannelMap[C]["result"];
export type SendPayload<C extends SendChannel> = SendChannelMap[C];

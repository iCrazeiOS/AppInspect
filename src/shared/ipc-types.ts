// ── IPC channel definitions and payload types for AppInspect ──

import type {
	AnalysisResult,
	AppSettings,
	BinaryHardening,
	DisasmInstruction,
	DisasmSection,
	FatArch,
	FileEntry,
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
	StringEntry,
	SymbolEntry
} from "./types";

// ── Tab-specific return types ──

export interface OverviewTabData {
	tab: "overview";
	data: AnalysisResult["overview"] & { hooks: HookInfo };
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

export interface EntitlementsTabData {
	tab: "entitlements";
	data: Record<string, unknown>;
}

export interface InfoPlistTabData {
	tab: "infoPlist";
	data: { [key: string]: PlistValue };
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
	| EntitlementsTabData
	| InfoPlistTabData
	| SecurityTabData
	| FilesTabData
	| HooksTabData;

export interface CrossBinarySearchResult {
	binaryIndex: number;
	binaryName: string;
	binaryType: string;
	match: string;
	/** Symbol type (exported/imported/local) — only present for symbols tab results. */
	symbolType?: string;
}

export type SearchableTab = "classes" | "strings" | "symbols" | "libraries";

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
	"export-json": {
		params: { sessionId: string; tabs?: TabName[] };
		result: { success: boolean; path?: string };
	};
	"open-file-picker": {
		params: undefined;
		result: string | null;
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
	"get-settings": {
		params: undefined;
		result: AppSettings;
	};
	"set-settings": {
		params: AppSettings;
		result: undefined;
	};
	"read-hex": {
		params: { sessionId: string; offset: number; length: number };
		result: { offset: number; length: number; data: number[]; fileSize: number } | null;
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
	"get-disasm-sections": {
		params: { sessionId: string };
		result: DisasmSection[];
	};
	"read-disasm": {
		params: {
			sessionId: string;
			sectionIndex: number;
			byteOffset: number;
			maxBytes: number;
		};
		result: {
			instructions: DisasmInstruction[];
			bytesConsumed: number;
			instructionBytes: number;
		} | null;
	};
	"search-disasm": {
		params: {
			sessionId: string;
			sectionIndex: number;
			query: string;
			isRegex?: boolean;
			maxResults?: number;
		};
		result: {
			matches: Array<{ address: bigint; offset: number; preview: string }>;
			hasMore: boolean;
		};
	};
	"get-disasm-functions": {
		params: {
			sessionId: string;
			sectionIndex: number;
		};
		result: Array<{ address: bigint; name: string }>;
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

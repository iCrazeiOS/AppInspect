import type {
	AnalysisResult,
	AppSettings,
	DisasmInstruction,
	DisasmSection,
	LibraryGraphData
} from "../shared/types";
import type {
	TabData,
	TabName,
	ProgressPayload,
	AnalysisCompletePayload,
	AnalysisErrorPayload,
	CrossBinarySearchResult,
	SearchableTab
} from "../shared/ipc-types";

export interface AppInspectAPI {
	analyseFile(filePath: string): Promise<{ sessionId: string; result: AnalysisResult } | null>;
	analyseIPA(filePath: string): Promise<{ sessionId: string; result: AnalysisResult } | null>;
	analyseBinary(
		sessionId: string,
		binaryIndex: number,
		cpuType?: number,
		cpuSubtype?: number
	): Promise<AnalysisResult>;
	getTabData(sessionId: string, tab: TabName): Promise<TabData>;
	exportJSON(sessionId: string, tabs?: TabName[]): Promise<{ success: boolean; path?: string }>;
	openFilePicker(): Promise<string | null>;
	getSettings(): Promise<AppSettings>;
	setSettings(settings: AppSettings): Promise<void>;
	searchAllBinaries(
		sessionId: string,
		query: string,
		tab: SearchableTab,
		isRegex?: boolean,
		caseSensitive?: boolean
	): Promise<CrossBinarySearchResult[]>;
	closeSession(sessionId: string): Promise<void>;
	getLibraryGraph(sessionId: string): Promise<LibraryGraphData>;
	readHex(
		sessionId: string,
		offset: number,
		length: number
	): Promise<{ offset: number; length: number; data: number[]; fileSize: number } | null>;
	searchHex(
		sessionId: string,
		regionOffset: number,
		regionSize: number,
		pattern: number[],
		caseInsensitive?: boolean
	): Promise<{ matches: number[] } | null>;
	getDisasmSections(sessionId: string): Promise<DisasmSection[]>;
	readDisasm(
		sessionId: string,
		sectionIndex: number,
		byteOffset: number,
		maxBytes: number
	): Promise<{ instructions: DisasmInstruction[]; bytesConsumed: number } | null>;
	searchDisasm(
		sessionId: string,
		sectionIndex: number,
		query: string,
		isRegex?: boolean,
		maxResults?: number
	): Promise<{
		matches: Array<{ address: bigint; offset: number; preview: string }>;
		hasMore: boolean;
	}>;
	getDisasmFunctions(
		sessionId: string,
		sectionIndex: number
	): Promise<Array<{ address: bigint; name: string }>>;
	showItemInFolder(filePath: string): Promise<void>;
	openFile(filePath: string): Promise<void>;
	getPlatform(): Promise<string>;
	getPathForFile(file: File): string;
	onProgress(cb: (data: ProgressPayload) => void): void;
	onComplete(cb: (data: AnalysisCompletePayload) => void): void;
	onError(cb: (data: AnalysisErrorPayload) => void): void;
	onCloseActiveTab(cb: () => void): void;
	onOpenFile(cb: () => void): void;
}

declare global {
	interface Window {
		api: AppInspectAPI;
	}
}

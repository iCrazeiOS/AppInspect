import type {
	AnalysisResult,
	AppSettings,
	AsarFileContent,
	LibraryGraphData,
	SizeTreeNode
} from "../shared/types";
import type {
	TabData,
	TabName,
	ProgressPayload,
	AnalysisCompletePayload,
	AnalysisErrorPayload,
	CrossBinarySearchResult,
	InvokeChannelMap,
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
	savePNG(defaultName: string, data: Uint8Array): Promise<{ success: boolean; path?: string }>;
	openFilePicker(): Promise<string | null>;
	openFolderPicker(): Promise<string | null>;
	isDirectory(filePath: string): Promise<boolean>;
	getSettings(): Promise<AppSettings>;
	setSettings(settings: AppSettings): Promise<void>;
	getCacheInfo(): Promise<InvokeChannelMap["get-cache-info"]["result"]>;
	clearCache(): Promise<InvokeChannelMap["clear-cache"]["result"]>;
	searchAllBinaries(
		sessionId: string,
		query: string,
		tab: SearchableTab,
		isRegex?: boolean,
		caseSensitive?: boolean
	): Promise<CrossBinarySearchResult[]>;
	closeSession(sessionId: string): Promise<void>;
	getLibraryGraph(sessionId: string): Promise<LibraryGraphData>;
	getSizeTree(sessionId: string): Promise<SizeTreeNode>;
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
	readAsarFile(
		sessionId: string,
		path: string,
		maxBytes?: number,
		includeImage?: boolean
	): Promise<AsarFileContent | null>;
	showItemInFolder(filePath: string): Promise<void>;
	openFile(filePath: string): Promise<void>;
	getPlatform(): Promise<string>;
	getPathForFile(file: File): string;
	onProgress(cb: (data: ProgressPayload) => void): void;
	onComplete(cb: (data: AnalysisCompletePayload) => void): void;
	onError(cb: (data: AnalysisErrorPayload) => void): void;
	onCloseActiveTab(cb: () => void): void;
	onOpenFile(cb: () => void): void;
	onOpenFolder(cb: () => void): void;
}

declare global {
	interface Window {
		api: AppInspectAPI;
	}
}

import { contextBridge, ipcRenderer, webUtils } from "electron";

contextBridge.exposeInMainWorld("api", {
	analyseFile: (filePath: string) => ipcRenderer.invoke("analyse-file", { path: filePath }),
	analyseIPA: (filePath: string) => ipcRenderer.invoke("analyse-ipa", { path: filePath }),
	analyseBinary: (
		sessionId: string,
		binaryIndex: number,
		cpuType?: number,
		cpuSubtype?: number
	) => ipcRenderer.invoke("analyse-binary", { sessionId, binaryIndex, cpuType, cpuSubtype }),
	getTabData: (sessionId: string, tab: string) =>
		ipcRenderer.invoke("get-tab-data", { sessionId, tab }),
	exportJSON: (sessionId: string, tabs?: string[]) =>
		ipcRenderer.invoke("export-json", { sessionId, tabs }),
	openFilePicker: () => ipcRenderer.invoke("open-file-picker"),
	getSettings: () => ipcRenderer.invoke("get-settings"),
	setSettings: (settings: any) => ipcRenderer.invoke("set-settings", settings),
	searchAllBinaries: (
		sessionId: string,
		query: string,
		tab: string,
		isRegex?: boolean,
		caseSensitive?: boolean
	) =>
		ipcRenderer.invoke("search-all-binaries", {
			sessionId,
			query,
			tab,
			isRegex,
			caseSensitive
		}),
	closeSession: (sessionId: string) => ipcRenderer.invoke("close-session", { sessionId }),
	getLibraryGraph: (sessionId: string) => ipcRenderer.invoke("get-library-graph", { sessionId }),
	readHex: (sessionId: string, offset: number, length: number) =>
		ipcRenderer.invoke("read-hex", { sessionId, offset, length }),
	searchHex: (
		sessionId: string,
		regionOffset: number,
		regionSize: number,
		pattern: number[],
		caseInsensitive?: boolean
	) =>
		ipcRenderer.invoke("search-hex", {
			sessionId,
			regionOffset,
			regionSize,
			pattern,
			caseInsensitive
		}),
	getDisasmSections: (sessionId: string) =>
		ipcRenderer.invoke("get-disasm-sections", { sessionId }),
	readDisasm: (sessionId: string, sectionIndex: number, byteOffset: number, maxBytes: number) =>
		ipcRenderer.invoke("read-disasm", { sessionId, sectionIndex, byteOffset, maxBytes }),
	searchDisasm: (
		sessionId: string,
		sectionIndex: number,
		query: string,
		isRegex?: boolean,
		maxResults?: number
	) =>
		ipcRenderer.invoke("search-disasm", {
			sessionId,
			sectionIndex,
			query,
			isRegex,
			maxResults
		}),
	showItemInFolder: (filePath: string) =>
		ipcRenderer.invoke("show-item-in-folder", { path: filePath }),
	openFile: (filePath: string) => ipcRenderer.invoke("open-file", { path: filePath }),
	getPlatform: () => ipcRenderer.invoke("get-platform"),
	getPathForFile: (file: File) => webUtils.getPathForFile(file),
	onProgress: (
		cb: (data: { sessionId: string; phase: string; percent: number; message: string }) => void
	) => {
		ipcRenderer.on("update-progress", (_event, data) => cb(data));
	},
	onComplete: (cb: (data: { sessionId: string }) => void) => {
		ipcRenderer.on("analysis-complete", (_event, data) => cb(data));
	},
	onError: (cb: (data: { sessionId: string; message: string }) => void) => {
		ipcRenderer.on("analysis-error", (_event, data) => cb(data));
	},
	onCloseActiveTab: (cb: () => void) => {
		ipcRenderer.on("close-active-tab", () => cb());
	},
	onOpenFile: (cb: () => void) => {
		ipcRenderer.on("open-file-menu", () => cb());
	}
});

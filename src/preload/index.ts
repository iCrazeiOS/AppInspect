import { contextBridge, ipcRenderer, webUtils } from "electron";
import type { AppSettings } from "../shared/types";

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
	savePNG: (defaultName: string, data: Uint8Array) =>
		ipcRenderer.invoke("save-png", { defaultName, data }),
	exportJSON: (sessionId: string, tabs?: string[]) =>
		ipcRenderer.invoke("export-json", { sessionId, tabs }),
	exportHeaders: (sessionId: string) => ipcRenderer.invoke("export-headers", { sessionId }),
	openFilePicker: () => ipcRenderer.invoke("open-file-picker", { mode: "file" }),
	openFolderPicker: () => ipcRenderer.invoke("open-file-picker", { mode: "folder" }),
	isDirectory: (filePath: string) => ipcRenderer.invoke("is-directory", { path: filePath }),
	getSettings: () => ipcRenderer.invoke("get-settings"),
	setSettings: (settings: AppSettings) => ipcRenderer.invoke("set-settings", settings),
	getCacheInfo: () => ipcRenderer.invoke("get-cache-info"),
	clearCache: () => ipcRenderer.invoke("clear-cache"),
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
	getSizeTree: (sessionId: string) => ipcRenderer.invoke("get-size-tree", { sessionId }),
	readHex: (sessionId: string, offset: number, length: number) =>
		ipcRenderer.invoke("read-hex", { sessionId, offset, length }),
	readAsarFile: (sessionId: string, path: string, maxBytes?: number, includeImage?: boolean) =>
		ipcRenderer.invoke("read-asar-file", { sessionId, path, maxBytes, includeImage }),
	openAsarFile: (sessionId: string, path: string) =>
		ipcRenderer.invoke("open-asar-file", { sessionId, path }),
	readFilePreview: (sessionId: string, path: string, maxBytes?: number, includeImage?: boolean) =>
		ipcRenderer.invoke("read-file-preview", { sessionId, path, maxBytes, includeImage }),
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
	},
	onOpenFolder: (cb: () => void) => {
		ipcRenderer.on("open-folder-menu", () => cb());
	}
});

import { contextBridge, ipcRenderer, webUtils } from "electron";

contextBridge.exposeInMainWorld("api", {
  analyseFile: (filePath: string) =>
    ipcRenderer.invoke("analyse-file", { path: filePath }),
  analyseIPA: (filePath: string) =>
    ipcRenderer.invoke("analyse-ipa", { path: filePath }),
  analyseBinary: (binaryIndex: number, cpuType?: number, cpuSubtype?: number) =>
    ipcRenderer.invoke("analyse-binary", { binaryIndex, cpuType, cpuSubtype }),
  getTabData: (tab: string, binaryIndex?: number) =>
    ipcRenderer.invoke("get-tab-data", { tab, binaryIndex }),
  exportJSON: (tabs?: string[]) =>
    ipcRenderer.invoke("export-json", { tabs }),
  openFilePicker: () =>
    ipcRenderer.invoke("open-file-picker"),
  getSettings: () =>
    ipcRenderer.invoke("get-settings"),
  setSettings: (settings: any) =>
    ipcRenderer.invoke("set-settings", settings),
  searchAllBinaries: (query: string, tab: string) =>
    ipcRenderer.invoke("search-all-binaries", { query, tab }),
  showItemInFolder: (filePath: string) =>
    ipcRenderer.invoke("show-item-in-folder", { path: filePath }),
  openFile: (filePath: string) =>
    ipcRenderer.invoke("open-file", { path: filePath }),
  getPlatform: () =>
    ipcRenderer.invoke("get-platform"),
  getPathForFile: (file: File) => webUtils.getPathForFile(file),
  onProgress: (cb: (data: { phase: string; percent: number; message: string }) => void) => {
    ipcRenderer.on("update-progress", (_event, data) => cb(data));
  },
  onComplete: (cb: () => void) => {
    ipcRenderer.on("analysis-complete", () => cb());
  },
  onError: (cb: (data: { message: string }) => void) => {
    ipcRenderer.on("analysis-error", (_event, data) => cb(data));
  },
});

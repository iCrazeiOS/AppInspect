import { contextBridge, ipcRenderer, webUtils } from "electron";

contextBridge.exposeInMainWorld("api", {
  analyzeFile: (filePath: string) =>
    ipcRenderer.invoke("analyze-file", { path: filePath }),
  analyzeIPA: (filePath: string) =>
    ipcRenderer.invoke("analyze-ipa", { path: filePath }),
  analyzeBinary: (binaryIndex: number, cpuType?: number, cpuSubtype?: number) =>
    ipcRenderer.invoke("analyze-binary", { binaryIndex, cpuType, cpuSubtype }),
  getTabData: (tab: string, binaryIndex?: number) =>
    ipcRenderer.invoke("get-tab-data", { tab, binaryIndex }),
  exportJSON: (tabs?: string[]) =>
    ipcRenderer.invoke("export-json", { tabs }),
  openFilePicker: () =>
    ipcRenderer.invoke("open-file-picker"),
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

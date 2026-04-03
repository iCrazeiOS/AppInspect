import { contextBridge, ipcRenderer } from "electron";

contextBridge.exposeInMainWorld("api", {
  analyzeIPA: (filePath: string) =>
    ipcRenderer.invoke("analyze-ipa", { path: filePath }),
  analyzeBinary: (binaryIndex: number) =>
    ipcRenderer.invoke("analyze-binary", { binaryIndex }),
  getTabData: (tab: string, binaryIndex?: number) =>
    ipcRenderer.invoke("get-tab-data", { tab, binaryIndex }),
  exportJSON: (tabs?: string[]) =>
    ipcRenderer.invoke("export-json", { tabs }),
  openFilePicker: () =>
    ipcRenderer.invoke("open-file-picker"),
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

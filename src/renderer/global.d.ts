import type { AnalysisResult, AppSettings } from "../shared/types";
import type { TabData, TabName, ProgressPayload, AnalysisErrorPayload } from "../shared/ipc-types";

export interface AppInspectAPI {
  analyseFile(filePath: string): Promise<AnalysisResult>;
  analyseIPA(filePath: string): Promise<AnalysisResult>;
  analyseBinary(binaryIndex: number, cpuType?: number, cpuSubtype?: number): Promise<AnalysisResult>;
  getTabData(tab: TabName, binaryIndex?: number): Promise<TabData>;
  exportJSON(tabs?: TabName[]): Promise<{ success: boolean; path?: string }>;
  openFilePicker(): Promise<string | null>;
  getSettings(): Promise<AppSettings>;
  setSettings(settings: AppSettings): Promise<void>;
  getPathForFile(file: File): string;
  onProgress(cb: (data: ProgressPayload) => void): void;
  onComplete(cb: () => void): void;
  onError(cb: (data: AnalysisErrorPayload) => void): void;
}

declare global {
  interface Window {
    api: AppInspectAPI;
  }
}

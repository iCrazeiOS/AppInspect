import type { AnalysisResult } from "../shared/types";
import type { TabData, TabName, ProgressPayload, AnalysisErrorPayload } from "../shared/ipc-types";

export interface DisectAPI {
  analyzeIPA(filePath: string): Promise<AnalysisResult>;
  analyzeBinary(binaryIndex: number): Promise<AnalysisResult>;
  getTabData(tab: TabName, binaryIndex?: number): Promise<TabData>;
  exportJSON(tabs?: TabName[]): Promise<{ success: boolean; path?: string }>;
  openFilePicker(): Promise<string | null>;
  onProgress(cb: (data: ProgressPayload) => void): void;
  onComplete(cb: () => void): void;
  onError(cb: (data: AnalysisErrorPayload) => void): void;
}

declare global {
  interface Window {
    api: DisectAPI;
  }
}

/**
 * Analysis Orchestrator — public facade.
 *
 * Re-exports the analysis API from its focused modules. Every consumer
 * (main/index.ts, mcp/server.ts, ipc/handlers.ts, tests) imports from here.
 */

export type { ScanOptions } from "./binary-pipeline";
export { analyseBinaryFile } from "./binary-pipeline";
export { pruneCache } from "./cache";
export { buildFileTree } from "./file-tree";
export { detectFileType } from "./file-type";
export { formatHexdump } from "./hex";
export type { CrossBinarySearchResult, SearchableTab } from "./search-index";
export { AnalysisSession } from "./session";

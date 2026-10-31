/**
 * Cross-binary search types.
 *
 * Lightweight per-binary name index consumed by AnalysisSession.searchAllBinaries.
 */

export interface BinarySearchIndex {
	objc: string[];
	strings: string[];
	symbols: string[];
	symbolTypes: string[];
	libraries: string[];
	swift: string[];
}

export type SearchableTab = "objc" | "strings" | "symbols" | "libraries" | "swift";

export interface CrossBinarySearchResult {
	binaryIndex: number;
	binaryName: string;
	binaryType: string;
	match: string;
	symbolType?: string;
}

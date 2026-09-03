/**
 * Cross-binary search types.
 *
 * Lightweight per-binary name index consumed by AnalysisSession.searchAllBinaries.
 */

export interface BinarySearchIndex {
	classes: string[];
	strings: string[];
	symbols: string[];
	symbolTypes: string[];
	libraries: string[];
}

export type SearchableTab = "classes" | "strings" | "symbols" | "libraries";

export interface CrossBinarySearchResult {
	binaryIndex: number;
	binaryName: string;
	binaryType: string;
	match: string;
	symbolType?: string;
}

/**
 * Library dependency graph helpers.
 *
 * Classification and naming utilities plus the cross-binary dependency graph
 * builder displayed in the Libraries tab graph view.
 */

import * as fs from "node:fs";
import type {
	AnalysisResult,
	LibraryGraphData,
	LibraryGraphEdge,
	LibraryGraphNode,
	LinkedLibrary
} from "../../shared/types";
import type { BinaryInfo } from "../ipa/extractor";
import { parseLoadCommands } from "../parser/load-commands";
import { CPU_TYPE_ARM64, parseFatHeader, parseMachOHeader } from "../parser/macho";

export function classifyLib(name: string): "system" | "framework" | "swift" | "embedded" {
	if (name.startsWith("/usr/lib/swift") || name.includes("libswift")) return "swift";
	if (name.includes(".framework/")) return "framework";
	if (name.startsWith("/") || name.startsWith("@rpath/libswift")) return "system";
	return "embedded";
}

export function libBasename(fullPath: string): string {
	const parts = fullPath.split("/");
	let name = parts[parts.length - 1] ?? fullPath;
	if (fullPath.includes(".framework")) {
		const pre = fullPath.split(".framework")[0]!.split("/");
		name = pre[pre.length - 1] ?? name;
	}
	return name;
}

/** Hooking framework library names that indicate a jailbreak tweak */
const TWEAK_DEPS = ["substrate", "ellekit", "libhooker", "substitute"];

export function isTweakDep(libName: string): boolean {
	const lower = libName.toLowerCase();
	return TWEAK_DEPS.some((d) => lower.includes(d));
}

/**
 * Lightweight: read a binary and parse only its load commands to extract
 * linked libraries. Skips strings, symbols, ObjC, signatures, etc.
 */
export function parseLibrariesOnly(binaryPath: string): LinkedLibrary[] {
	try {
		const fileBuf = fs.readFileSync(binaryPath);
		let buffer = fileBuf.buffer.slice(
			fileBuf.byteOffset,
			fileBuf.byteOffset + fileBuf.byteLength
		);

		// Handle fat binary — select arm64 or first arch
		const fatResult = parseFatHeader(buffer);
		const headerOffset = 0;
		if (fatResult.ok) {
			const arm64 = fatResult.data.find((a) => a.cputype === CPU_TYPE_ARM64);
			const arch = arm64 ?? fatResult.data[0];
			if (arch && arch.offset > 0) {
				buffer = buffer.slice(arch.offset, arch.offset + arch.size);
			}
		}

		const headerResult = parseMachOHeader(buffer, headerOffset);
		if (!headerResult.ok) return [];

		const machO = headerResult.data;
		const headerSize = machO.is64Bit ? 32 : 28;
		const lcOffset = machO.offset + headerSize;
		const lcResult = parseLoadCommands(
			buffer,
			lcOffset,
			machO.header.ncmds,
			machO.header.sizeofcmds,
			machO.littleEndian,
			machO.is64Bit
		);

		return lcResult.libraries.map((lib) => ({
			name: lib.name,
			currentVersion: lib.currentVersion,
			compatVersion: lib.compatVersion,
			weak: lib.weak
		}));
	} catch {
		return [];
	}
}

/**
 * Build a dependency graph across all binaries in the container. For each
 * binary, parses only its load commands (lightweight) to extract linked
 * libraries, then merges into a single graph. The active binary reuses its
 * already-parsed libraries from `activeResult`.
 */
export function buildLibraryGraph(
	binaries: BinaryInfo[],
	activeResult: AnalysisResult | null,
	activeBinaryName: string
): LibraryGraphData {
	const nodes = new Map<string, LibraryGraphNode>();
	const edges: LibraryGraphEdge[] = [];

	// If no binaries discovered (plain Mach-O), use the cached result directly
	if (binaries.length === 0 && activeResult) {
		const rootId = activeBinaryName || "Binary";
		nodes.set(rootId, { id: rootId, label: rootId, type: "binary", binaryType: "main" });
		for (const lib of activeResult.libraries) {
			const cat = classifyLib(lib.name);
			if (!nodes.has(lib.name)) {
				nodes.set(lib.name, {
					id: lib.name,
					label: libBasename(lib.name),
					type: "library",
					category: cat,
					weak: lib.weak,
					version: lib.currentVersion
				});
			}
			edges.push({ source: rootId, target: lib.name, weak: lib.weak });
		}
		return { nodes: Array.from(nodes.values()), edges };
	}

	// For containers with multiple binaries, scan each one
	for (let i = 0; i < binaries.length; i++) {
		const bin = binaries[i]!;
		const binId = bin.name;

		let libs: LinkedLibrary[] = [];
		if (bin.name === activeBinaryName && activeResult) {
			libs = activeResult.libraries;
		} else {
			libs = parseLibrariesOnly(bin.path);
		}

		// Detect if this binary is a tweak (links a hooking framework)
		const isTweak = bin.type !== "main" && libs.some((l) => isTweakDep(l.name));
		const binaryType = isTweak ? ("tweak" as const) : bin.type;
		nodes.set(binId, { id: binId, label: bin.name, type: "binary", binaryType });

		for (const lib of libs) {
			const matchedBinary = binaries.find(
				(b) => b.name !== bin.name && lib.name.includes(b.name)
			);

			if (matchedBinary) {
				edges.push({ source: binId, target: matchedBinary.name, weak: lib.weak });
			} else {
				const cat = classifyLib(lib.name);
				if (!nodes.has(lib.name)) {
					nodes.set(lib.name, {
						id: lib.name,
						label: libBasename(lib.name),
						type: "library",
						category: cat,
						weak: lib.weak,
						version: lib.currentVersion
					});
				}
				edges.push({ source: binId, target: lib.name, weak: lib.weak });
			}
		}
	}

	return { nodes: Array.from(nodes.values()), edges };
}

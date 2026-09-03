/**
 * Shared container-driver helpers.
 *
 * The two blocks the IPA / DEB / macOS-app drivers repeat verbatim: an
 * optional secondary-binary security sweep and the binary list assembled for
 * the overview.
 */

import * as fs from "node:fs";

import type { BinaryInfo as ContainerBinary, SecurityFinding } from "../../../shared/types";
import type { BinaryInfo } from "../../ipa/extractor";
import { loadSettings } from "../../settings";
import { analyseBinaryFile, yieldToEventLoop } from "../binary-pipeline";

/**
 * When the `scanAllBinaries` setting is enabled, run the security scan over
 * every binary past the main one and return their findings tagged with the
 * source binary name. Returns an empty list when disabled or single-binary.
 */
export async function scanAdditionalBinaries(
	binaries: BinaryInfo[],
	progressCallback: (phase: string, percent: number) => void,
	progressPercent: number
): Promise<SecurityFinding[]> {
	const findings: SecurityFinding[] = [];
	if (!loadSettings().scanAllBinaries || binaries.length <= 1) return findings;

	progressCallback("Scanning additional binaries...", progressPercent);
	await yieldToEventLoop();
	for (let i = 1; i < binaries.length; i++) {
		try {
			const extraResult = await analyseBinaryFile(binaries[i]!.path, () => {}, 0);
			for (const finding of extraResult.security.findings) {
				findings.push({ ...finding, source: binaries[i]!.name });
			}
		} catch {
			// Non-critical: skip binaries that fail
		}
	}
	return findings;
}

/** Assemble the overview binary list, resolving each on-disk size (0 if unreadable). */
export function assembleBinaryList(binaries: BinaryInfo[]): ContainerBinary[] {
	return binaries.map((b) => ({
		name: b.name,
		path: b.path,
		type: b.type,
		size: (() => {
			try {
				return fs.statSync(b.path).size;
			} catch {
				return 0;
			}
		})()
	}));
}

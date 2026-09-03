/**
 * Hex viewer helpers.
 *
 * Pure file-backed reads and pattern scans over a binary slice, plus the
 * classic hexdump formatter. All functions take an explicit path and fat-slice
 * offset so they hold no session state.
 */

import * as fs from "node:fs";

export interface HexReadResult {
	offset: number;
	length: number;
	data: number[];
	fileSize: number;
}

/** Read raw bytes from a binary slice, capped at 64 KiB, for hex display. */
export function readHexAt(
	binaryPath: string | null,
	fatSliceOffset: number,
	offset: number,
	length: number
): HexReadResult | null {
	if (!binaryPath) return null;

	const MAX_LEN = 65536;
	const safeLength = Math.min(Math.max(0, length), MAX_LEN);

	const fd = fs.openSync(binaryPath, "r");
	try {
		const stat = fs.fstatSync(fd);
		const fileSize = stat.size;
		const absOffset = fatSliceOffset + offset;

		// Compute the logical binary slice size
		const sliceSize =
			fatSliceOffset > 0 ? Math.min(fileSize - fatSliceOffset, fileSize) : fileSize;

		if (absOffset >= fileSize) {
			return { offset, length: 0, data: [], fileSize: sliceSize };
		}
		const readLen = Math.min(safeLength, fileSize - absOffset);
		const buf = Buffer.alloc(readLen);
		fs.readSync(fd, buf, 0, readLen, absOffset);

		return { offset, length: readLen, data: Array.from(buf), fileSize: sliceSize };
	} finally {
		fs.closeSync(fd);
	}
}

/** Search for a byte pattern within a region of a binary slice. */
export function searchHexInFile(
	binaryPath: string | null,
	fatSliceOffset: number,
	regionOffset: number,
	regionSize: number,
	pattern: number[],
	caseInsensitive = false
): { matches: number[] } | null {
	if (!binaryPath || pattern.length === 0) return null;

	const MAX_MATCHES = 10000;
	const CHUNK_SIZE = 65536;
	const matches: number[] = [];

	const fd = fs.openSync(binaryPath, "r");
	try {
		const stat = fs.fstatSync(fd);
		const fileSize = stat.size;
		const absStart = fatSliceOffset + regionOffset;
		const sliceSize =
			fatSliceOffset > 0 ? Math.min(fileSize - fatSliceOffset, fileSize) : fileSize;
		const safeRegionSize = Math.min(regionSize, sliceSize - regionOffset);

		if (absStart >= fileSize || safeRegionSize <= 0) {
			return { matches: [] };
		}

		// Read in chunks with overlap for cross-boundary matches
		const overlap = pattern.length - 1;
		let pos = 0;
		let carryover = Buffer.alloc(0);

		while (pos < safeRegionSize && matches.length < MAX_MATCHES) {
			const readStart = absStart + pos;
			const readLen = Math.min(CHUNK_SIZE, safeRegionSize - pos);
			const buf = Buffer.alloc(readLen);
			const bytesRead = fs.readSync(fd, buf, 0, readLen, readStart);
			if (bytesRead === 0) break;

			// Prepend carryover from previous chunk for cross-boundary matching
			const searchBuf =
				carryover.length > 0
					? Buffer.concat([carryover, buf.subarray(0, bytesRead)])
					: buf.subarray(0, bytesRead);
			const searchStart = carryover.length > 0 ? 0 : 0;
			const baseOffset = pos - carryover.length;

			for (let i = searchStart; i <= searchBuf.length - pattern.length; i++) {
				let found = true;
				for (let j = 0; j < pattern.length; j++) {
					let a = searchBuf[i + j]!;
					let b = pattern[j]!;
					if (caseInsensitive) {
						if (a >= 0x41 && a <= 0x5a) a |= 0x20;
						if (b >= 0x41 && b <= 0x5a) b |= 0x20;
					}
					if (a !== b) {
						found = false;
						break;
					}
				}
				if (found) {
					matches.push(regionOffset + baseOffset + i);
					if (matches.length >= MAX_MATCHES) break;
				}
			}

			pos += bytesRead;
			// Keep the last (pattern.length - 1) bytes as carryover
			if (overlap > 0 && bytesRead === readLen && pos < safeRegionSize) {
				carryover = Buffer.from(buf.subarray(bytesRead - overlap, bytesRead));
			} else {
				carryover = Buffer.alloc(0);
			}
		}

		return { matches };
	} finally {
		fs.closeSync(fd);
	}
}

/** Format raw bytes as a classic hexdump string (16 bytes per line). */
export function formatHexdump(data: number[], offset: number): string {
	const lines: string[] = [];
	for (let i = 0; i < data.length; i += 16) {
		const rowBytes = data.slice(i, i + 16);
		const addr = (offset + i).toString(16).padStart(8, "0").toUpperCase();
		const hexParts: string[] = [];
		for (let j = 0; j < 16; j++) {
			if (j < rowBytes.length) {
				hexParts.push(rowBytes[j]!.toString(16).padStart(2, "0").toUpperCase());
			} else {
				hexParts.push("  ");
			}
		}
		const hexLeft = hexParts.slice(0, 8).join(" ");
		const hexRight = hexParts.slice(8).join(" ");
		const ascii = rowBytes
			.map((b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : "."))
			.join("");
		lines.push(`${addr}  ${hexLeft}  ${hexRight}  |${ascii}|`);
	}
	return lines.join("\n");
}

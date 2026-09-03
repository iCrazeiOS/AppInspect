/**
 * Address translation helpers shared across Mach-O parsers.
 */

import type { Segment64 } from "./load-commands";

/**
 * Convert a virtual memory address to a file offset using the segment list.
 * Returns null if no segment contains the given vmaddr.
 */
export function vmaddrToFileOffset(vmaddr: bigint, segments: Segment64[]): number | null {
	for (const seg of segments) {
		if (vmaddr >= seg.vmaddr && vmaddr < seg.vmaddr + seg.vmsize) {
			return Number(vmaddr - seg.vmaddr) + Number(seg.fileoff);
		}
	}
	return null;
}

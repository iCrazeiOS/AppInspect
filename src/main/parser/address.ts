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

/**
 * Like `vmaddrToFileOffset`, but null when the address lies past the segment's file
 * data — zerofill storage such as `__bss` and `__common`, which holds zero on disk.
 */
export function vmaddrToFileBackedOffset(vmaddr: bigint, segments: Segment64[]): number | null {
	for (const seg of segments) {
		if (vmaddr >= seg.vmaddr && vmaddr < seg.vmaddr + seg.vmsize) {
			const delta = vmaddr - seg.vmaddr;
			return delta < seg.filesize ? Number(delta) + Number(seg.fileoff) : null;
		}
	}
	return null;
}

/**
 * Electron's patched `fs` reports an `.asar` path as a directory with size 0,
 * so a plain `statSync` cannot see the archive as a file. Run a synchronous
 * block with ASAR support disabled so the archive looks like the regular file
 * it is. The previous flag is restored even when the block throws.
 */

interface ProcessWithNoAsar {
	noAsar: boolean;
}

export function withoutAsar<T>(fn: () => T): T {
	const proc = process as unknown as ProcessWithNoAsar;
	const previous = proc.noAsar;
	proc.noAsar = true;
	try {
		return fn();
	} finally {
		proc.noAsar = previous;
	}
}

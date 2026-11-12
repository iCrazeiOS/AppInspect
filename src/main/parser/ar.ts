/**
 * Unix `ar` archive parser.
 *
 * Static libraries (`.a`) and Debian packages (`.deb`) are both ar archives: an
 * 8-byte magic followed by members, each a 60-byte text header plus data padded to
 * an even length. Handles both long-name conventions:
 *
 *  - BSD/Darwin: `#1/<len>` — the name is the first `<len>` bytes of the data
 *  - GNU/SysV: `/<offset>` into the `//` long-name table; short names end in `/`
 *
 * GNU symbol and long-name tables (`/`, `/SYM64/`, `//`) are consumed rather than
 * returned. Darwin's symbol table (`__.SYMDEF…`) is an ordinary member and is
 * returned like any other.
 */

import type { Result } from "./result";

export const AR_MAGIC = "!<arch>\n";
const AR_HEADER_SIZE = 60;

export interface ArMember {
	name: string;
	/** Absolute offset of the member's data within the buffer */
	offset: number;
	size: number;
}

function ascii(bytes: Uint8Array, start: number, end: number): string {
	let s = "";
	for (let i = start; i < end && i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
	return s;
}

/** True when `bytes` starts with the ar magic at `offset`. */
export function hasArMagic(bytes: Uint8Array, offset = 0): boolean {
	return ascii(bytes, offset, offset + AR_MAGIC.length) === AR_MAGIC;
}

/**
 * List the members of the ar archive occupying `bytes[start, start + length)`. Fails
 * only when the magic is missing; a truncated or malformed member header ends the
 * listing with the members read so far.
 */
export function parseArArchive(
	bytes: Uint8Array,
	start = 0,
	length = bytes.length - start
): Result<ArMember[]> {
	if (!hasArMagic(bytes, start)) {
		return { ok: false, error: "Not an ar archive (bad magic)" };
	}

	const end = Math.min(bytes.length, start + length);
	const members: ArMember[] = [];
	let longNames = "";
	let pos = start + AR_MAGIC.length;

	while (pos + AR_HEADER_SIZE <= end) {
		const rawName = ascii(bytes, pos, pos + 16).trimEnd();
		const size = Number.parseInt(ascii(bytes, pos + 48, pos + 58).trim(), 10);
		if (ascii(bytes, pos + 58, pos + 60) !== "`\n" || !Number.isFinite(size) || size < 0) break;

		let dataOffset = pos + AR_HEADER_SIZE;
		let dataSize = size;
		if (dataOffset + dataSize > end) break;

		let name: string | null = rawName;
		if (rawName.startsWith("#1/")) {
			// BSD: the name is stored at the start of the data, NUL-padded
			const nameLength = Number.parseInt(rawName.slice(3), 10);
			if (!Number.isFinite(nameLength) || nameLength < 0 || nameLength > dataSize) break;
			name = ascii(bytes, dataOffset, dataOffset + nameLength).replace(/\0+$/, "");
			dataOffset += nameLength;
			dataSize -= nameLength;
		} else if (rawName === "/" || rawName === "/SYM64/") {
			name = null; // GNU symbol table
		} else if (rawName === "//") {
			longNames = ascii(bytes, dataOffset, dataOffset + dataSize);
			name = null;
		} else if (/^\/\d+$/.test(rawName)) {
			const at = Number.parseInt(rawName.slice(1), 10);
			const terminator = longNames.indexOf("/\n", at);
			name = longNames.slice(at, terminator === -1 ? undefined : terminator);
		} else if (rawName.endsWith("/")) {
			name = rawName.slice(0, -1); // GNU short name
		}

		if (name !== null) members.push({ name, offset: dataOffset, size: dataSize });

		// Members are aligned to an even offset
		pos = pos + AR_HEADER_SIZE + size;
		if ((pos - start) % 2 !== 0) pos++;
	}

	return { ok: true, data: members };
}

/**
 * Load Command Parser + Segment/Section Enumeration
 *
 * Walks the load commands following a Mach-O 64-bit header and returns
 * typed structures for each recognised command type. Unrecognised commands
 * are kept as generic { cmd, cmdsize } entries for extensibility.
 *
 * Does NOT dereference any pointers or parse data regions (symbol tables,
 * code-signature blobs, etc.) — only records offsets and sizes.
 */

// ── Load Command Constants ────────────────────────────────────────────

export const LC_SEGMENT = 0x1;
export const LC_SYMTAB = 0x2;
export const LC_DYSYMTAB = 0xb;
export const LC_LOAD_DYLIB = 0xc;
export const LC_ID_DYLIB = 0xd;
export const LC_UUID = 0x1b;
export const LC_CODE_SIGNATURE = 0x1d;
export const LC_SEGMENT_64 = 0x19;
export const LC_LAZY_LOAD_DYLIB = 0x20;
export const LC_DYLD_INFO = 0x22;
export const LC_FUNCTION_STARTS = 0x26;
export const LC_SOURCE_VERSION = 0x2a;
export const LC_ENCRYPTION_INFO = 0x21;
export const LC_ENCRYPTION_INFO_64 = 0x2c;
export const LC_BUILD_VERSION = 0x32;
export const LC_MAIN = 0x80000028;
export const LC_LOAD_WEAK_DYLIB = 0x80000018;
export const LC_RPATH = 0x8000001c;
export const LC_REEXPORT_DYLIB = 0x8000001f;
export const LC_DYLD_INFO_ONLY = 0x80000022;
export const LC_LOAD_UPWARD_DYLIB = 0x80000023;
export const LC_DYLD_CHAINED_FIXUPS = 0x80000034;

// ── Types ─────────────────────────────────────────────────────────────

export interface Section64 {
	sectname: string;
	segname: string;
	addr: bigint;
	size: bigint;
	offset: number;
	align: number;
	reloff: number;
	nreloc: number;
	flags: number;
	reserved1: number;
	reserved2: number;
	reserved3: number;
}

export interface Segment64 {
	cmd: number;
	cmdsize: number;
	segname: string;
	vmaddr: bigint;
	vmsize: bigint;
	fileoff: bigint;
	filesize: bigint;
	maxprot: number;
	initprot: number;
	nsects: number;
	flags: number;
	sections: Section64[];
}

export interface DylibCommand {
	cmd: number;
	cmdsize: number;
	name: string;
	currentVersion: string;
	compatVersion: string;
	weak: boolean;
}

export interface EncryptionInfo64 {
	cmd: number;
	cmdsize: number;
	cryptoff: number;
	cryptsize: number;
	cryptid: number;
}

export interface UUIDCommand {
	cmd: number;
	cmdsize: number;
	uuid: string;
}

export interface BuildVersionCommand {
	cmd: number;
	cmdsize: number;
	platform: number;
	minos: string;
	sdk: string;
	ntools: number;
}

export interface MainCommand {
	cmd: number;
	cmdsize: number;
	entryoff: bigint;
	stacksize: bigint;
}

export interface SymtabCommand {
	cmd: number;
	cmdsize: number;
	symoff: number;
	nsyms: number;
	stroff: number;
	strsize: number;
}

export interface DysymtabCommand {
	cmd: number;
	cmdsize: number;
	ilocalsym: number;
	nlocalsym: number;
	iextdefsym: number;
	nextdefsym: number;
	iundefsym: number;
	nundefsym: number;
}

export interface LinkeditDataCommand {
	cmd: number;
	cmdsize: number;
	dataoff: number;
	datasize: number;
}

export interface RpathCommand {
	cmd: number;
	cmdsize: number;
	path: string;
}

export interface SourceVersionCommand {
	cmd: number;
	cmdsize: number;
	version: bigint;
}

export interface DyldInfoCommand {
	cmd: number;
	cmdsize: number;
	rebaseOff: number;
	rebaseSize: number;
	bindOff: number;
	bindSize: number;
	weakBindOff: number;
	weakBindSize: number;
	lazyBindOff: number;
	lazyBindSize: number;
	exportOff: number;
	exportSize: number;
}

export interface GenericLoadCommand {
	cmd: number;
	cmdsize: number;
}

export type LoadCommand =
	| Segment64
	| DylibCommand
	| EncryptionInfo64
	| UUIDCommand
	| BuildVersionCommand
	| MainCommand
	| SymtabCommand
	| DysymtabCommand
	| LinkeditDataCommand
	| RpathCommand
	| SourceVersionCommand
	| DyldInfoCommand
	| GenericLoadCommand;

export interface LoadCommandsResult {
	segments: Segment64[];
	loadCommands: LoadCommand[];
	libraries: DylibCommand[];
	encryption: EncryptionInfo64 | null;
	uuid: string | null;
	buildVersion: BuildVersionCommand | null;
	symtabInfo: SymtabCommand | null;
	codeSignatureInfo: { offset: number; size: number } | null;
	chainedFixupsInfo: { offset: number; size: number } | null;
	functionStartsInfo: { offset: number; size: number } | null;
}

// ── Helpers ───────────────────────────────────────────────────────────

/**
 * Read a null-terminated C string from a DataView.
 * Returns at most `maxLen` characters (stops at first null byte).
 */
export function readCString(dataView: DataView, offset: number, maxLen: number): string {
	const bytes: number[] = [];
	for (let i = 0; i < maxLen; i++) {
		const byte = dataView.getUint8(offset + i);
		if (byte === 0) break;
		bytes.push(byte);
	}
	return String.fromCharCode(...bytes);
}

/**
 * Decode a packed Mach-O version number (major << 16 | minor << 8 | patch)
 * into a "major.minor.patch" string.
 */
export function readVersion(packed: number): string {
	const major = (packed >>> 16) & 0xffff;
	const minor = (packed >>> 8) & 0xff;
	const patch = packed & 0xff;
	return `${major}.${minor}.${patch}`;
}

/**
 * Format 16 raw bytes as a standard UUID string:
 * XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
 */
function formatUUID(dataView: DataView, offset: number): string {
	const hex: string[] = [];
	for (let i = 0; i < 16; i++) {
		hex.push(
			dataView
				.getUint8(offset + i)
				.toString(16)
				.padStart(2, "0")
		);
	}
	const h = hex.join("");
	return [h.slice(0, 8), h.slice(8, 12), h.slice(12, 16), h.slice(16, 20), h.slice(20, 32)]
		.join("-")
		.toUpperCase();
}

// ── Section Parser ────────────────────────────────────────────────────

function parseSection64(view: DataView, offset: number, le: boolean): Section64 {
	return {
		sectname: readCString(view, offset, 16),
		segname: readCString(view, offset + 16, 16),
		addr: view.getBigUint64(offset + 32, le),
		size: view.getBigUint64(offset + 40, le),
		offset: view.getUint32(offset + 48, le),
		align: view.getUint32(offset + 52, le),
		reloff: view.getUint32(offset + 56, le),
		nreloc: view.getUint32(offset + 60, le),
		flags: view.getUint32(offset + 64, le),
		reserved1: view.getUint32(offset + 68, le),
		reserved2: view.getUint32(offset + 72, le),
		reserved3: view.getUint32(offset + 76, le)
	};
}

// Section64 struct size: 16+16+8+8+4+4+4+4+4+4+4+4 = 80 bytes
const SECTION_64_SIZE = 80;
// Section (32-bit) struct size: 16+16+4+4+4+4+4+4+4+4+4 = 68 bytes
const SECTION_32_SIZE = 68;
// Segment command sizes (header only, before sections)
const SEGMENT_COMMAND_32_SIZE = 56;
const SEGMENT_COMMAND_64_SIZE = 72;

// ── Section32 Parser ──────────────────────────────────────────────────

function parseSection32(view: DataView, offset: number, le: boolean): Section64 {
	return {
		sectname: readCString(view, offset, 16),
		segname: readCString(view, offset + 16, 16),
		addr: BigInt(view.getUint32(offset + 32, le)),
		size: BigInt(view.getUint32(offset + 36, le)),
		offset: view.getUint32(offset + 40, le),
		align: view.getUint32(offset + 44, le),
		reloff: view.getUint32(offset + 48, le),
		nreloc: view.getUint32(offset + 52, le),
		flags: view.getUint32(offset + 56, le),
		reserved1: view.getUint32(offset + 60, le),
		reserved2: view.getUint32(offset + 64, le),
		reserved3: 0 // Not present in 32-bit section
	};
}

// ── Main Parser ───────────────────────────────────────────────────────

/**
 * Parse all load commands starting at `offset` within `buffer`.
 *
 * @param buffer      The raw file buffer
 * @param offset      Byte offset where load commands begin (header offset + 32 for 64-bit, +28 for 32-bit)
 * @param ncmds       Number of load commands (from mach_header.ncmds)
 * @param sizeofcmds  Total byte size of all load commands
 * @param littleEndian Endianness detected from magic
 * @param is64Bit     Whether this is a 64-bit Mach-O (affects segment/section parsing)
 */
export function parseLoadCommands(
	buffer: ArrayBuffer,
	offset: number,
	ncmds: number,
	sizeofcmds: number,
	littleEndian: boolean,
	_is64Bit: boolean = true
): LoadCommandsResult {
	const view = new DataView(buffer);
	const le = littleEndian;

	const result: LoadCommandsResult = {
		segments: [],
		loadCommands: [],
		libraries: [],
		encryption: null,
		uuid: null,
		buildVersion: null,
		symtabInfo: null,
		codeSignatureInfo: null,
		chainedFixupsInfo: null,
		functionStartsInfo: null
	};

	const endOffset = offset + sizeofcmds;
	let cursor = offset;

	for (let i = 0; i < ncmds && cursor < endOffset; i++) {
		// Every load command starts with cmd(4) + cmdsize(4)
		const cmd = view.getUint32(cursor, le);
		const cmdsize = view.getUint32(cursor + 4, le);

		if (cmdsize < 8) {
			// Invalid — avoid infinite loop
			break;
		}

		let parsed: LoadCommand;

		switch (cmd) {
			case LC_SEGMENT: {
				// 32-bit segment command
				const segname = readCString(view, cursor + 8, 16);
				const vmaddr = BigInt(view.getUint32(cursor + 24, le));
				const vmsize = BigInt(view.getUint32(cursor + 28, le));
				const fileoff = BigInt(view.getUint32(cursor + 32, le));
				const filesize = BigInt(view.getUint32(cursor + 36, le));
				const maxprot = view.getInt32(cursor + 40, le);
				const initprot = view.getInt32(cursor + 44, le);
				const nsects = view.getUint32(cursor + 48, le);
				const flags = view.getUint32(cursor + 52, le);

				const sections: Section64[] = [];
				// Sections start at cursor + 56 (segment_command header size)
				let sectOffset = cursor + SEGMENT_COMMAND_32_SIZE;
				for (let s = 0; s < nsects; s++) {
					sections.push(parseSection32(view, sectOffset, le));
					sectOffset += SECTION_32_SIZE;
				}

				const seg: Segment64 = {
					cmd,
					cmdsize,
					segname,
					vmaddr,
					vmsize,
					fileoff,
					filesize,
					maxprot,
					initprot,
					nsects,
					flags,
					sections
				};
				result.segments.push(seg);
				parsed = seg;
				break;
			}

			case LC_SEGMENT_64: {
				const segname = readCString(view, cursor + 8, 16);
				const vmaddr = view.getBigUint64(cursor + 24, le);
				const vmsize = view.getBigUint64(cursor + 32, le);
				const fileoff = view.getBigUint64(cursor + 40, le);
				const filesize = view.getBigUint64(cursor + 48, le);
				const maxprot = view.getInt32(cursor + 56, le);
				const initprot = view.getInt32(cursor + 60, le);
				const nsects = view.getUint32(cursor + 64, le);
				const flags = view.getUint32(cursor + 68, le);

				const sections: Section64[] = [];
				// Sections start at cursor + 72 (segment_command_64 header size)
				let sectOffset = cursor + SEGMENT_COMMAND_64_SIZE;
				for (let s = 0; s < nsects; s++) {
					sections.push(parseSection64(view, sectOffset, le));
					sectOffset += SECTION_64_SIZE;
				}

				const seg: Segment64 = {
					cmd,
					cmdsize,
					segname,
					vmaddr,
					vmsize,
					fileoff,
					filesize,
					maxprot,
					initprot,
					nsects,
					flags,
					sections
				};
				result.segments.push(seg);
				parsed = seg;
				break;
			}

			case LC_LOAD_DYLIB:
			case LC_ID_DYLIB:
			case LC_LOAD_WEAK_DYLIB:
			case LC_REEXPORT_DYLIB:
			case LC_LAZY_LOAD_DYLIB:
			case LC_LOAD_UPWARD_DYLIB: {
				const nameOffset = view.getUint32(cursor + 8, le);
				// timestamp at cursor + 12 (skip)
				const currentVersion = readVersion(view.getUint32(cursor + 16, le));
				const compatVersion = readVersion(view.getUint32(cursor + 20, le));
				const name = readCString(view, cursor + nameOffset, cmdsize - nameOffset);

				const dylib: DylibCommand = {
					cmd,
					cmdsize,
					name,
					currentVersion,
					compatVersion,
					weak: cmd === LC_LOAD_WEAK_DYLIB
				};
				// Only add to libraries list for load commands, not LC_ID_DYLIB
				if (cmd !== LC_ID_DYLIB) {
					result.libraries.push(dylib);
				}
				parsed = dylib;
				break;
			}

			case LC_DYLD_INFO:
			case LC_DYLD_INFO_ONLY: {
				const dyldInfo: DyldInfoCommand = {
					cmd,
					cmdsize,
					rebaseOff: view.getUint32(cursor + 8, le),
					rebaseSize: view.getUint32(cursor + 12, le),
					bindOff: view.getUint32(cursor + 16, le),
					bindSize: view.getUint32(cursor + 20, le),
					weakBindOff: view.getUint32(cursor + 24, le),
					weakBindSize: view.getUint32(cursor + 28, le),
					lazyBindOff: view.getUint32(cursor + 32, le),
					lazyBindSize: view.getUint32(cursor + 36, le),
					exportOff: view.getUint32(cursor + 40, le),
					exportSize: view.getUint32(cursor + 44, le)
				};
				parsed = dyldInfo;
				break;
			}

			case LC_ENCRYPTION_INFO:
			case LC_ENCRYPTION_INFO_64: {
				// Both 32-bit and 64-bit encryption info have the same structure
				const enc: EncryptionInfo64 = {
					cmd,
					cmdsize,
					cryptoff: view.getUint32(cursor + 8, le),
					cryptsize: view.getUint32(cursor + 12, le),
					cryptid: view.getUint32(cursor + 16, le)
				};
				result.encryption = enc;
				parsed = enc;
				break;
			}

			case LC_UUID: {
				const uuidStr = formatUUID(view, cursor + 8);
				const uuidCmd: UUIDCommand = { cmd, cmdsize, uuid: uuidStr };
				result.uuid = uuidStr;
				parsed = uuidCmd;
				break;
			}

			case LC_BUILD_VERSION: {
				const bv: BuildVersionCommand = {
					cmd,
					cmdsize,
					platform: view.getUint32(cursor + 8, le),
					minos: readVersion(view.getUint32(cursor + 12, le)),
					sdk: readVersion(view.getUint32(cursor + 16, le)),
					ntools: view.getUint32(cursor + 20, le)
				};
				result.buildVersion = bv;
				parsed = bv;
				break;
			}

			case LC_MAIN: {
				const main: MainCommand = {
					cmd,
					cmdsize,
					entryoff: view.getBigUint64(cursor + 8, le),
					stacksize: view.getBigUint64(cursor + 16, le)
				};
				parsed = main;
				break;
			}

			case LC_SYMTAB: {
				const sym: SymtabCommand = {
					cmd,
					cmdsize,
					symoff: view.getUint32(cursor + 8, le),
					nsyms: view.getUint32(cursor + 12, le),
					stroff: view.getUint32(cursor + 16, le),
					strsize: view.getUint32(cursor + 20, le)
				};
				result.symtabInfo = sym;
				parsed = sym;
				break;
			}

			case LC_DYSYMTAB: {
				const dsym: DysymtabCommand = {
					cmd,
					cmdsize,
					ilocalsym: view.getUint32(cursor + 8, le),
					nlocalsym: view.getUint32(cursor + 12, le),
					iextdefsym: view.getUint32(cursor + 16, le),
					nextdefsym: view.getUint32(cursor + 20, le),
					iundefsym: view.getUint32(cursor + 24, le),
					nundefsym: view.getUint32(cursor + 28, le)
				};
				parsed = dsym;
				break;
			}

			case LC_CODE_SIGNATURE: {
				const cs: LinkeditDataCommand = {
					cmd,
					cmdsize,
					dataoff: view.getUint32(cursor + 8, le),
					datasize: view.getUint32(cursor + 12, le)
				};
				result.codeSignatureInfo = { offset: cs.dataoff, size: cs.datasize };
				parsed = cs;
				break;
			}

			case LC_DYLD_CHAINED_FIXUPS: {
				const cf: LinkeditDataCommand = {
					cmd,
					cmdsize,
					dataoff: view.getUint32(cursor + 8, le),
					datasize: view.getUint32(cursor + 12, le)
				};
				result.chainedFixupsInfo = { offset: cf.dataoff, size: cf.datasize };
				parsed = cf;
				break;
			}

			case LC_RPATH: {
				const pathOffset = view.getUint32(cursor + 8, le);
				const path = readCString(view, cursor + pathOffset, cmdsize - pathOffset);
				const rp: RpathCommand = { cmd, cmdsize, path };
				parsed = rp;
				break;
			}

			case LC_FUNCTION_STARTS: {
				const fs: LinkeditDataCommand = {
					cmd,
					cmdsize,
					dataoff: view.getUint32(cursor + 8, le),
					datasize: view.getUint32(cursor + 12, le)
				};
				result.functionStartsInfo = { offset: fs.dataoff, size: fs.datasize };
				parsed = fs;
				break;
			}

			case LC_SOURCE_VERSION: {
				const sv: SourceVersionCommand = {
					cmd,
					cmdsize,
					version: view.getBigUint64(cursor + 8, le)
				};
				parsed = sv;
				break;
			}

			default: {
				parsed = { cmd, cmdsize };
				break;
			}
		}

		result.loadCommands.push(parsed);

		// ALWAYS advance by cmdsize, never by struct size
		cursor += cmdsize;
	}

	return result;
}

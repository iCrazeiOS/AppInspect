/**
 * Static library (`.a`) extraction.
 *
 * A static library is an ar archive of relocatable objects, and a universal one is a
 * fat file whose slices are each such an archive. Every Mach-O member is written to
 * its own file so the per-binary pipeline can analyse it. Members are matched across
 * architecture slices by name, and a member present in several slices is written as a
 * universal object, so the usual architecture selection applies to it. Non-Mach-O
 * members (the archive symbol table, LLVM bitcode) are skipped.
 */

import * as fs from "node:fs";
import * as path from "node:path";

import { formatArch } from "../../shared/arch";
import { AR_MAGIC, hasArMagic, parseArArchive } from "../parser/ar";
import { FAT_MAGIC, MACHO_MAGICS, MH_MAGIC, MH_MAGIC_64, parseFatHeader } from "../parser/macho";

export interface StaticLibraryMember {
	name: string;
	path: string;
}

export type StaticLibraryExtraction = { success: true } | { success: false; error: string };

const FAT_HEADER_SIZE = 8;
const FAT_ARCH_SIZE = 20;
/** Alignment (log2) of each slice in a written universal object. */
const OBJECT_SLICE_ALIGN = 3;
/** Bytes read to classify a file: enough for a fat header and the first ar member header. */
const SNIFF_BYTES = 4096;

/** Debian packages share the ar format; their first member is always `debian-binary`. */
function isDebianArchive(bytes: Uint8Array, offset: number): boolean {
	const name = Buffer.from(
		bytes.subarray(offset + AR_MAGIC.length, offset + AR_MAGIC.length + 16)
	)
		.toString("ascii")
		.trim();
	return name === "debian-binary" || name === "debian-binary/";
}

/**
 * True for an ar archive that is not a Debian package, or a universal file whose
 * slices are ar archives (a fat static library). Reads only the first few KB.
 */
export function isStaticLibraryFile(filePath: string): boolean {
	let fd: number | null = null;
	try {
		fd = fs.openSync(filePath, "r");
		const head = Buffer.alloc(SNIFF_BYTES);
		const bytesRead = fs.readSync(fd, head, 0, head.length, 0);
		const bytes = head.subarray(0, bytesRead);
		if (hasArMagic(bytes)) return !isDebianArchive(bytes, 0);
		if (bytes.length < 4 || bytes.readUInt32BE(0) !== FAT_MAGIC) return false;

		const fat = parseFatHeader(head.buffer.slice(head.byteOffset, head.byteOffset + bytesRead));
		const first = fat.ok ? fat.data[0] : undefined;
		if (!first) return false;
		const magic = Buffer.alloc(AR_MAGIC.length);
		fs.readSync(fd, magic, 0, magic.length, first.offset);
		return hasArMagic(magic);
	} catch {
		return false;
	} finally {
		if (fd !== null) fs.closeSync(fd);
	}
}

function isMachOObject(bytes: Uint8Array): boolean {
	if (bytes.length < 4) return false;
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	const magic = view.getUint32(0, false);
	return (
		magic !== FAT_MAGIC &&
		(MACHO_MAGICS.has(magic) || MACHO_MAGICS.has(view.getUint32(0, true)))
	);
}

/** A member name usable as a file name on every platform. */
function safeFileName(name: string, index: number): string {
	const base = name.replace(/[/\\:*?"<>|\0]/g, "_").trim();
	return base === "" || base === "." || base === ".." ? `member-${index}.o` : base;
}

/** `Foo.o`, then `Foo (2).o`, … for members that share a name within one archive. */
function numberedName(name: string, occurrence: number): string {
	if (occurrence === 1) return name;
	const ext = path.extname(name);
	return `${name.slice(0, name.length - ext.length)} (${occurrence})${ext}`;
}

interface Slice {
	cputype: number;
	cpusubtype: number;
	offset: number;
	size: number;
}

/** Write `slices` as a universal file (big-endian fat header, aligned slices). */
function buildUniversal(slices: { cputype: number; cpusubtype: number; data: Uint8Array }[]) {
	const alignment = 1 << OBJECT_SLICE_ALIGN;
	const align = (n: number) => Math.ceil(n / alignment) * alignment;
	let cursor = align(FAT_HEADER_SIZE + slices.length * FAT_ARCH_SIZE);
	const placed = slices.map((s) => {
		const offset = cursor;
		cursor = align(offset + s.data.length);
		return { ...s, offset };
	});
	const out = Buffer.alloc(placed.reduce((end, s) => Math.max(end, s.offset + s.data.length), 0));
	out.writeUInt32BE(FAT_MAGIC, 0);
	out.writeUInt32BE(placed.length, 4);
	placed.forEach((s, i) => {
		const base = FAT_HEADER_SIZE + i * FAT_ARCH_SIZE;
		out.writeUInt32BE(s.cputype >>> 0, base);
		out.writeUInt32BE(s.cpusubtype >>> 0, base + 4);
		out.writeUInt32BE(s.offset, base + 8);
		out.writeUInt32BE(s.data.length, base + 12);
		out.writeUInt32BE(OBJECT_SLICE_ALIGN, base + 16);
		out.set(s.data, s.offset);
	});
	return out;
}

/**
 * Extract every Mach-O member of `libraryPath` into `destDir` (created if missing),
 * one file per member name. Fails when the file is not a static library or holds
 * no Mach-O objects.
 */
export async function extractStaticLibrary(
	libraryPath: string,
	destDir: string
): Promise<StaticLibraryExtraction> {
	let bytes: Buffer;
	try {
		bytes = fs.readFileSync(libraryPath);
	} catch (err) {
		return { success: false, error: err instanceof Error ? err.message : String(err) };
	}

	let slices: Slice[];
	if (hasArMagic(bytes)) {
		slices = [{ cputype: 0, cpusubtype: 0, offset: 0, size: bytes.length }];
	} else {
		// Copy the header bytes: parseFatHeader takes a plain ArrayBuffer
		const fat = parseFatHeader(new Uint8Array(bytes.subarray(0, SNIFF_BYTES)).buffer);
		if (!fat.ok || fat.data[0]?.cputype === 0) {
			return { success: false, error: "Not a static library (no ar archive found)" };
		}
		slices = fat.data.filter(
			(s) => s.offset + s.size <= bytes.length && hasArMagic(bytes, s.offset)
		);
		if (slices.length === 0) {
			return { success: false, error: "Not a static library (no ar archive found)" };
		}
	}

	// File name → one object per architecture slice
	const members = new Map<string, { cputype: number; cpusubtype: number; data: Uint8Array }[]>();
	let index = 0;
	for (const slice of slices) {
		const parsed = parseArArchive(bytes, slice.offset, slice.size);
		if (!parsed.ok) continue;
		const seen = new Map<string, number>();
		for (const member of parsed.data) {
			index++;
			const data = bytes.subarray(member.offset, member.offset + member.size);
			if (!isMachOObject(data)) continue;
			const base = safeFileName(member.name, index);
			// Counted case-insensitively so no two files collide on such file systems
			const key = base.toLowerCase();
			const occurrence = (seen.get(key) ?? 0) + 1;
			seen.set(key, occurrence);
			const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
			const magic = view.getUint32(0, false);
			const le = magic !== MH_MAGIC_64 && magic !== MH_MAGIC;
			const entry = {
				cputype: view.getUint32(4, le),
				cpusubtype: view.getUint32(8, le),
				data
			};
			const name = numberedName(base, occurrence);
			const list = members.get(name);
			if (list) list.push(entry);
			else members.set(name, [entry]);
		}
	}

	if (members.size === 0) {
		return { success: false, error: "Static library contains no Mach-O object files" };
	}

	try {
		fs.mkdirSync(destDir, { recursive: true });
		for (const [name, objects] of members) {
			const out = objects.length === 1 ? objects[0]!.data : buildUniversal(objects);
			fs.writeFileSync(path.join(destDir, name), out);
		}
	} catch (err) {
		return { success: false, error: err instanceof Error ? err.message : String(err) };
	}
	return { success: true };
}

/** The member files extracted into `dir`, sorted by name. */
export function listStaticLibraryMembers(dir: string): StaticLibraryMember[] {
	let entries: fs.Dirent[];
	try {
		entries = fs.readdirSync(dir, { withFileTypes: true });
	} catch {
		return [];
	}
	return entries
		.filter((e) => e.isFile())
		.map((e) => ({ name: e.name, path: path.join(dir, e.name) }))
		.sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" }));
}

/**
 * Architectures present across extracted members, in first-seen order. Reads only
 * each member's header, so it works the same on a cache hit.
 */
export function memberArchitectures(members: StaticLibraryMember[]): string[] {
	const names = new Set<string>();
	for (const member of members) {
		let fd: number | null = null;
		try {
			fd = fs.openSync(member.path, "r");
			const head = Buffer.alloc(SNIFF_BYTES);
			const bytesRead = fs.readSync(fd, head, 0, head.length, 0);
			if (bytesRead >= 4 && head.readUInt32BE(0) === FAT_MAGIC) {
				const fat = parseFatHeader(new Uint8Array(head.subarray(0, bytesRead)).buffer);
				if (fat.ok)
					for (const a of fat.data) names.add(formatArch(a.cputype, a.cpusubtype));
			} else if (bytesRead >= 12 && isMachOObject(head)) {
				const le =
					head.readUInt32BE(0) !== MH_MAGIC_64 && head.readUInt32BE(0) !== MH_MAGIC;
				const cputype = le ? head.readUInt32LE(4) : head.readUInt32BE(4);
				const cpusubtype = le ? head.readUInt32LE(8) : head.readUInt32BE(8);
				names.add(formatArch(cputype, cpusubtype));
			}
		} catch {
			// Unreadable member: skip
		} finally {
			if (fd !== null) fs.closeSync(fd);
		}
	}
	return [...names];
}

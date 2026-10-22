/**
 * ASAR archive parser.
 *
 * Reads the Chromium Pickle header of an Electron `app.asar` archive and
 * exposes its entries as a lazy, read-only filesystem. File data is never
 * loaded here — callers read individual files by offset, or from the
 * `.unpacked` sibling directory.
 */

import { createHash } from "node:crypto";
import * as fs from "node:fs";

import type { AsarEntry } from "../../shared/types";
import type { Result } from "../parser/result";
import { withoutAsar } from "../util/no-asar";
import { isInside, safeJoin } from "../util/safe-path";

// ── Constants ──────────────────────────────────────────────────────────

const HEADER_START = 8;
const PREAMBLE_SIZE = 16;
const MAX_HEADER_SIZE = 64 * 1024 * 1024;
const MAX_ENTRIES = 200_000;
const MAX_DEPTH = 64;
const MAX_NAME_LENGTH = 4096;
const MAX_LINK_HOPS = 8;

// ── Types ──────────────────────────────────────────────────────────────

export interface AsarFileRecord {
	path: string;
	size: number;
	offset: number;
	unpacked: boolean;
	executable: boolean;
	link?: string;
}

export interface AsarArchive {
	path: string;
	size: number;
	dataOffset: number;
	headerHash: string;
	entries: AsarEntry[];
	files: Map<string, AsarFileRecord>;
	/** Regular files and links; directories are not counted. */
	fileCount: number;
	unpackedCount: number;
}

interface AsarTree {
	entries: AsarEntry[];
	files: Map<string, AsarFileRecord>;
	fileCount: number;
	unpackedCount: number;
}

// ── Helpers ────────────────────────────────────────────────────────────

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isValidName(name: string): boolean {
	if (name.length === 0 || name.length > MAX_NAME_LENGTH) return false;
	if (name === "." || name === "..") return false;
	return (
		!name.includes("/") && !name.includes("\\") && !name.includes("\0") && !name.includes(":")
	);
}

/** Offsets and sizes are numbers, or decimal strings in newer archives. */
function toSafeInteger(value: unknown): number | null {
	if (typeof value === "number") {
		return Number.isSafeInteger(value) && value >= 0 ? value : null;
	}
	if (typeof value === "string" && /^[0-9]+$/.test(value)) {
		const parsed = Number(value);
		return Number.isSafeInteger(parsed) ? parsed : null;
	}
	return null;
}

/** Resolve a link target relative to the entry's directory, refusing escapes. */
function resolveLink(entryPath: string, link: string): string | null {
	if (link.startsWith("/") || link.includes("\\") || link.includes("\0")) return null;
	const segments = entryPath.split("/");
	segments.pop();
	for (const segment of link.split("/")) {
		if (segment === "" || segment === ".") continue;
		if (segment === "..") {
			if (segments.length === 0) return null;
			segments.pop();
		} else {
			segments.push(segment);
		}
	}
	return segments.length > 0 ? segments.join("/") : null;
}

function readAt(filePath: string, offset: number, length: number): Result<Buffer> {
	const data = Buffer.alloc(length);
	let fd: number | null = null;
	try {
		fd = fs.openSync(filePath, "r");
		let read = 0;
		while (read < length) {
			const bytes = fs.readSync(fd, data, read, length - read, offset + read);
			if (bytes === 0) {
				return { ok: false, error: "Unexpected end of file while reading ASAR data" };
			}
			read += bytes;
		}
		return { ok: true, data };
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		return { ok: false, error: `Failed to read ASAR data: ${message}` };
	} finally {
		if (fd !== null) {
			try {
				fs.closeSync(fd);
			} catch {
				/* already closed */
			}
		}
	}
}

// ── Header parsing ─────────────────────────────────────────────────────

function buildTree(root: Record<string, unknown>, dataSize: number): Result<AsarTree> {
	const files = new Map<string, AsarFileRecord>();
	const seen = new Set<string>();
	let fileCount = 0;
	let unpackedCount = 0;
	let entryCount = 0;

	const walk = (
		nodes: Record<string, unknown>,
		parentPath: string,
		depth: number
	): Result<AsarEntry[]> => {
		if (depth > MAX_DEPTH) {
			return { ok: false, error: `ASAR directory nesting exceeds ${MAX_DEPTH} levels` };
		}

		const entries: AsarEntry[] = [];
		for (const name of Object.keys(nodes)) {
			if (!isValidName(name)) {
				return { ok: false, error: `Invalid ASAR entry name: ${JSON.stringify(name)}` };
			}
			entryCount++;
			if (entryCount > MAX_ENTRIES) {
				return { ok: false, error: `ASAR archive has more than ${MAX_ENTRIES} entries` };
			}

			const node = nodes[name];
			if (!isRecord(node)) {
				return { ok: false, error: `Invalid ASAR entry: ${name}` };
			}
			const entryPath = parentPath ? `${parentPath}/${name}` : name;
			if (seen.has(entryPath)) {
				return { ok: false, error: `Duplicate ASAR entry: ${entryPath}` };
			}
			seen.add(entryPath);

			if (node.files !== undefined) {
				if (!isRecord(node.files)) {
					return { ok: false, error: `Invalid ASAR directory: ${entryPath}` };
				}
				const children = walk(node.files, entryPath, depth + 1);
				if (!children.ok) return children;
				entries.push({
					name,
					path: entryPath,
					size: children.data.reduce((sum, child) => sum + child.size, 0),
					isDirectory: true,
					children: children.data
				});
				continue;
			}

			if (node.link !== undefined) {
				if (
					typeof node.link !== "string" ||
					node.link.length === 0 ||
					node.link.length > MAX_NAME_LENGTH
				) {
					return { ok: false, error: `Invalid ASAR link: ${entryPath}` };
				}
				files.set(entryPath, {
					path: entryPath,
					size: 0,
					offset: 0,
					unpacked: false,
					executable: false,
					link: node.link
				});
				entries.push({
					name,
					path: entryPath,
					size: 0,
					isDirectory: false,
					link: node.link
				});
				fileCount++;
				continue;
			}

			const size = toSafeInteger(node.size);
			if (size === null) {
				return { ok: false, error: `Invalid size for ASAR entry: ${entryPath}` };
			}
			const unpacked = node.unpacked === true;
			const executable = node.executable === true;

			let offset = 0;
			if (!unpacked) {
				const parsed = toSafeInteger(node.offset);
				if (parsed === null) {
					return { ok: false, error: `Invalid offset for ASAR entry: ${entryPath}` };
				}
				if (parsed > dataSize || size > dataSize - parsed) {
					return {
						ok: false,
						error: `ASAR entry extends beyond the data region: ${entryPath}`
					};
				}
				offset = parsed;
			}

			files.set(entryPath, { path: entryPath, size, offset, unpacked, executable });
			const entry: AsarEntry = { name, path: entryPath, size, isDirectory: false };
			if (unpacked) entry.unpacked = true;
			if (executable) entry.executable = true;
			entries.push(entry);
			fileCount++;
			if (unpacked) unpackedCount++;
		}

		entries.sort((a, b) => {
			if (a.isDirectory !== b.isDirectory) return a.isDirectory ? -1 : 1;
			return a.name.localeCompare(b.name);
		});
		return { ok: true, data: entries };
	};

	const entries = walk(root, "", 0);
	if (!entries.ok) return entries;
	return { ok: true, data: { entries: entries.data, files, fileCount, unpackedCount } };
}

// ── Public API ─────────────────────────────────────────────────────────

export function readAsarHeader(archivePath: string): Result<AsarArchive> {
	return withoutAsar(() => parseAsarHeader(archivePath));
}

function parseAsarHeader(archivePath: string): Result<AsarArchive> {
	let fd: number | null = null;
	try {
		const stat = fs.statSync(archivePath);
		if (!stat.isFile()) {
			return { ok: false, error: "ASAR path is not a file" };
		}
		if (stat.size < PREAMBLE_SIZE) {
			return { ok: false, error: "ASAR archive is too small to contain a header" };
		}

		fd = fs.openSync(archivePath, "r");
		const preamble = Buffer.alloc(PREAMBLE_SIZE);
		if (fs.readSync(fd, preamble, 0, PREAMBLE_SIZE, 0) !== PREAMBLE_SIZE) {
			return { ok: false, error: "Failed to read the ASAR preamble" };
		}

		const headerSize = preamble.readUInt32LE(4);
		if (preamble.readUInt32LE(0) !== 4) {
			return { ok: false, error: "Unsupported ASAR pickle header" };
		}
		if (headerSize < 8) {
			return { ok: false, error: `Invalid ASAR header size: ${headerSize}` };
		}
		if (headerSize > MAX_HEADER_SIZE) {
			return { ok: false, error: `ASAR header exceeds ${MAX_HEADER_SIZE} bytes` };
		}
		const dataOffset = HEADER_START + headerSize;
		if (dataOffset > stat.size) {
			return { ok: false, error: "ASAR header extends beyond the end of the file" };
		}

		const jsonLength = preamble.readUInt32LE(12);
		if (jsonLength === 0 || PREAMBLE_SIZE + jsonLength > dataOffset) {
			return { ok: false, error: `Invalid ASAR JSON length: ${jsonLength}` };
		}
		const json = Buffer.alloc(jsonLength);
		let read = 0;
		while (read < jsonLength) {
			const bytes = fs.readSync(fd, json, read, jsonLength - read, PREAMBLE_SIZE + read);
			if (bytes === 0) {
				return { ok: false, error: "Unexpected end of file while reading the ASAR header" };
			}
			read += bytes;
		}

		let parsed: unknown;
		try {
			parsed = JSON.parse(json.toString("utf8"));
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			return { ok: false, error: `Invalid ASAR header JSON: ${message}` };
		}
		if (!isRecord(parsed)) {
			return { ok: false, error: "ASAR header root is not an object" };
		}
		if (!isRecord(parsed.files)) {
			return { ok: false, error: "ASAR header has no files object" };
		}

		const tree = buildTree(parsed.files, stat.size - dataOffset);
		if (!tree.ok) return tree;

		return {
			ok: true,
			data: {
				path: archivePath,
				size: stat.size,
				dataOffset,
				headerHash: createHash("sha256").update(json).digest("hex"),
				entries: tree.data.entries,
				files: tree.data.files,
				fileCount: tree.data.fileCount,
				unpackedCount: tree.data.unpackedCount
			}
		};
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		return { ok: false, error: `Failed to read ASAR header: ${message}` };
	} finally {
		if (fd !== null) {
			try {
				fs.closeSync(fd);
			} catch {
				/* already closed */
			}
		}
	}
}

export function readAsarFile(
	archive: AsarArchive,
	entryPath: string,
	maxBytes: number
): Result<{ data: Buffer; truncated: boolean }> {
	return withoutAsar(() => readAsarEntry(archive, entryPath, maxBytes));
}

function readAsarEntry(
	archive: AsarArchive,
	entryPath: string,
	maxBytes: number
): Result<{ data: Buffer; truncated: boolean }> {
	try {
		const limit = Number.isFinite(maxBytes) ? Math.max(0, Math.floor(maxBytes)) : 0;
		let record = archive.files.get(entryPath);
		if (!record) {
			return { ok: false, error: `ASAR entry not found: ${entryPath}` };
		}

		const visited = new Set<string>();
		let hops = 0;
		while (record.link !== undefined) {
			if (visited.has(record.path)) {
				return { ok: false, error: `ASAR link cycle at ${record.path}` };
			}
			visited.add(record.path);
			if (hops++ >= MAX_LINK_HOPS) {
				return { ok: false, error: `ASAR link chain exceeds ${MAX_LINK_HOPS} hops` };
			}
			const target = resolveLink(record.path, record.link);
			if (target === null) {
				return { ok: false, error: `ASAR link escapes the archive: ${record.path}` };
			}
			const next = archive.files.get(target);
			if (!next) {
				return { ok: false, error: `ASAR link target not found: ${target}` };
			}
			record = next;
		}

		if (record.unpacked) {
			const root = `${archive.path}.unpacked`;
			let realRoot: string;
			try {
				realRoot = fs.realpathSync(root);
			} catch {
				return { ok: false, error: `Unpacked ASAR directory not found: ${root}` };
			}
			const joined = safeJoin(root, record.path);
			if (joined === null) {
				return { ok: false, error: `ASAR path escapes the archive: ${record.path}` };
			}
			let realTarget: string;
			try {
				realTarget = fs.realpathSync(joined);
			} catch {
				return { ok: false, error: `Unpacked ASAR file not found: ${record.path}` };
			}
			if (!isInside(realRoot, realTarget)) {
				return {
					ok: false,
					error: `Unpacked ASAR file escapes the archive: ${record.path}`
				};
			}
			let size: number;
			try {
				const stat = fs.statSync(realTarget);
				if (!stat.isFile()) {
					return {
						ok: false,
						error: `Unpacked ASAR entry is not a file: ${record.path}`
					};
				}
				size = stat.size;
			} catch {
				return { ok: false, error: `Unpacked ASAR file is unreadable: ${record.path}` };
			}
			const toRead = Math.min(size, limit);
			const data = readAt(realTarget, 0, toRead);
			if (!data.ok) return data;
			return { ok: true, data: { data: data.data, truncated: size > toRead } };
		}

		const toRead = Math.min(record.size, limit);
		const data = readAt(archive.path, archive.dataOffset + record.offset, toRead);
		if (!data.ok) return data;
		return { ok: true, data: { data: data.data, truncated: record.size > toRead } };
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		return { ok: false, error: `Failed to read ASAR file: ${message}` };
	}
}

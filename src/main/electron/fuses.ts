/**
 * Electron fuse-wire reader.
 *
 * `@electron/fuses` embeds a short wire in the Electron Framework binary. It
 * is located by sentinel, scanning the file in chunks so a large universal
 * binary is never loaded whole.
 */

import * as fs from "node:fs";

import type { ElectronFuse, ElectronFuseState } from "../../shared/types";

/** Fuse order in the wire; index matches the state byte offset. */
export const FUSE_NAMES = [
	"RunAsNode",
	"EnableCookieEncryption",
	"EnableNodeOptionsEnvironmentVariable",
	"EnableNodeCliInspectArguments",
	"EnableEmbeddedAsarIntegrityValidation",
	"OnlyLoadAppFromAsar",
	"LoadBrowserProcessSpecificV8Snapshot",
	"GrantFileProtocolExtraPrivileges",
	"WasmTrapHandlers"
];

const SENTINEL = Buffer.from("dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX", "latin1");
const FUSE_VERSION = 1;
const CHUNK_SIZE = 4 * 1024 * 1024;
const WIRE_TAIL = SENTINEL.length + 2 + FUSE_NAMES.length;

const FUSE_STATES = new Map<number, ElectronFuseState>([
	[0x30, "disabled"],
	[0x31, "enabled"],
	[0x72, "removed"]
]);

function readWire(fd: number, fileSize: number, sentinelOffset: number): ElectronFuse[] {
	const wireStart = sentinelOffset + SENTINEL.length;
	const head = Buffer.alloc(2);
	if (fs.readSync(fd, head, 0, 2, wireStart) !== 2) return [];

	const version = head[0];
	const length = head[1];
	if (version !== FUSE_VERSION || length === undefined || length === 0) return [];

	const statesStart = wireStart + 2;
	if (statesStart + length > fileSize) return [];
	const states = Buffer.alloc(length);
	if (fs.readSync(fd, states, 0, length, statesStart) !== length) return [];

	const count = Math.min(length, FUSE_NAMES.length);
	const fuses: ElectronFuse[] = [];
	for (let i = 0; i < count; i++) {
		const name = FUSE_NAMES[i];
		const state = FUSE_STATES.get(states[i]!);
		if (!name || !state) return [];
		fuses.push({ name, state });
	}
	return fuses;
}

export function readFuses(binaryPath: string): ElectronFuse[] {
	let fd: number | null = null;
	try {
		fd = fs.openSync(binaryPath, "r");
		const fileSize = fs.fstatSync(fd).size;
		const buffer = Buffer.alloc(Math.min(fileSize, CHUNK_SIZE) + WIRE_TAIL);

		for (let position = 0; position < fileSize; position += CHUNK_SIZE) {
			const bytes = fs.readSync(fd, buffer, 0, buffer.length, position);
			const index = buffer.subarray(0, bytes).indexOf(SENTINEL);
			if (index !== -1) return readWire(fd, fileSize, position + index);
		}
		return [];
	} catch {
		return [];
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

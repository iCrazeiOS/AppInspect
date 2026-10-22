import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";

import { FUSE_NAMES, readFuses } from "../fuses";

const SENTINEL = "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX";
const CHUNK_SIZE = 4 * 1024 * 1024;

let TMP_DIR = "";

beforeAll(() => {
	TMP_DIR = mkdtempSync(path.join(tmpdir(), "appinspect-fuses-"));
});
afterAll(() => {
	rmSync(TMP_DIR, { recursive: true, force: true });
});

function wire(states: number[]): Buffer {
	return Buffer.concat([
		Buffer.from(SENTINEL, "latin1"),
		Buffer.from([1, states.length]),
		Buffer.from(states)
	]);
}

function writeFixture(name: string, buffer: Buffer): string {
	const filePath = path.join(TMP_DIR, name);
	writeFileSync(filePath, buffer);
	return filePath;
}

describe("readFuses", () => {
	it("reads all three fuse states in wire order", () => {
		const states = [0x31, 0x30, 0x72, 0x31, 0x30, 0x72, 0x31, 0x30, 0x72];
		const fuses = readFuses(writeFixture("states.bin", wire(states)));

		expect(fuses).toHaveLength(FUSE_NAMES.length);
		expect(fuses.map((fuse) => fuse.name)).toEqual(FUSE_NAMES);
		expect(fuses.map((fuse) => fuse.state)).toEqual([
			"enabled",
			"disabled",
			"removed",
			"enabled",
			"disabled",
			"removed",
			"enabled",
			"disabled",
			"removed"
		]);
	});

	it("finds a sentinel at a chunk boundary", () => {
		const padding = Buffer.alloc(CHUNK_SIZE - 1);
		const fuses = readFuses(
			writeFixture("boundary.bin", Buffer.concat([padding, wire([0x31])]))
		);

		expect(fuses).toEqual([{ name: FUSE_NAMES[0]!, state: "enabled" }]);
	});

	it("uses the first sentinel in a fat binary", () => {
		const first = wire([0x30]);
		const second = wire([0x31]);
		const fuses = readFuses(writeFixture("fat.bin", Buffer.concat([first, second])));

		expect(fuses).toEqual([{ name: FUSE_NAMES[0]!, state: "disabled" }]);
	});

	it("returns an empty list without a sentinel", () => {
		expect(readFuses(writeFixture("plain.bin", Buffer.alloc(1024)))).toEqual([]);
	});

	it("returns an empty list for a missing file", () => {
		expect(readFuses(path.join(TMP_DIR, "missing.bin"))).toEqual([]);
	});

	it("returns an empty list for a short wire", () => {
		const sentinel = Buffer.from(SENTINEL, "latin1");
		expect(readFuses(writeFixture("short-wire.bin", sentinel))).toEqual([]);
		expect(
			readFuses(writeFixture("version-only.bin", Buffer.concat([sentinel, Buffer.from([1])])))
		).toEqual([]);
	});

	it("returns an empty list for an unknown fuse version", () => {
		const buffer = Buffer.concat([Buffer.from(SENTINEL, "latin1"), Buffer.from([2, 1, 0x31])]);
		expect(readFuses(writeFixture("wrong-version.bin", buffer))).toEqual([]);
	});

	it("returns an empty list when the length exceeds the remaining bytes", () => {
		const buffer = Buffer.concat([
			Buffer.from(SENTINEL, "latin1"),
			Buffer.from([1, 9, 0x31, 0x30])
		]);
		expect(readFuses(writeFixture("short-states.bin", buffer))).toEqual([]);
	});

	it("returns an empty list for an unknown state byte", () => {
		expect(readFuses(writeFixture("bad-state.bin", wire([0x41])))).toEqual([]);
	});
});

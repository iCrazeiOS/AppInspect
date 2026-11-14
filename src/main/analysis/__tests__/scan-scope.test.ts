/**
 * Tests for section-scoped analysis (AnalysisSession.setRequestedSections).
 */

import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { AnalysisSession } from "../orchestrator";

const TMP_DIR = path.join(import.meta.dir, ".tmp-scan-scope-test");
const TEST_FILE = path.join(TMP_DIR, "scoped.bin");
const STRINGS = "scopedString\0";
const HEADER_SIZE = 32;
const SEG_SIZE = 72;
const SECT_SIZE = 80;
const CMD_SIZE = SEG_SIZE + SECT_SIZE;
const STRING_OFFSET = HEADER_SIZE + CMD_SIZE;
const TEXT_VMADDR = 0x100000000n;

function name16(value: string): Uint8Array {
	const out = new Uint8Array(16);
	for (let i = 0; i < value.length && i < 16; i++) out[i] = value.charCodeAt(i);
	return out;
}

function buildBinary(): Uint8Array {
	const fileSize = STRING_OFFSET + STRINGS.length;
	const bytes = new Uint8Array(fileSize);
	const view = new DataView(bytes.buffer);

	// mach_header_64
	view.setUint32(0, 0xfeedfacf, true);
	view.setUint32(4, 0x0100000c, true);
	view.setUint32(8, 0, true);
	view.setUint32(12, 0x2, true);
	view.setUint32(16, 1, true);
	view.setUint32(20, CMD_SIZE, true);
	view.setUint32(24, 0x00200000, true);
	view.setUint32(28, 0, true);

	// LC_SEGMENT_64 __TEXT
	view.setUint32(32, 0x19, true);
	view.setUint32(36, CMD_SIZE, true);
	bytes.set(name16("__TEXT"), 40);
	view.setBigUint64(56, TEXT_VMADDR, true);
	view.setBigUint64(64, BigInt(fileSize), true);
	view.setBigUint64(72, 0n, true);
	view.setBigUint64(80, BigInt(fileSize), true);
	view.setUint32(88, 7, true);
	view.setUint32(92, 5, true);
	view.setUint32(96, 1, true);
	view.setUint32(100, 0, true);

	// section_64 __TEXT.__cstring
	bytes.set(name16("__cstring"), 104);
	bytes.set(name16("__TEXT"), 120);
	view.setBigUint64(136, TEXT_VMADDR + BigInt(STRING_OFFSET), true);
	view.setBigUint64(144, BigInt(STRINGS.length), true);
	view.setUint32(152, STRING_OFFSET, true);
	view.setUint32(156, 0, true);
	view.setUint32(160, 0, true);
	view.setUint32(164, 0, true);
	view.setUint32(168, 0, true);
	view.setUint32(172, 0, true);
	view.setUint32(176, 0, true);
	view.setUint32(180, 0, true);

	for (let i = 0; i < STRINGS.length; i++) {
		bytes[STRING_OFFSET + i] = STRINGS.charCodeAt(i);
	}
	return bytes;
}

beforeAll(() => {
	mkdirSync(TMP_DIR, { recursive: true });
	writeFileSync(TEST_FILE, buildBinary());
});

afterAll(() => {
	rmSync(TMP_DIR, { recursive: true, force: true });
});

describe("section-scoped analysis", () => {
	it("runs only the parsers needed for the strings tab", async () => {
		const session = new AnalysisSession();
		session.setRequestedSections(["strings"]);
		const phases: string[] = [];

		const result = await session.analyseMachO(TEST_FILE, (phase) => phases.push(phase));

		expect(result.strings.map((s) => s.value)).toContain("scopedString");
		expect(phases).toContain("Extracting strings...");
		expect(phases).not.toContain("Parsing symbols...");
		expect(phases).not.toContain("Extracting ObjC metadata...");
		expect(phases).not.toContain("Extracting Swift metadata...");
		expect(phases).not.toContain("Parsing code signature...");
		expect(phases).not.toContain("Running security scan...");
		expect(result.symbols).toEqual([]);
		expect(result.objc.classes).toEqual([]);
		expect(result.swift.present).toBe(false);
		expect(result.security.findings).toEqual([]);
	});

	it("runs the security and codesign passes a hardening overview depends on", async () => {
		const session = new AnalysisSession();
		session.setRequestedSections(["overview"]);
		const phases: string[] = [];

		await session.analyseMachO(TEST_FILE, (phase) => phases.push(phase));

		expect(phases).toContain("Parsing symbols...");
		expect(phases).toContain("Parsing code signature...");
		expect(phases).toContain("Running security scan...");
		expect(phases).not.toContain("Extracting strings...");
		expect(phases).not.toContain("Extracting ObjC metadata...");
		expect(phases).not.toContain("Extracting Swift metadata...");
	});

	it("does not build a file tree when it was not requested", async () => {
		const session = new AnalysisSession();
		session.setRequestedSections(["strings"]);
		const result = await session.analyseMachO(TEST_FILE, () => {});

		expect(result.files).toEqual([]);
	});

	it("restores the full analysis when the scope is cleared", async () => {
		const session = new AnalysisSession();
		session.setRequestedSections(["strings"]);
		session.setRequestedSections(null);
		const phases: string[] = [];

		await session.analyseMachO(TEST_FILE, (phase) => phases.push(phase));

		expect(phases).toContain("Extracting strings...");
		expect(phases).toContain("Parsing symbols...");
		expect(phases).toContain("Extracting ObjC metadata...");
		expect(phases).toContain("Extracting Swift metadata...");
	});
});

import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { AnalysisSession, analyseBinaryFile } from "../orchestrator";
import type { BinarySearchIndex } from "../search-index";

const TMP_DIR = path.join(import.meta.dir, ".tmp-search-index-test");
const TEST_FILE = path.join(TMP_DIR, "dylib-test.bin");

// Build a minimal 64-bit ARM64 Mach-O with a single LC_LOAD_DYLIB command so
// that `libraries` (one of the four name sources the search index consumes) is
// genuinely populated. No segments/symtab means strings/symbols/classes stay
// empty — enough to prove the light path leaves every name source untouched.
const DYLIB_NAME = "/usr/lib/libTest.dylib";

function buildBinary(): Uint8Array {
	const nameOffset = 24;
	const namePadded = Math.ceil((DYLIB_NAME.length + 1) / 8) * 8;
	const cmdSize = nameOffset + namePadded;
	const bytes = new Uint8Array(32 + cmdSize);
	const view = new DataView(bytes.buffer);

	// mach_header_64
	view.setUint32(0, 0xfeedfacf, true); // MH_MAGIC_64
	view.setUint32(4, 0x0100000c, true); // CPU_TYPE_ARM64
	view.setUint32(8, 0, true); // cpusubtype
	view.setUint32(12, 0x2, true); // MH_EXECUTE
	view.setUint32(16, 1, true); // ncmds
	view.setUint32(20, cmdSize, true); // sizeofcmds
	view.setUint32(24, 0x00200000, true); // MH_PIE
	view.setUint32(28, 0, true); // reserved

	// LC_LOAD_DYLIB
	view.setUint32(32, 0xc, true); // cmd
	view.setUint32(36, cmdSize, true); // cmdsize
	view.setUint32(40, nameOffset, true); // name offset
	view.setUint32(44, 0, true); // timestamp
	view.setUint32(48, 0x00010000, true); // current version 1.0.0
	view.setUint32(52, 0x00010000, true); // compat version 1.0.0
	for (let i = 0; i < DYLIB_NAME.length; i++) {
		bytes[32 + nameOffset + i] = DYLIB_NAME.charCodeAt(i);
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

describe("analyseBinaryFile light path (search index)", () => {
	it("produces name sources byte-identical to a full analysis", async () => {
		const full = await analyseBinaryFile(TEST_FILE, () => {}, 0);
		const light = await analyseBinaryFile(TEST_FILE, () => {}, 0, undefined, undefined, {
			skipCodesign: true,
			skipSecurity: true,
			skipHooks: true
		});

		// The dylib command must be picked up, or the test would be vacuous.
		expect(full.libraries.map((l) => l.name)).toContain(DYLIB_NAME);

		// The four sources the search index keeps must not change.
		expect(light.libraries.map((l) => l.name)).toEqual(full.libraries.map((l) => l.name));
		expect(light.strings.map((s) => s.value)).toEqual(full.strings.map((s) => s.value));
		expect(light.symbols.map((s) => s.name)).toEqual(full.symbols.map((s) => s.name));
		expect(light.classes.map((c) => c.name)).toEqual(full.classes.map((c) => c.name));
	});

	it("skips the terminal steps it is told to skip", async () => {
		const light = await analyseBinaryFile(TEST_FILE, () => {}, 0, undefined, undefined, {
			skipCodesign: true,
			skipSecurity: true,
			skipHooks: true
		});

		expect(light.entitlements).toEqual([]);
		expect(light.teamId).toBeNull();
		expect(light.security.findings).toEqual([]);
		expect(light.hooks.frameworks).toEqual([]);
	});
});

describe("AnalysisSession.searchAllBinaries swift tab", () => {
	async function sessionWithSwift(swift: string[]): Promise<AnalysisSession> {
		const session = new AnalysisSession();
		await session.analyseMachO(TEST_FILE, () => {});
		const entry: BinarySearchIndex = {
			objc: [],
			strings: [],
			symbols: [],
			symbolTypes: [],
			libraries: [],
			swift
		};
		(session as unknown as { searchIndex: Map<number, BinarySearchIndex> }).searchIndex =
			new Map([[0, entry]]);
		return session;
	}

	it("matches Swift type full names case-insensitively by default", async () => {
		const session = await sessionWithSwift(["Nationwide.Foo.Bar", "Other.Baz"]);
		const results = await session.searchAllBinaries("foo", "swift", () => {});
		expect(results).toHaveLength(1);
		expect(results[0]).toMatchObject({ binaryIndex: 0, match: "Nationwide.Foo.Bar" });
	});

	it("honours case sensitivity and regex", async () => {
		const session = await sessionWithSwift(["Nationwide.Foo.Bar", "Other.Baz"]);
		expect(await session.searchAllBinaries("foo", "swift", () => {}, false, true)).toHaveLength(
			0
		);
		const re = await session.searchAllBinaries("^Other\\.", "swift", () => {}, true, true);
		expect(re.map((r) => r.match)).toEqual(["Other.Baz"]);
	});

	it("indexes a real analysis with no Swift types as empty", async () => {
		const session = new AnalysisSession();
		await session.analyseMachO(TEST_FILE, () => {});
		expect(await session.searchAllBinaries("x", "swift", () => {})).toEqual([]);
	});
});

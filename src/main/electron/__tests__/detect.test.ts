import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import plist from "plist";

import { detectElectron } from "../detect";

const SENTINEL = "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX";

let TMP_DIR = "";

beforeAll(() => {
	TMP_DIR = mkdtempSync(path.join(tmpdir(), "appinspect-electron-"));
});
afterAll(() => {
	rmSync(TMP_DIR, { recursive: true, force: true });
});

// ── ASAR fixtures ──────────────────────────────────────────────────────

interface FixtureNode {
	data?: string;
	files?: Record<string, FixtureNode>;
}

function packAsar(tree: Record<string, FixtureNode>): { buffer: Buffer; headerHash: string } {
	const chunks: Buffer[] = [];
	let offset = 0;

	const build = (nodes: Record<string, FixtureNode>): Record<string, unknown> => {
		const result: Record<string, unknown> = {};
		for (const [name, node] of Object.entries(nodes)) {
			if (node.files) {
				result[name] = { files: build(node.files) };
				continue;
			}
			const data = Buffer.from(node.data ?? "");
			result[name] = { size: data.length, offset };
			offset += data.length;
			chunks.push(data);
		}
		return result;
	};

	const json = Buffer.from(JSON.stringify({ files: build(tree) }));
	const headerSize = 8 + ((json.length + 3) & ~3);
	const data = Buffer.concat(chunks);
	const buffer = Buffer.alloc(8 + headerSize + data.length);
	buffer.writeUInt32LE(4, 0);
	buffer.writeUInt32LE(headerSize, 4);
	buffer.writeUInt32LE(json.length + 4, 8);
	buffer.writeUInt32LE(json.length, 12);
	json.copy(buffer, 16);
	data.copy(buffer, 8 + headerSize);
	return { buffer, headerHash: createHash("sha256").update(json).digest("hex") };
}

const DEFAULT_ASAR = packAsar({
	"package.json": { data: '{"name":"demo","version":"1.0.0","main":"index.js"}' },
	"index.js": { data: "console.log(1)" },
	maps: { files: { "app.js.map": { data: "{}" } } },
	addons: { files: { "native.node": { data: "" } } }
});

function fuseWire(states: number[] = [0x31]): Buffer {
	return Buffer.concat([
		Buffer.from(SENTINEL, "latin1"),
		Buffer.from([1, states.length]),
		Buffer.from(states)
	]);
}

interface AppOptions {
	electronVersion?: string;
	integrityHash?: string | null;
	algorithm?: string;
	/** "valid" writes the normal table; "absent" writes a plist with no table. */
	integrityEntry?: "valid" | "absent" | "malformed" | "unsupported";
	asar?: Buffer | null;
	flatFramework?: boolean;
}

function makeApp(name: string, options: AppOptions = {}): string {
	const root = path.join(TMP_DIR, name);
	const contents = path.join(root, "Contents");
	const resources = path.join(contents, "Resources");
	mkdirSync(resources, { recursive: true });

	const frameworkDir = path.join(contents, "Frameworks", "Electron Framework.framework");
	const frameworkRoot = options.flatFramework
		? frameworkDir
		: path.join(frameworkDir, "Versions", "A");
	mkdirSync(path.join(frameworkRoot, "Resources"), { recursive: true });
	writeFileSync(path.join(frameworkRoot, "Electron Framework"), fuseWire());
	writeFileSync(
		path.join(frameworkRoot, "Resources", "Info.plist"),
		plist.build({ CFBundleVersion: options.electronVersion ?? "40.4.0" })
	);

	if (options.asar !== null) {
		writeFileSync(path.join(resources, "app.asar"), options.asar ?? DEFAULT_ASAR.buffer);
	}

	if (options.integrityHash !== null) {
		const entry = options.integrityEntry ?? "valid";
		let plistData: Record<string, unknown> = {};
		if (entry === "absent") {
			plistData = { CFBundleName: "Demo" };
		} else if (entry === "malformed") {
			plistData = {
				ElectronAsarIntegrity: {
					"Resources/app.asar": { algorithm: "SHA256", hash: 123 }
				}
			};
		} else if (entry === "unsupported") {
			plistData = {
				ElectronAsarIntegrity: {
					"Resources/app.asar": {
						algorithm: "MD5",
						hash: options.integrityHash ?? DEFAULT_ASAR.headerHash
					}
				}
			};
		} else {
			plistData = {
				ElectronAsarIntegrity: {
					"Resources/app.asar": {
						algorithm: options.algorithm ?? "SHA256",
						hash: options.integrityHash ?? DEFAULT_ASAR.headerHash
					}
				}
			};
		}
		writeFileSync(path.join(contents, "Info.plist"), plist.build(plistData));
	}

	return root;
}

describe("detectElectron", () => {
	it("reads the framework, archive and integrity entry", () => {
		const root = makeApp("Demo.app");
		const info = detectElectron(root, true);
		if (!info) throw new Error("expected Electron info");

		expect(info.electronVersion).toBe("40.4.0");
		expect(info.asarPath).toBe(path.join(root, "Contents", "Resources", "app.asar"));
		expect(info.asarSize).toBe(DEFAULT_ASAR.buffer.length);
		expect(info.fileCount).toBe(4);
		expect(info.unpackedCount).toBe(0);
		expect(info.packageJson).toEqual({
			name: "demo",
			version: "1.0.0",
			main: "index.js"
		});
		expect(info.integrity).toEqual({
			algorithm: "SHA256",
			expected: DEFAULT_ASAR.headerHash,
			actual: DEFAULT_ASAR.headerHash,
			valid: true
		});
		expect(info.sourceMaps).toEqual(["maps/app.js.map"]);
		expect(info.nativeAddons).toEqual(["addons/native.node"]);
		expect(info.fuses).toEqual([{ name: "RunAsNode", state: "enabled" }]);
		expect(info.integrityIssue).toBeUndefined();
	});

	it("marks a mismatched integrity hash as invalid", () => {
		const info = detectElectron(
			makeApp("Mismatch.app", { integrityHash: "00".repeat(32) }),
			true
		);
		if (!info) throw new Error("expected Electron info");

		expect(info.integrity?.valid).toBe(false);
		expect(info.integrity?.expected).toBe("00".repeat(32));
		expect(info.integrity?.actual).toBe(DEFAULT_ASAR.headerHash);
	});

	it("accepts a lower-case algorithm name", () => {
		const info = detectElectron(makeApp("Lowercase.app", { algorithm: "sha256" }), true);
		expect(info?.integrity?.valid).toBe(true);
		expect(info?.integrityIssue).toBeUndefined();
	});

	it("reports a plist without an integrity entry as missing", () => {
		const info = detectElectron(makeApp("Absent.app", { integrityEntry: "absent" }), true);
		expect(info?.integrity).toBeUndefined();
		expect(info?.integrityIssue).toEqual({ kind: "missing" });
	});

	it("reports an unsupported integrity algorithm", () => {
		const info = detectElectron(
			makeApp("Unsupported.app", { integrityEntry: "unsupported" }),
			true
		);
		expect(info?.integrity).toBeUndefined();
		expect(info?.integrityIssue).toEqual({
			kind: "unsupported-algorithm",
			algorithm: "MD5"
		});
	});

	it("reports a malformed integrity entry", () => {
		const info = detectElectron(
			makeApp("MalformedEntry.app", { integrityEntry: "malformed" }),
			true
		);
		expect(info?.integrity).toBeUndefined();
		expect(info?.integrityIssue).toEqual({ kind: "malformed" });
	});

	it("does not record an issue when no Info.plist exists", () => {
		const info = detectElectron(makeApp("NoPlist.app", { integrityHash: null }), true);
		expect(info?.integrity).toBeUndefined();
		expect(info?.integrityIssue).toBeUndefined();
	});

	it("keeps info when the archive is malformed", () => {
		const info = detectElectron(
			makeApp("Malformed.app", {
				asar: Buffer.from("not an asar"),
				integrityHash: null
			}),
			true
		);
		if (!info) throw new Error("expected Electron info");

		expect(info.electronVersion).toBe("40.4.0");
		expect(info.asarPath).toBeUndefined();
		expect(info.fileCount).toBe(0);
		expect(info.packageJson).toBeUndefined();
		expect(info.integrity).toBeUndefined();
		expect(info.sourceMaps).toEqual([]);
		expect(info.nativeAddons).toEqual([]);
		expect(info.fuses).toHaveLength(1);
	});

	it("supports a flat framework layout", () => {
		const info = detectElectron(makeApp("Flat.app", { flatFramework: true }), true);
		if (!info) throw new Error("expected Electron info");

		expect(info.electronVersion).toBe("40.4.0");
		expect(info.fuses).toEqual([{ name: "RunAsNode", state: "enabled" }]);
	});

	it("detects an archive without a framework", () => {
		const root = path.join(TMP_DIR, "AsarOnly");
		mkdirSync(path.join(root, "resources"), { recursive: true });
		writeFileSync(path.join(root, "resources", "app.asar"), DEFAULT_ASAR.buffer);

		const info = detectElectron(root, false);
		if (!info) throw new Error("expected Electron info");

		expect(info.asarPath).toBe(path.join(root, "resources", "app.asar"));
		expect(info.fileCount).toBe(4);
		expect(info.electronVersion).toBeUndefined();
		expect(info.fuses).toEqual([]);
		expect(info.integrity).toBeUndefined();
	});

	it("finds an archive when given the Contents directory", () => {
		const root = path.join(TMP_DIR, "ContentsOnly");
		mkdirSync(path.join(root, "Resources"), { recursive: true });
		writeFileSync(path.join(root, "Resources", "app.asar"), DEFAULT_ASAR.buffer);

		const info = detectElectron(root, true);
		expect(info?.asarPath).toBe(path.join(root, "Resources", "app.asar"));
	});

	it("detects a framework without an archive", () => {
		const info = detectElectron(
			makeApp("NoAsar.app", { asar: null, integrityHash: null }),
			true
		);
		if (!info) throw new Error("expected Electron info");

		expect(info.asarPath).toBeUndefined();
		expect(info.fileCount).toBe(0);
		expect(info.electronVersion).toBe("40.4.0");
	});

	it("returns null for a non-Electron bundle", () => {
		const root = path.join(TMP_DIR, "Native.app");
		mkdirSync(path.join(root, "Contents", "Resources"), { recursive: true });
		expect(detectElectron(root, true)).toBeNull();
	});
});

import { describe, expect, it } from "bun:test";
import {
	CS_MAGIC_CODEDIRECTORY,
	CS_MAGIC_ENTITLEMENTS,
	CS_MAGIC_SUPERBLOB,
	CS_SLOT_CODEDIRECTORY,
	CS_SLOT_ENTITLEMENTS,
	extractEntitlements,
	parseCodeSignature
} from "../codesign";

// ── Fixture Helpers ──────────────────────────────────────────────────

/**
 * Write a uint32 in big-endian to a DataView.
 */
function writeU32BE(view: DataView, offset: number, value: number): void {
	view.setUint32(offset, value, false);
}

/**
 * Write a string as raw bytes into a buffer at the given offset.
 */
function writeString(view: DataView, offset: number, str: string): void {
	for (let i = 0; i < str.length; i++) {
		view.setUint8(offset + i, str.charCodeAt(i));
	}
}

/**
 * Build entitlements XML plist string from a key-value object.
 */
function buildEntitlementsXml(entries: Record<string, unknown>): string {
	let inner = "";
	for (const [key, value] of Object.entries(entries)) {
		inner += `\t<key>${key}</key>\n`;
		if (typeof value === "boolean") {
			inner += value ? "\t<true/>\n" : "\t<false/>\n";
		} else if (typeof value === "string") {
			inner += `\t<string>${value}</string>\n`;
		}
	}
	return (
		`<?xml version="1.0" encoding="UTF-8"?>\n` +
		`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n` +
		`<plist version="1.0">\n<dict>\n${inner}</dict>\n</plist>`
	);
}

/**
 * Build a SuperBlob buffer containing the given sub-blobs.
 * Each sub-blob is { type, data: Uint8Array }.
 * The entire buffer is prefixed with `prefixSize` bytes of zeros
 * to simulate the SuperBlob living at an offset within a larger file.
 */
function buildSuperBlob(
	subBlobs: Array<{ type: number; data: Uint8Array }>,
	prefixSize: number = 0
): ArrayBuffer {
	// SuperBlob header: magic(4) + length(4) + count(4) = 12 bytes
	// BlobIndex entries: count * 8 bytes
	const headerSize = 12 + subBlobs.length * 8;

	// Calculate offsets for each sub-blob (relative to SuperBlob start)
	const blobOffsets: number[] = [];
	let currentOffset = headerSize;
	for (const blob of subBlobs) {
		blobOffsets.push(currentOffset);
		currentOffset += blob.data.byteLength;
	}

	const totalSuperBlobSize = currentOffset;
	const buf = new ArrayBuffer(prefixSize + totalSuperBlobSize);
	const view = new DataView(buf);

	// Write SuperBlob header
	const sbStart = prefixSize;
	writeU32BE(view, sbStart, CS_MAGIC_SUPERBLOB);
	writeU32BE(view, sbStart + 4, totalSuperBlobSize);
	writeU32BE(view, sbStart + 8, subBlobs.length);

	// Write BlobIndex entries
	for (let i = 0; i < subBlobs.length; i++) {
		const entryOffset = sbStart + 12 + i * 8;
		writeU32BE(view, entryOffset, subBlobs[i]!.type);
		writeU32BE(view, entryOffset + 4, blobOffsets[i]!);
	}

	// Write sub-blob data
	for (let i = 0; i < subBlobs.length; i++) {
		const dest = sbStart + blobOffsets[i]!;
		const src = subBlobs[i]!.data;
		for (let j = 0; j < src.byteLength; j++) {
			view.setUint8(dest + j, src[j]!);
		}
	}

	return buf;
}

/**
 * Build an entitlements blob (magic 0xFADE7171) from an XML string.
 */
function buildEntitlementsBlob(xmlString: string): Uint8Array {
	const xmlBytes = new TextEncoder().encode(xmlString);
	const blobSize = 8 + xmlBytes.byteLength;
	const buf = new ArrayBuffer(blobSize);
	const view = new DataView(buf);

	writeU32BE(view, 0, CS_MAGIC_ENTITLEMENTS);
	writeU32BE(view, 4, blobSize);
	for (let i = 0; i < xmlBytes.byteLength; i++) {
		view.setUint8(8 + i, xmlBytes[i]!);
	}

	return new Uint8Array(buf);
}

/**
 * Build a code directory blob (magic 0xFADE0C02) with optional teamID.
 */
function buildCodeDirectoryBlob(opts: {
	version?: number;
	flags?: number;
	codeLimit?: number;
	hashType?: number;
	teamID?: string | null;
}): Uint8Array {
	const version = opts.version ?? 0x20400;
	const flags = opts.flags ?? 0;
	const codeLimit = opts.codeLimit ?? 65536;
	const hashType = opts.hashType ?? 2; // SHA-256
	const teamID = opts.teamID ?? null;

	// Fixed header: 52 bytes minimum
	// If teamID is present (version >= 0x20200), teamOffset is at byte 48
	const headerSize = 52;
	const teamBytes = teamID ? new TextEncoder().encode(teamID) : null;
	const teamOffset = teamID ? headerSize : 0;
	const totalSize = headerSize + (teamBytes ? teamBytes.byteLength + 1 : 0); // +1 for null terminator

	const buf = new ArrayBuffer(totalSize);
	const view = new DataView(buf);

	writeU32BE(view, 0, CS_MAGIC_CODEDIRECTORY); // magic
	writeU32BE(view, 4, totalSize); // length
	writeU32BE(view, 8, version); // version
	writeU32BE(view, 12, flags); // flags
	writeU32BE(view, 16, 0); // hashOffset
	writeU32BE(view, 20, 0); // identOffset
	writeU32BE(view, 24, 0); // nSpecialSlots
	writeU32BE(view, 28, 0); // nCodeSlots
	writeU32BE(view, 32, codeLimit); // codeLimit
	view.setUint8(36, 32); // hashSize
	view.setUint8(37, hashType); // hashType
	view.setUint8(38, 0); // platform
	view.setUint8(39, 12); // pageSize (log2)
	writeU32BE(view, 40, 0); // spare2

	// teamOffset at byte 48
	if (version >= 0x20200) {
		writeU32BE(view, 44, 0); // scatter offset (unused)
		writeU32BE(view, 48, teamOffset);
	}

	// Write teamID string after header
	if (teamBytes) {
		for (let i = 0; i < teamBytes.byteLength; i++) {
			view.setUint8(headerSize + i, teamBytes[i]!);
		}
		view.setUint8(headerSize + teamBytes.byteLength, 0); // null terminator
	}

	return new Uint8Array(buf);
}

// ── Tests ────────────────────────────────────────────────────────────

describe("parseCodeSignature", () => {
	it("should parse a SuperBlob with entitlements and code directory", () => {
		const xml = buildEntitlementsXml({
			"com.apple.security.app-sandbox": true,
			"com.apple.application-identifier": "TEAM123.com.example.app"
		});
		const entBlob = buildEntitlementsBlob(xml);
		const cdBlob = buildCodeDirectoryBlob({
			version: 0x20400,
			flags: 0x00020002,
			codeLimit: 131072,
			hashType: 2,
			teamID: "TEAM123ABC"
		});

		const buffer = buildSuperBlob([
			{ type: CS_SLOT_CODEDIRECTORY, data: cdBlob },
			{ type: CS_SLOT_ENTITLEMENTS, data: entBlob }
		]);

		const result = parseCodeSignature(buffer, 0, buffer.byteLength);
		expect(result).not.toBeNull();
		expect(result!.entitlements).not.toBeNull();
		expect(result!.entitlements!["com.apple.security.app-sandbox"]).toBe(true);
		expect(result!.entitlements!["com.apple.application-identifier"]).toBe(
			"TEAM123.com.example.app"
		);

		expect(result!.codeDirectory).not.toBeNull();
		expect(result!.codeDirectory!.teamID).toBe("TEAM123ABC");
		expect(result!.codeDirectory!.flags).toBe(0x00020002);
		expect(result!.codeDirectory!.codeLimit).toBe(131072);
		expect(result!.codeDirectory!.hashType).toBe(2);
		expect(result!.codeDirectory!.version).toBe(0x20400);
	});

	it("should extract entitlements XML correctly", () => {
		const xml = buildEntitlementsXml({
			"get-task-allow": true,
			"keychain-access-groups": "ABCDE12345.*"
		});
		const entBlob = buildEntitlementsBlob(xml);

		const buffer = buildSuperBlob([{ type: CS_SLOT_ENTITLEMENTS, data: entBlob }]);

		const result = parseCodeSignature(buffer, 0, buffer.byteLength);
		expect(result).not.toBeNull();
		expect(result!.entitlements).not.toBeNull();
		expect(result!.entitlements!["get-task-allow"]).toBe(true);
		expect(result!.entitlementsRaw).toContain("get-task-allow");
	});

	it("should extract teamID from code directory with version >= 0x20200", () => {
		const cdBlob = buildCodeDirectoryBlob({
			version: 0x20200,
			teamID: "9F86D081885"
		});

		const buffer = buildSuperBlob([{ type: CS_SLOT_CODEDIRECTORY, data: cdBlob }]);

		const result = parseCodeSignature(buffer, 0, buffer.byteLength);
		expect(result).not.toBeNull();
		expect(result!.codeDirectory).not.toBeNull();
		expect(result!.codeDirectory!.teamID).toBe("9F86D081885");
	});

	it("should not extract teamID from code directory with version < 0x20200", () => {
		const cdBlob = buildCodeDirectoryBlob({
			version: 0x20100,
			teamID: null
		});

		const buffer = buildSuperBlob([{ type: CS_SLOT_CODEDIRECTORY, data: cdBlob }]);

		const result = parseCodeSignature(buffer, 0, buffer.byteLength);
		expect(result).not.toBeNull();
		expect(result!.codeDirectory).not.toBeNull();
		expect(result!.codeDirectory!.teamID).toBeNull();
	});

	it("should return null for missing/zero code signature offset", () => {
		const buffer = new ArrayBuffer(100);
		expect(parseCodeSignature(buffer, 0, 0)).toBeNull();
		expect(parseCodeSignature(buffer, 0, 4)).toBeNull();
		expect(extractEntitlements(buffer, 0, 0)).toBeNull();
	});

	it("should throw on invalid SuperBlob magic", () => {
		const buf = new ArrayBuffer(64);
		const view = new DataView(buf);
		// Write some garbage magic
		writeU32BE(view, 0, 0xdeadbeef);
		writeU32BE(view, 4, 64);
		writeU32BE(view, 8, 0);

		expect(() => parseCodeSignature(buf, 0, 64)).toThrow(/Invalid SuperBlob magic/);
	});

	it("should return null entitlements when SuperBlob has no entitlements blob", () => {
		const cdBlob = buildCodeDirectoryBlob({
			version: 0x20400,
			teamID: "TEAM999"
		});

		// Only include code directory, no entitlements
		const buffer = buildSuperBlob([{ type: CS_SLOT_CODEDIRECTORY, data: cdBlob }]);

		const result = parseCodeSignature(buffer, 0, buffer.byteLength);
		expect(result).not.toBeNull();
		expect(result!.entitlements).toBeNull();
		expect(result!.entitlementsRaw).toBeNull();
		expect(result!.codeDirectory).not.toBeNull();
		expect(result!.codeDirectory!.teamID).toBe("TEAM999");
	});

	it("should handle SuperBlob at a non-zero offset in the buffer", () => {
		const xml = buildEntitlementsXml({
			"com.apple.developer.team-identifier": "ABCXYZ"
		});
		const entBlob = buildEntitlementsBlob(xml);
		const prefixSize = 4096; // Simulate SuperBlob at offset 4096

		const buffer = buildSuperBlob([{ type: CS_SLOT_ENTITLEMENTS, data: entBlob }], prefixSize);

		const csSize = buffer.byteLength - prefixSize;
		const result = parseCodeSignature(buffer, prefixSize, csSize);
		expect(result).not.toBeNull();
		expect(result!.entitlements).not.toBeNull();
		expect(result!.entitlements!["com.apple.developer.team-identifier"]).toBe("ABCXYZ");
	});

	it("should skip unrecognised blob types without errors", () => {
		const xml = buildEntitlementsXml({ "test-key": true });
		const entBlob = buildEntitlementsBlob(xml);

		// Build a fake requirements blob (type 0x00002)
		const reqBlob = new Uint8Array(16);
		const reqView = new DataView(reqBlob.buffer);
		writeU32BE(reqView, 0, 0xfade0c01); // requirements magic
		writeU32BE(reqView, 4, 16);

		const buffer = buildSuperBlob([
			{ type: 0x00002, data: reqBlob }, // requirements - should be skipped
			{ type: CS_SLOT_ENTITLEMENTS, data: entBlob }
		]);

		const result = parseCodeSignature(buffer, 0, buffer.byteLength);
		expect(result).not.toBeNull();
		expect(result!.entitlements).not.toBeNull();
		expect(result!.entitlements!["test-key"]).toBe(true);
	});
});

describe("extractEntitlements", () => {
	it("should return just the entitlements object", () => {
		const xml = buildEntitlementsXml({
			"application-identifier": "TEAM.com.example",
			"aps-environment": "production"
		});
		const entBlob = buildEntitlementsBlob(xml);

		const buffer = buildSuperBlob([{ type: CS_SLOT_ENTITLEMENTS, data: entBlob }]);

		const ent = extractEntitlements(buffer, 0, buffer.byteLength);
		expect(ent).not.toBeNull();
		expect(ent!["application-identifier"]).toBe("TEAM.com.example");
		expect(ent!["aps-environment"]).toBe("production");
	});

	it("should return null when no entitlements exist", () => {
		const cdBlob = buildCodeDirectoryBlob({ version: 0x20400 });
		const buffer = buildSuperBlob([{ type: CS_SLOT_CODEDIRECTORY, data: cdBlob }]);

		const ent = extractEntitlements(buffer, 0, buffer.byteLength);
		expect(ent).toBeNull();
	});
});

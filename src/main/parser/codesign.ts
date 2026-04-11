/**
 * Code Signature + Entitlements Parser
 *
 * Parses the code signature SuperBlob embedded in a Mach-O binary.
 * Extracts entitlements (XML plist) and code directory metadata.
 *
 * IMPORTANT: All code signature structures use BIG-ENDIAN byte order,
 * unlike the rest of the little-endian Mach-O file.
 *
 * Does NOT verify signatures, parse DER entitlements, validate
 * certificate chains, or parse requirements blobs.
 */

import plist from "plist";
import { readCString } from "./load-commands";
import { silenceXmldom } from "./plist";

// ── Magic Constants ──────────────────────────────────────────────────

export const CS_MAGIC_SUPERBLOB = 0xfade0cc0;
export const CS_MAGIC_ENTITLEMENTS = 0xfade7171;
export const CS_MAGIC_CODEDIRECTORY = 0xfade0c02;

// ── Blob Type Constants ──────────────────────────────────────────────

export const CS_SLOT_CODEDIRECTORY = 0x00000;
export const CS_SLOT_ENTITLEMENTS = 0x00005;

// ── Types ────────────────────────────────────────────────────────────

export interface BlobIndex {
	type: number;
	offset: number;
}

export interface CodeDirectory {
	version: number;
	flags: number;
	hashOffset: number;
	identOffset: number;
	nSpecialSlots: number;
	nCodeSlots: number;
	codeLimit: number;
	hashSize: number;
	hashType: number;
	platform: number;
	pageSize: number;
	spare2: number;
	teamID: string | null;
}

export interface CodeSignatureResult {
	entitlements: Record<string, unknown> | null;
	entitlementsRaw: string | null;
	codeDirectory: CodeDirectory | null;
}

// ── Parsers ──────────────────────────────────────────────────────────

/**
 * Parse the entitlements blob (magic 0xFADE7171).
 * Returns the parsed plist object and raw XML string, or null if parsing fails.
 */
function parseEntitlementsBlob(
	view: DataView,
	blobStart: number
): { entitlements: Record<string, unknown>; raw: string } | null {
	const magic = view.getUint32(blobStart, false);
	if (magic !== CS_MAGIC_ENTITLEMENTS) {
		return null;
	}

	const length = view.getUint32(blobStart + 4, false);
	// XML plist starts after the 8-byte blob header (magic + length)
	const xmlLength = length - 8;
	if (xmlLength <= 0) {
		return null;
	}

	const xmlBytes: number[] = [];
	for (let i = 0; i < xmlLength; i++) {
		xmlBytes.push(view.getUint8(blobStart + 8 + i));
	}
	const xmlString = String.fromCharCode(...xmlBytes);

	try {
		const parsed = silenceXmldom(() => plist.parse(xmlString));
		if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
			return { entitlements: parsed as Record<string, unknown>, raw: xmlString };
		}
		return null;
	} catch {
		return null;
	}
}

/**
 * Parse the code directory blob (magic 0xFADE0C02).
 * Extracts version, flags, hash info, and optionally teamID.
 */
function parseCodeDirectoryBlob(
	view: DataView,
	blobStart: number,
	_blobMaxLen: number
): CodeDirectory | null {
	const magic = view.getUint32(blobStart, false);
	if (magic !== CS_MAGIC_CODEDIRECTORY) {
		return null;
	}

	const length = view.getUint32(blobStart + 4, false);

	// Code directory header fields (all uint32 BE after magic+length)
	const version = view.getUint32(blobStart + 8, false);
	const flags = view.getUint32(blobStart + 12, false);
	const hashOffset = view.getUint32(blobStart + 16, false);
	const identOffset = view.getUint32(blobStart + 20, false);
	const nSpecialSlots = view.getUint32(blobStart + 24, false);
	const nCodeSlots = view.getUint32(blobStart + 28, false);
	const codeLimit = view.getUint32(blobStart + 32, false);
	const hashSize = view.getUint8(blobStart + 36);
	const hashType = view.getUint8(blobStart + 37);
	const platform = view.getUint8(blobStart + 38);
	const pageSize = view.getUint8(blobStart + 39);
	const spare2 = view.getUint32(blobStart + 40, false);

	// teamID: available if version >= 0x20200, offset at byte 48 from blob start
	let teamID: string | null = null;
	if (version >= 0x20200 && length > 52) {
		const teamOffset = view.getUint32(blobStart + 48, false);
		if (teamOffset > 0 && teamOffset < length) {
			teamID = readCString(view, blobStart + teamOffset, Math.min(256, length - teamOffset));
		}
	}

	return {
		version,
		flags,
		hashOffset,
		identOffset,
		nSpecialSlots,
		nCodeSlots,
		codeLimit,
		hashSize,
		hashType,
		platform,
		pageSize,
		spare2,
		teamID
	};
}

// ── Public API ───────────────────────────────────────────────────────

/**
 * Parse the code signature SuperBlob at the given offset within the buffer.
 *
 * @param buffer   The full Mach-O file buffer
 * @param csOffset Byte offset to the SuperBlob (from LC_CODE_SIGNATURE)
 * @param csSize   Size in bytes of the code signature region
 * @returns Parsed code signature info, or null if offset/size is invalid
 */
export function parseCodeSignature(
	buffer: ArrayBuffer,
	csOffset: number,
	csSize: number
): CodeSignatureResult | null {
	if (csOffset == null || csSize == null || csOffset < 0 || csSize < 12) {
		return null;
	}

	if (csOffset + csSize > buffer.byteLength) {
		return null;
	}

	const view = new DataView(buffer);

	// Read SuperBlob header
	const magic = view.getUint32(csOffset, false);
	if (magic !== CS_MAGIC_SUPERBLOB) {
		throw new Error(
			`Invalid SuperBlob magic: 0x${magic.toString(16).padStart(8, "0")} (expected 0xFADE0CC0)`
		);
	}

	const _length = view.getUint32(csOffset + 4, false);
	const count = view.getUint32(csOffset + 8, false);

	// Read BlobIndex entries
	const blobs: BlobIndex[] = [];
	for (let i = 0; i < count; i++) {
		const entryOffset = csOffset + 12 + i * 8;
		const type = view.getUint32(entryOffset, false);
		const offset = view.getUint32(entryOffset + 4, false);
		blobs.push({ type, offset });
	}

	const result: CodeSignatureResult = {
		entitlements: null,
		entitlementsRaw: null,
		codeDirectory: null
	};

	// Process each blob
	for (const blob of blobs) {
		// Blob offset is relative to SuperBlob start
		const blobAbsOffset = csOffset + blob.offset;
		const blobMaxLen = csSize - blob.offset;

		if (blobMaxLen < 8) continue;

		switch (blob.type) {
			case CS_SLOT_ENTITLEMENTS: {
				const ent = parseEntitlementsBlob(view, blobAbsOffset);
				if (ent) {
					result.entitlements = ent.entitlements;
					result.entitlementsRaw = ent.raw;
				}
				break;
			}

			case CS_SLOT_CODEDIRECTORY: {
				const cd = parseCodeDirectoryBlob(view, blobAbsOffset, blobMaxLen);
				if (cd) {
					result.codeDirectory = cd;
				}
				break;
			}

			// Skip other blob types (requirements, etc.)
			default:
				break;
		}
	}

	return result;
}

/**
 * Convenience wrapper: extract just the entitlements dictionary from a code signature.
 *
 * @param buffer   The full Mach-O file buffer
 * @param csOffset Byte offset to the SuperBlob
 * @param csSize   Size in bytes of the code signature region
 * @returns Entitlements object or null
 */
export function extractEntitlements(
	buffer: ArrayBuffer,
	csOffset: number,
	csSize: number
): Record<string, unknown> | null {
	const result = parseCodeSignature(buffer, csOffset, csSize);
	return result?.entitlements ?? null;
}

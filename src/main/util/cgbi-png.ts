/**
 * Apple CgBI PNG transcoder.
 *
 * Xcode's pngcrush writes PNGs with an extra `CgBI` chunk, a raw-deflate IDAT
 * stream, BGRA channel order and premultiplied alpha. Chromium cannot decode
 * that variant, so image previews transcode it to a standard RGBA PNG first.
 */

import { deflateSync, inflateRawSync, inflateSync } from "node:zlib";

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const CGBI = "CgBI";

/** Refuse to expand previews past this, so a crafted PNG cannot exhaust memory. */
const MAX_CGBI_PIXELS = 16 * 1024 * 1024;
const MAX_INFLATED_BYTES = 64 * 1024 * 1024;

const CRC_TABLE = (() => {
	const table = new Uint32Array(256);
	for (let n = 0; n < 256; n++) {
		let c = n;
		for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
		table[n] = c >>> 0;
	}
	return table;
})();

interface PngChunk {
	type: string;
	data: Buffer;
}

function readChunks(data: Buffer): PngChunk[] | null {
	if (data.length < PNG_SIGNATURE.length || !data.subarray(0, 8).equals(PNG_SIGNATURE)) {
		return null;
	}
	const chunks: PngChunk[] = [];
	let offset = 8;
	let sawEnd = false;
	while (offset + 12 <= data.length) {
		const length = data.readUInt32BE(offset);
		const typeStart = offset + 4;
		const dataStart = typeStart + 4;
		const dataEnd = dataStart + length;
		if (dataEnd + 4 > data.length) return null;
		const type = data.toString("latin1", typeStart, typeStart + 4);
		chunks.push({ type, data: data.subarray(dataStart, dataEnd) });
		offset = dataEnd + 4;
		if (type === "IEND") {
			sawEnd = true;
			break;
		}
	}
	return sawEnd ? chunks : null;
}

function paeth(left: number, up: number, upLeft: number): number {
	const p = left + up - upLeft;
	const pa = Math.abs(p - left);
	const pb = Math.abs(p - up);
	const pc = Math.abs(p - upLeft);
	if (pa <= pb && pa <= pc) return left;
	return pb <= pc ? up : upLeft;
}

/** Reverse the PNG scanline filters, returning raw pixel bytes. */
function unfilter(
	data: Buffer,
	width: number,
	height: number,
	bytesPerPixel: number
): Buffer | null {
	const rowBytes = width * bytesPerPixel;
	const out = Buffer.alloc(height * rowBytes);
	let position = 0;
	for (let y = 0; y < height; y++) {
		const filter = data[position++]!;
		const rowStart = y * rowBytes;
		const previousStart = rowStart - rowBytes;
		for (let x = 0; x < rowBytes; x++) {
			const encoded = data[position++]!;
			const left = x >= bytesPerPixel ? out[rowStart + x - bytesPerPixel]! : 0;
			const up = y > 0 ? out[previousStart + x]! : 0;
			const upLeft =
				y > 0 && x >= bytesPerPixel ? out[previousStart + x - bytesPerPixel]! : 0;
			let value: number;
			switch (filter) {
				case 0:
					value = encoded;
					break;
				case 1:
					value = encoded + left;
					break;
				case 2:
					value = encoded + up;
					break;
				case 3:
					value = encoded + Math.floor((left + up) / 2);
					break;
				case 4:
					value = encoded + paeth(left, up, upLeft);
					break;
				default:
					return null;
			}
			out[rowStart + x] = value & 0xff;
		}
	}
	return out;
}

/** Undo premultiplied alpha for one colour channel. */
function unpremultiply(value: number, alpha: number): number {
	if (alpha === 0) return 0;
	if (alpha === 255) return value;
	return Math.min(255, Math.round((value * 255) / alpha));
}

/** Convert CgBI pixel bytes (BGRA, premultiplied) to straight RGBA. */
function toRgba(raw: Buffer, width: number, height: number, colorType: number): Buffer {
	const out = Buffer.alloc(width * height * 4);
	const pixels = width * height;
	let source = 0;
	let target = 0;

	for (let i = 0; i < pixels; i++) {
		switch (colorType) {
			case 6: {
				const b = raw[source++]!;
				const g = raw[source++]!;
				const r = raw[source++]!;
				const a = raw[source++]!;
				out[target++] = unpremultiply(r, a);
				out[target++] = unpremultiply(g, a);
				out[target++] = unpremultiply(b, a);
				out[target++] = a;
				break;
			}
			case 2: {
				const b = raw[source++]!;
				const g = raw[source++]!;
				const r = raw[source++]!;
				out[target++] = r;
				out[target++] = g;
				out[target++] = b;
				out[target++] = 255;
				break;
			}
			case 4: {
				const gray = raw[source++]!;
				const alpha = raw[source++]!;
				const value = unpremultiply(gray, alpha);
				out[target++] = value;
				out[target++] = value;
				out[target++] = value;
				out[target++] = alpha;
				break;
			}
			default: {
				const value = raw[source++]!;
				out[target++] = value;
				out[target++] = value;
				out[target++] = value;
				out[target++] = 255;
			}
		}
	}
	return out;
}

function crc32(data: Buffer): number {
	let crc = 0xffffffff;
	for (let i = 0; i < data.length; i++) {
		crc = CRC_TABLE[(crc ^ data[i]!) & 0xff]! ^ (crc >>> 8);
	}
	return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type: string, data: Buffer): Buffer {
	const chunk = Buffer.alloc(12 + data.length);
	chunk.writeUInt32BE(data.length, 0);
	chunk.write(type, 4, 4, "latin1");
	data.copy(chunk, 8);
	chunk.writeUInt32BE(crc32(chunk.subarray(4, 8 + data.length)), 8 + data.length);
	return chunk;
}

function encodePng(width: number, height: number, rgba: Buffer): Buffer {
	const ihdr = Buffer.alloc(13);
	ihdr.writeUInt32BE(width, 0);
	ihdr.writeUInt32BE(height, 4);
	ihdr[8] = 8; // bit depth
	ihdr[9] = 6; // RGBA
	ihdr[10] = 0; // deflate
	ihdr[11] = 0; // adaptive filtering
	ihdr[12] = 0; // no interlace

	const stride = width * 4;
	const rows = Buffer.alloc(height * (stride + 1));
	for (let y = 0; y < height; y++) {
		const target = y * (stride + 1);
		rows[target] = 0;
		rgba.copy(rows, target + 1, y * stride, (y + 1) * stride);
	}

	return Buffer.concat([
		PNG_SIGNATURE,
		pngChunk("IHDR", ihdr),
		pngChunk("IDAT", deflateSync(rows)),
		pngChunk("IEND", Buffer.alloc(0))
	]);
}

/**
 * Convert an Apple-optimised PNG to a standard RGBA PNG.
 *
 * Returns `null` when the input is not a CgBI PNG (leave it untouched) or when
 * it uses a variant this transcoder cannot safely handle.
 */
export function convertCgbiPng(data: Buffer): Buffer | null {
	const chunks = readChunks(data);
	if (!chunks?.some((chunk) => chunk.type === CGBI)) return null;

	const header = chunks.find((chunk) => chunk.type === "IHDR");
	if (!header || header.data.length < 13) return null;

	const width = header.data.readUInt32BE(0);
	const height = header.data.readUInt32BE(4);
	const bitDepth = header.data[8];
	const colorType = header.data[9];
	const compression = header.data[10];
	const filterMethod = header.data[11];
	const interlace = header.data[12];

	if (width === 0 || height === 0) return null;
	if (bitDepth !== 8 || compression !== 0 || filterMethod !== 0 || interlace !== 0) {
		return null;
	}

	let channels: number;
	switch (colorType) {
		case 0:
			channels = 1;
			break;
		case 2:
			channels = 3;
			break;
		case 4:
			channels = 2;
			break;
		case 6:
			channels = 4;
			break;
		default:
			return null;
	}

	if (width * height > MAX_CGBI_PIXELS) return null;
	const expected = height * (width * channels + 1);
	if (expected > MAX_INFLATED_BYTES) return null;

	const idat = Buffer.concat(
		chunks.filter((chunk) => chunk.type === "IDAT").map((chunk) => chunk.data)
	);
	if (idat.length === 0) return null;

	let inflated: Buffer;
	try {
		inflated = inflateRawSync(idat, { maxOutputLength: expected });
	} catch {
		// Some encoders wrap the CgBI stream in a standard zlib container.
		try {
			inflated = inflateSync(idat, { maxOutputLength: expected });
		} catch {
			return null;
		}
	}
	if (inflated.length !== expected) return null;

	const raw = unfilter(inflated, width, height, channels);
	if (raw === null) return null;

	return encodePng(width, height, toRgba(raw, width, height, colorType));
}

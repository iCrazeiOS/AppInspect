/**
 * Test fixture builder for Apple-optimised (CgBI) PNGs.
 *
 * Encodes raw pixels with the PNG scanline filters and either raw-deflate
 * (normal CgBI) or zlib-wrapped IDAT data.
 */

import { deflateRawSync, deflateSync } from "node:zlib";

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

const CRC_TABLE = (() => {
	const table = new Uint32Array(256);
	for (let n = 0; n < 256; n++) {
		let c = n;
		for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
		table[n] = c >>> 0;
	}
	return table;
})();

function crc32(data: Buffer): number {
	let crc = 0xffffffff;
	for (let i = 0; i < data.length; i++) {
		crc = CRC_TABLE[(crc ^ data[i]!) & 0xff]! ^ (crc >>> 8);
	}
	return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type: string, data: Buffer): Buffer {
	const out = Buffer.alloc(12 + data.length);
	out.writeUInt32BE(data.length, 0);
	out.write(type, 4, 4, "latin1");
	data.copy(out, 8);
	out.writeUInt32BE(crc32(out.subarray(4, 8 + data.length)), 8 + data.length);
	return out;
}

function paeth(left: number, up: number, upLeft: number): number {
	const p = left + up - upLeft;
	const pa = Math.abs(p - left);
	const pb = Math.abs(p - up);
	const pc = Math.abs(p - upLeft);
	if (pa <= pb && pa <= pc) return left;
	return pb <= pc ? up : upLeft;
}

function filterRows(
	pixels: Buffer,
	width: number,
	height: number,
	channels: number,
	filters: number[]
): Buffer {
	const rowBytes = width * channels;
	const out = Buffer.alloc(height * (rowBytes + 1));
	for (let y = 0; y < height; y++) {
		const filter = filters[y % filters.length]!;
		const rowStart = y * rowBytes;
		const previousStart = rowStart - rowBytes;
		out[y * (rowBytes + 1)] = filter;
		for (let x = 0; x < rowBytes; x++) {
			const value = pixels[rowStart + x]!;
			const left = x >= channels ? pixels[rowStart + x - channels]! : 0;
			const up = y > 0 ? pixels[previousStart + x]! : 0;
			const upLeft = y > 0 && x >= channels ? pixels[previousStart + x - channels]! : 0;
			let encoded: number;
			switch (filter) {
				case 0:
					encoded = value;
					break;
				case 1:
					encoded = value - left;
					break;
				case 2:
					encoded = value - up;
					break;
				case 3:
					encoded = value - Math.floor((left + up) / 2);
					break;
				case 4:
					encoded = value - paeth(left, up, upLeft);
					break;
				default:
					throw new Error(`Unsupported test filter ${filter}`);
			}
			out[y * (rowBytes + 1) + 1 + x] = encoded & 0xff;
		}
	}
	return out;
}

export interface CgbiPngOptions {
	width: number;
	height: number;
	/** Pixel bytes in the archive's stored order (BGRA for colour types 2/6). */
	pixels: Buffer;
	/** Defaults to 6 (RGBA). */
	colorType?: number;
	/** Defaults to 8. */
	bitDepth?: number;
	/** Defaults to 0 (no interlace). */
	interlace?: number;
	/** PNG filters to apply per row (defaults to all zero). */
	filters?: number[];
	/** Omit the CgBI chunk to build a standard PNG instead. */
	cgbi?: boolean;
	/** Wrap the IDAT stream in a zlib container. */
	zlib?: boolean;
}

export function buildCgbiPng(options: CgbiPngOptions): Buffer {
	const {
		width,
		height,
		pixels,
		colorType = 6,
		bitDepth = 8,
		interlace = 0,
		filters = [0],
		cgbi = true,
		zlib = false
	} = options;
	const channels = colorType === 6 ? 4 : colorType === 2 ? 3 : colorType === 4 ? 2 : 1;
	if (pixels.length !== width * height * channels) {
		throw new Error("Fixture pixel buffer size does not match its dimensions");
	}

	const ihdr = Buffer.alloc(13);
	ihdr.writeUInt32BE(width, 0);
	ihdr.writeUInt32BE(height, 4);
	ihdr[8] = bitDepth;
	ihdr[9] = colorType;
	ihdr[10] = 0;
	ihdr[11] = 0;
	ihdr[12] = interlace;

	const rows = filterRows(pixels, width, height, channels, filters);
	const idat = zlib ? deflateSync(rows) : deflateRawSync(rows);

	const parts: Buffer[] = [PNG_SIGNATURE];
	if (cgbi) parts.push(chunk("CgBI", Buffer.from([0x50, 0x00, 0x20, 0x02])));
	parts.push(chunk("IHDR", ihdr), chunk("IDAT", idat), chunk("IEND", Buffer.alloc(0)));
	return Buffer.concat(parts);
}

import { describe, expect, it } from "bun:test";
import { inflateSync } from "node:zlib";

import { convertCgbiPng } from "../cgbi-png";
import { buildCgbiPng } from "./fixtures";

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

interface DecodedPng {
	width: number;
	height: number;
	bitDepth: number;
	colorType: number;
	rows: Buffer;
}

function decodePng(png: Buffer): DecodedPng {
	expect(png.subarray(0, 8)).toEqual(PNG_SIGNATURE);
	let offset = 8;
	let header: Buffer | null = null;
	const idat: Buffer[] = [];
	while (offset + 12 <= png.length) {
		const length = png.readUInt32BE(offset);
		const type = png.toString("latin1", offset + 4, offset + 8);
		const data = png.subarray(offset + 8, offset + 8 + length);
		if (type === "IHDR") header = data;
		if (type === "IDAT") idat.push(data);
		offset += 12 + length;
	}
	if (!header) throw new Error("Converted PNG has no IHDR");
	return {
		width: header.readUInt32BE(0),
		height: header.readUInt32BE(4),
		bitDepth: header[8]!,
		colorType: header[9]!,
		rows: inflateSync(Buffer.concat(idat))
	};
}

describe("convertCgbiPng", () => {
	it("converts premultiplied BGRA pixels to straight RGBA", () => {
		const png = buildCgbiPng({
			width: 2,
			height: 1,
			pixels: Buffer.from([64, 32, 16, 128, 10, 20, 30, 255])
		});

		const converted = convertCgbiPng(png);
		if (!converted) throw new Error("Expected a converted PNG");

		const decoded = decodePng(converted);
		expect(decoded).toMatchObject({ width: 2, height: 1, bitDepth: 8, colorType: 6 });
		expect(decoded.rows).toEqual(Buffer.from([0, 32, 64, 128, 128, 30, 20, 10, 255]));
		expect(converted.includes("CgBI")).toBe(false);
	});

	it("reverses every PNG scanline filter", () => {
		const png = buildCgbiPng({
			width: 1,
			height: 5,
			filters: [0, 1, 2, 3, 4],
			pixels: Buffer.from([
				64, 32, 16, 128, 0, 0, 255, 255, 0, 255, 0, 255, 255, 0, 0, 255, 255, 255, 255, 255
			])
		});

		const converted = convertCgbiPng(png);
		if (!converted) throw new Error("Expected a converted PNG");

		expect(decodePng(converted).rows).toEqual(
			Buffer.from([
				0, 32, 64, 128, 128, 0, 255, 0, 0, 255, 0, 0, 255, 0, 255, 0, 0, 0, 255, 255, 0,
				255, 255, 255, 255
			])
		);
	});

	it("converts opaque BGR images", () => {
		const png = buildCgbiPng({
			width: 1,
			height: 1,
			colorType: 2,
			pixels: Buffer.from([10, 20, 30])
		});

		const converted = convertCgbiPng(png);
		if (!converted) throw new Error("Expected a converted PNG");
		expect(decodePng(converted).rows).toEqual(Buffer.from([0, 30, 20, 10, 255]));
	});

	it("converts premultiplied grayscale with alpha", () => {
		const png = buildCgbiPng({
			width: 1,
			height: 1,
			colorType: 4,
			pixels: Buffer.from([64, 128])
		});

		const converted = convertCgbiPng(png);
		if (!converted) throw new Error("Expected a converted PNG");
		expect(decodePng(converted).rows).toEqual(Buffer.from([0, 128, 128, 128, 128]));
	});

	it("accepts a zlib-wrapped IDAT stream", () => {
		const png = buildCgbiPng({
			width: 1,
			height: 1,
			zlib: true,
			pixels: Buffer.from([0, 0, 255, 255])
		});

		const converted = convertCgbiPng(png);
		if (!converted) throw new Error("Expected a converted PNG");
		expect(decodePng(converted).rows).toEqual(Buffer.from([0, 255, 0, 0, 255]));
	});

	it("returns null for standard PNGs", () => {
		const png = buildCgbiPng({
			width: 1,
			height: 1,
			cgbi: false,
			pixels: Buffer.from([0, 0, 255, 255])
		});
		expect(convertCgbiPng(png)).toBeNull();
	});

	it("returns null for unsupported variants", () => {
		const pixels = Buffer.from([0, 0, 0, 255]);
		expect(
			convertCgbiPng(buildCgbiPng({ width: 1, height: 1, pixels, interlace: 1 }))
		).toBeNull();
		expect(
			convertCgbiPng(buildCgbiPng({ width: 1, height: 1, pixels, bitDepth: 16 }))
		).toBeNull();
		expect(
			convertCgbiPng(
				buildCgbiPng({ width: 1, height: 1, colorType: 3, pixels: Buffer.from([0]) })
			)
		).toBeNull();
	});

	it("returns null for truncated or malformed input", () => {
		const png = buildCgbiPng({ width: 1, height: 1, pixels: Buffer.from([0, 0, 255, 255]) });
		const idat = png.indexOf("IDAT");
		expect(convertCgbiPng(png.subarray(0, idat + 6))).toBeNull();
		expect(convertCgbiPng(png.subarray(0, png.length - 3))).toBeNull();
		expect(convertCgbiPng(Buffer.from("not a png"))).toBeNull();
	});
});

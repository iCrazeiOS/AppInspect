import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import path from "node:path";

import { FILE_PREVIEW_IMAGE_BYTES } from "../../../shared/file-preview";
import { buildFilePreview, readFilePreview } from "../file-preview";

const TMP_DIR = path.join(import.meta.dir, ".tmp-file-preview");
const ROOT = path.join(TMP_DIR, "root");
const OUTSIDE = path.join(TMP_DIR, "outside");

function writeFile(filePath: string, content: string | Buffer): void {
	mkdirSync(path.dirname(filePath), { recursive: true });
	writeFileSync(filePath, content);
}

describe("readFilePreview", () => {
	beforeAll(() => {
		rmSync(TMP_DIR, { recursive: true, force: true });
		writeFile(path.join(ROOT, "hello.txt"), "Hello, world!\n");
		writeFile(path.join(ROOT, "bytes.bin"), Buffer.from([0x61, 0x00, 0x62]));
		writeFile(path.join(ROOT, "logo.png"), Buffer.from("not-a-real-png"));
		writeFile(path.join(ROOT, "long.txt"), "0123456789");
		writeFile(path.join(OUTSIDE, "secret.txt"), "secret");
	});

	afterAll(() => {
		rmSync(TMP_DIR, { recursive: true, force: true });
	});

	it("returns text previews", () => {
		const content = readFilePreview(path.join(ROOT, "hello.txt"), [ROOT], 1024);
		expect(content).toEqual({
			path: path.join(ROOT, "hello.txt"),
			size: 14,
			truncated: false,
			kind: "text",
			text: "Hello, world!\n"
		});
	});

	it("marks files with a NUL byte as binary and omits text", () => {
		const content = readFilePreview(path.join(ROOT, "bytes.bin"), [ROOT], 1024);
		expect(content?.kind).toBe("binary");
		expect(content?.text).toBeUndefined();
		expect(content?.size).toBe(3);
	});

	it("returns image metadata with a data URL only when includeImage is true", () => {
		const withoutImage = readFilePreview(path.join(ROOT, "logo.png"), [ROOT], 1024);
		expect(withoutImage?.kind).toBe("image");
		expect(withoutImage?.image).toBeUndefined();

		const withImage = readFilePreview(path.join(ROOT, "logo.png"), [ROOT], 1024, true);
		expect(withImage?.image).toBe(
			`data:image/png;base64,${Buffer.from("not-a-real-png").toString("base64")}`
		);
	});

	it("ignores maxBytes for images and uses the image cap", () => {
		const content = readFilePreview(path.join(ROOT, "logo.png"), [ROOT], 1, true);
		expect(content?.kind).toBe("image");
		expect(content?.truncated).toBe(false);
		expect(content?.size).toBe(Buffer.from("not-a-real-png").length);
		expect(content?.image).toBeDefined();
	});

	it("truncates text at maxBytes and reports the full size", () => {
		const content = readFilePreview(path.join(ROOT, "long.txt"), [ROOT], 4);
		expect(content).toEqual({
			path: path.join(ROOT, "long.txt"),
			size: 10,
			truncated: true,
			kind: "text",
			text: "0123"
		});
	});

	it("clamps non-positive maxBytes to a single byte", () => {
		const content = readFilePreview(path.join(ROOT, "long.txt"), [ROOT], 0);
		expect(content?.truncated).toBe(true);
		expect(content?.text).toBe("0");
	});

	it("falls back to the default cap for a non-finite maxBytes", () => {
		const content = readFilePreview(path.join(ROOT, "long.txt"), [ROOT], Number.NaN);
		expect(content?.truncated).toBe(false);
		expect(content?.text).toBe("0123456789");
	});

	it("rejects files outside the allowed roots", () => {
		expect(readFilePreview(path.join(OUTSIDE, "secret.txt"), [ROOT], 1024)).toBeNull();
	});

	it("rejects directories", () => {
		expect(readFilePreview(ROOT, [ROOT], 1024)).toBeNull();
	});

	it("returns null for missing files", () => {
		expect(readFilePreview(path.join(ROOT, "missing.txt"), [ROOT], 1024)).toBeNull();
	});

	it("rejects symlinks that escape the allowed root", () => {
		const link = path.join(ROOT, "escape.txt");
		try {
			symlinkSync(path.join(OUTSIDE, "secret.txt"), link);
		} catch {
			return; // Symlink creation is not permitted on this platform.
		}
		expect(readFilePreview(link, [ROOT], 1024)).toBeNull();
	});
});

describe("buildFilePreview", () => {
	it("omits the data URL when an image is truncated", () => {
		const content = buildFilePreview(
			"big.png",
			Buffer.from("prefix"),
			FILE_PREVIEW_IMAGE_BYTES + 1,
			true,
			true
		);
		expect(content.kind).toBe("image");
		expect(content.image).toBeUndefined();
		expect(content.size).toBe(FILE_PREVIEW_IMAGE_BYTES + 1);
	});

	it("decodes text up to the first NUL-free bytes", () => {
		const content = buildFilePreview("entry.txt", Buffer.from("abc"), 3, false, false);
		expect(content).toEqual({
			path: "entry.txt",
			size: 3,
			truncated: false,
			kind: "text",
			text: "abc"
		});
	});
});

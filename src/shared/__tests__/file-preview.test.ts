import { describe, expect, it } from "bun:test";

import { imageMimeType } from "../file-preview";

describe("imageMimeType", () => {
	it("maps raster image extensions to MIME types", () => {
		expect(imageMimeType("icon.png")).toBe("image/png");
		expect(imageMimeType("photo.jpg")).toBe("image/jpeg");
		expect(imageMimeType("photo.jpeg")).toBe("image/jpeg");
		expect(imageMimeType("anim.gif")).toBe("image/gif");
		expect(imageMimeType("logo.webp")).toBe("image/webp");
		expect(imageMimeType("bitmap.bmp")).toBe("image/bmp");
		expect(imageMimeType("favicon.ico")).toBe("image/x-icon");
		expect(imageMimeType("poster.avif")).toBe("image/avif");
		expect(imageMimeType("scan.tif")).toBe("image/tiff");
		expect(imageMimeType("scan.tiff")).toBe("image/tiff");
	});

	it("is case-insensitive and handles nested paths", () => {
		expect(imageMimeType("static/img/ICON.PNG")).toBe("image/png");
		expect(imageMimeType("assets/Photo.JpEg")).toBe("image/jpeg");
		expect(imageMimeType("assets/PHOTO.TIFF")).toBe("image/tiff");
	});

	it("returns null for unknown, missing and dotfile extensions", () => {
		expect(imageMimeType("app.js")).toBeNull();
		expect(imageMimeType("icon.svg")).toBeNull();
		expect(imageMimeType("LICENSE")).toBeNull();
		expect(imageMimeType(".png")).toBeNull();
		expect(imageMimeType("nested/.gitignore")).toBeNull();
		expect(imageMimeType("archive.png.txt")).toBeNull();
		expect(imageMimeType("folder.png/file")).toBeNull();
	});
});

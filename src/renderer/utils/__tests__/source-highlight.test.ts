import { describe, expect, it } from "bun:test";
import { FILE_PREVIEW_BYTES } from "../../../shared/file-preview";
import { HIGHLIGHT_AUTO_BYTES, highlightLanguage, highlightSource } from "../source-highlight";

describe("highlightLanguage", () => {
	it("maps common source extensions", () => {
		expect(highlightLanguage("dist/main.js")).toBe("javascript");
		expect(highlightLanguage("src/App.TSX")).toBe("typescript");
		expect(highlightLanguage("styles/site.scss")).toBe("scss");
		expect(highlightLanguage("index.html")).toBe("xml");
		expect(highlightLanguage("package.json")).toBe("json");
		expect(highlightLanguage("src/main.rs")).toBe("rust");
		expect(highlightLanguage("Classes/Thing.m")).toBe("objectivec");
	});

	it("returns null for unsupported or extensionless files", () => {
		expect(highlightLanguage("README.txt")).toBeNull();
		expect(highlightLanguage("LICENSE")).toBeNull();
		expect(highlightLanguage("image.png")).toBeNull();
	});

	it("auto-highlights up to the default preview cap", () => {
		expect(HIGHLIGHT_AUTO_BYTES).toBe(FILE_PREVIEW_BYTES);
	});
});

describe("highlightSource", () => {
	it("returns token markup for supported languages", () => {
		const html = highlightSource("const value = 1;", "javascript");
		expect(html).not.toBeNull();
		expect(html).toContain('class="hljs-keyword"');
		expect(html).toContain('class="hljs-number"');
	});

	it("escapes markup in the source", () => {
		const html = highlightSource('const x = "<img src=x onerror=alert(1)>";', "javascript");
		expect(html).not.toBeNull();
		expect(html).not.toContain("<img");
		expect(html).toContain("&lt;img");
	});

	it("returns null for an unknown language", () => {
		expect(highlightSource("hello", "not-a-language")).toBeNull();
	});
});

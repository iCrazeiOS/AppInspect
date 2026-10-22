import { describe, expect, it } from "bun:test";
import { beautifyParser, beautifyText, prettyPrintJson } from "../beautify";

describe("beautifyParser", () => {
	it("detects supported extensions case-insensitively", () => {
		expect(beautifyParser("app/main.js")).toBe("babel");
		expect(beautifyParser("app/main.MJS")).toBe("babel");
		expect(beautifyParser("src/App.TSX")).toBe("typescript");
		expect(beautifyParser("package.json")).toBe("json-stringify");
		expect(beautifyParser("bundle.webmanifest")).toBe("json-stringify");
		expect(beautifyParser("styles/theme.SCSS")).toBe("scss");
		expect(beautifyParser("index.html")).toBe("html");
		expect(beautifyParser("assets/icon.svg")).toBe("html");
	});

	it("returns null for unsupported or missing extensions", () => {
		expect(beautifyParser("LICENSE")).toBeNull();
		expect(beautifyParser("dist/app.d.ts")).toBe("typescript");
		expect(beautifyParser("native.node")).toBeNull();
		expect(beautifyParser("archive.tar.gz")).toBeNull();
		expect(beautifyParser("README")).toBeNull();
	});
});

describe("prettyPrintJson", () => {
	it("indents objects and arrays that parse", () => {
		expect(prettyPrintJson('{"name":"app","version":"1.0.0"}')).toBe(
			'{\n    "name": "app",\n    "version": "1.0.0"\n}'
		);
		expect(prettyPrintJson("[1,2]")).toBe("[\n    1,\n    2\n]");
	});

	it("returns null for non-JSON text and invalid JSON", () => {
		expect(prettyPrintJson("const x = 1;")).toBeNull();
		expect(prettyPrintJson('{"broken":')).toBeNull();
	});
});

describe("beautifyText", () => {
	it("indents JSON", async () => {
		expect(await beautifyText('{"a":1}', "json-stringify")).toBe('{\n    "a": 1\n}');
	});

	it("expands minified JavaScript", async () => {
		expect(await beautifyText("function f(){return 1;}", "babel")).toBe(
			"function f() {\n    return 1;\n}"
		);
	});

	it("formats TypeScript", async () => {
		expect(await beautifyText("const x:number=1", "typescript")).toBe("const x: number = 1;");
	});

	it("formats CSS", async () => {
		expect(await beautifyText("a{color:red}", "css")).toBe("a {\n    color: red;\n}");
	});

	it("formats HTML", async () => {
		expect(await beautifyText("<div><p>hi</p><p>bye</p></div>", "html")).toBe(
			"<div>\n    <p>hi</p>\n    <p>bye</p>\n</div>"
		);
	});

	it("returns null for invalid input", async () => {
		expect(await beautifyText('{"broken":', "json-stringify")).toBeNull();
		expect(await beautifyText("function (", "babel")).toBeNull();
	});

	it("does not append a trailing newline", async () => {
		expect(await beautifyText("const a = 1;", "babel")).toBe("const a = 1;");
	});
});

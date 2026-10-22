import { describe, expect, it } from "bun:test";
import { formatCount, plural } from "../format";

describe("plural", () => {
	it("returns the singular noun for one", () => {
		expect(plural(1, "module")).toBe("module");
		expect(plural(1, "entry", "entries")).toBe("entry");
	});

	it("returns the plural noun for zero and many", () => {
		expect(plural(0, "module")).toBe("modules");
		expect(plural(2, "entry", "entries")).toBe("entries");
	});
});

describe("formatCount", () => {
	it("formats one item with the singular noun", () => {
		expect(formatCount(1, "file")).toBe("1 file");
	});

	it("formats many items with the plural noun", () => {
		expect(formatCount(2, "file")).toBe("2 files");
		expect(formatCount(3, "library", "libraries")).toBe("3 libraries");
	});
});

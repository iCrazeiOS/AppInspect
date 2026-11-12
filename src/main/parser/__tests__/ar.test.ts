import { describe, expect, it } from "bun:test";
import { parseArArchive } from "../ar";
import { arArchive } from "./fixtures";

const text = (bytes: Uint8Array, m: { offset: number; size: number }) =>
	Buffer.from(bytes.subarray(m.offset, m.offset + m.size)).toString("ascii");

describe("parseArArchive", () => {
	it("rejects data without the ar magic", () => {
		expect(parseArArchive(new Uint8Array(16)).ok).toBe(false);
	});

	it("reads short names and BSD #1/ long names, padding odd members", () => {
		const bytes = arArchive([
			{ name: "odd.o", data: "abc" },
			{ name: "a-much-longer-member-name.o", data: "payload", style: "bsd" },
			{ name: "last.o", data: "z" }
		]);
		const parsed = parseArArchive(bytes);
		if (!parsed.ok) throw new Error(parsed.error);
		expect(parsed.data.map((m) => m.name)).toEqual([
			"odd.o",
			"a-much-longer-member-name.o",
			"last.o"
		]);
		expect(parsed.data.map((m) => text(bytes, m))).toEqual(["abc", "payload", "z"]);
	});

	it("resolves GNU long names and consumes the symbol and name tables", () => {
		const longName = "gnu-style-long-member-name.o";
		const bytes = arArchive([
			{ name: "/", data: "symbols" },
			{ name: "//", data: `${longName}/\n` },
			{ name: "/0", data: "long" },
			{ name: "short.o/", data: "short" }
		]);
		const parsed = parseArArchive(bytes);
		if (!parsed.ok) throw new Error(parsed.error);
		expect(parsed.data.map((m) => [m.name, text(bytes, m)])).toEqual([
			[longName, "long"],
			["short.o", "short"]
		]);
	});

	it("stops at a truncated member", () => {
		const bytes = arArchive([
			{ name: "whole.o", data: "1234" },
			{ name: "cut.o", data: "12345678" }
		]);
		const parsed = parseArArchive(bytes.subarray(0, bytes.length - 4));
		expect(parsed.ok && parsed.data.map((m) => m.name)).toEqual(["whole.o"]);
	});
});

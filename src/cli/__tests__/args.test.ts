/**
 * Tests for CLI argument parsing (parseArgs).
 */

import { describe, expect, it } from "bun:test";
import { parseArgs, UsageError } from "../index";

describe("parseArgs", () => {
	it("applies defaults with a single positional file", () => {
		const options = parseArgs(["/tmp/App.ipa"]);
		expect(options.file).toBe("/tmp/App.ipa");
		expect(options.format).toBe("json");
		expect(options.pretty).toBe(true);
		expect(options.failOn).toBe("none");
		expect(options.quiet).toBe(false);
		expect(options.sections).toBeUndefined();
	});

	it("parses format, output and threshold flags", () => {
		const options = parseArgs([
			"--sarif",
			"--out",
			"report.sarif",
			"--no-pretty",
			"--fail-on",
			"warning",
			"--quiet",
			"/tmp/App.ipa"
		]);
		expect(options.format).toBe("sarif");
		expect(options.out).toBe("report.sarif");
		expect(options.pretty).toBe(false);
		expect(options.failOn).toBe("warning");
		expect(options.quiet).toBe(true);
		expect(options.file).toBe("/tmp/App.ipa");
	});

	it("collects repeated --section values in order", () => {
		const options = parseArgs([
			"--section",
			"security",
			"--section",
			"strings",
			"/tmp/App.ipa"
		]);
		expect(options.sections).toEqual(["security", "strings"]);
	});

	it("parses --binary as a non-negative integer", () => {
		expect(parseArgs(["--binary", "2", "/tmp/App.ipa"]).binary).toBe(2);
		expect(parseArgs(["--binary", "0", "/tmp/App.ipa"]).binary).toBe(0);
	});

	it("rejects a non-integer --binary", () => {
		expect(() => parseArgs(["--binary", "-1", "/tmp/App.ipa"])).toThrow(UsageError);
		expect(() => parseArgs(["--binary", "abc", "/tmp/App.ipa"])).toThrow(UsageError);
		expect(() => parseArgs(["/tmp/App.ipa", "--binary"])).toThrow(UsageError);
	});

	it("parses --arch by name", () => {
		expect(parseArgs(["--arch", "arm64", "/tmp/App.ipa"]).arch).toEqual({
			cpuType: 0x0100000c
		});
		expect(parseArgs(["--arch", "x86_64h", "/tmp/App.ipa"]).arch).toEqual({
			cpuType: 0x01000007,
			cpuSubtype: 8
		});
	});

	it("rejects an unknown or missing --arch", () => {
		expect(() => parseArgs(["--arch", "riscv64", "/tmp/App.ipa"])).toThrow(UsageError);
		expect(() => parseArgs(["/tmp/App.ipa", "--arch"])).toThrow(UsageError);
	});

	it("rejects unknown flags as a usage error", () => {
		expect(() => parseArgs(["--nope", "/tmp/App.ipa"])).toThrow(UsageError);
	});

	it("rejects an invalid --section value", () => {
		expect(() => parseArgs(["--section", "bogus", "/tmp/App.ipa"])).toThrow(UsageError);
	});

	it("rejects a second positional argument", () => {
		expect(() => parseArgs(["/tmp/App.ipa", "/tmp/Other.ipa"])).toThrow(UsageError);
	});

	it("defaults noClobber to false", () => {
		expect(parseArgs(["x"]).noClobber).toBe(false);
	});

	it("parses --no-clobber", () => {
		expect(parseArgs(["--no-clobber", "x"]).noClobber).toBe(true);
	});

	it("supports --help and --version without a file", () => {
		expect(parseArgs(["--help"]).help).toBe(true);
		expect(parseArgs(["--version"]).version).toBe(true);
	});
});

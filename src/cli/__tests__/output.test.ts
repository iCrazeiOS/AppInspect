import { afterAll, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { buildObjectFile } from "../../main/parser/__tests__/fixtures";

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "appinspect-cli-"));
afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

describe("CLI output", () => {
	it("writes the whole report to a pipe before exiting", async () => {
		// Enough strings for the JSON to exceed a pipe buffer many times over
		const strings = Array.from({ length: 20_000 }, (_, i) => `string number ${i}\0`).join("");
		const { buffer } = buildObjectFile({
			sections: [
				{
					segname: "__TEXT",
					sectname: "__cstring",
					data: new TextEncoder().encode(strings)
				}
			]
		});
		const file = path.join(dir, "big.o");
		fs.writeFileSync(file, new Uint8Array(buffer));

		const proc = Bun.spawn(
			["bun", path.join(import.meta.dir, "..", "index.ts"), file, "--quiet", "--no-pretty"],
			{ stdout: "pipe", stderr: "ignore" }
		);
		const text = await new Response(proc.stdout).text();
		expect(await proc.exited).toBe(0);
		expect(text.length).toBeGreaterThan(1_000_000);
		expect(JSON.parse(text).data.strings).toHaveLength(20_000);
	});
});

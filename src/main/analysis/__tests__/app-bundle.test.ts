import { afterEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { buildMachHeader64 } from "../../parser/__tests__/fixtures";
import { AnalysisSession } from "../session";

const MACHO = Buffer.from(buildMachHeader64());
const noop = () => {};

const tempDirs: string[] = [];

function makeTempDir(): string {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "appinspect-app-"));
	tempDirs.push(dir);
	return dir;
}

afterEach(() => {
	for (const dir of tempDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

function write(root: string, relPath: string, data: Buffer = MACHO): string {
	const full = path.join(root, relPath);
	fs.mkdirSync(path.dirname(full), { recursive: true });
	fs.writeFileSync(full, data);
	return full;
}

const INFO_PLIST = Buffer.from(
	'<?xml version="1.0"?><plist version="1.0"><dict>' +
		"<key>CFBundleExecutable</key><string>Wrapped</string>" +
		"<key>CFBundleIdentifier</key><string>com.example.wrapped</string>" +
		"</dict></plist>"
);

/** macOS installs iOS apps on Apple silicon as `Name.app/Wrapper/Name.app`. */
function makeWrappedApp(root: string): { outer: string; inner: string } {
	const outer = path.join(root, "Wrapped.app");
	const inner = path.join(outer, "Wrapper", "Wrapped.app");
	write(inner, "Wrapped");
	write(inner, "Info.plist", INFO_PLIST);
	write(inner, "Frameworks/Kit.framework/Kit");
	fs.symlinkSync(path.join("Wrapper", "Wrapped.app"), path.join(outer, "WrappedBundle"));
	return { outer, inner };
}

describe("analyseApp", () => {
	it("analyses the inner bundle of an iOS app wrapped for Apple silicon", async () => {
		const root = makeTempDir();
		const { outer, inner } = makeWrappedApp(root);

		const result = await new AnalysisSession().analyseFile(outer, noop);

		// The opened wrapper stays the display path, the inner bundle is the root
		expect(result.overview.filePath).toBe(outer);
		expect(result.overview.ipa.bundlePath).toBe(fs.realpathSync(inner));
		expect(result.overview.ipa.appName).toBe("Wrapped");
		expect(result.overview.ipa.binaries.map((b) => [b.name, b.type])).toEqual([
			["Wrapped", "main"],
			["Kit", "framework"]
		]);
		expect(result.overview.infoPlist?.CFBundleIdentifier).toBe("com.example.wrapped");

		// The file tree shows the app's contents, not the wrapper directory
		const names = result.files.map((entry) => entry.name);
		expect(names).toContain("Wrapped");
		expect(names).toContain("Frameworks");
		expect(names).not.toContain("Wrapper");
	});

	it("still analyses a macOS bundle", async () => {
		const root = makeTempDir();
		const app = path.join(root, "Mac.app");
		write(app, "Contents/MacOS/Mac");
		write(
			app,
			"Contents/Info.plist",
			Buffer.from(
				'<?xml version="1.0"?><plist version="1.0"><dict>' +
					"<key>CFBundleExecutable</key><string>Mac</string>" +
					"</dict></plist>"
			)
		);

		const result = await new AnalysisSession().analyseFile(app, noop);

		expect(result.overview.filePath).toBe(app);
		expect(result.overview.ipa.bundlePath).toBe(app);
		expect(result.overview.ipa.binaries[0]).toMatchObject({ name: "Mac", type: "main" });
	});

	it("rejects a .app bundle without binaries", async () => {
		const root = makeTempDir();
		const app = path.join(root, "Empty.app");
		fs.mkdirSync(app, { recursive: true });

		await expect(new AnalysisSession().analyseFile(app, noop)).rejects.toThrow(
			"No binaries found in .app bundle"
		);
	});
});

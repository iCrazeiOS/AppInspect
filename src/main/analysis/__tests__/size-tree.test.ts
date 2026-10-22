import { afterEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { AsarEntry, SizeBreakdown, SizeTreeNode } from "../../../shared/types";
import { buildSizeTree, splitBinaryNode } from "../size-tree";

const tempDirs: string[] = [];

function makeTempDir(): string {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "appinspect-test-sizetree-"));
	tempDirs.push(dir);
	return dir;
}

afterEach(() => {
	for (const dir of tempDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

function write(root: string, rel: string, bytes: number): string {
	const full = path.join(root, rel);
	fs.mkdirSync(path.dirname(full), { recursive: true });
	fs.writeFileSync(full, Buffer.alloc(bytes));
	return full;
}

function child(node: SizeTreeNode, name: string): SizeTreeNode {
	const found = node.children?.find((c) => c.name === name);
	if (!found) throw new Error(`no child ${name}`);
	return found;
}

/** 1000-byte slice: 600 section bytes (450 attributed), 300 link-edit, 100 header. */
const BREAKDOWN: SizeBreakdown = {
	binarySize: 1000,
	sectionSize: 600,
	attributedSize: 450,
	segments: [
		{ name: "__TEXT", fileSize: 700, vmSize: 700, sections: [] },
		{ name: "__LINKEDIT", fileSize: 300, vmSize: 300, sections: [] }
	],
	modules: [
		{
			name: "Kit",
			kind: "swift",
			size: 300,
			codeSize: 300,
			inferredSize: 0,
			symbolCount: 1,
			topFunctions: []
		},
		{
			name: "SQLite",
			kind: "c",
			size: 150,
			codeSize: 150,
			inferredSize: 0,
			symbolCount: 1,
			topFunctions: []
		},
		{
			name: "Unattributed",
			kind: "unattributed",
			size: 150,
			codeSize: 0,
			inferredSize: 0,
			symbolCount: 0,
			topFunctions: []
		}
	]
};

describe("splitBinaryNode", () => {
	it("splits a binary into modules plus overhead that sums to the file size", () => {
		// 400 extra bytes: another architecture slice in a fat file
		const node = splitBinaryNode("Kit", 1400, BREAKDOWN);
		expect(node.kind).toBe("binary");
		expect(node.size).toBe(1400);
		expect(node.children).toEqual([
			{ name: "Other architecture slices", size: 400, kind: "overhead" },
			{ name: "Kit", size: 300, kind: "module", moduleKind: "swift" },
			{ name: "Link-edit data", size: 300, kind: "overhead" },
			{ name: "SQLite", size: 150, kind: "module", moduleKind: "c" },
			{ name: "Unattributed section data", size: 150, kind: "overhead" },
			{ name: "Headers & padding", size: 100, kind: "overhead" }
		]);
	});
});

describe("buildSizeTree", () => {
	it("keeps Core ML models whole, splits the active binary, and sorts by size", () => {
		const root = path.join(makeTempDir(), "Kit.framework");
		const binary = write(root, "Kit", 1000);
		write(root, "Model.mlmodelc/weights/weight.bin", 5000);
		write(root, "Model.mlmodelc/model.mil", 200);
		write(root, "Legacy.mlmodel", 300);
		write(root, "en.lproj/Localizable.strings", 50);
		write(root, "Other", 10);

		const tree = buildSizeTree(root, { path: binary, breakdown: BREAKDOWN }, new Set([binary]));

		expect(tree.name).toBe("Kit.framework");
		expect(tree.size).toBe(1000 + 5200 + 300 + 50 + 10);
		expect(tree.children!.map((c) => c.name)).toEqual([
			"Model.mlmodelc",
			"Kit",
			"Legacy.mlmodel",
			"en.lproj",
			"Other"
		]);
		expect(child(tree, "Model.mlmodelc")).toEqual({
			name: "Model.mlmodelc",
			size: 5200,
			kind: "mlmodel"
		});
		expect(child(tree, "Legacy.mlmodel").kind).toBe("mlmodel");
		expect(child(tree, "Kit").children!.map((c) => c.kind)).toContain("module");
		expect(child(child(tree, "en.lproj"), "Localizable.strings").kind).toBe("file");
	});

	it("marks other known binaries as code without splitting them", () => {
		const root = makeTempDir();
		const main = write(root, "App", 1000);
		const framework = write(root, "Frameworks/Lib.framework/Lib", 70);

		const tree = buildSizeTree(
			root,
			{ path: main, breakdown: BREAKDOWN },
			new Set([main, framework])
		);
		const lib = child(child(child(tree, "Frameworks"), "Lib.framework"), "Lib");
		expect(lib).toEqual({ name: "Lib", size: 70, kind: "binary" });
	});

	it("skips symlinks so versioned macOS frameworks are not double counted", () => {
		const root = makeTempDir();
		write(root, "Versions/A/Kit", 100);
		fs.symlinkSync("A", path.join(root, "Versions", "Current"));
		fs.symlinkSync("Versions/Current/Kit", path.join(root, "Kit"));

		const tree = buildSizeTree(root, null);
		expect(tree.size).toBe(100);
		expect(tree.children!.map((c) => c.name)).toEqual(["Versions"]);
	});

	it("leaves out what Xcode strips when embedding, and lists it", () => {
		const root = path.join(makeTempDir(), "Kit.framework");
		const binary = write(root, "Kit", 1000);
		write(root, "Headers/Kit.h", 400);
		write(root, "PrivateHeaders/Internal.h", 30);
		write(root, "Modules/Kit.swiftmodule/arm64-apple-ios.swiftinterface", 200);
		write(root, "Modules/module.modulemap", 20);
		write(root, "Versions/A/Headers/Kit.h", 50);
		write(root, "libStub.tbd", 10);
		write(root, ".DS_Store", 6);
		write(root, "Assets.car", 300);

		const tree = buildSizeTree(root, { path: binary, breakdown: BREAKDOWN }, new Set(), true);
		expect(tree.children!.map((c) => c.name)).toEqual(["Kit", "Assets.car"]);
		expect(tree.size).toBe(1300);
		expect(tree.excluded).toEqual([
			{ path: "Headers", size: 400 },
			{ path: "Modules", size: 220 },
			{ path: "Versions/A/Headers", size: 50 },
			{ path: "PrivateHeaders", size: 30 },
			{ path: "libStub.tbd", size: 10 },
			{ path: ".DS_Store", size: 6 }
		]);

		// Without asEmbedded everything is counted
		expect(buildSizeTree(root, null).size).toBe(1000 + 400 + 30 + 220 + 50 + 10 + 6 + 300);
	});

	it("returns a single split node for a bare binary", () => {
		const binary = write(makeTempDir(), "tool", 1000);
		const tree = buildSizeTree(binary, { path: binary, breakdown: BREAKDOWN });
		expect(tree.kind).toBe("binary");
		expect(tree.size).toBe(1000);
	});
});

describe("buildSizeTree with an Electron archive", () => {
	const ENTRIES: AsarEntry[] = [
		{
			name: "node_modules",
			path: "node_modules",
			size: 600,
			isDirectory: true,
			children: [
				{
					name: "dep.js",
					path: "node_modules/dep.js",
					size: 600,
					isDirectory: false
				}
			]
		},
		{ name: "package.json", path: "package.json", size: 200, isDirectory: false },
		{ name: "native.node", path: "native.node", size: 100, isDirectory: false, unpacked: true }
	];

	it("splits app.asar into packed entries plus header/padding overhead", () => {
		const root = makeTempDir();
		const asar = write(root, "Resources/app.asar", 1000);
		write(root, "Resources/app.asar.unpacked/native.node", 100);

		const tree = buildSizeTree(root, null, new Set(), false, { path: asar, entries: ENTRIES });
		const resources = child(tree, "Resources");
		const node = child(resources, "app.asar");

		expect(node.kind).toBe("asar");
		expect(node.size).toBe(1000);
		// Unpacked entries are already counted under app.asar.unpacked
		expect(node.children!.map((c) => c.name)).toEqual([
			"node_modules",
			"package.json",
			"Archive header & padding"
		]);
		expect(child(node, "node_modules")).toMatchObject({
			size: 600,
			kind: "directory"
		});
		expect(child(child(node, "node_modules"), "dep.js")).toEqual({
			name: "dep.js",
			size: 600,
			kind: "file"
		});
		expect(child(node, "Archive header & padding")).toEqual({
			name: "Archive header & padding",
			size: 200,
			kind: "overhead"
		});
		expect(tree.size).toBe(1000 + 100);
	});

	it("keeps the file leaf when the archive has no packed entries", () => {
		const root = makeTempDir();
		const asar = write(root, "app.asar", 1000);

		const tree = buildSizeTree(root, null, new Set(), false, {
			path: asar,
			entries: [ENTRIES[2]!]
		});
		expect(child(tree, "app.asar")).toEqual({ name: "app.asar", size: 1000, kind: "file" });
	});

	it("leaves other archives alone", () => {
		const root = makeTempDir();
		write(root, "app.asar", 1000);
		write(root, "other.asar", 500);

		const tree = buildSizeTree(root, null, new Set(), false, {
			path: path.join(root, "app.asar"),
			entries: ENTRIES
		});
		expect(child(tree, "other.asar").kind).toBe("file");
	});
});

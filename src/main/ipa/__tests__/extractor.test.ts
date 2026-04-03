import { describe, it, expect, afterEach } from "bun:test";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { zipSync } from "fflate";
import {
  extractIPA,
  discoverAppBundle,
  discoverBinaries,
  cleanupExtracted,
} from "../extractor";

/** Create a unique temp directory for each test */
function makeTempDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), `disect-test-${prefix}-`));
}

/** Build a minimal IPA-like ZIP with the standard Payload/App.app structure */
function buildTestIPA(): Uint8Array {
  const encoder = new TextEncoder();

  // Minimal Info.plist content (just a stub, not parsed in this module)
  const infoPlist = encoder.encode(
    '<?xml version="1.0"?><plist version="1.0"><dict>' +
      "<key>CFBundleExecutable</key><string>TestApp</string>" +
      "</dict></plist>"
  );

  // Stub binary data
  const mainBinary = new Uint8Array([0xfe, 0xed, 0xfa, 0xce, 0x00, 0x01]);
  const frameworkBinary = new Uint8Array([0xfe, 0xed, 0xfa, 0xce, 0x00, 0x02]);

  return zipSync({
    "Payload/TestApp.app/TestApp": mainBinary,
    "Payload/TestApp.app/Info.plist": infoPlist,
    "Payload/TestApp.app/Frameworks/SomeFramework.framework/SomeFramework":
      frameworkBinary,
  });
}

// Track temp dirs for cleanup
const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs) {
    try {
      cleanupExtracted(dir);
    } catch {
      // Best-effort cleanup
    }
  }
  tempDirs.length = 0;
});

describe("extractIPA", () => {
  it("should extract a valid IPA/ZIP file preserving directory structure", () => {
    const tmpDir = makeTempDir("extract");
    tempDirs.push(tmpDir);

    const ipaData = buildTestIPA();
    const ipaPath = path.join(tmpDir, "test.ipa");
    fs.writeFileSync(ipaPath, ipaData);

    const destDir = path.join(tmpDir, "extracted");
    const result = extractIPA(ipaPath, destDir);

    expect(result.success).toBe(true);
    if (!result.success) return;

    // Verify directory structure
    const payloadDir = path.join(destDir, "Payload");
    expect(fs.existsSync(payloadDir)).toBe(true);

    const appDir = path.join(payloadDir, "TestApp.app");
    expect(fs.existsSync(appDir)).toBe(true);

    // Verify main binary
    const mainBinary = path.join(appDir, "TestApp");
    expect(fs.existsSync(mainBinary)).toBe(true);
    const mainData = fs.readFileSync(mainBinary);
    expect(mainData[0]).toBe(0xfe);

    // Verify Info.plist
    const infoPlist = path.join(appDir, "Info.plist");
    expect(fs.existsSync(infoPlist)).toBe(true);

    // Verify framework
    const fwBinary = path.join(
      appDir,
      "Frameworks",
      "SomeFramework.framework",
      "SomeFramework"
    );
    expect(fs.existsSync(fwBinary)).toBe(true);
  });

  it("should return an error for non-ZIP data", () => {
    const tmpDir = makeTempDir("nonzip");
    tempDirs.push(tmpDir);

    // Write random bytes that are not a valid ZIP
    const badPath = path.join(tmpDir, "bad.ipa");
    const randomBytes = new Uint8Array(256);
    for (let i = 0; i < randomBytes.length; i++) {
      randomBytes[i] = Math.floor(Math.random() * 256);
    }
    fs.writeFileSync(badPath, randomBytes);

    const destDir = path.join(tmpDir, "extracted");
    const result = extractIPA(badPath, destDir);

    expect(result.success).toBe(false);
    if (result.success) return;
    expect(result.error).toContain("Failed to extract IPA");
  });

  it("should return an error for a non-existent file", () => {
    const tmpDir = makeTempDir("nofile");
    tempDirs.push(tmpDir);

    const result = extractIPA(
      path.join(tmpDir, "does-not-exist.ipa"),
      path.join(tmpDir, "out")
    );

    expect(result.success).toBe(false);
  });
});

describe("discoverAppBundle", () => {
  it("should find the .app directory inside Payload/", () => {
    const tmpDir = makeTempDir("discover");
    tempDirs.push(tmpDir);

    const ipaData = buildTestIPA();
    const ipaPath = path.join(tmpDir, "test.ipa");
    fs.writeFileSync(ipaPath, ipaData);

    const destDir = path.join(tmpDir, "extracted");
    extractIPA(ipaPath, destDir);

    const appBundle = discoverAppBundle(destDir);
    expect(appBundle).not.toBeNull();
    expect(appBundle!).toContain("TestApp.app");
    expect(path.basename(appBundle!)).toBe("TestApp.app");
  });

  it("should return null if Payload directory is missing", () => {
    const tmpDir = makeTempDir("nopayload");
    tempDirs.push(tmpDir);

    // Create a ZIP without a Payload directory
    const zipData = zipSync({
      "SomeOtherDir/file.txt": new TextEncoder().encode("hello"),
    });
    const ipaPath = path.join(tmpDir, "bad.ipa");
    fs.writeFileSync(ipaPath, zipData);

    const destDir = path.join(tmpDir, "extracted");
    extractIPA(ipaPath, destDir);

    const appBundle = discoverAppBundle(destDir);
    expect(appBundle).toBeNull();
  });

  it("should return null for an empty directory", () => {
    const tmpDir = makeTempDir("empty");
    tempDirs.push(tmpDir);

    const result = discoverAppBundle(tmpDir);
    expect(result).toBeNull();
  });
});

describe("discoverBinaries", () => {
  it("should find the main binary and framework", () => {
    const tmpDir = makeTempDir("binaries");
    tempDirs.push(tmpDir);

    const ipaData = buildTestIPA();
    const ipaPath = path.join(tmpDir, "test.ipa");
    fs.writeFileSync(ipaPath, ipaData);

    const destDir = path.join(tmpDir, "extracted");
    extractIPA(ipaPath, destDir);

    const appBundle = discoverAppBundle(destDir);
    expect(appBundle).not.toBeNull();

    const binaries = discoverBinaries(appBundle!);

    // Should find main binary
    const mainBin = binaries.find((b) => b.type === "main");
    expect(mainBin).toBeDefined();
    expect(mainBin!.name).toBe("TestApp");

    // Should find framework
    const framework = binaries.find((b) => b.type === "framework");
    expect(framework).toBeDefined();
    expect(framework!.name).toBe("SomeFramework");
    expect(framework!.type).toBe("framework");

    // Should have exactly 2 binaries (no extensions in fixture)
    expect(binaries.length).toBe(2);
  });

  it("should return an empty list for a directory with no binaries", () => {
    const tmpDir = makeTempDir("nobinaries");
    tempDirs.push(tmpDir);

    // Create a bare .app dir with no matching binary
    const appDir = path.join(tmpDir, "Empty.app");
    fs.mkdirSync(appDir, { recursive: true });

    const binaries = discoverBinaries(appDir);
    expect(binaries.length).toBe(0);
  });
});

describe("cleanupExtracted", () => {
  it("should remove the extraction directory", () => {
    const tmpDir = makeTempDir("cleanup");
    // Don't track in tempDirs since we're testing cleanup itself

    const subDir = path.join(tmpDir, "a", "b");
    fs.mkdirSync(subDir, { recursive: true });
    fs.writeFileSync(path.join(subDir, "file.txt"), "test");

    expect(fs.existsSync(tmpDir)).toBe(true);
    cleanupExtracted(tmpDir);
    expect(fs.existsSync(tmpDir)).toBe(false);
  });

  it("should not throw for a non-existent directory", () => {
    expect(() => cleanupExtracted("/tmp/does-not-exist-xyz-123")).not.toThrow();
  });
});

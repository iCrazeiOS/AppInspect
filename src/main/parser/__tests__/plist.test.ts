import { describe, expect, it, afterAll } from "bun:test";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { parseInfoPlist, parseMobileprovision } from "../plist";

// ── Test Helpers ──────────────────────────────────────────────────────

const tmpDirs: string[] = [];

function makeTmpAppBundle(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "plist-test-"));
  const appDir = path.join(dir, "Test.app");
  fs.mkdirSync(appDir, { recursive: true });
  tmpDirs.push(dir);
  return appDir;
}

afterAll(() => {
  for (const dir of tmpDirs) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ── XML Info.plist Fixture ────────────────────────────────────────────

const XML_INFO_PLIST = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>com.example.testapp</string>
  <key>CFBundleName</key>
  <string>TestApp</string>
  <key>CFBundleDisplayName</key>
  <string>Test App</string>
  <key>CFBundleShortVersionString</key>
  <string>1.2.3</string>
  <key>CFBundleVersion</key>
  <string>42</string>
  <key>CFBundleExecutable</key>
  <string>TestApp</string>
  <key>MinimumOSVersion</key>
  <string>15.0</string>
  <key>LSRequiresIPhoneOS</key>
  <true/>
  <key>UIRequiredDeviceCapabilities</key>
  <array>
    <string>arm64</string>
  </array>
  <key>CFBundleURLTypes</key>
  <array>
    <dict>
      <key>CFBundleURLSchemes</key>
      <array>
        <string>testapp</string>
      </array>
    </dict>
  </array>
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
  </dict>
  <key>UIBackgroundModes</key>
  <array>
    <string>fetch</string>
    <string>remote-notification</string>
  </array>
  <key>NSCameraUsageDescription</key>
  <string>We need camera access for scanning</string>
  <key>NSLocationWhenInUseUsageDescription</key>
  <string>We need location for nearby features</string>
</dict>
</plist>`;

// ── Mobileprovision XML Fixture ───────────────────────────────────────

const MOBILEPROVISION_XML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>TeamIdentifier</key>
  <array>
    <string>ABCDE12345</string>
  </array>
  <key>TeamName</key>
  <string>Example Team</string>
  <key>ExpirationDate</key>
  <date>2027-01-01T00:00:00Z</date>
  <key>CreationDate</key>
  <date>2026-01-01T00:00:00Z</date>
  <key>Entitlements</key>
  <dict>
    <key>application-identifier</key>
    <string>ABCDE12345.com.example.testapp</string>
    <key>get-task-allow</key>
    <true/>
  </dict>
  <key>ProvisionedDevices</key>
  <array>
    <string>aabbccdd11223344</string>
    <string>eeff00112233aabb</string>
  </array>
</dict>
</plist>`;

// ── Tests: parseInfoPlist ─────────────────────────────────────────────

describe("parseInfoPlist", () => {
  it("should parse an XML Info.plist and extract all fields", () => {
    const appDir = makeTmpAppBundle();
    fs.writeFileSync(path.join(appDir, "Info.plist"), XML_INFO_PLIST);

    const result = parseInfoPlist(appDir);
    expect(result).not.toBeNull();
    if (!result || !result.ok) {
      throw new Error("Expected successful parse");
    }

    const d = result.data;
    expect(d.CFBundleIdentifier).toBe("com.example.testapp");
    expect(d.CFBundleName).toBe("TestApp");
    expect(d.CFBundleDisplayName).toBe("Test App");
    expect(d.CFBundleShortVersionString).toBe("1.2.3");
    expect(d.CFBundleVersion).toBe("42");
    expect(d.CFBundleExecutable).toBe("TestApp");
    expect(d.MinimumOSVersion).toBe("15.0");
    expect(d.LSRequiresIPhoneOS).toBe(true);
    expect(d.UIRequiredDeviceCapabilities).toEqual(["arm64"]);
    expect(d.CFBundleURLTypes).toHaveLength(1);
    expect(d.NSAppTransportSecurity).toEqual({
      NSAllowsArbitraryLoads: true,
    });
    expect(d.UIBackgroundModes).toEqual(["fetch", "remote-notification"]);
  });

  it("should extract privacy usage description strings", () => {
    const appDir = makeTmpAppBundle();
    fs.writeFileSync(path.join(appDir, "Info.plist"), XML_INFO_PLIST);

    const result = parseInfoPlist(appDir);
    expect(result).not.toBeNull();
    if (!result || !result.ok) throw new Error("Expected successful parse");

    expect(result.data.privacyUsageStrings).toEqual({
      NSCameraUsageDescription: "We need camera access for scanning",
      NSLocationWhenInUseUsageDescription:
        "We need location for nearby features",
    });
  });

  it("should include the full raw plist object", () => {
    const appDir = makeTmpAppBundle();
    fs.writeFileSync(path.join(appDir, "Info.plist"), XML_INFO_PLIST);

    const result = parseInfoPlist(appDir);
    expect(result).not.toBeNull();
    if (!result || !result.ok) throw new Error("Expected successful parse");

    expect(result.data.raw.CFBundleIdentifier).toBe("com.example.testapp");
    expect(result.data.raw.NSCameraUsageDescription).toBe(
      "We need camera access for scanning"
    );
  });

  it("should return null when Info.plist does not exist", () => {
    const appDir = makeTmpAppBundle();
    // No Info.plist written
    const result = parseInfoPlist(appDir);
    expect(result).toBeNull();
  });

  it("should return an error for malformed plist", () => {
    const appDir = makeTmpAppBundle();
    fs.writeFileSync(
      path.join(appDir, "Info.plist"),
      "this is not a valid plist at all"
    );

    const result = parseInfoPlist(appDir);
    expect(result).not.toBeNull();
    expect(result!.ok).toBe(false);
    if (result!.ok) return;
    expect(result!.error).toContain("Failed to parse Info.plist");
  });
});

// ── Tests: parseMobileprovision ───────────────────────────────────────

describe("parseMobileprovision", () => {
  it("should extract XML from a DER-like envelope and parse fields", () => {
    const appDir = makeTmpAppBundle();

    // Simulate CMS/DER envelope: random binary prefix + XML + random suffix
    const prefix = Buffer.from([
      0x30, 0x82, 0x10, 0x00, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
      0x0d, 0x01, 0x07, 0x02,
    ]);
    const xmlBuf = Buffer.from(MOBILEPROVISION_XML, "utf-8");
    const suffix = Buffer.from([
      0x00, 0x00, 0x00, 0xff, 0xfe, 0xab, 0xcd, 0xef,
    ]);
    const combined = Buffer.concat([prefix, xmlBuf, suffix]);

    fs.writeFileSync(path.join(appDir, "embedded.mobileprovision"), combined);

    const result = parseMobileprovision(appDir);
    expect(result).not.toBeNull();
    if (!result || !result.ok) {
      throw new Error(`Expected successful parse, got: ${JSON.stringify(result)}`);
    }

    const d = result.data;
    expect(d.TeamIdentifier).toEqual(["ABCDE12345"]);
    expect(d.TeamName).toBe("Example Team");
    expect(d.ExpirationDate).toBeInstanceOf(Date);
    expect(d.CreationDate).toBeInstanceOf(Date);
    expect(d.Entitlements).toEqual({
      "application-identifier": "ABCDE12345.com.example.testapp",
      "get-task-allow": true,
    });
    expect(d.ProvisionedDevices).toEqual([
      "aabbccdd11223344",
      "eeff00112233aabb",
    ]);
    expect(d.ProvisionsAllDevices).toBeUndefined();
  });

  it("should return null when embedded.mobileprovision does not exist", () => {
    const appDir = makeTmpAppBundle();
    const result = parseMobileprovision(appDir);
    expect(result).toBeNull();
  });

  it("should return an error when no XML boundaries are found", () => {
    const appDir = makeTmpAppBundle();
    // Write random binary with no XML inside
    const garbage = Buffer.from([
      0x30, 0x82, 0x00, 0x50, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ]);
    fs.writeFileSync(path.join(appDir, "embedded.mobileprovision"), garbage);

    const result = parseMobileprovision(appDir);
    expect(result).not.toBeNull();
    expect(result!.ok).toBe(false);
    if (result!.ok) return;
    expect(result!.error).toContain("could not find XML plist boundaries");
  });
});

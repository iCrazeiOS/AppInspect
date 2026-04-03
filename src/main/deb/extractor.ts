/**
 * DEB package extractor
 *
 * Parses Debian .deb files (ar archives) to extract:
 * - Package control metadata
 * - Data contents (dylibs, executables, plists)
 *
 * .deb files are `ar` archives containing:
 *   debian-binary   — version string "2.0\n"
 *   control.tar.*   — package metadata
 *   data.tar.*      — installed file tree
 */

import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { execFile } from "child_process";
import type { DEBControlInfo } from "../../shared/types";

// Mach-O magic values for binary detection
const MACHO_MAGICS = new Set([
  0xfeedface, // MH_MAGIC (32-bit)
  0xcefaedfe, // MH_CIGAM (32-bit swapped)
  0xfeedfacf, // MH_MAGIC_64 (64-bit)
  0xcffaedfe, // MH_CIGAM_64 (64-bit swapped)
  0xcafebabe, // FAT_MAGIC
  0xbebafeca, // FAT_CIGAM
]);

export interface DEBBinaryInfo {
  name: string;
  path: string;
  type: "tweak" | "executable" | "library" | "prefbundle";
}

export interface DEBExtractionResult {
  success: true;
  control: DEBControlInfo;
  binaries: DEBBinaryInfo[];
  dataDir: string;
  extractedDir: string;
}

export interface DEBExtractionError {
  success: false;
  error: string;
}

// ── AR archive parsing ─────────────────────────────────────────────

const AR_MAGIC = "!<arch>\n";
const AR_HEADER_SIZE = 60;

interface ARMember {
  name: string;
  size: number;
  offset: number; // offset of data in the buffer
}

function parseARMembers(buf: Buffer): ARMember[] {
  const magic = buf.toString("ascii", 0, 8);
  if (magic !== AR_MAGIC) {
    throw new Error("Not a valid ar archive (bad magic)");
  }

  const members: ARMember[] = [];
  let pos = 8;

  while (pos + AR_HEADER_SIZE <= buf.length) {
    const name = buf.toString("ascii", pos, pos + 16).trim().replace(/\/$/, "");
    const sizeStr = buf.toString("ascii", pos + 48, pos + 58).trim();
    const endMarker = buf.toString("ascii", pos + 58, pos + 60);

    if (endMarker !== "`\n") {
      break; // Invalid header, stop
    }

    const size = parseInt(sizeStr, 10);
    if (isNaN(size)) break;

    const dataOffset = pos + AR_HEADER_SIZE;
    members.push({ name, size, offset: dataOffset });

    // Next member is aligned to 2-byte boundary
    pos = dataOffset + size;
    if (pos % 2 !== 0) pos++;
  }

  return members;
}

// ── Control file parsing ───────────────────────────────────────────

function parseControlFile(text: string): DEBControlInfo {
  const fields: Record<string, string> = {};
  let currentKey = "";

  for (const line of text.split("\n")) {
    if (line.startsWith(" ") || line.startsWith("\t")) {
      // Continuation of previous field
      if (currentKey) {
        fields[currentKey] += "\n" + line.trim();
      }
    } else {
      const colonIdx = line.indexOf(":");
      if (colonIdx > 0) {
        currentKey = line.substring(0, colonIdx).trim().toLowerCase();
        fields[currentKey] = line.substring(colonIdx + 1).trim();
      }
    }
  }

  return {
    package: fields["package"] ?? "",
    name: fields["name"] ?? fields["package"] ?? "",
    version: fields["version"] ?? "",
    architecture: fields["architecture"] ?? "",
    description: fields["description"] ?? "",
    author: fields["author"],
    maintainer: fields["maintainer"],
    section: fields["section"],
    depends: fields["depends"],
    installedSize: fields["installed-size"]
      ? parseInt(fields["installed-size"], 10)
      : undefined,
  };
}

// ── Tar extraction helpers ─────────────────────────────────────────

function extractTar(tarPath: string, destDir: string): Promise<void> {
  fs.mkdirSync(destDir, { recursive: true });

  // On Windows, use bsdtar from System32 (supports gz/xz/lzma/bz2/zst via libarchive).
  // On macOS/Linux, use system tar.
  const tarBin = process.platform === "win32"
    ? path.join(process.env["SYSTEMROOT"] ?? "C:\\Windows", "System32", "tar.exe")
    : "tar";

  return new Promise((resolve, reject) => {
    execFile(tarBin, ["xf", tarPath, "-C", destDir], { timeout: 60000 }, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

// ── Binary discovery ───────────────────────────────────────────────

function isMachO(filePath: string): boolean {
  try {
    const fd = fs.openSync(filePath, "r");
    const buf = Buffer.alloc(4);
    fs.readSync(fd, buf, 0, 4, 0);
    fs.closeSync(fd);
    const magic = buf.readUInt32BE(0);
    const magicLE = buf.readUInt32LE(0);
    return MACHO_MAGICS.has(magic) || MACHO_MAGICS.has(magicLE);
  } catch {
    return false;
  }
}

function findBinariesRecursive(
  dir: string,
  results: DEBBinaryInfo[],
  rootDir: string,
): void {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      findBinariesRecursive(fullPath, results, rootDir);
      continue;
    }

    if (!entry.isFile()) continue;

    const relPath = path.relative(rootDir, fullPath).replace(/\\/g, "/");

    // Classify by location
    if (entry.name.endsWith(".dylib")) {
      const isTweak =
        relPath.includes("MobileSubstrate/DynamicLibraries") ||
        relPath.includes("TweakInject");
      results.push({
        name: entry.name,
        path: fullPath,
        type: isTweak ? "tweak" : "library",
      });
    } else if (
      relPath.includes("/usr/libexec/") ||
      relPath.includes("/usr/bin/") ||
      relPath.includes("/usr/sbin/") ||
      relPath.includes("/usr/local/bin/")
    ) {
      if (isMachO(fullPath)) {
        results.push({
          name: entry.name,
          path: fullPath,
          type: "executable",
        });
      }
    } else if (relPath.includes(".app/") && !entry.name.includes(".")) {
      // App bundle binaries (e.g. /Applications/Ghost.app/Ghost)
      if (isMachO(fullPath)) {
        results.push({
          name: entry.name,
          path: fullPath,
          type: "executable",
        });
      }
    } else if (relPath.includes(".bundle/") && !entry.name.includes(".")) {
      // Bundle binaries (PreferenceBundles, ControlCenter modules, etc.)
      if (isMachO(fullPath)) {
        results.push({
          name: entry.name,
          path: fullPath,
          type: relPath.includes("PreferenceBundles/") ? "prefbundle" : "library",
        });
      }
    }
  }
}

function discoverDEBBinaries(dataDir: string): DEBBinaryInfo[] {
  const results: DEBBinaryInfo[] = [];
  findBinariesRecursive(dataDir, results, dataDir);

  // Sort: tweaks first, then executables, then libraries, then prefbundles
  const priority: Record<string, number> = {
    tweak: 0,
    executable: 1,
    library: 2,
    prefbundle: 3,
  };
  results.sort((a, b) => (priority[a.type] ?? 99) - (priority[b.type] ?? 99));

  return results;
}

// ── Main extraction ────────────────────────────────────────────────

export async function extractDEB(
  debPath: string,
): Promise<DEBExtractionResult | DEBExtractionError> {
  try {
    const buf = fs.readFileSync(debPath);
    const members = parseARMembers(buf);

    const tempDir = path.join(os.tmpdir(), `appinspect-deb-${Date.now()}`);
    fs.mkdirSync(tempDir, { recursive: true });

    // Write each member to disk
    for (const member of members) {
      const outPath = path.join(tempDir, member.name);
      fs.writeFileSync(
        outPath,
        buf.subarray(member.offset, member.offset + member.size),
      );
    }

    // Parse control file
    const controlMember = members.find((m) => m.name.startsWith("control.tar"));
    let control: DEBControlInfo = {
      package: "",
      name: path.basename(debPath, ".deb"),
      version: "",
      architecture: "",
      description: "",
    };

    if (controlMember) {
      const controlTarPath = path.join(tempDir, controlMember.name);
      const controlDir = path.join(tempDir, "control-extracted");
      try {
        await extractTar(controlTarPath, controlDir);
        // control file may be at root or in ./ prefix
        const controlFilePath =
          fs.existsSync(path.join(controlDir, "control"))
            ? path.join(controlDir, "control")
            : fs.existsSync(path.join(controlDir, ".", "control"))
              ? path.join(controlDir, ".", "control")
              : null;

        if (controlFilePath) {
          control = parseControlFile(fs.readFileSync(controlFilePath, "utf-8"));
        }
      } catch (err) {
        // Non-fatal: we can still analyze binaries without control metadata
        const msg = err instanceof Error ? err.message : String(err);
        console.warn(`[DEB] Failed to parse control: ${msg}`);
      }
    }

    // Extract data archive
    const dataMember = members.find((m) => m.name.startsWith("data.tar"));
    if (!dataMember) {
      return { success: false, error: "No data.tar member found in .deb archive" };
    }

    const dataTarPath = path.join(tempDir, dataMember.name);
    const dataDir = path.join(tempDir, "data");
    try {
      await extractTar(dataTarPath, dataDir);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { success: false, error: `Failed to extract data archive: ${msg}` };
    }

    // Discover binaries
    const binaries = discoverDEBBinaries(dataDir);

    return {
      success: true,
      control,
      binaries,
      dataDir,
      extractedDir: tempDir,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, error: `Failed to extract .deb: ${msg}` };
  }
}

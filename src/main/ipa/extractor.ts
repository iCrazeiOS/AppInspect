import * as fs from "fs";
import * as path from "path";
import { unzipSync } from "fflate";

export interface BinaryInfo {
  name: string;
  path: string;
  type: "main" | "framework" | "extension";
}

export interface ExtractionResult {
  success: true;
  extractedDir: string;
}

export interface ExtractionError {
  success: false;
  error: string;
}

/**
 * Extract an IPA file (which is a ZIP archive) to a destination directory.
 * Uses fflate.unzipSync for decompression.
 */
export function extractIPA(
  ipaPath: string,
  destDir: string
): ExtractionResult | ExtractionError {
  try {
    const fileBuffer = fs.readFileSync(ipaPath);
    const data = new Uint8Array(fileBuffer);
    const unzipped = unzipSync(data);

    // Ensure destDir exists
    fs.mkdirSync(destDir, { recursive: true });

    for (const [filePath, fileData] of Object.entries(unzipped)) {
      // Normalize path separators for the current OS
      const normalizedPath = filePath.split("/").join(path.sep);
      const fullPath = path.join(destDir, normalizedPath);

      // Skip directory entries (they end with / and have zero length)
      if (filePath.endsWith("/")) {
        fs.mkdirSync(fullPath, { recursive: true });
        continue;
      }

      // Ensure parent directory exists
      const parentDir = path.dirname(fullPath);
      fs.mkdirSync(parentDir, { recursive: true });

      // Write the file
      fs.writeFileSync(fullPath, fileData);
    }

    return { success: true, extractedDir: destDir };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { success: false, error: `Failed to extract IPA: ${message}` };
  }
}

/**
 * Discover the .app bundle inside an extracted IPA's Payload directory.
 * Returns the absolute path to the .app directory, or null if not found.
 */
export function discoverAppBundle(extractedDir: string): string | null {
  const payloadDir = path.join(extractedDir, "Payload");

  if (!fs.existsSync(payloadDir)) {
    return null;
  }

  try {
    const entries = fs.readdirSync(payloadDir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isDirectory() && entry.name.endsWith(".app")) {
        return path.join(payloadDir, entry.name);
      }
    }
  } catch {
    return null;
  }

  return null;
}

/**
 * Discover binaries in an app bundle: the main executable,
 * frameworks in Frameworks/, and app extensions in PlugIns/.
 */
export function discoverBinaries(appBundlePath: string): BinaryInfo[] {
  const binaries: BinaryInfo[] = [];

  // Determine main executable name from the .app folder name
  const appName = path.basename(appBundlePath, ".app");
  const mainBinaryPath = path.join(appBundlePath, appName);

  if (fs.existsSync(mainBinaryPath)) {
    binaries.push({
      name: appName,
      path: mainBinaryPath,
      type: "main",
    });
  }

  // Discover frameworks in Frameworks/
  const frameworksDir = path.join(appBundlePath, "Frameworks");
  if (fs.existsSync(frameworksDir)) {
    try {
      const entries = fs.readdirSync(frameworksDir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory() && entry.name.endsWith(".framework")) {
          const frameworkName = path.basename(entry.name, ".framework");
          const frameworkBinaryPath = path.join(
            frameworksDir,
            entry.name,
            frameworkName
          );
          binaries.push({
            name: frameworkName,
            path: frameworkBinaryPath,
            type: "framework",
          });
        }
      }
    } catch {
      // Ignore errors reading frameworks directory
    }
  }

  // Discover app extensions in PlugIns/
  const plugInsDir = path.join(appBundlePath, "PlugIns");
  if (fs.existsSync(plugInsDir)) {
    try {
      const entries = fs.readdirSync(plugInsDir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory() && entry.name.endsWith(".appex")) {
          const extensionName = path.basename(entry.name, ".appex");
          const extensionPath = path.join(plugInsDir, entry.name);
          binaries.push({
            name: extensionName,
            path: extensionPath,
            type: "extension",
          });
        }
      }
    } catch {
      // Ignore errors reading plugins directory
    }
  }

  return binaries;
}

/**
 * Remove the temporary extraction directory recursively.
 */
export function cleanupExtracted(destDir: string): void {
  if (fs.existsSync(destDir)) {
    fs.rmSync(destDir, { recursive: true, force: true });
  }
}

/**
 * Security Scan Engine
 *
 * Pattern-matching and binary-hardening checks for Mach-O binaries.
 * No ML, no network requests — regex patterns only.
 */

import type {
  StringEntry,
  Symbol,
  EncryptionInfo,
  SecurityFinding,
  BinaryHardening,
} from '../../shared/types';

import { LC_RPATH } from '../parser/load-commands';

// ── Constants ──

const MH_PIE = 0x200000;

// ── Credential / secret patterns ──

const SECRET_PATTERNS: Array<{
  name: string;
  pattern: RegExp;
  message: string;
}> = [
  {
    name: 'AWS Access Key',
    pattern: /AKIA[0-9A-Z]{16}/,
    message: 'AWS access key found in binary strings',
  },
  {
    name: 'API Key assignment',
    pattern: /[aA][pP][iI][-_]?[kK][eE][yY]\s*[:=]\s*['"][^'"]{8,}/,
    message: 'Possible API key assignment found',
  },
  {
    name: 'Bearer token',
    pattern: /[Bb]earer\s+[A-Za-z0-9\-._~+/]{20,}/,
    message: 'Bearer token found in binary strings',
  },
  {
    name: 'MongoDB URI',
    pattern: /mongodb(\+srv)?:\/\/[^\s'"]+/,
    message: 'MongoDB connection URI found',
  },
  {
    name: 'PostgreSQL URI',
    pattern: /postgres(ql)?:\/\/[^\s'"]+/,
    message: 'PostgreSQL connection URI found',
  },
  {
    name: 'MySQL URI',
    pattern: /mysql:\/\/[^\s'"]+/,
    message: 'MySQL connection URI found',
  },
  {
    name: 'Secret Key assignment',
    pattern: /[sS]ecret[-_]?[kK]ey\s*[:=]\s*['"][^'"]{8,}/,
    message: 'Possible secret key assignment found',
  },
  {
    name: 'Password assignment',
    pattern: /[pP]assword\s*[:=]\s*['"][^'"]{4,}/,
    message: 'Possible hardcoded password found',
  },
  {
    name: 'URL with credentials',
    pattern: /https?:\/\/[^\s/:@'"]{1,64}:[^\s/@'"]{1,64}@[^\s'"]+/,
    message: 'URL with embedded credentials found',
  },
  {
    name: 'Google/Firebase API Key',
    pattern: /AIza[0-9A-Za-z\-_]{35}/,
    message: 'Google/Firebase/Gemini API key found',
  },
  {
    name: 'Slack token',
    pattern: /xox[bpas]-[0-9A-Za-z\-]+/,
    message: 'Slack token found in binary strings',
  },
  {
    name: 'OpenAI API Key',
    pattern: /sk-[A-Za-z0-9]{20,}/,
    message: 'OpenAI API key found in binary strings',
  },
  {
    name: 'Anthropic API Key',
    pattern: /sk-ant-[A-Za-z0-9\-]{20,}/,
    message: 'Anthropic API key found in binary strings',
  },
];

// ── Insecure API patterns ──

const UNSAFE_API_SYMBOLS: Array<{
  names: string[];
  category: string;
  severity: SecurityFinding['severity'];
  message: string;
}> = [
  {
    names: ['_strcpy', '_strcat', '_sprintf', '_gets', '_scanf', '_vsprintf'],
    category: 'unsafe-api',
    severity: 'warning',
    message: 'Memory-unsafe function used',
  },
  {
    names: ['_CC_MD5', '_CC_SHA1', '_MD5_Init', '_SHA1_Init'],
    category: 'weak-crypto',
    severity: 'warning',
    message: 'Weak cryptographic function used',
  },
  {
    names: ['_system', '_popen', '_fork', '_execve'],
    category: 'dangerous-api',
    severity: 'warning',
    message: 'Dangerous system call used',
  },
  {
    names: ['_dlopen', '_dlsym'],
    category: 'dynamic-loading',
    severity: 'info',
    message: 'Dynamic library loading used',
  },
];

// ── Jailbreak detection patterns ──

const JAILBREAK_PATTERNS: RegExp[] = [
  /cydia:\/\//,
  /\/Applications\/Cydia\.app/,
  /frida/i,
  /substrate/,
  /MobileSubstrate/,
];

// ── Bundle file scanning (React Native, Flutter, configs) ──

export interface BundleFileEntry {
  /** Path relative to the app bundle root */
  relativePath: string;
  /** File content as text */
  content: string;
}

/** File extensions to scan inside app bundles */
const SCANNABLE_EXTENSIONS = new Set([
  '.js', '.jsbundle', '.bundle',
  '.json',
  '.xml', '.yaml', '.yml',
  '.env',
  '.html', '.htm',
  '.txt', '.strings',
  '.config', '.cfg', '.ini', '.properties',
]);

/**
 * Check if a file extension is scannable for secrets.
 */
export function isScannableExtension(ext: string): boolean {
  return SCANNABLE_EXTENSIONS.has(ext.toLowerCase());
}

/**
 * Quick heuristic to check if a JSON file is a Lottie animation or asset
 * data that won't contain secrets. Avoids scanning large asset files.
 */
function isAssetJSON(content: string): boolean {
  // Lottie animations start with {"v":"... or have common Lottie keys
  const head = content.slice(0, 200);
  if (/"v"\s*:\s*"[\d.]+"/.test(head) && (/"fr"\s*:/.test(head) || /"ip"\s*:/.test(head) || /"op"\s*:/.test(head))) {
    return true;
  }
  return false;
}

/**
 * Scan text file contents from the app bundle for credential leaks
 * and jailbreak detection strings. Used for React Native JS bundles,
 * config files, and other non-binary content.
 *
 * Scans line-by-line to prevent greedy patterns (e.g. URL-with-credentials)
 * from spanning across unrelated content and producing false positives.
 */
export function scanBundleFileContents(files: BundleFileEntry[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const seen = new Set<string>(); // dedupe by category+evidence+source

  for (const file of files) {
    // Skip very large files
    const { loadSettings } = require("../settings") as typeof import("../settings");
    const maxFileSize = loadSettings().maxFileSizeMB * 1024 * 1024;
    if (file.content.length > maxFileSize) continue;

    // Skip Lottie/animation JSON files (large, never contain secrets)
    if (file.relativePath.endsWith('.json') && isAssetJSON(file.content)) continue;

    // Skip package manager metadata (npm registry URLs trigger false positives)
    const baseName = file.relativePath.split('/').pop() ?? '';
    if (baseName === 'package-lock.json' || baseName === 'yarn.lock') continue;

    const lines = file.content.split('\n');

    for (let li = 0; li < lines.length; li++) {
      const line = lines[li]!;

      // PEM private key reassembly across consecutive lines
      if (PEM_BEGIN_RE.test(line)) {
        const pemLines = [line];
        let foundEnd = false;
        let lj = li + 1;
        while (lj < lines.length && lj - li < 200) {
          const next = lines[lj]!.trim();
          if (PEM_END_RE.test(next)) { pemLines.push(next); foundEnd = true; break; }
          if (PEM_BASE64_LINE_RE.test(next)) { pemLines.push(next); }
          else break;
          lj++;
        }
        const hasKeyMaterial = pemLines.length > 2 ||
          (!foundEnd && pemLines.length === 1);

        if (hasKeyMaterial) {
          const fullPem = pemLines.join('\n');
          const key = `credential-leak|pem-key|${file.relativePath}`;
          if (!seen.has(key)) {
            seen.add(key);
            findings.push({
              severity: 'critical',
              category: 'credential-leak',
              message: foundEnd
                ? 'Private key found in bundle file (full PEM block)'
                : 'Private key header found in bundle file',
              evidence: truncate(fullPem),
              source: file.relativePath,
            });
          }
        }
        if (foundEnd) li = lj;
        continue;
      }

      // Check secret patterns
      for (const { pattern, message } of SECRET_PATTERNS) {
        const match = pattern.exec(line);
        if (match) {
          const key = `credential-leak|${truncate(match[0])}|${file.relativePath}`;
          if (!seen.has(key)) {
            seen.add(key);
            findings.push({
              severity: 'critical',
              category: 'credential-leak',
              message: `${message} (in bundle file)`,
              evidence: truncate(match[0]),
              source: file.relativePath,
            });
          }
        }
      }

      // Check jailbreak detection patterns
      for (const jbPattern of JAILBREAK_PATTERNS) {
        const match = jbPattern.exec(line);
        if (match) {
          const key = `jailbreak-detection|${truncate(match[0])}|${file.relativePath}`;
          if (!seen.has(key)) {
            seen.add(key);
            findings.push({
              severity: 'info',
              category: 'jailbreak-detection',
              message: 'Jailbreak detection string found (in bundle file)',
              evidence: truncate(match[0]),
              source: file.relativePath,
            });
          }
        }
      }
    }
  }

  return findings;
}

// ── Public API ──

export interface SecurityScanParams {
  strings: StringEntry[];
  symbols: Symbol[];
  headerFlags: number;
  encryption: EncryptionInfo | null;
  loadCommands: Array<{ cmd: number; [key: string]: unknown }>;
}

/**
 * Run all security checks and return an array of findings.
 */
export function runSecurityScan(params: SecurityScanParams): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  findings.push(...checkBinaryHardeningFindings(params));
  findings.push(...checkSecretPatterns(params.strings));
  findings.push(...checkInsecureAPIs(params.symbols));
  findings.push(...checkJailbreakDetection(params.strings));

  return findings;
}

/**
 * Return a compact summary of binary hardening features.
 */
export function getBinaryHardening(params: {
  symbols: Symbol[];
  headerFlags: number;
  encryption: EncryptionInfo | null;
}): BinaryHardening {
  const symbolNames = new Set(params.symbols.map((s) => s.name));

  return {
    pie: (params.headerFlags & MH_PIE) !== 0,
    arc: hasARC(symbolNames),
    stackCanaries: hasStackCanaries(symbolNames),
    encrypted:
      params.encryption !== null && params.encryption.cryptid !== 0,
    stripped: params.symbols.length < 10,
  };
}

// ── Internal helpers ──

function hasStackCanaries(symbolNames: Set<string>): boolean {
  return (
    symbolNames.has('___stack_chk_guard') ||
    symbolNames.has('___stack_chk_fail')
  );
}

function hasARC(symbolNames: Set<string>): boolean {
  return (
    symbolNames.has('_objc_release') ||
    symbolNames.has('_objc_autorelease') ||
    symbolNames.has('_objc_storeStrong')
  );
}

function truncate(s: string, max = 500): string {
  return s.length > max ? s.slice(0, max) + '...' : s;
}

function checkBinaryHardeningFindings(
  params: SecurityScanParams,
): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const symbolNames = new Set(params.symbols.map((s) => s.name));

  // PIE
  const pieEnabled = (params.headerFlags & MH_PIE) !== 0;
  findings.push({
    severity: pieEnabled ? 'info' : 'warning',
    category: 'binary-hardening',
    message: pieEnabled
      ? 'PIE (Position Independent Executable) enabled'
      : 'PIE (Position Independent Executable) is NOT enabled',
    evidence: `headerFlags=0x${params.headerFlags.toString(16)}`,
  });

  // Stack canaries
  const canaries = hasStackCanaries(symbolNames);
  findings.push({
    severity: canaries ? 'info' : 'warning',
    category: 'binary-hardening',
    message: canaries
      ? 'Stack canaries detected'
      : 'Stack canaries NOT detected',
    evidence: canaries
      ? 'Symbol ___stack_chk_guard or ___stack_chk_fail found'
      : 'No stack canary symbols found',
  });

  // ARC
  const arc = hasARC(symbolNames);
  findings.push({
    severity: arc ? 'info' : 'warning',
    category: 'binary-hardening',
    message: arc
      ? 'ARC (Automatic Reference Counting) detected'
      : 'ARC (Automatic Reference Counting) NOT detected',
    evidence: arc
      ? 'ObjC ARC symbols found'
      : 'No ObjC ARC symbols found',
  });

  // Encryption
  if (params.encryption) {
    const encrypted = params.encryption.cryptid !== 0;
    findings.push({
      severity: encrypted ? 'warning' : 'info',
      category: 'binary-hardening',
      message: encrypted
        ? 'Binary is encrypted (cryptid != 0) — likely from App Store'
        : 'Binary is decrypted (cryptid == 0)',
      evidence: `cryptid=${params.encryption.cryptid}`,
    });
  }

  // Stripped
  if (params.symbols.length < 10) {
    findings.push({
      severity: 'info',
      category: 'binary-hardening',
      message: 'Symbols appear to be stripped (very few symbols present)',
      evidence: `symbolCount=${params.symbols.length}`,
    });
  }

  // Rpath
  const hasRpath = params.loadCommands.some((lc) => lc.cmd === LC_RPATH);
  if (hasRpath) {
    findings.push({
      severity: 'info',
      category: 'binary-hardening',
      message: 'Rpath present (potential hijack vector)',
      evidence: 'LC_RPATH load command found',
    });
  }

  return findings;
}

// Base64 detection: at least 20 chars of valid base64 with optional padding
const BASE64_RE = /^[A-Za-z0-9+/]{20,}={0,2}$/;

function tryBase64Decode(s: string): string | null {
  const trimmed = s.trim();
  if (!BASE64_RE.test(trimmed)) return null;
  try {
    const decoded = Buffer.from(trimmed, 'base64').toString('utf8');
    // Sanity check: decoded content should be mostly printable ASCII
    const printable = decoded.replace(/[^\x20-\x7e]/g, '');
    if (printable.length < decoded.length * 0.7) return null;
    return decoded;
  } catch {
    return null;
  }
}

// PEM detection patterns
const PEM_BEGIN_RE = /-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/;
const PEM_END_RE = /-----END (RSA |EC |DSA )?PRIVATE KEY-----/;
const PEM_BASE64_LINE_RE = /^[A-Za-z0-9+/]{1,76}={0,2}$/;

function checkSecretPatterns(strings: StringEntry[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (let i = 0; i < strings.length; i++) {
    const entry = strings[i]!;

    // ── PEM private key reassembly ──
    // The header, base64 lines, and footer are separate null-terminated strings
    // in the binary. Collect adjacent strings to reconstruct the full PEM block.
    const pemMatch = PEM_BEGIN_RE.exec(entry.value);
    if (pemMatch) {
      const pemLines = [entry.value];
      let j = i + 1;
      let foundEnd = false;
      // Collect up to 200 following strings (RSA-4096 ≈ 50 lines)
      while (j < strings.length && j - i < 200) {
        const next = strings[j]!.value;
        if (PEM_END_RE.test(next)) {
          pemLines.push(next);
          foundEnd = true;
          break;
        }
        if (PEM_BASE64_LINE_RE.test(next)) {
          pemLines.push(next);
        } else {
          // Non-base64, non-footer line — stop collecting
          break;
        }
        j++;
      }

      // Only report if there's actual base64 key material between header and footer.
      // Bare header+footer with nothing in between are just format strings used
      // by RSA utility code, not actual embedded keys.
      const hasKeyMaterial = pemLines.length > 2 ||
        (!foundEnd && pemLines.length === 1); // lone header with no end = suspicious

      if (hasKeyMaterial) {
        const fullPem = pemLines.join('\n');
        findings.push({
          severity: 'critical',
          category: 'credential-leak',
          message: foundEnd
            ? 'Private key embedded in binary (full PEM block)'
            : 'Private key header found in binary',
          evidence: truncate(fullPem),
          location: `offset=0x${entry.offset.toString(16)}`,
        });
      }

      // Skip past the strings we consumed
      if (foundEnd) i = j;
      continue;
    }

    // ── Standard secret patterns ──
    for (const { pattern, message } of SECRET_PATTERNS) {
      const match = pattern.exec(entry.value);
      if (match) {
        findings.push({
          severity: 'critical',
          category: 'credential-leak',
          message,
          evidence: truncate(match[0]),
          location: `offset=0x${entry.offset.toString(16)}`,
        });
      }
    }

    // Also check base64-encoded strings
    const decoded = tryBase64Decode(entry.value);
    if (decoded) {
      for (const { pattern, message } of SECRET_PATTERNS) {
        const match = pattern.exec(decoded);
        if (match) {
          findings.push({
            severity: 'critical',
            category: 'credential-leak',
            message: `${message} (base64 encoded)`,
            evidence: truncate(match[0]),
            location: `offset=0x${entry.offset.toString(16)}`,
          });
        }
      }
    }
  }

  return findings;
}

function checkInsecureAPIs(symbols: Symbol[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (const sym of symbols) {
    for (const group of UNSAFE_API_SYMBOLS) {
      if (group.names.includes(sym.name)) {
        findings.push({
          severity: group.severity,
          category: group.category,
          message: `${group.message}: ${sym.name}`,
          evidence: sym.name,
        });
      }
    }
  }

  return findings;
}

function checkJailbreakDetection(strings: StringEntry[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (const entry of strings) {
    for (const pattern of JAILBREAK_PATTERNS) {
      const match = pattern.exec(entry.value);
      if (match) {
        findings.push({
          severity: 'info',
          category: 'jailbreak-detection',
          message: 'Jailbreak detection string found',
          evidence: truncate(match[0]),
          location: `offset=0x${entry.offset.toString(16)}`,
        });
      }
    }
  }

  return findings;
}

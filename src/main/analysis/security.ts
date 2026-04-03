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
    name: 'Private Key',
    pattern: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/,
    message: 'Private key embedded in binary',
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
    pattern: /https?:\/\/[^:]+:[^@]+@[^\s'"]+/,
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

function truncate(s: string, max = 100): string {
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

function checkSecretPatterns(strings: StringEntry[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (const entry of strings) {
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

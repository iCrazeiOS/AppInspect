/**
 * Info.plist and embedded.mobileprovision Parser
 *
 * Parses Info.plist (binary or XML format) and embedded.mobileprovision
 * (CMS/DER envelope containing XML plist) from an extracted .app bundle.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import bplist from "bplist-parser";
import plist from "plist";

// ── Result Types ──────────────────────────────────────────────────────

export interface ParseSuccess<T> {
	ok: true;
	data: T;
}

export interface ParseError {
	ok: false;
	error: string;
}

export type ParseResult<T> = ParseSuccess<T> | ParseError;

// ── Info.plist Types ──────────────────────────────────────────────────

export interface InfoPlistData {
	CFBundleIdentifier: string | undefined;
	CFBundleName: string | undefined;
	CFBundleDisplayName: string | undefined;
	CFBundleShortVersionString: string | undefined;
	CFBundleVersion: string | undefined;
	CFBundleExecutable: string | undefined;
	MinimumOSVersion: string | undefined;
	LSRequiresIPhoneOS: boolean | undefined;
	UIRequiredDeviceCapabilities: string[] | undefined;
	CFBundleURLTypes: unknown[] | undefined;
	NSAppTransportSecurity: Record<string, unknown> | undefined;
	UIBackgroundModes: string[] | undefined;
	privacyUsageStrings: Record<string, string>;
	raw: Record<string, unknown>;
}

// ── Mobileprovision Types ─────────────────────────────────────────────

export interface MobileprovisionData {
	TeamIdentifier: string[] | undefined;
	TeamName: string | undefined;
	ExpirationDate: Date | undefined;
	CreationDate: Date | undefined;
	Entitlements: Record<string, unknown> | undefined;
	ProvisionedDevices: string[] | undefined;
	ProvisionsAllDevices: boolean | undefined;
}

// ── Helpers ───────────────────────────────────────────────────────────

/**
 * Suppress xmldom's console warnings/errors during a callback.
 * The `plist` package uses xmldom which dumps parse warnings to the console
 * for malformed XML — this silences them.
 */
export function silenceXmldom<T>(fn: () => T): T {
	const origWarn = console.warn;
	const origError = console.error;
	console.warn = (...args: unknown[]) => {
		if (typeof args[0] === "string" && args[0].includes("[xmldom")) return;
		origWarn.apply(console, args);
	};
	console.error = (...args: unknown[]) => {
		if (typeof args[0] === "string" && args[0].includes("[xmldom")) return;
		origError.apply(console, args);
	};
	try {
		return fn();
	} finally {
		console.warn = origWarn;
		console.error = origError;
	}
}

/**
 * Parse a plist buffer, trying binary format first, then XML.
 */
export function parsePlistBuffer(buf: Buffer): Record<string, unknown> {
	// Try binary plist first
	try {
		const parsed = bplist.parseBuffer(buf);
		if (Array.isArray(parsed) && parsed.length > 0) {
			return parsed[0] as Record<string, unknown>;
		}
	} catch {
		// Not binary plist — fall through to XML
	}

	// Try XML plist
	const xmlString = buf.toString("utf-8");
	const parsed = silenceXmldom(() => plist.parse(xmlString));
	if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
		return parsed as Record<string, unknown>;
	}

	throw new Error("Plist is not a valid dictionary");
}

/**
 * Extract privacy usage description strings (NS*UsageDescription keys).
 */
function extractPrivacyStrings(raw: Record<string, unknown>): Record<string, string> {
	const result: Record<string, string> = {};
	for (const key of Object.keys(raw)) {
		if (key.startsWith("NS") && key.endsWith("UsageDescription")) {
			const val = raw[key];
			if (typeof val === "string") {
				result[key] = val;
			}
		}
	}
	return result;
}

// ── Public API ────────────────────────────────────────────────────────

/**
 * Parse Info.plist from an extracted .app bundle directory.
 * Returns null when Info.plist does not exist.
 */
export function parseInfoPlist(appBundlePath: string): ParseResult<InfoPlistData> | null {
	const plistPath = path.join(appBundlePath, "Info.plist");

	if (!fs.existsSync(plistPath)) {
		return null;
	}

	try {
		const buf = fs.readFileSync(plistPath);
		const raw = parsePlistBuffer(buf);

		const data: InfoPlistData = {
			CFBundleIdentifier: raw.CFBundleIdentifier as string | undefined,
			CFBundleName: raw.CFBundleName as string | undefined,
			CFBundleDisplayName: raw.CFBundleDisplayName as string | undefined,
			CFBundleShortVersionString: raw.CFBundleShortVersionString as string | undefined,
			CFBundleVersion: raw.CFBundleVersion as string | undefined,
			CFBundleExecutable: raw.CFBundleExecutable as string | undefined,
			MinimumOSVersion: raw.MinimumOSVersion as string | undefined,
			LSRequiresIPhoneOS: raw.LSRequiresIPhoneOS as boolean | undefined,
			UIRequiredDeviceCapabilities: raw.UIRequiredDeviceCapabilities as string[] | undefined,
			CFBundleURLTypes: raw.CFBundleURLTypes as unknown[] | undefined,
			NSAppTransportSecurity: raw.NSAppTransportSecurity as
				| Record<string, unknown>
				| undefined,
			UIBackgroundModes: raw.UIBackgroundModes as string[] | undefined,
			privacyUsageStrings: extractPrivacyStrings(raw),
			raw
		};

		return { ok: true, data };
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		return { ok: false, error: `Failed to parse Info.plist: ${message}` };
	}
}

/**
 * Parse embedded.mobileprovision from an extracted .app bundle directory.
 * Extracts the XML plist from the CMS/DER envelope by finding XML boundaries.
 * Returns null when embedded.mobileprovision does not exist.
 */
export function parseMobileprovision(
	appBundlePath: string
): ParseResult<MobileprovisionData> | null {
	const provisionPath = path.join(appBundlePath, "embedded.mobileprovision");

	if (!fs.existsSync(provisionPath)) {
		return null;
	}

	try {
		const buf = fs.readFileSync(provisionPath);
		const raw = buf.toString("latin1");

		// Find the XML plist boundaries within the DER envelope
		const xmlStart = raw.indexOf("<?xml");
		const xmlEnd = raw.indexOf("</plist>");

		if (xmlStart === -1 || xmlEnd === -1) {
			return {
				ok: false,
				error: "Failed to parse mobileprovision: could not find XML plist boundaries"
			};
		}

		const xmlString = raw.substring(xmlStart, xmlEnd + "</plist>".length);
		const parsed = silenceXmldom(() => plist.parse(xmlString)) as Record<string, unknown>;

		const data: MobileprovisionData = {
			TeamIdentifier: parsed.TeamIdentifier as string[] | undefined,
			TeamName: parsed.TeamName as string | undefined,
			ExpirationDate: parsed.ExpirationDate as Date | undefined,
			CreationDate: parsed.CreationDate as Date | undefined,
			Entitlements: parsed.Entitlements as Record<string, unknown> | undefined,
			ProvisionedDevices: parsed.ProvisionedDevices as string[] | undefined,
			ProvisionsAllDevices: parsed.ProvisionsAllDevices as boolean | undefined
		};

		return { ok: true, data };
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		return {
			ok: false,
			error: `Failed to parse mobileprovision: ${message}`
		};
	}
}

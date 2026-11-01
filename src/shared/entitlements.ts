import type { Entitlement } from "./types";

/**
 * Flatten the stored entitlement list back into a key/value dictionary for
 * display.
 *
 * The result has a null prototype: keys come from an untrusted plist inside the
 * analysed binary, so `__proto__` must not become the setter.
 */
export function entitlementsToObject(entries: Entitlement[] | undefined): Record<string, unknown> {
	const object: Record<string, unknown> = Object.create(null);
	if (Array.isArray(entries)) {
		for (const entry of entries) object[entry.key] = entry.value;
	}
	return object;
}

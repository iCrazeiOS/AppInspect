/**
 * Lightweight localStorage wrapper for persisting UI layout sizes
 * (column widths, panel widths) across sessions.
 *
 * All keys are prefixed with "appinspect:" to avoid collisions.
 */

const PREFIX = "appinspect:";

/** Save a record of widths under the given key. */
export function saveWidths(key: string, widths: Record<string, string>): void {
	try {
		localStorage.setItem(PREFIX + key, JSON.stringify(widths));
	} catch {
		/* quota exceeded or unavailable — ignore */
	}
}

/** Load a previously saved widths record, or null if none. */
export function loadWidths(key: string): Record<string, string> | null {
	try {
		const raw = localStorage.getItem(PREFIX + key);
		if (raw) return JSON.parse(raw);
	} catch {
		/* corrupt or unavailable — ignore */
	}
	return null;
}

export { formatCount, formatSize, plural } from "../../shared/format";

const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;

/** Compact age for file timestamps, e.g. "5m ago", "3d ago", "2mo ago". */
export function formatRelativeTime(timestampMs: number, nowMs = Date.now()): string {
	const elapsed = nowMs - timestampMs;
	if (!Number.isFinite(elapsed) || elapsed < MINUTE_MS) return "just now";
	if (elapsed < HOUR_MS) return `${Math.floor(elapsed / MINUTE_MS)}m ago`;
	if (elapsed < DAY_MS) return `${Math.floor(elapsed / HOUR_MS)}h ago`;
	const days = Math.floor(elapsed / DAY_MS);
	if (days < 7) return `${days}d ago`;
	if (days < 30) return `${Math.floor(days / 7)}w ago`;
	if (days < 365) return `${Math.floor(days / 30)}mo ago`;
	return `${Math.floor(days / 365)}y ago`;
}

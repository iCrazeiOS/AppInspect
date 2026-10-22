/** Human-readable byte count (B / KB / MB / GB, one decimal). */
export function formatSize(bytes: number): string {
	if (bytes < 1024) return `${bytes} B`;
	if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
	if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
	return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

/** Singular noun when `count` is 1, plural otherwise. */
export function plural(count: number, singular: string, pluralForm = `${singular}s`): string {
	return count === 1 ? singular : pluralForm;
}

/** Locale-formatted count with a correctly inflected noun, e.g. "1 file" / "2 files". */
export function formatCount(count: number, singular: string, pluralForm?: string): string {
	return `${count.toLocaleString()} ${plural(count, singular, pluralForm)}`;
}

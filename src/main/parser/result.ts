/**
 * Canonical parser result type.
 *
 * Parsers with a hard-failure mode — where the input is either valid and
 * fully parseable or it isn't — return this instead of throwing or returning
 * null. Collection extractors that recover partial data return their values
 * directly; for those, an empty result is meaningful, not a failure.
 */

export type Result<T> = { ok: true; data: T } | { ok: false; error: string };

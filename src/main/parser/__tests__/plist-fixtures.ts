/** Test fixtures for plist parsing and previews. */

/**
 * Binary plist for `{ name: "AppInspect", enabled: true, count: 3, items: ["a", "b"] }`,
 * generated with Python's `plistlib` in FMT_BINARY mode.
 */
export const BINARY_INFO_PLIST = Buffer.from(
	"YnBsaXN0MDDUAQIDBAUGBwpVY291bnRXZW5hYmxlZFVpdGVtc1RuYW1lEAMJoggJUWFRYlpBcHBJbnNwZWN0CBEXHyUqLC0wMjQAAAAAAAABAQAAAAAAAAALAAAAAAAAAAAAAAAAAAAAPw==",
	"base64"
);

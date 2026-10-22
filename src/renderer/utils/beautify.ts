/** Source formatting helpers for the file preview pane. */

import type { Plugin } from "prettier";
import * as babel from "prettier/plugins/babel";
import * as estree from "prettier/plugins/estree";
import * as html from "prettier/plugins/html";
import * as postcss from "prettier/plugins/postcss";
import * as typescript from "prettier/plugins/typescript";
import { format } from "prettier/standalone";

/** Prettier parser used to beautify a previewed file. */
export type BeautifyParser =
	| "babel"
	| "typescript"
	| "json-stringify"
	| "css"
	| "scss"
	| "less"
	| "html";

const PARSERS: Record<string, BeautifyParser> = {
	json: "json-stringify",
	map: "json-stringify",
	webmanifest: "json-stringify",
	js: "babel",
	mjs: "babel",
	cjs: "babel",
	jsx: "babel",
	ts: "typescript",
	mts: "typescript",
	cts: "typescript",
	tsx: "typescript",
	css: "css",
	scss: "scss",
	less: "less",
	html: "html",
	htm: "html",
	xhtml: "html",
	svg: "html"
};

const PLUGINS: Plugin[] = [babel, estree, typescript, postcss, html];

/** Prettier parser for a file path, or null when the type is unsupported. */
export function beautifyParser(filePath: string): BeautifyParser | null {
	const name = filePath.slice(filePath.lastIndexOf("/") + 1);
	const dot = name.lastIndexOf(".");
	if (dot <= 0) return null;
	return PARSERS[name.slice(dot + 1).toLowerCase()] ?? null;
}

/** Re-serialise JSON text with indentation, or null when it does not parse. */
export function prettyPrintJson(text: string): string | null {
	const trimmed = text.trimStart();
	if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return null;
	try {
		return JSON.stringify(JSON.parse(text), null, 4);
	} catch {
		return null;
	}
}

/**
 * Format source text for display. Returns null when the input cannot be parsed;
 * Prettier's trailing newline is trimmed so the preview has no blank last line.
 */
export async function beautifyText(text: string, parser: BeautifyParser): Promise<string | null> {
	try {
		const formatted = await format(text, {
			parser,
			plugins: PLUGINS,
			tabWidth: 4,
			printWidth: 100,
			useTabs: false,
			endOfLine: "lf"
		});
		return formatted.endsWith("\n") ? formatted.slice(0, -1) : formatted;
	} catch {
		return null;
	}
}

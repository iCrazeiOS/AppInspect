/** Syntax highlighting for source previews, backed by highlight.js. */

import hljs from "highlight.js/lib/common";
import { ASAR_PREVIEW_BYTES } from "../../shared/asar-preview";

/** Preview text up to this size is highlighted without asking. */
export const HIGHLIGHT_AUTO_BYTES = ASAR_PREVIEW_BYTES;

const EXTENSIONS: Record<string, string> = {
	js: "javascript",
	mjs: "javascript",
	cjs: "javascript",
	jsx: "javascript",
	ts: "typescript",
	mts: "typescript",
	cts: "typescript",
	tsx: "typescript",
	css: "css",
	scss: "scss",
	sass: "scss",
	less: "less",
	html: "xml",
	htm: "xml",
	xhtml: "xml",
	svg: "xml",
	xml: "xml",
	plist: "xml",
	vue: "xml",
	svelte: "xml",
	json: "json",
	map: "json",
	json5: "json",
	webmanifest: "json",
	yaml: "yaml",
	yml: "yaml",
	ini: "ini",
	sh: "bash",
	bash: "bash",
	zsh: "bash",
	py: "python",
	rb: "ruby",
	go: "go",
	rs: "rust",
	c: "c",
	h: "c",
	cpp: "cpp",
	hpp: "cpp",
	cc: "cpp",
	cxx: "cpp",
	java: "java",
	kt: "kotlin",
	kts: "kotlin",
	swift: "swift",
	m: "objectivec",
	mm: "objectivec",
	md: "markdown",
	markdown: "markdown",
	graphql: "graphql",
	gql: "graphql",
	sql: "sql",
	php: "php",
	lua: "lua",
	pl: "perl",
	cs: "csharp"
};

/** highlight.js language for a file path, or null when the type is unsupported. */
export function highlightLanguage(filePath: string): string | null {
	const name = filePath.slice(filePath.lastIndexOf("/") + 1);
	const dot = name.lastIndexOf(".");
	if (dot <= 0) return null;
	const language = EXTENSIONS[name.slice(dot + 1).toLowerCase()];
	return language && hljs.getLanguage(language) ? language : null;
}

/** Highlight source text as HTML, or null when the language is unsupported. */
export function highlightSource(text: string, language: string): string | null {
	if (!hljs.getLanguage(language)) return null;
	try {
		return hljs.highlight(text, { language, ignoreIllegals: true }).value;
	} catch {
		return null;
	}
}

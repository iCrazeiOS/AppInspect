/**
 * Syntax highlighting for Objective-C method signatures and Logos hooks.
 *
 * Logos itself is a tiny grammar: a handful of `%directive` keywords bolted
 * onto Objective-C. Rather than pulling in a highlighter + theme, this emits
 * the small set of spans the classes tab needs. All output is HTML-escaped.
 */

interface Token {
	text: string;
	cls?: string;
}

// From the Logos TextMate grammar (davidmurray/Sublime-Logos).
const LOGOS_DIRECTIVES = new Set([
	"init",
	"hookf",
	"hook",
	"subclass",
	"group",
	"class",
	"new",
	"ctor",
	"end",
	"config",
	"orig",
	"log",
	"dtor",
	"property",
	"c"
]);

const CODE_KEYWORDS = new Set([
	"return",
	"if",
	"else",
	"for",
	"while",
	"do",
	"switch",
	"case",
	"break",
	"continue",
	"goto",
	"sizeof",
	"typedef",
	"struct",
	"enum",
	"union",
	"static",
	"extern",
	"const",
	"void",
	"id",
	"BOOL",
	"SEL",
	"Class",
	"IMP",
	"int",
	"char",
	"short",
	"long",
	"float",
	"double",
	"unsigned",
	"signed",
	"self",
	"super",
	"nil",
	"Nil",
	"NULL",
	"YES",
	"NO"
]);

const IDENT_START = /[A-Za-z_$]/;
const IDENT_CHAR = /[A-Za-z0-9_$]/;

function escapeHtml(text: string): string {
	return text
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#39;");
}

function render(tokens: Token[]): string {
	let html = "";
	for (const token of tokens) {
		const text = escapeHtml(token.text);
		html += token.cls ? `<span class="${token.cls}">${text}</span>` : text;
	}
	return html;
}

function tokenizeObjCMethod(sig: string): Token[] {
	const tokens: Token[] = [];
	let i = 0;
	let seenReturnType = false;
	let typeIsArgument = false;

	while (i < sig.length) {
		const ch = sig[i]!;

		if (ch === "-" || ch === "+") {
			tokens.push({ text: ch, cls: "hl-sign" });
			i++;
			continue;
		}

		if (ch === "(") {
			const close = sig.indexOf(")", i + 1);
			if (close !== -1) {
				tokens.push({ text: "(", cls: "hl-punct" });
				tokens.push({ text: sig.slice(i + 1, close), cls: "hl-type" });
				tokens.push({ text: ")", cls: "hl-punct" });
				// The first parenthesised group is the return type, the rest
				// are argument types.
				typeIsArgument = seenReturnType;
				seenReturnType = true;
				i = close + 1;
				continue;
			}
		}

		if (ch === ":") {
			tokens.push({ text: ch, cls: "hl-punct" });
			i++;
			continue;
		}

		if (ch === " " || ch === "\t") {
			let j = i;
			while (j < sig.length && (sig[j] === " " || sig[j] === "\t")) j++;
			tokens.push({ text: sig.slice(i, j) });
			i = j;
			continue;
		}

		if (IDENT_START.test(ch)) {
			let j = i + 1;
			while (j < sig.length && IDENT_CHAR.test(sig[j]!)) j++;
			const word = sig.slice(i, j);
			// A selector label is the identifier immediately before a colon;
			// otherwise an identifier after an argument type is the argument name.
			const isLabel = /^\s*:/.test(sig.slice(j));
			const cls = typeIsArgument && !isLabel ? "hl-arg" : "hl-selector";
			tokens.push({ text: word, cls });
			typeIsArgument = false;
			i = j;
			continue;
		}

		tokens.push({ text: ch, cls: "hl-punct" });
		i++;
	}

	return tokens;
}

function tokenizeCode(text: string): Token[] {
	const tokens: Token[] = [];
	let i = 0;

	while (i < text.length) {
		const ch = text[i]!;
		const next = text[i + 1];

		if (ch === "/" && next === "/") {
			tokens.push({ text: text.slice(i), cls: "hl-comment" });
			break;
		}

		if (ch === "/" && next === "*") {
			const end = text.indexOf("*/", i + 2);
			const stop = end === -1 ? text.length : end + 2;
			tokens.push({ text: text.slice(i, stop), cls: "hl-comment" });
			i = stop;
			continue;
		}

		if (ch === '"' || (ch === "@" && next === '"')) {
			const start = i;
			i += ch === "@" ? 2 : 1;
			while (i < text.length && text[i] !== '"') {
				if (text[i] === "\\") i++;
				i++;
			}
			i = Math.min(i + 1, text.length);
			tokens.push({ text: text.slice(start, i), cls: "hl-string" });
			continue;
		}

		if (ch === "'") {
			const start = i;
			i++;
			while (i < text.length && text[i] !== "'") {
				if (text[i] === "\\") i++;
				i++;
			}
			i = Math.min(i + 1, text.length);
			tokens.push({ text: text.slice(start, i), cls: "hl-string" });
			continue;
		}

		if (ch === "%") {
			let j = i + 1;
			while (j < text.length && /[A-Za-z]/.test(text[j]!)) j++;
			if (LOGOS_DIRECTIVES.has(text.slice(i + 1, j))) {
				tokens.push({ text: text.slice(i, j), cls: "hl-keyword" });
				i = j;
			} else {
				tokens.push({ text: ch, cls: "hl-punct" });
				i++;
			}
			continue;
		}

		if (ch >= "0" && ch <= "9") {
			let j = i + 1;
			while (j < text.length && /[0-9a-fA-FxX.]/.test(text[j]!)) j++;
			tokens.push({ text: text.slice(i, j), cls: "hl-number" });
			i = j;
			continue;
		}

		if (IDENT_START.test(ch)) {
			let j = i + 1;
			while (j < text.length && IDENT_CHAR.test(text[j]!)) j++;
			const word = text.slice(i, j);
			let cls: string | undefined;
			if (CODE_KEYWORDS.has(word)) cls = "hl-keyword";
			else if (text[j] === "(") cls = "hl-selector";
			else if (word === "orig" || /^arg\d+$/.test(word)) cls = "hl-arg";
			else if (/^[A-Z]/.test(word)) cls = "hl-type";
			tokens.push(cls ? { text: word, cls } : { text: word });
			i = j;
			continue;
		}

		if ("{}();,".includes(ch)) {
			tokens.push({ text: ch, cls: "hl-punct" });
			i++;
			continue;
		}

		tokens.push({ text: ch });
		i++;
	}

	return tokens;
}

/** Highlight an Objective-C method signature such as `-(void)doThing:(id)arg0`. */
export function highlightObjCMethod(signature: string): string {
	return render(tokenizeObjCMethod(signature));
}

/** Highlight a Logos hook block (directives, method declarations, ObjC body). */
export function highlightLogos(code: string): string {
	return code
		.split("\n")
		.map((line) => {
			const trimmed = line.trimStart();
			if ((trimmed.startsWith("-") || trimmed.startsWith("+")) && trimmed.includes("(")) {
				return render(tokenizeObjCMethod(line));
			}
			return render(tokenizeCode(line));
		})
		.join("\n");
}

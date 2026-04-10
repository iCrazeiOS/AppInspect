/**
 * ObjC method signature parsing and Logos hook code generation.
 *
 * Pure functions with no DOM dependencies — extracted from the classes tab
 * renderer so they can be reused or tested independently.
 */

// ── Method signature parsing helpers ──

export interface ParsedMethod {
	isInstance: boolean;
	returnType: string;
	selector: string;
	parts: { label: string; type: string; argName: string }[];
}

export function parseMethodSignature(sig: string): ParsedMethod | null {
	const trimmed = sig.trim();
	if (!trimmed.startsWith("-") && !trimmed.startsWith("+")) return null;

	const isInstance = trimmed[0] === "-";
	let rest = trimmed.slice(1).trim();

	// Extract return type in parens
	let returnType = "void";
	if (rest.startsWith("(")) {
		const closeIdx = rest.indexOf(")");
		if (closeIdx > 0) {
			returnType = rest.slice(1, closeIdx).trim();
			rest = rest.slice(closeIdx + 1).trim();
		}
	}

	// No-arg selector: e.g. "init" or "sharedInstance"
	if (!rest.includes(":")) {
		return { isInstance, returnType, selector: rest, parts: [] };
	}

	// Parse "label:(type)argName label2:(type2)argName2 ..."
	const parts: ParsedMethod["parts"] = [];
	const selectorParts: string[] = [];
	const regex = /(\w*)\s*:\s*(?:\(([^)]*)\))?\s*(\w+)?/g;
	for (const match of rest.matchAll(regex)) {
		const label = match[1] || "";
		const type = match[2]?.trim() || "id";
		const argName = match[3] || `arg${parts.length}`;
		selectorParts.push(`${label}:`);
		parts.push({ label, type, argName });
	}

	return { isInstance, returnType, selector: selectorParts.join(""), parts };
}

// ── Type formatting helpers ──

export function formatSpecForType(type: string): string {
	const raw = type.trim();
	const isPointer = raw.endsWith("*");
	const t = raw.replace(/\s*\*\s*$/, "").trim();
	// void * is a pointer, plain void is no-value
	if (t === "void" && isPointer) return "%p";
	if (t === "void") return "";
	if (
		t === "id" ||
		t === "NSString" ||
		t === "NSArray" ||
		t === "NSDictionary" ||
		t === "NSNumber" ||
		t === "NSData" ||
		t === "NSError" ||
		t === "NSObject" ||
		t === "NSURL" ||
		t === "NSSet" ||
		t === "NSDate" ||
		isPointer
	)
		return "%@";
	if (t === "BOOL" || t === "bool") return "%@";
	if (
		t === "int" ||
		t === "NSInteger" ||
		t === "NSUInteger" ||
		t === "unsigned int" ||
		t === "uint32_t" ||
		t === "int32_t"
	)
		return "%d";
	if (t === "long" || t === "unsigned long") return "%ld";
	if (t === "long long" || t === "unsigned long long" || t === "int64_t" || t === "uint64_t")
		return "%lld";
	if (t === "float") return "%f";
	if (t === "double" || t === "CGFloat") return "%f";
	if (t === "char" || t === "unsigned char") return "%c";
	if (t === "SEL") return "%@";
	if (t === "Class") return "%@";
	if (t === "CGRect") return "%@";
	if (t === "CGSize") return "%@";
	if (t === "CGPoint") return "%@";
	return "%p"; // fallback
}

export function argFormatExpr(argName: string, type: string): string {
	const t = type.replace(/\s*\*\s*$/, "").trim();
	if (t === "BOOL" || t === "bool") return `${argName} ? @"YES" : @"NO"`;
	if (t === "SEL") return `NSStringFromSelector(${argName})`;
	if (t === "Class") return `NSStringFromClass(${argName})`;
	if (t === "CGRect") return `NSStringFromCGRect(${argName})`;
	if (t === "CGSize") return `NSStringFromCGSize(${argName})`;
	if (t === "CGPoint") return `NSStringFromCGPoint(${argName})`;
	return argName;
}

export function returnFormatExpr(type: string): { fmt: string; expr: string } {
	const t = type.replace(/\s*\*\s*$/, "").trim();
	if (t === "void") return { fmt: "", expr: "" };
	const spec = formatSpecForType(type);
	if (t === "BOOL" || t === "bool") return { fmt: "%@", expr: 'orig ? @"YES" : @"NO"' };
	if (t === "SEL") return { fmt: "%@", expr: "NSStringFromSelector(orig)" };
	if (t === "Class") return { fmt: "%@", expr: "NSStringFromClass(orig)" };
	if (t === "CGRect") return { fmt: "%@", expr: "NSStringFromCGRect(orig)" };
	if (t === "CGSize") return { fmt: "%@", expr: "NSStringFromCGSize(orig)" };
	if (t === "CGPoint") return { fmt: "%@", expr: "NSStringFromCGPoint(orig)" };
	return { fmt: spec, expr: "orig" };
}

/** Sanitize types that can't appear in hook code (e.g. "? *", unknown struct pointers) */
export function sanitizeTypeForHook(type: string): string {
	const t = type.trim();
	// "? *" or just "?" — unknown type pointer
	if (t === "?" || t === "? *") return "void *";
	// Unknown struct/class pointer types (contains non-ObjC chars) — use void *
	if (t.endsWith("*") && /[^a-zA-Z0-9_ *]/.test(t.replace(/\s*\*\s*$/, ""))) return "void *";
	return t;
}

// ── Logos hook generation ──

export function generateLogosHook(className: string, parsed: ParsedMethod): string {
	const prefix = parsed.isInstance ? "-" : "+";
	const retType = sanitizeTypeForHook(parsed.returnType);
	const isVoid = retType === "void";

	// Build method declaration with sanitized types
	let decl: string;
	if (parsed.parts.length === 0) {
		decl = `(${retType})${parsed.selector}`;
	} else {
		const argParts = parsed.parts.map(
			(p) => `${p.label}:(${sanitizeTypeForHook(p.type)})${p.argName}`
		);
		decl = `(${retType})${argParts.join(" ")}`;
	}

	// Build NSLog format string — interleave labels with format specifiers
	// Use sanitized types for format specifiers and arg expressions
	const argFmts = parsed.parts.map((p) => formatSpecForType(sanitizeTypeForHook(p.type)));
	const argExprs = parsed.parts.map((p) => argFormatExpr(p.argName, sanitizeTypeForHook(p.type)));

	// e.g. "-[Class initWithStyle:%lld reuseIdentifier:%@]"
	let logSelector: string;
	if (parsed.parts.length === 0) {
		logSelector = parsed.selector;
	} else {
		logSelector = parsed.parts.map((p, i) => `${p.label}:${argFmts[i]}`).join(" ");
	}
	const logMethod = `${prefix}[${className} ${logSelector}]`;

	const lines: string[] = [];
	lines.push(`%hook ${className}`);
	lines.push(`${prefix}${decl} {`);

	if (isVoid) {
		lines.push(`    %orig;`);
		if (parsed.parts.length > 0) {
			lines.push(`    NSLog(@"${logMethod}", ${argExprs.join(", ")});`);
		} else {
			lines.push(`    NSLog(@"${logMethod}");`);
		}
	} else {
		lines.push(`    ${retType} orig = %orig;`);
		const retFmt = returnFormatExpr(retType);
		if (parsed.parts.length > 0) {
			lines.push(
				`    NSLog(@"${logMethod} -> ${retFmt.fmt}", ${argExprs.join(", ")}, ${retFmt.expr});`
			);
		} else {
			lines.push(`    NSLog(@"${logMethod} -> ${retFmt.fmt}", ${retFmt.expr});`);
		}
		lines.push(`    return orig;`);
	}

	lines.push(`}`);
	lines.push(`%end`);

	return lines.join("\n");
}

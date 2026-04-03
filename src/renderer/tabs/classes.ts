/**
 * Classes tab: three-panel layout — class list, method list, method detail sidebar.
 */

import { SearchBar, EmptyState } from "../components";
import { saveSearchState, getSearchState, registerSearchBar } from "../search-state";

interface ObjCMethod {
  selector: string;
  signature: string;
}

interface ObjCClass {
  name: string;
  methods: ObjCMethod[];
}

interface ClassesData {
  classes: ObjCClass[];
  protocols: string[];
}

const ROW_HEIGHT = 28;
const BUFFER = 20;

// ── Method signature parsing helpers ──

interface ParsedMethod {
  isInstance: boolean;
  returnType: string;
  selector: string;
  parts: { label: string; type: string; argName: string }[];
}

function parseMethodSignature(sig: string): ParsedMethod | null {
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
  let match: RegExpExecArray | null;
  while ((match = regex.exec(rest)) !== null) {
    const label = match[1] || "";
    const type = match[2]?.trim() || "id";
    const argName = match[3] || `arg${parts.length}`;
    selectorParts.push(label + ":");
    parts.push({ label, type, argName });
  }

  return { isInstance, returnType, selector: selectorParts.join(""), parts };
}

function formatSpecForType(type: string): string {
  const t = type.replace(/\s*\*\s*$/, "").trim();
  if (t === "id" || t === "NSString" || t === "NSArray" || t === "NSDictionary" ||
      t === "NSNumber" || t === "NSData" || t === "NSError" || t === "NSObject" ||
      t === "NSURL" || t === "NSSet" || t === "NSDate" ||
      t.endsWith("*")) return "%@";
  if (t === "BOOL" || t === "bool") return "%@";
  if (t === "int" || t === "NSInteger" || t === "NSUInteger" ||
      t === "unsigned int" || t === "uint32_t" || t === "int32_t") return "%d";
  if (t === "long" || t === "unsigned long") return "%ld";
  if (t === "long long" || t === "unsigned long long" ||
      t === "int64_t" || t === "uint64_t") return "%lld";
  if (t === "float") return "%f";
  if (t === "double" || t === "CGFloat") return "%f";
  if (t === "char" || t === "unsigned char") return "%c";
  if (t === "SEL") return "%@";
  if (t === "Class") return "%@";
  if (t === "CGRect") return "%@";
  if (t === "CGSize") return "%@";
  if (t === "CGPoint") return "%@";
  if (t === "void") return "";
  return "%p"; // pointer fallback
}

function argFormatExpr(argName: string, type: string): string {
  const t = type.replace(/\s*\*\s*$/, "").trim();
  if (t === "BOOL" || t === "bool") return `${argName} ? @"YES" : @"NO"`;
  if (t === "SEL") return `NSStringFromSelector(${argName})`;
  if (t === "Class") return `NSStringFromClass(${argName})`;
  if (t === "CGRect") return `NSStringFromCGRect(${argName})`;
  if (t === "CGSize") return `NSStringFromCGSize(${argName})`;
  if (t === "CGPoint") return `NSStringFromCGPoint(${argName})`;
  return argName;
}

function returnFormatExpr(type: string): { fmt: string; expr: string } {
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

function generateLogosHook(className: string, parsed: ParsedMethod): string {
  const prefix = parsed.isInstance ? "-" : "+";
  const retType = parsed.returnType;
  const isVoid = retType === "void";

  // Build method declaration
  let decl: string;
  if (parsed.parts.length === 0) {
    decl = `(${retType})${parsed.selector}`;
  } else {
    const argParts = parsed.parts.map(
      (p) => `${p.label}:(${p.type})${p.argName}`
    );
    decl = `(${retType})${argParts.join(" ")}`;
  }

  // Build NSLog format string — interleave labels with format specifiers
  const argFmts = parsed.parts.map((p) => formatSpecForType(p.type));
  const argExprs = parsed.parts.map((p) => argFormatExpr(p.argName, p.type));

  // e.g. "-[Class initWithStyle:%lld reuseIdentifier:%@]"
  let logSelector: string;
  if (parsed.parts.length === 0) {
    logSelector = parsed.selector;
  } else {
    logSelector = parsed.parts.map((p, i) => `${p.label}:${argFmts[i]}`).join(" ");
  }
  const logMethod = `${prefix}[${className} ${logSelector}]`;

  let lines: string[] = [];
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
      lines.push(`    NSLog(@"${logMethod} -> ${retFmt.fmt}", ${argExprs.join(", ")}, ${retFmt.expr});`);
    } else {
      lines.push(`    NSLog(@"${logMethod} -> ${retFmt.fmt}", ${retFmt.expr});`);
    }
    lines.push(`    return orig;`);
  }

  lines.push(`}`);
  lines.push(`%end`);

  return lines.join("\n");
}

// ── Copy-to-clipboard helper with feedback ──

function copyWithFeedback(btn: HTMLButtonElement, text: string): void {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = "Copied!";
    btn.classList.add("cls-sb-btn--copied");
    setTimeout(() => {
      btn.textContent = orig;
      btn.classList.remove("cls-sb-btn--copied");
    }, 1200);
  });
}

// ── Main render ──

export function renderClasses(container: HTMLElement, data: any): void {
  container.innerHTML = "";

  const classesData = data as ClassesData | null;
  if (
    !classesData ||
    (!classesData.classes?.length && !classesData.protocols?.length)
  ) {
    const empty = new EmptyState({
      icon: "\u{1F3D7}",
      message: "No Objective-C classes found in this binary.",
    });
    empty.mount(container);
    return;
  }

  const allClasses = classesData.classes ?? [];
  const allProtocols = classesData.protocols ?? [];
  let filteredClasses = allClasses;
  let selectedClass: ObjCClass | null = null;
  let selectedMethod: ObjCMethod | null = null;

  // Stats bar
  const stats = document.createElement("div");
  stats.className = "cls-stats";
  const totalMethods = allClasses.reduce((s, c) => s + c.methods.length, 0);
  stats.textContent = `${allClasses.length.toLocaleString()} classes \u00B7 ${totalMethods.toLocaleString()} methods \u00B7 ${allProtocols.length.toLocaleString()} protocols`;
  container.appendChild(stats);

  // Three-panel layout wrapper
  const wrapper = document.createElement("div");
  wrapper.className = "cls-panels";
  container.appendChild(wrapper);

  // ── Left panel ──
  const leftPanel = document.createElement("div");
  leftPanel.className = "cls-left";
  wrapper.appendChild(leftPanel);

  // Search bar
  const searchBar = new SearchBar((term, isRegex) => {
    if (!term) {
      filteredClasses = allClasses;
    } else {
      try {
        const re = isRegex ? new RegExp(term, "i") : null;
        const lower = term.toLowerCase();
        filteredClasses = allClasses.filter((c) =>
          re ? re.test(c.name) : c.name.toLowerCase().includes(lower)
        );
      } catch {
        return;
      }
    }
    saveSearchState("classes", term, isRegex);
    searchBar.updateCount(filteredClasses.length, allClasses.length);
    renderList();
  });
  searchBar.mount(leftPanel);
  registerSearchBar("classes", searchBar);
  searchBar.updateCount(filteredClasses.length, allClasses.length);

  // Restore saved search state
  const savedState = getSearchState("classes");
  if (savedState && savedState.term) {
    searchBar.setValue(savedState.term, savedState.isRegex);
  }

  // Virtual scroll container for class list
  const scrollContainer = document.createElement("div");
  scrollContainer.className = "cls-scroll";
  leftPanel.appendChild(scrollContainer);

  const spacer = document.createElement("div");
  spacer.className = "cls-spacer";
  scrollContainer.appendChild(spacer);

  const rowContainer = document.createElement("div");
  rowContainer.className = "cls-rows";
  scrollContainer.appendChild(rowContainer);

  function renderList(): void {
    spacer.style.height = `${filteredClasses.length * ROW_HEIGHT}px`;
    renderVisibleRows();
  }

  function renderVisibleRows(): void {
    const scrollTop = scrollContainer.scrollTop;
    const viewportHeight = scrollContainer.clientHeight;
    const total = filteredClasses.length;

    const startIndex = Math.max(
      0,
      Math.floor(scrollTop / ROW_HEIGHT) - BUFFER
    );
    const visibleCount = Math.ceil(viewportHeight / ROW_HEIGHT);
    const endIndex = Math.min(total, startIndex + visibleCount + BUFFER * 2);

    rowContainer.style.transform = `translateY(${startIndex * ROW_HEIGHT}px)`;

    const fragment = document.createDocumentFragment();
    for (let i = startIndex; i < endIndex; i++) {
      const cls = filteredClasses[i];
      if (!cls) continue;
      const row = document.createElement("div");
      row.className = "cls-row";
      if (selectedClass && selectedClass.name === cls.name) {
        row.classList.add("cls-row-active");
      }
      row.style.height = `${ROW_HEIGHT}px`;
      row.textContent = cls.name;
      row.title = cls.name;
      row.addEventListener("click", () => {
        selectedClass = cls;
        selectedMethod = null;
        renderVisibleRows();
        renderDetail();
        renderSidebar();
      });
      fragment.appendChild(row);
    }
    rowContainer.innerHTML = "";
    rowContainer.appendChild(fragment);
  }

  let rafId = 0;
  scrollContainer.addEventListener(
    "scroll",
    () => {
      if (rafId) return;
      rafId = requestAnimationFrame(() => {
        rafId = 0;
        renderVisibleRows();
      });
    },
    { passive: true }
  );

  // Protocols collapsible section
  if (allProtocols.length > 0) {
    const protoSection = document.createElement("div");
    protoSection.className = "cls-proto-section";

    const protoHeader = document.createElement("button");
    protoHeader.className = "cls-proto-header";
    protoHeader.textContent = `\u25B6 Protocols (${allProtocols.length})`;
    let protoExpanded = false;

    const protoList = document.createElement("div");
    protoList.className = "cls-proto-list";
    protoList.style.display = "none";

    for (const p of allProtocols) {
      const item = document.createElement("div");
      item.className = "cls-proto-item";
      item.textContent = p;
      protoList.appendChild(item);
    }

    protoHeader.addEventListener("click", () => {
      protoExpanded = !protoExpanded;
      protoHeader.textContent = `${protoExpanded ? "\u25BC" : "\u25B6"} Protocols (${allProtocols.length})`;
      protoList.style.display = protoExpanded ? "block" : "none";
    });

    protoSection.appendChild(protoHeader);
    protoSection.appendChild(protoList);
    leftPanel.appendChild(protoSection);
  }

  // ── Middle panel (method list) ──
  const rightPanel = document.createElement("div");
  rightPanel.className = "cls-right";
  wrapper.appendChild(rightPanel);

  // ── Right sidebar (method detail) ──
  const sidebar = document.createElement("div");
  sidebar.className = "cls-sidebar";
  wrapper.appendChild(sidebar);

  function renderDetail(): void {
    rightPanel.innerHTML = "";
    if (!selectedClass) {
      const hint = document.createElement("div");
      hint.className = "cls-detail-hint";
      hint.textContent = "Select a class to view its methods";
      rightPanel.appendChild(hint);
      return;
    }

    const heading = document.createElement("h3");
    heading.className = "cls-detail-name";
    heading.textContent = selectedClass.name;
    rightPanel.appendChild(heading);

    const methodCount = document.createElement("div");
    methodCount.className = "cls-detail-count";
    methodCount.textContent = `${selectedClass.methods.length} method${selectedClass.methods.length !== 1 ? "s" : ""}`;
    rightPanel.appendChild(methodCount);

    if (selectedClass.methods.length === 0) {
      const noMethods = document.createElement("div");
      noMethods.className = "cls-detail-hint";
      noMethods.textContent = "No methods found for this class.";
      rightPanel.appendChild(noMethods);
      return;
    }

    const methodList = document.createElement("ul");
    methodList.className = "cls-method-list";
    const cls = selectedClass;
    for (const m of cls.methods) {
      const sig = typeof m === "string" ? m : m.signature;
      const li = document.createElement("li");
      li.className = "cls-method-item";
      if (selectedMethod && selectedMethod === m) {
        li.classList.add("cls-method-active");
      }
      li.textContent = sig;
      li.title = "Click to inspect";
      li.addEventListener("click", () => {
        selectedMethod = m;
        renderDetail();
        renderSidebar();
      });
      methodList.appendChild(li);
    }
    rightPanel.appendChild(methodList);
  }

  function renderSidebar(): void {
    sidebar.innerHTML = "";

    if (!selectedMethod || !selectedClass) {
      sidebar.classList.remove("cls-sidebar--open");
      return;
    }

    sidebar.classList.add("cls-sidebar--open");

    const inner = document.createElement("div");
    inner.className = "cls-sb-inner";
    sidebar.appendChild(inner);

    const sig = typeof selectedMethod === "string" ? selectedMethod : selectedMethod.signature;
    const className = selectedClass.name;
    const parsed = parseMethodSignature(sig);

    // Close button
    const closeBtn = document.createElement("button");
    closeBtn.className = "cls-sb-close";
    closeBtn.textContent = "\u00D7";
    closeBtn.title = "Close";
    closeBtn.addEventListener("click", () => {
      selectedMethod = null;
      sidebar.classList.remove("cls-sidebar--open");
      sidebar.innerHTML = "";
      renderDetail();
    });
    inner.appendChild(closeBtn);

    // Full method signature (wrapping)
    const sigBlock = document.createElement("div");
    sigBlock.className = "cls-sb-sig";
    sigBlock.textContent = sig;
    inner.appendChild(sigBlock);

    // Class name
    const classLabel = document.createElement("div");
    classLabel.className = "cls-sb-class";
    classLabel.textContent = className;
    inner.appendChild(classLabel);

    // ── Copy buttons section ──
    const actions = document.createElement("div");
    actions.className = "cls-sb-actions";
    inner.appendChild(actions);

    // Copy class name
    const copyClassBtn = document.createElement("button");
    copyClassBtn.className = "cls-sb-btn";
    copyClassBtn.textContent = "Copy Class Name";
    copyClassBtn.addEventListener("click", () => copyWithFeedback(copyClassBtn, className));
    actions.appendChild(copyClassBtn);

    if (parsed) {
      // Copy selector (e.g. "doA:withB:")
      const copySelectorBtn = document.createElement("button");
      copySelectorBtn.className = "cls-sb-btn";
      copySelectorBtn.textContent = "Copy Selector";
      copySelectorBtn.addEventListener("click", () =>
        copyWithFeedback(copySelectorBtn, parsed.selector)
      );
      actions.appendChild(copySelectorBtn);

      // Copy full signature
      const copySigBtn = document.createElement("button");
      copySigBtn.className = "cls-sb-btn";
      copySigBtn.textContent = "Copy Signature";
      copySigBtn.addEventListener("click", () => copyWithFeedback(copySigBtn, sig));
      actions.appendChild(copySigBtn);

      // ── Logos Hook section ──
      const hookSection = document.createElement("div");
      hookSection.className = "cls-sb-hook-section";
      inner.appendChild(hookSection);

      const hookLabel = document.createElement("div");
      hookLabel.className = "cls-sb-section-title";
      hookLabel.textContent = "Logos Hook";
      hookSection.appendChild(hookLabel);

      const hookCode = generateLogosHook(className, parsed);

      const codeBlock = document.createElement("pre");
      codeBlock.className = "cls-sb-code";
      codeBlock.textContent = hookCode;
      hookSection.appendChild(codeBlock);

      const copyHookBtn = document.createElement("button");
      copyHookBtn.className = "cls-sb-btn cls-sb-btn--accent";
      copyHookBtn.textContent = "Copy Logos Hook";
      copyHookBtn.addEventListener("click", () => copyWithFeedback(copyHookBtn, hookCode));
      hookSection.appendChild(copyHookBtn);
    } else {
      // Fallback: just copy the raw signature
      const copySigBtn = document.createElement("button");
      copySigBtn.className = "cls-sb-btn";
      copySigBtn.textContent = "Copy Signature";
      copySigBtn.addEventListener("click", () => copyWithFeedback(copySigBtn, sig));
      actions.appendChild(copySigBtn);
    }
  }

  // Initial render
  renderList();
  renderDetail();
  renderSidebar();
}

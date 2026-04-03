/**
 * Hooks tab: displays detected hook information for jailbreak tweaks.
 * Shows hook framework, target bundles, and hooked classes.
 */

import { EmptyState } from "../components";

interface HookInfo {
  frameworks: string[];
  targetBundles: string[];
  hookedClasses: string[];
  hookSymbols: string[];
}

export function renderHooks(container: HTMLElement, data: unknown): void {
  container.innerHTML = "";

  const hooks = data as HookInfo | null;

  if (
    !hooks ||
    (!hooks.frameworks?.length && !hooks.hookedClasses?.length)
  ) {
    const empty = new EmptyState({
      icon: "\u{1F517}",
      message: "No hooks detected in this binary.",
    });
    empty.mount(container);
    return;
  }

  const wrapper = document.createElement("div");
  wrapper.className = "hooks-tab";
  wrapper.style.cssText =
    "display:flex;flex-direction:column;height:100%;min-height:0;";

  // ── Summary bar ──
  const summary = document.createElement("div");
  summary.className = "hooks-summary";

  if (hooks.frameworks.length) {
    const chip = document.createElement("span");
    chip.className = "hooks-chip hooks-chip--framework";
    chip.textContent = hooks.frameworks.join(", ");
    summary.appendChild(chip);
  }

  if (hooks.targetBundles.length) {
    for (const bundle of hooks.targetBundles) {
      const chip = document.createElement("span");
      chip.className = "hooks-chip hooks-chip--bundle";
      chip.textContent = bundle;
      summary.appendChild(chip);
    }
  }

  if (hooks.hookedClasses.length) {
    const info = document.createElement("span");
    info.className = "hooks-stat";
    info.textContent = `${hooks.hookedClasses.length} hooked class${hooks.hookedClasses.length !== 1 ? "es" : ""}`;
    summary.appendChild(info);
  }

  wrapper.appendChild(summary);

  // ── Accuracy note ──
  const note = document.createElement("p");
  note.className = "hooks-note";
  note.textContent = "Hook details may be inaccurate. Accurate resolution requires disassembly.";
  wrapper.appendChild(note);

  // ── Hook symbols ──
  if (hooks.hookSymbols.length) {
    const section = document.createElement("div");
    section.className = "hooks-class-list";

    const title = document.createElement("h3");
    title.className = "hooks-section-title";
    title.textContent = "Hook Symbols";
    section.appendChild(title);

    const grid = document.createElement("div");
    grid.className = "hooks-class-grid";
    for (const sym of [...new Set(hooks.hookSymbols)]) {
      const tag = document.createElement("span");
      tag.className = "ov-hook-class-tag";
      tag.textContent = sym;
      grid.appendChild(tag);
    }
    section.appendChild(grid);
    wrapper.appendChild(section);
  }

  // ── Hooked classes ──
  if (hooks.hookedClasses.length) {
    const section = document.createElement("div");
    section.className = "hooks-class-list";

    const title = document.createElement("h3");
    title.className = "hooks-section-title";
    title.textContent = "Hooked Classes";
    section.appendChild(title);

    const grid = document.createElement("div");
    grid.className = "hooks-class-grid";
    for (const cls of hooks.hookedClasses) {
      const tag = document.createElement("span");
      tag.className = "ov-hook-class-tag";
      tag.textContent = cls;
      grid.appendChild(tag);
    }
    section.appendChild(grid);
    wrapper.appendChild(section);
  }

  container.appendChild(wrapper);
}

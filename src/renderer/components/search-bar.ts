/**
 * Search bar component with regex toggle and debounced input.
 */

export class SearchBar {
  private onFilter: (term: string, isRegex: boolean) => void;
  private container: HTMLElement | null = null;
  private root: HTMLElement | null = null;
  private input: HTMLInputElement | null = null;
  private regexBtn: HTMLButtonElement | null = null;
  private countEl: HTMLElement | null = null;
  private timerId: ReturnType<typeof setTimeout> | null = null;
  private regexMode = false;

  private static DEBOUNCE_MS = 200;

  constructor(onFilter: (term: string, isRegex: boolean) => void) {
    this.onFilter = onFilter;
  }

  mount(container: HTMLElement): void {
    this.container = container;

    const root = document.createElement("div");
    root.className = "sb-root";
    this.root = root;

    // Input wrapper
    const inputWrap = document.createElement("div");
    inputWrap.className = "sb-input-wrap";

    // Search icon
    const icon = document.createElement("span");
    icon.className = "sb-icon";
    icon.textContent = "\u{1F50D}";
    inputWrap.appendChild(icon);

    // Input
    const input = document.createElement("input");
    input.type = "text";
    input.className = "sb-input";
    input.placeholder = "Search\u2026";
    input.spellcheck = false;
    input.addEventListener("input", () => this.handleInput());
    this.input = input;
    inputWrap.appendChild(input);

    // Regex toggle
    const regexBtn = document.createElement("button");
    regexBtn.className = "sb-regex-btn";
    regexBtn.textContent = ".*";
    regexBtn.title = "Toggle regex mode";
    regexBtn.addEventListener("click", () => this.toggleRegex());
    this.regexBtn = regexBtn;
    inputWrap.appendChild(regexBtn);

    root.appendChild(inputWrap);

    // Count display
    const count = document.createElement("span");
    count.className = "sb-count";
    this.countEl = count;
    root.appendChild(count);

    container.appendChild(root);
  }

  private handleInput(): void {
    if (this.timerId !== null) clearTimeout(this.timerId);
    this.timerId = setTimeout(() => {
      this.timerId = null;
      this.emitFilter();
    }, SearchBar.DEBOUNCE_MS);
  }

  private toggleRegex(): void {
    this.regexMode = !this.regexMode;
    if (this.regexBtn) {
      this.regexBtn.classList.toggle("sb-regex-active", this.regexMode);
    }
    this.emitFilter();
  }

  private emitFilter(): void {
    const term = this.input?.value ?? "";

    // Validate regex if in regex mode
    if (this.regexMode && term) {
      try {
        new RegExp(term);
        this.input?.classList.remove("sb-invalid");
      } catch {
        this.input?.classList.add("sb-invalid");
        return; // Don't filter with invalid regex
      }
    } else {
      this.input?.classList.remove("sb-invalid");
    }

    this.onFilter(term, this.regexMode);
  }

  updateCount(shown: number, total: number): void {
    if (this.countEl) {
      this.countEl.textContent = `Showing ${shown.toLocaleString()} of ${total.toLocaleString()}`;
    }
  }

  getValue(): string {
    return this.input?.value ?? "";
  }

  isRegexMode(): boolean {
    return this.regexMode;
  }

  destroy(): void {
    if (this.timerId !== null) clearTimeout(this.timerId);
    if (this.root && this.container) {
      this.container.removeChild(this.root);
    }
    this.root = null;
    this.container = null;
    this.input = null;
    this.regexBtn = null;
    this.countEl = null;
  }
}

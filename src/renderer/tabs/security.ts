/**
 * Security Scan tab renderer.
 */

import { SearchBar } from "../components";
import { saveSearchState, getSearchState, registerSearchBar } from "../search-state";

// ── Types ──

interface SecurityFinding {
  severity: "critical" | "warning" | "info";
  category: string;
  message: string;
  evidence: string;
  location?: string;
  functionName?: string;
}

interface BinaryHardening {
  pie: boolean;
  arc: boolean;
  stackCanaries: boolean;
  encrypted: boolean;
  stripped: boolean;
}

interface SecurityData {
  findings: SecurityFinding[];
  hardening: BinaryHardening;
}

// ── Constants ──

const SEVERITY_ORDER: Record<string, number> = { critical: 0, warning: 1, info: 2 };

const SEVERITY_LABELS: Record<string, string> = {
  critical: "CRITICAL",
  warning: "WARNING",
  info: "INFO",
};

const HARDENING_LABELS: { key: keyof BinaryHardening; label: string }[] = [
  { key: "pie", label: "PIE" },
  { key: "arc", label: "ARC" },
  { key: "stackCanaries", label: "Stack Canaries" },
  { key: "encrypted", label: "Encryption" },
  { key: "stripped", label: "Stripped" },
];

const MAX_EVIDENCE_LEN = 200;

// ── Render ──

export function renderSecurity(container: HTMLElement, data: any): void {
  container.innerHTML = "";

  const sec: SecurityData = (data?.findings ? data : data?.security) ?? { findings: [], hardening: {} };
  const findings = sec.findings ?? [];
  const hardening = sec.hardening ?? ({} as BinaryHardening);

  // State
  const activeFilters = new Set<string>(["critical", "warning", "info"]);
  let searchTerm = "";
  let searchRegex = false;

  // ── Root wrapper ──
  const root = document.createElement("div");
  root.className = "sec-root";

  // ── Summary badges ──
  const summaryRow = document.createElement("div");
  summaryRow.className = "sec-summary";
  const counts = { critical: 0, warning: 0, info: 0 };
  for (const f of findings) {
    if (f.severity in counts) counts[f.severity as keyof typeof counts]++;
  }
  for (const sev of ["critical", "warning", "info"] as const) {
    const badge = document.createElement("span");
    badge.className = `sec-badge sec-badge--${sev}`;
    badge.textContent = `${counts[sev]} ${SEVERITY_LABELS[sev]}`;
    summaryRow.appendChild(badge);
  }
  root.appendChild(summaryRow);

  // ── Binary hardening section ──
  const hardeningSection = document.createElement("div");
  hardeningSection.className = "sec-hardening";

  const hardeningTitle = document.createElement("h3");
  hardeningTitle.className = "sec-section-title";
  hardeningTitle.textContent = "Binary Hardening";
  hardeningSection.appendChild(hardeningTitle);

  const hardeningGrid = document.createElement("div");
  hardeningGrid.className = "sec-hardening-grid";

  for (const { key, label } of HARDENING_LABELS) {
    const cell = document.createElement("div");
    cell.className = "sec-hardening-cell";

    const icon = document.createElement("span");
    const enabled = !!hardening[key];
    icon.className = `sec-hardening-icon ${enabled ? "sec-hardening-pass" : "sec-hardening-fail"}`;
    icon.textContent = enabled ? "\u2713" : "\u2717";

    const text = document.createElement("span");
    text.className = "sec-hardening-label";
    text.textContent = label;

    cell.appendChild(icon);
    cell.appendChild(text);
    hardeningGrid.appendChild(cell);
  }
  hardeningSection.appendChild(hardeningGrid);
  root.appendChild(hardeningSection);

  // ── Filter buttons ──
  const filterRow = document.createElement("div");
  filterRow.className = "sec-filters";

  const filterLabel = document.createElement("span");
  filterLabel.className = "sec-filter-label";
  filterLabel.textContent = "Filter:";
  filterRow.appendChild(filterLabel);

  const filterButtons: Record<string, HTMLButtonElement> = {};
  for (const sev of ["critical", "warning", "info"] as const) {
    const btn = document.createElement("button");
    btn.className = `sec-filter-btn sec-filter-btn--${sev} sec-filter-btn--active`;
    btn.textContent = SEVERITY_LABELS[sev];
    btn.addEventListener("click", () => {
      if (activeFilters.has(sev)) {
        activeFilters.delete(sev);
        btn.classList.remove("sec-filter-btn--active");
      } else {
        activeFilters.add(sev);
        btn.classList.add("sec-filter-btn--active");
      }
      renderFindings();
    });
    filterButtons[sev] = btn;
    filterRow.appendChild(btn);
  }
  root.appendChild(filterRow);

  // ── Search bar ──
  const searchWrap = document.createElement("div");
  searchWrap.className = "sec-search";
  const searchBar = new SearchBar((term, isRegex) => {
    searchTerm = term;
    searchRegex = isRegex;
    saveSearchState("security", term, isRegex);
    renderFindings();
  });
  root.appendChild(searchWrap);

  // ── Findings list ──
  const findingsList = document.createElement("div");
  findingsList.className = "sec-findings";
  root.appendChild(findingsList);

  container.appendChild(root);

  // Mount search bar after root is in the DOM
  searchBar.mount(searchWrap);
  registerSearchBar("security", searchBar);

  // Restore saved search state
  const savedState = getSearchState("security");
  if (savedState && savedState.term) {
    searchBar.setValue(savedState.term, savedState.isRegex);
  }

  // ── Filtering + rendering logic ──
  function getFilteredFindings(): SecurityFinding[] {
    let filtered = findings.filter((f) => activeFilters.has(f.severity));

    if (searchTerm) {
      if (searchRegex) {
        try {
          const re = new RegExp(searchTerm, "i");
          filtered = filtered.filter(
            (f) =>
              re.test(f.message) ||
              re.test(f.category) ||
              re.test(f.evidence) ||
              (f.location && re.test(f.location)) ||
              (f.functionName && re.test(f.functionName))
          );
        } catch {
          // Invalid regex, skip filtering
        }
      } else {
        const lower = searchTerm.toLowerCase();
        filtered = filtered.filter(
          (f) =>
            f.message.toLowerCase().includes(lower) ||
            f.category.toLowerCase().includes(lower) ||
            f.evidence.toLowerCase().includes(lower) ||
            (f.location && f.location.toLowerCase().includes(lower)) ||
            (f.functionName && f.functionName.toLowerCase().includes(lower))
        );
      }
    }

    // Sort: critical first, then warning, then info
    filtered.sort(
      (a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)
    );

    return filtered;
  }

  function renderFindings(): void {
    findingsList.innerHTML = "";
    const filtered = getFilteredFindings();
    searchBar.updateCount(filtered.length, findings.length);

    if (filtered.length === 0) {
      const empty = document.createElement("div");
      empty.className = "sec-no-findings";
      empty.textContent = findings.length === 0 ? "No security findings." : "No findings match the current filters.";
      findingsList.appendChild(empty);
      return;
    }

    for (const finding of filtered) {
      const card = document.createElement("div");
      card.className = "sec-finding-card";

      // Top row: severity badge + category
      const topRow = document.createElement("div");
      topRow.className = "sec-finding-top";

      const sevBadge = document.createElement("span");
      sevBadge.className = `sec-badge sec-badge--${finding.severity}`;
      sevBadge.textContent = SEVERITY_LABELS[finding.severity] ?? finding.severity;
      topRow.appendChild(sevBadge);

      const cat = document.createElement("span");
      cat.className = "sec-finding-category";
      cat.textContent = finding.category;
      topRow.appendChild(cat);

      card.appendChild(topRow);

      // Message
      const msg = document.createElement("div");
      msg.className = "sec-finding-message";
      msg.textContent = finding.message;
      card.appendChild(msg);

      // Evidence
      if (finding.evidence) {
        const evi = document.createElement("div");
        evi.className = "sec-finding-evidence";
        evi.textContent =
          finding.evidence.length > MAX_EVIDENCE_LEN
            ? finding.evidence.slice(0, MAX_EVIDENCE_LEN) + "\u2026"
            : finding.evidence;
        card.appendChild(evi);
      }

      // Function name
      if (finding.functionName) {
        const fn = document.createElement("div");
        fn.className = "sec-finding-function";
        const label = document.createElement("span");
        label.className = "sec-finding-function-label";
        label.textContent = "Referenced in: ";
        const name = document.createElement("code");
        name.className = "sec-finding-function-name";
        name.textContent = finding.functionName;
        fn.appendChild(label);
        fn.appendChild(name);
        card.appendChild(fn);
      }

      // Location
      if (finding.location) {
        const loc = document.createElement("div");
        loc.className = "sec-finding-location";
        loc.textContent = finding.location;
        card.appendChild(loc);
      }

      findingsList.appendChild(card);
    }
  }

  // Initial render
  renderFindings();
}

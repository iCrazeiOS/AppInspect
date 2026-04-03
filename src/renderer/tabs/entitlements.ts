/**
 * Entitlements tab: key-value display with dangerous entitlement highlighting.
 */

import { JsonTree, EmptyState } from "../components";

/** Entitlements that are flagged as dangerous (red). */
const RED_PATTERNS = [
  "com.apple.private.",
  "platform-application",
];

/** Entitlements that are flagged as warnings (orange). */
const ORANGE_KEYS = [
  "get-task-allow",
  "com.apple.security.cs.disable-library-validation",
];

type BadgeLevel = "red" | "orange" | null;

function classifyKey(key: string): BadgeLevel {
  for (const pat of RED_PATTERNS) {
    if (key === pat || key.startsWith(pat)) return "red";
  }
  for (const k of ORANGE_KEYS) {
    if (key === k) return "orange";
  }
  return null;
}

export function renderEntitlements(container: HTMLElement, data: any): void {
  container.innerHTML = "";

  // data may be { embedded: {...}, profile: {...} } or a flat object
  const embedded: Record<string, unknown> | null =
    data?.embedded ?? data?.entitlements ?? null;
  const profile: Record<string, unknown> | null = data?.profile ?? null;
  const flat: Record<string, unknown> | null =
    embedded ??
    (data && typeof data === "object" && !Array.isArray(data) ? data : null);

  if (!flat || Object.keys(flat).length === 0) {
    const empty = new EmptyState({
      icon: "\u{1F512}",
      message: "No entitlements found in this binary.",
    });
    empty.mount(container);
    return;
  }

  // Determine which sources are available
  const hasBothSources = embedded !== null && profile !== null;

  // Dangerous entitlements summary
  const allKeys = Object.keys(flat);
  const dangerousEntries: { key: string; level: BadgeLevel }[] = [];
  for (const key of allKeys) {
    const level = classifyKey(key);
    if (level) dangerousEntries.push({ key, level });
  }

  if (dangerousEntries.length > 0) {
    const dangerSection = document.createElement("div");
    dangerSection.className = "ent-danger-section";

    const dangerTitle = document.createElement("div");
    dangerTitle.className = "ent-danger-title";
    dangerTitle.textContent = "Flagged Entitlements";
    dangerSection.appendChild(dangerTitle);

    const badgeList = document.createElement("div");
    badgeList.className = "ent-badge-list";

    for (const entry of dangerousEntries) {
      const badge = document.createElement("span");
      badge.className = `ent-badge ent-badge-${entry.level}`;
      badge.textContent = entry.key;
      badge.title =
        entry.level === "red"
          ? "Private / dangerous entitlement"
          : "Potentially risky entitlement";
      badgeList.appendChild(badge);
    }

    dangerSection.appendChild(badgeList);
    container.appendChild(dangerSection);
  }

  // Source sections
  const renderSource = (
    label: string,
    obj: Record<string, unknown>
  ): void => {
    if (hasBothSources) {
      const sourceLabel = document.createElement("div");
      sourceLabel.className = "ent-source-label";
      sourceLabel.textContent = label;
      container.appendChild(sourceLabel);
    }

    const treeContainer = document.createElement("div");
    treeContainer.className = "ent-tree";
    container.appendChild(treeContainer);

    const tree = new JsonTree();
    tree.mount(treeContainer);
    tree.setData(obj);
  };

  if (hasBothSources) {
    renderSource("Embedded (Code Signature)", embedded!);
    renderSource("Provisioning Profile", profile!);
  } else {
    renderSource("Entitlements", flat);
  }
}

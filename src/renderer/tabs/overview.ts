/**
 * Overview tab renderer — app summary, binary hardening, provisioning.
 */

import type { AnalysisResult } from "../../shared/types";
import { EmptyState } from "../components";
import { el } from "../utils/dom";
import { decodeCpuType, decodeFileType } from "../utils/macho";

type OverviewData = AnalysisResult["overview"];

// ── Card builders ──

function buildKV(label: string, value: string, extraClass?: string): HTMLElement {
  const row = el("div", "ov-kv");
  row.appendChild(el("span", "ov-kv-label", label));
  const valEl = el("span", extraClass ? `ov-kv-value ${extraClass}` : "ov-kv-value", value);
  row.appendChild(valEl);
  return row;
}

function buildBadge(text: string, variant: "green" | "red" | "yellow"): HTMLElement {
  return el("span", `ov-badge ov-badge--${variant}`, text);
}

function buildHardeningRow(label: string, enabled: boolean): HTMLElement {
  const row = el("div", "ov-hardening-row");
  const indicator = el("span", enabled ? "ov-check ov-check--pass" : "ov-check ov-check--fail");
  indicator.textContent = enabled ? "\u2713" : "\u2717";
  row.appendChild(indicator);
  row.appendChild(el("span", "ov-hardening-label", label));
  return row;
}

function buildCard(title: string, ...children: HTMLElement[]): HTMLElement {
  const card = el("div", "ov-card");
  card.appendChild(el("h3", "ov-card-title", title));
  const body = el("div", "ov-card-body");
  for (const child of children) body.appendChild(child);
  card.appendChild(body);
  return card;
}

// ── Main render ──

export function renderOverview(container: HTMLElement, data: OverviewData | null): void {
  container.innerHTML = "";

  if (!data) {
    const empty = new EmptyState({
      icon: "\u{1F4CA}",
      message: "No overview data available.",
    });
    empty.mount(container);
    return;
  }

  const wrapper = el("div", "ov-grid");

  // ── Summary card (adapts to source type) ──
  const sourceType = (data as any).sourceType ?? "ipa";
  const { header, buildVersion, encryptionInfo, hardening, ipa } = data;

  const infoPlist = (data as any).infoPlist as Record<string, any> | undefined;
  const minIOS = buildVersion?.minos ?? "N/A";
  const arch = decodeCpuType(header.cputype);
  const fileType = decodeFileType(header.filetype);

  const encrypted = encryptionInfo ? encryptionInfo.cryptid !== 0 : false;
  const encBadge = encrypted
    ? buildBadge("Encrypted", "red")
    : buildBadge("Not Encrypted", "green");

  const teamId = (data as any).teamId ?? "N/A";
  const uuid = (data as any).uuid ?? "N/A";

  if (sourceType === "deb") {
    // ── DEB Package Info card ──
    const debControl = (data as any).debControl as Record<string, any> | undefined;
    const debItems: HTMLElement[] = [];
    if (debControl) {
      debItems.push(buildKV("Package", String(debControl.package || "N/A")));
      debItems.push(buildKV("Name", String(debControl.name || "N/A")));
      debItems.push(buildKV("Version", String(debControl.version || "N/A")));
      debItems.push(buildKV("Architecture", String(debControl.architecture || "N/A")));
      if (debControl.author) debItems.push(buildKV("Author", String(debControl.author)));
      if (debControl.maintainer) debItems.push(buildKV("Maintainer", String(debControl.maintainer)));
      if (debControl.section) debItems.push(buildKV("Section", String(debControl.section)));
      if (debControl.depends) debItems.push(buildKV("Depends", String(debControl.depends)));
      if (debControl.description) {
        const descRow = el("div", "ov-kv");
        descRow.appendChild(el("span", "ov-kv-label", "Description"));
        descRow.appendChild(el("span", "ov-kv-value", String(debControl.description)));
        debItems.push(descRow);
      }
      if (debControl.installedSize) {
        const kb = Number(debControl.installedSize);
        const sizeStr = kb >= 1024 ? `${(kb / 1024).toFixed(1)} MB` : `${kb} KB`;
        debItems.push(buildKV("Installed Size", sizeStr));
      }
    }
    wrapper.appendChild(buildCard("Package Info", ...debItems));
  } else if (sourceType === "macho") {
    // ── Bare Mach-O Binary Info card ──
    const filePath = (data as any).filePath ?? "N/A";
    const fileName = filePath.split(/[\\/]/).pop() ?? "N/A";
    const binarySize = ipa?.binaries?.[0]?.size;

    const machoItems: HTMLElement[] = [
      buildKV("File Name", fileName),
      buildKV("Architecture", arch),
      buildKV("File Type", fileType),
      buildKV("UUID", String(uuid)),
    ];
    if (binarySize != null) {
      const sizeStr = binarySize > 1024 * 1024
        ? `${(binarySize / (1024 * 1024)).toFixed(1)} MB`
        : `${(binarySize / 1024).toFixed(1)} KB`;
      machoItems.push(buildKV("File Size", sizeStr));
    }
    machoItems.push(buildKV("Min iOS", minIOS));
    machoItems.push(buildKV("Team ID", String(teamId)));
    wrapper.appendChild(buildCard("Binary Info", ...machoItems));
  } else {
    // ── IPA App Summary card (existing) ──
    const bundleId = infoPlist?.["CFBundleIdentifier"] ?? "N/A";
    const displayName =
      infoPlist?.["CFBundleDisplayName"] ?? infoPlist?.["CFBundleName"] ?? ipa?.appName ?? "N/A";
    const version = infoPlist?.["CFBundleShortVersionString"] ?? "N/A";
    const buildNumber = infoPlist?.["CFBundleVersion"] ?? "N/A";

    const summaryItems: HTMLElement[] = [
      buildKV("Bundle ID", String(bundleId)),
      buildKV("Display Name", String(displayName)),
      buildKV("Version", String(version)),
      buildKV("Build", String(buildNumber)),
      buildKV("Min iOS", String(minIOS)),
      buildKV("Architecture", arch),
      buildKV("File Type", fileType),
      buildKV("UUID", String(uuid)),
    ];

    // Encryption row with badge
    const encRow = el("div", "ov-kv");
    encRow.appendChild(el("span", "ov-kv-label", "Encryption"));
    encRow.appendChild(encBadge);
    summaryItems.push(encRow);

    summaryItems.push(buildKV("Team ID", String(teamId)));

    wrapper.appendChild(buildCard("App Summary", ...summaryItems));
  }

  // ── Binary Details card (for DEB/Mach-O — show architecture/header info) ──
  if (sourceType === "deb") {
    const binDetails: HTMLElement[] = [
      buildKV("Architecture", arch),
      buildKV("File Type", fileType),
      buildKV("UUID", String(uuid)),
      buildKV("Min iOS", minIOS),
      buildKV("Team ID", String(teamId)),
    ];

    // Encryption row
    const encRow = el("div", "ov-kv");
    encRow.appendChild(el("span", "ov-kv-label", "Encryption"));
    encRow.appendChild(encBadge);
    binDetails.push(encRow);

    wrapper.appendChild(buildCard("Binary Details", ...binDetails));
  }

  // ── Binary Hardening card ──
  const hardeningItems = [
    buildHardeningRow("PIE (Position Independent)", hardening.pie),
    buildHardeningRow("ARC (Automatic Reference Counting)", hardening.arc),
    buildHardeningRow("Stack Canaries", hardening.stackCanaries),
    buildHardeningRow("Stripped", hardening.stripped),
  ];
  wrapper.appendChild(buildCard("Binary Hardening", ...hardeningItems));

  // ── Hooks summary (compact — full detail in Hooks tab) ──
  const hooks = (data as any).hooks as {
    frameworks?: string[];
    targetBundles?: string[];
    hookedClasses?: string[];
  } | undefined;

  if (hooks && (hooks.frameworks?.length || hooks.hookedClasses?.length || hooks.targetBundles?.length)) {
    const hookItems: HTMLElement[] = [];

    if (hooks.frameworks?.length) {
      hookItems.push(buildKV("Hook Framework", hooks.frameworks.join(", ")));
    }

    if (hooks.targetBundles?.length) {
      hookItems.push(buildKV("Target Bundles", hooks.targetBundles.join(", ")));
    }

    if (hooks.hookedClasses?.length) {
      hookItems.push(buildKV("Hooked Classes", String(hooks.hookedClasses.length)));
    }

    wrapper.appendChild(buildCard("Hooks", ...hookItems));
  }

  // ── Provisioning Profile card (if available) ──
  const profile = (data as any).provisioningProfile as Record<string, any> | undefined;
  if (profile) {
    const provItems: HTMLElement[] = [];
    if (profile.teamName) provItems.push(buildKV("Team Name", String(profile.teamName)));
    if (profile.expirationDate)
      provItems.push(buildKV("Expiration", String(profile.expirationDate)));
    if (profile.deviceCount != null)
      provItems.push(buildKV("Device Count", String(profile.deviceCount)));
    if (profile.devices)
      provItems.push(buildKV("Device Count", String(profile.devices.length)));
    if (provItems.length > 0) {
      wrapper.appendChild(buildCard("Provisioning Profile", ...provItems));
    }
  }

  container.appendChild(wrapper);
}

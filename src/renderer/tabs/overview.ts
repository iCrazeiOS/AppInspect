/**
 * Overview tab renderer — app summary, binary hardening, provisioning.
 */

import type { AnalysisResult } from "../../shared/types";
import { EmptyState } from "../components";

type OverviewData = AnalysisResult["overview"];

// ── Helpers ──

const CPU_TYPE_NAMES: Record<number, string> = {
  7: "x86",
  12: "ARM",
  16777223: "x86_64",
  16777228: "ARM64",
};

const FILE_TYPE_NAMES: Record<number, string> = {
  1: "MH_OBJECT",
  2: "MH_EXECUTE",
  6: "MH_DYLIB",
  8: "MH_BUNDLE",
};

function decodeCpuType(cputype: number): string {
  return CPU_TYPE_NAMES[cputype] ?? `Unknown (${cputype})`;
}

function decodeFileType(filetype: number): string {
  return FILE_TYPE_NAMES[filetype] ?? `Unknown (${filetype})`;
}

function hexStr(n: number): string {
  return "0x" + n.toString(16).toUpperCase().padStart(8, "0");
}

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (className) e.className = className;
  if (text !== undefined) e.textContent = text;
  return e;
}

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

  // ── App Summary card ──
  const { header, buildVersion, encryptionInfo, hardening, ipa } = data;

  const infoPlist = (data as any).infoPlist as Record<string, any> | undefined;
  const bundleId = infoPlist?.["CFBundleIdentifier"] ?? "N/A";
  const displayName =
    infoPlist?.["CFBundleDisplayName"] ?? infoPlist?.["CFBundleName"] ?? ipa?.appName ?? "N/A";
  const version = infoPlist?.["CFBundleShortVersionString"] ?? "N/A";
  const buildNumber = infoPlist?.["CFBundleVersion"] ?? "N/A";
  const minIOS = buildVersion?.minos ?? "N/A";
  const arch = decodeCpuType(header.cputype);
  const fileType = decodeFileType(header.filetype);

  const encrypted = encryptionInfo ? encryptionInfo.cryptid !== 0 : false;
  const encBadge = encrypted
    ? buildBadge("Encrypted", "red")
    : buildBadge("Not Encrypted", "green");

  const teamId = (data as any).teamId ?? "N/A";

  const summaryItems: HTMLElement[] = [
    buildKV("Bundle ID", String(bundleId)),
    buildKV("Display Name", String(displayName)),
    buildKV("Version", String(version)),
    buildKV("Build", String(buildNumber)),
    buildKV("Min iOS", String(minIOS)),
    buildKV("Architecture", arch),
    buildKV("File Type", fileType),
    buildKV("UUID", String((data as any).uuid ?? "N/A")),
  ];

  // Encryption row with badge
  const encRow = el("div", "ov-kv");
  encRow.appendChild(el("span", "ov-kv-label", "Encryption"));
  encRow.appendChild(encBadge);
  summaryItems.push(encRow);

  summaryItems.push(buildKV("Team ID", String(teamId)));

  wrapper.appendChild(buildCard("App Summary", ...summaryItems));

  // ── Binary Hardening card ──
  const hardeningItems = [
    buildHardeningRow("PIE (Position Independent)", hardening.pie),
    buildHardeningRow("ARC (Automatic Reference Counting)", hardening.arc),
    buildHardeningRow("Stack Canaries", hardening.stackCanaries),
    buildHardeningRow("Stripped", hardening.stripped),
  ];
  wrapper.appendChild(buildCard("Binary Hardening", ...hardeningItems));

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

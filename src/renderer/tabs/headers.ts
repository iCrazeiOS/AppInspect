/**
 * Headers tab renderer — Mach-O header summary, load commands table, segments tree.
 */

import type { MachOHeader, LoadCommand, Segment, Section } from "../../shared/types";
import type { AnalysisResult } from "../../shared/types";
import { EmptyState } from "../components";
import { el } from "../utils/dom";
import { decodeCpuType, decodeFileType, hexStr, cpuSubtypeName } from "../utils/macho";
import { decodeLCName } from "../../shared/macho";

type HeadersData = AnalysisResult["headers"];

const MH_FLAGS: Record<number, string> = {
  0x1: "MH_NOUNDEFS",
  0x2: "MH_INCRLINK",
  0x4: "MH_DYLDLINK",
  0x8: "MH_BINDATLOAD",
  0x10: "MH_PREBOUND",
  0x20: "MH_SPLIT_SEGS",
  0x80: "MH_TWOLEVEL",
  0x100: "MH_FORCE_FLAT",
  0x200: "MH_NOMULTIDEFS",
  0x400: "MH_NOFIXPREBINDING",
  0x800: "MH_PREBINDABLE",
  0x1000: "MH_ALLMODSBOUND",
  0x2000: "MH_SUBSECTIONS_VIA_SYMBOLS",
  0x4000: "MH_CANONICAL",
  0x8000: "MH_WEAK_DEFINES",
  0x10000: "MH_BINDS_TO_WEAK",
  0x20000: "MH_ALLOW_STACK_EXECUTION",
  0x40000: "MH_ROOT_SAFE",
  0x80000: "MH_SETUID_SAFE",
  0x100000: "MH_NO_REEXPORTED_DYLIBS",
  0x200000: "MH_PIE",
  0x400000: "MH_DEAD_STRIPPABLE_DYLIB",
  0x800000: "MH_HAS_TLV_DESCRIPTORS",
  0x1000000: "MH_NO_HEAP_EXECUTION",
  0x2000000: "MH_APP_EXTENSION_SAFE",
};

function decodeCpuSubtype(cputype: number, cpusubtype: number): string {
  const sub = cpusubtype & 0x00ffffff;
  const name = cpuSubtypeName(cputype, cpusubtype);
  if (name) return name;
  if (sub === 0) return "ALL";
  if ((cputype === 7 || cputype === 0x01000007) && sub === 3) return "ALL";
  return String(sub);
}

function decodeFlags(flags: number): string[] {
  const result: string[] = [];
  for (const [bit, name] of Object.entries(MH_FLAGS)) {
    if (flags & Number(bit)) result.push(name);
  }
  return result.length > 0 ? result : [`0x${flags.toString(16)}`];
}

function humanSize(bytes: number | bigint | string): string {
  const n = typeof bytes === "string" ? Number(bytes) : Number(bytes);
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

function permStr(prot: number): string {
  const r = prot & 1 ? "r" : "-";
  const w = prot & 2 ? "w" : "-";
  const x = prot & 4 ? "x" : "-";
  return r + w + x;
}

// ── Render helpers ──

function buildSummaryRow(label: string, value: string): HTMLElement {
  const row = el("div", "hdr-kv");
  row.appendChild(el("span", "hdr-kv-label", label));
  row.appendChild(el("span", "hdr-kv-value", value));
  return row;
}

function buildFlagsList(flags: string[]): HTMLElement {
  const wrap = el("div", "hdr-flags");
  for (const f of flags) {
    wrap.appendChild(el("span", "hdr-flag-tag", f));
  }
  return wrap;
}

// ── Load command detail extraction ──

function lcDetail(lc: LoadCommand): string {
  switch (lc.type) {
    case "segment":
      return lc.segment.name;
    case "dylib":
      return lc.library.name;
    case "symtab":
      return `${lc.symtab.nsyms} symbols`;
    case "encryption_info":
      return `cryptid=${lc.encryption.cryptid}`;
    case "build_version":
      return `minos=${lc.buildVersion.minos} sdk=${lc.buildVersion.sdk}`;
    case "uuid":
      return lc.uuid;
    case "main":
      return `entry=0x${lc.entryoff.toString(16)}`;
    case "rpath":
      return lc.path;
    case "source_version":
      return lc.version;
    case "dyld_info":
      return `exports=${lc.exportSize}B bind=${lc.bindSize}B`;
    case "id_dylib":
      return `${lc.name} (${lc.currentVersion})`;
    case "generic":
      return "";
  }
}

// ── Segments tree ──

function buildSegmentTree(loadCommands: LoadCommand[]): HTMLElement {
  const tree = el("div", "hdr-seg-tree");

  const segments = loadCommands.filter(
    (lc): lc is Extract<LoadCommand, { type: "segment" }> => lc.type === "segment",
  );

  if (segments.length === 0) {
    tree.appendChild(el("div", "hdr-seg-empty", "No segments found."));
    return tree;
  }

  for (const seg of segments) {
    const s = seg.segment;
    const segNode = el("div", "hdr-seg-node");

    const segHeader = el("div", "hdr-seg-header");
    const toggle = el("span", "hdr-seg-toggle", "\u25B6");
    segHeader.appendChild(toggle);
    segHeader.appendChild(el("span", "hdr-seg-name", s.name || "(unnamed)"));
    segHeader.appendChild(
      el("span", "hdr-seg-meta", `${humanSize(s.filesize)} | offset ${hexStr(s.fileoff)} | ${permStr(s.initprot)}`),
    );
    segNode.appendChild(segHeader);

    const sectionsWrap = el("div", "hdr-seg-sections hidden");
    if (s.sections && s.sections.length > 0) {
      for (const sec of s.sections) {
        const secRow = el("div", "hdr-sec-row");
        secRow.appendChild(el("span", "hdr-sec-name", `${sec.segname},${sec.sectname}`));
        const sizeVal = typeof sec.size === "string" ? Number(sec.size) : Number(sec.size);
        secRow.appendChild(el("span", "hdr-sec-detail", `${humanSize(sizeVal)} | offset ${hexStr(sec.offset)}`));
        sectionsWrap.appendChild(secRow);
      }
    } else {
      sectionsWrap.appendChild(el("div", "hdr-sec-empty", "No sections"));
    }
    segNode.appendChild(sectionsWrap);

    // Toggle expand/collapse
    segHeader.addEventListener("click", () => {
      const isHidden = sectionsWrap.classList.contains("hidden");
      sectionsWrap.classList.toggle("hidden", !isHidden);
      toggle.textContent = isHidden ? "\u25BC" : "\u25B6";
    });
    segHeader.style.cursor = "pointer";

    tree.appendChild(segNode);
  }

  return tree;
}

// ── Main render ──

export function renderHeaders(container: HTMLElement, data: HeadersData | null): void {
  container.innerHTML = "";

  if (!data) {
    const empty = new EmptyState({
      icon: "\u{1F4D1}",
      message: "No header data available.",
    });
    empty.mount(container);
    return;
  }

  const wrapper = el("div", "hdr-wrapper");

  // ── Mach-O Header Summary ──
  const summaryCard = el("div", "hdr-card");
  summaryCard.appendChild(el("h3", "hdr-card-title", "Mach-O Header"));
  const summaryBody = el("div", "hdr-card-body");

  const hdr = data.machO;
  summaryBody.appendChild(buildSummaryRow("Magic", hexStr(hdr.magic)));
  summaryBody.appendChild(buildSummaryRow("CPU Type", decodeCpuType(hdr.cputype)));
  summaryBody.appendChild(buildSummaryRow("CPU Subtype", decodeCpuSubtype(hdr.cputype, hdr.cpusubtype)));
  summaryBody.appendChild(buildSummaryRow("File Type", decodeFileType(hdr.filetype)));
  summaryBody.appendChild(buildSummaryRow("Load Commands", String(hdr.ncmds)));
  summaryBody.appendChild(buildSummaryRow("Size of Commands", `${hdr.sizeofcmds} bytes`));

  // Flags
  const flagsRow = el("div", "hdr-kv");
  flagsRow.appendChild(el("span", "hdr-kv-label", "Flags"));
  flagsRow.appendChild(buildFlagsList(decodeFlags(hdr.flags)));
  summaryBody.appendChild(flagsRow);

  summaryCard.appendChild(summaryBody);
  wrapper.appendChild(summaryCard);

  // ── Load Commands table ──
  const lcCard = el("div", "hdr-card");
  lcCard.appendChild(el("h3", "hdr-card-title", `Load Commands (${data.loadCommands.length})`));

  const lcTable = el("table", "hdr-lc-table");
  const thead = el("thead");
  const trHead = el("tr");
  for (const hd of ["Type", "Size", "Details"]) {
    trHead.appendChild(el("th", "hdr-lc-th", hd));
  }
  thead.appendChild(trHead);
  lcTable.appendChild(thead);

  const tbody = el("tbody");
  for (const lc of data.loadCommands) {
    const tr = el("tr", "hdr-lc-row");
    tr.appendChild(el("td", "hdr-lc-td", decodeLCName(lc.cmd)));
    tr.appendChild(el("td", "hdr-lc-td", `${lc.cmdsize} B`));
    tr.appendChild(el("td", "hdr-lc-td hdr-lc-detail", lcDetail(lc)));
    tbody.appendChild(tr);
  }
  lcTable.appendChild(tbody);
  lcCard.appendChild(lcTable);
  wrapper.appendChild(lcCard);

  // ── Segments / Sections tree ──
  const segCard = el("div", "hdr-card");
  segCard.appendChild(el("h3", "hdr-card-title", "Segments & Sections"));
  segCard.appendChild(buildSegmentTree(data.loadCommands));
  wrapper.appendChild(segCard);

  container.appendChild(wrapper);
}

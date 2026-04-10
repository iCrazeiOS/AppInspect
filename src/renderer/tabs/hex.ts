/**
 * Hex tab renderer — segment/section selector with hex + ASCII dump viewer.
 */

import type { LoadCommand } from "../../shared/types";
import type { HexRegion } from "../components/hex-viewer";
import { EmptyState, HexViewer } from "../components";
import { el } from "../utils/dom";
import { registerSearchBar } from "../search-state";

interface HexTabData {
  loadCommands: LoadCommand[];
}

interface Region {
  label: string;
  offset: number;
  size: number;
  /** Named sub-regions for scroll position indicator (segments for whole-binary view) */
  regions?: HexRegion[];
}

let activeHexViewer: HexViewer | null = null;

// Mach-O section types with no file backing (offset=0 is meaningless)
const S_ZEROFILL = 0x01;
const S_GB_ZEROFILL = 0x0c;
const S_THREAD_LOCAL_ZEROFILL = 0x12;

function isZerofillSection(flags: number): boolean {
  const sectionType = flags & 0xff;
  return sectionType === S_ZEROFILL || sectionType === S_GB_ZEROFILL || sectionType === S_THREAD_LOCAL_ZEROFILL;
}


function buildRegions(loadCommands: LoadCommand[]): Region[] {
  const regions: Region[] = [];
  const segments = loadCommands.filter(
    (lc): lc is Extract<LoadCommand, { type: "segment" }> => lc.type === "segment",
  );

  // Compute whole-binary size from the furthest segment end
  let binaryEnd = 0;
  // Sections first so more-specific matches win in the linear scan
  const subRegions: HexRegion[] = [];
  for (const seg of segments) {
    const s = seg.segment;
    const end = s.fileoff + s.filesize;
    if (end > binaryEnd) binaryEnd = end;
    if (s.sections) {
      for (const sec of s.sections) {
        if (isZerofillSection(sec.flags)) continue;
        const size = Number(sec.size);
        if (size > 0) {
          subRegions.push({ label: `${sec.segname},${sec.sectname}`, offset: sec.offset, size });
        }
      }
    }
  }
  // Segments after sections — used as fallback for gaps between sections
  for (const seg of segments) {
    const s = seg.segment;
    if (s.filesize > 0) {
      subRegions.push({ label: s.name || "(unnamed)", offset: s.fileoff, size: s.filesize });
    }
  }
  if (binaryEnd > 0) {
    regions.push({ label: "Whole Binary", offset: 0, size: binaryEnd, regions: subRegions });
  }

  const entries: Region[] = [];
  for (const seg of segments) {
    const s = seg.segment;
    if (s.filesize > 0) {
      entries.push({ label: s.name || "(unnamed segment)", offset: s.fileoff, size: s.filesize });
    }
    if (s.sections) {
      for (const sec of s.sections) {
        if (isZerofillSection(sec.flags)) continue;
        const size = Number(sec.size);
        if (size > 0) {
          entries.push({ label: `${sec.segname},${sec.sectname}`, offset: sec.offset, size });
        }
      }
    }
  }
  entries.sort((a, b) => a.offset - b.offset);
  regions.push(...entries);
  return regions;
}

export function renderHex(container: HTMLElement, data: HexTabData | null, sessionId: string): void {
  container.innerHTML = "";

  if (activeHexViewer) {
    activeHexViewer.unmount();
    activeHexViewer = null;
  }

  if (!data || !data.loadCommands || data.loadCommands.length === 0) {
    const empty = new EmptyState({
      icon: "\u{1F50D}",
      message: "No segments available for hex viewing.",
    });
    empty.mount(container);
    return;
  }

  const regions = buildRegions(data.loadCommands);
  if (regions.length === 0) {
    const empty = new EmptyState({
      icon: "\u{1F50D}",
      message: "No segments or sections with data found.",
    });
    empty.mount(container);
    return;
  }

  const wrapper = el("div", "hex-tab-wrapper");

  // ── Hex viewer mount ──
  const viewerMount = el("div", "hex-tab-viewer");
  wrapper.appendChild(viewerMount);

  container.appendChild(wrapper);

  // Flat list for the dropdown picker
  const pickerRegions = regions.map((r) => ({ label: r.label, offset: r.offset, size: r.size }));

  // ── Open viewer for selected region ──
  function openRegion(index: number): void {
    const region = regions[index];
    if (!region) return;

    if (activeHexViewer) {
      activeHexViewer.unmount();
      activeHexViewer = null;
    }

    activeHexViewer = new HexViewer({
      sessionId,
      regionOffset: region.offset,
      regionSize: region.size,
      label: region.label.trim(),
      regions: region.regions,
      allRegions: pickerRegions,
      currentRegionIndex: index,
      onRegionChange: openRegion,
      onClose: () => {
        activeHexViewer = null;
        viewerMount.innerHTML = "";
      },
    });
    activeHexViewer.mount(viewerMount);
    registerSearchBar(sessionId, "hex", { focus: () => activeHexViewer?.focusSearch() });
  }

  // Auto-open first region
  openRegion(0);
}

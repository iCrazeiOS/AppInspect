/**
 * Library dependency graph — force-directed SVG visualization.
 * Rendered inline within the Libraries tab via a list/graph toggle.
 *
 * Uses a force simulation with collision detection that accounts for
 * label width, producing an organic, readable layout.
 */

import type { LibraryGraphData, LibraryGraphNode, LibraryGraphEdge } from "../../shared/types";
import { el } from "../utils/dom";

// ── Internal layout node ──

interface LayoutNode extends LibraryGraphNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  /** Half-width of the space this node occupies (max of radius and label half-width) */
  halfW: number;
  /** Half-height of the space this node occupies (radius + label) */
  halfH: number;
}

// ── SVG namespace ──

const SVG_NS = "http://www.w3.org/2000/svg";

// ── Helpers ──

const NODE_RADIUS: Record<string, number> = {
  "binary:main": 24,
  "binary:framework": 18,
  "binary:extension": 18,
  "binary:tweak": 18,
  "library:system": 10,
  "library:swift": 10,
  "library:embedded": 14,
};

function nodeRadius(n: LibraryGraphNode): number {
  const key = n.type === "binary"
    ? `binary:${n.binaryType ?? "main"}`
    : `library:${n.category ?? "system"}`;
  return NODE_RADIUS[key] ?? 10;
}

function nodeClass(n: LibraryGraphNode): string {
  if (n.type === "binary") return `gr-node--binary-${n.binaryType ?? "main"}`;
  return `gr-node--${n.category ?? "system"}`;
}

// Colors matching CSS for gradient stops
const NODE_COLOR: Record<string, string> = {
  "binary:main": "#58a6ff",
  "binary:framework": "#8b5cf6",
  "binary:extension": "#8b5cf6",
  "binary:tweak": "#e05d44",
  "library:system": "#2b5ea7",
  "library:swift": "#d29922",
  "library:embedded": "#238636",
};

function nodeColor(n: LibraryGraphNode): string {
  const key = n.type === "binary"
    ? `binary:${n.binaryType ?? "main"}`
    : `library:${n.category ?? "system"}`;
  return NODE_COLOR[key] ?? "#1f6feb";
}

const LABEL_CHAR_WIDTH = 6;
const LABEL_HEIGHT = 14;

function nodeHalfW(label: string, radius: number): number {
  return Math.max(radius, (label.length * LABEL_CHAR_WIDTH) / 2);
}

function nodeHalfH(radius: number): number {
  return radius + LABEL_HEIGHT;
}

// ── Build layout nodes ──

function buildLayoutNodes(data: LibraryGraphData): LayoutNode[] {
  const nodes: LayoutNode[] = [];

  // Count edges per node to determine placement weight
  const edgeCount = new Map<string, number>();
  for (const e of data.edges) {
    edgeCount.set(e.source, (edgeCount.get(e.source) ?? 0) + 1);
    edgeCount.set(e.target, (edgeCount.get(e.target) ?? 0) + 1);
  }

  // Place nodes in a spread-out initial layout:
  // - Main binary at center
  // - Other binaries in a ring close to center
  // - Libraries in a wider ring
  const mainNode = data.nodes.find((n) => n.type === "binary" && n.binaryType === "main");
  const binaries = data.nodes.filter((n) => n.type === "binary" && n !== mainNode);
  const libraries = data.nodes.filter((n) => n.type === "library");

  const addNode = (n: LibraryGraphNode, x: number, y: number) => {
    const r = nodeRadius(n);
    nodes.push({
      ...n, x, y,
      vx: 0, vy: 0,
      radius: r,
      halfW: nodeHalfW(n.label, r),
      halfH: nodeHalfH(r),
    });
  };

  // Main at origin
  if (mainNode) addNode(mainNode, 0, 0);

  // Other binaries in a tight ring
  const binRing = 100;
  for (let i = 0; i < binaries.length; i++) {
    const angle = (i / (binaries.length || 1)) * Math.PI * 2 - Math.PI / 2;
    addNode(binaries[i]!, Math.cos(angle) * binRing, Math.sin(angle) * binRing);
  }

  // Libraries in a ring — scale gently with count
  const libRing = 150 + libraries.length * 1.5;
  for (let i = 0; i < libraries.length; i++) {
    const angle = (i / (libraries.length || 1)) * Math.PI * 2;
    const jitter = (Math.random() - 0.5) * 40;
    const dist = libRing + jitter;
    addNode(libraries[i]!, Math.cos(angle) * dist, Math.sin(angle) * dist);
  }

  return nodes;
}

// ── Force simulation (runs synchronously to completion) ──

function runSimulation(nodes: LayoutNode[], edges: LibraryGraphEdge[], iterations: number): void {
  const REPULSION = 12000;
  const SPRING_K = 0.008;
  const REST_LEN = 100;
  const CENTER_K = 0.003;
  const DAMPING = 0.85;
  const PADDING = 18;

  const nodeMap = new Map(nodes.map((n) => [n.id, n]));

  // Pre-compute edge degree per node for weighted attraction
  const degree = new Map<string, number>();
  for (const e of edges) {
    degree.set(e.source, (degree.get(e.source) ?? 0) + 1);
    degree.set(e.target, (degree.get(e.target) ?? 0) + 1);
  }

  for (let iter = 0; iter < iterations; iter++) {
    const alpha = 1 - iter / iterations;
    const strength = Math.max(0.05, alpha);

    // Repulsion (all pairs)
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i]!;
        const b = nodes[j]!;
        let dx = b.x - a.x;
        let dy = b.y - a.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const force = (REPULSION * strength) / (dist * dist);
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        a.vx -= fx; a.vy -= fy;
        b.vx += fx; b.vy += fy;
      }
    }

    // Attraction along edges — stronger pull for low-degree nodes
    for (const e of edges) {
      const a = nodeMap.get(e.source);
      const b = nodeMap.get(e.target);
      if (!a || !b) continue;
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      // Leaf nodes (low degree) get pulled harder toward their parent
      const avgDeg = ((degree.get(e.source) ?? 1) + (degree.get(e.target) ?? 1)) / 2;
      const k = SPRING_K * (1 + 2 / avgDeg);
      const force = k * (dist - REST_LEN) * strength;
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;
      a.vx += fx; a.vy += fy;
      b.vx -= fx; b.vy -= fy;
    }

    // Centering
    for (const nd of nodes) {
      nd.vx -= nd.x * CENTER_K * strength;
      nd.vy -= nd.y * CENTER_K * strength;
    }

    // Damping + position update
    for (const nd of nodes) {
      nd.vx *= DAMPING;
      nd.vy *= DAMPING;
      nd.x += nd.vx;
      nd.y += nd.vy;
    }

    // Collision resolution (rectangle-based using halfW/halfH)
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i]!;
        const b = nodes[j]!;
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const overlapX = (a.halfW + b.halfW + PADDING) - Math.abs(dx);
        const overlapY = (a.halfH + b.halfH + PADDING) - Math.abs(dy);

        if (overlapX > 0 && overlapY > 0) {
          if (overlapX < overlapY) {
            const push = overlapX * 0.5;
            const sign = dx >= 0 ? 1 : -1;
            a.x -= sign * push;
            b.x += sign * push;
          } else {
            const push = overlapY * 0.5;
            const sign = dy >= 0 ? 1 : -1;
            a.y -= sign * push;
            b.y += sign * push;
          }
        }
      }
    }
  }

  // Final overlap cleanup — run collision-only passes to resolve any remaining overlaps
  for (let pass = 0; pass < 50; pass++) {
    let anyOverlap = false;
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i]!;
        const b = nodes[j]!;
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const overlapX = (a.halfW + b.halfW + PADDING) - Math.abs(dx);
        const overlapY = (a.halfH + b.halfH + PADDING) - Math.abs(dy);

        if (overlapX > 0 && overlapY > 0) {
          anyOverlap = true;
          if (overlapX < overlapY) {
            const push = overlapX * 0.55;
            const sign = dx >= 0 ? 1 : -1;
            a.x -= sign * push;
            b.x += sign * push;
          } else {
            const push = overlapY * 0.55;
            const sign = dy >= 0 ? 1 : -1;
            a.y -= sign * push;
            b.y += sign * push;
          }
        }
      }
    }
    if (!anyOverlap) break;
  }
}

// ── Graph renderer ──

class GraphRenderer {
  private container: HTMLElement;
  private svg: SVGSVGElement;
  private defs: SVGDefsElement;
  private viewport: SVGGElement;
  private edgesGroup: SVGGElement;
  private nodesGroup: SVGGElement;
  private tooltip: HTMLDivElement;
  private nodes: LayoutNode[];
  private edges: LibraryGraphEdge[];
  private graphData: LibraryGraphData;

  private nodeEls = new Map<string, SVGGElement>();
  private edgeEls = new Map<string, SVGLineElement>();
  private gradientEls = new Map<string, SVGLinearGradientElement>();

  // Pan & zoom
  private panX = 0;
  private panY = 0;
  private zoom = 1;
  private isPanning = false;
  private panStartX = 0;
  private panStartY = 0;
  private panStartPanX = 0;
  private panStartPanY = 0;

  // Drag
  private dragNode: LayoutNode | null = null;
  private dragOffsetX = 0;
  private dragOffsetY = 0;

  // Selection
  private selectedId: string | null = null;

  // Tooltip debounce
  private tooltipTimer: ReturnType<typeof setTimeout> | null = null;
  private tooltipNode: LayoutNode | null = null;

  // Event listener cleanup
  private boundMouseMove: (ev: MouseEvent) => void;
  private boundMouseUp: () => void;
  private boundResize: () => void;

  constructor(container: HTMLElement, graphData: LibraryGraphData) {
    this.container = container;
    this.graphData = graphData;
    this.nodes = buildLayoutNodes(graphData);
    this.edges = graphData.edges;

    // Run simulation synchronously before rendering
    runSimulation(this.nodes, this.edges, 800);

    this.svg = document.createElementNS(SVG_NS, "svg");
    this.svg.classList.add("gr-svg");

    this.defs = document.createElementNS(SVG_NS, "defs");
    this.svg.appendChild(this.defs);

    this.viewport = document.createElementNS(SVG_NS, "g");
    this.viewport.classList.add("gr-viewport");

    this.edgesGroup = document.createElementNS(SVG_NS, "g");
    this.edgesGroup.classList.add("gr-edges");

    this.nodesGroup = document.createElementNS(SVG_NS, "g");
    this.nodesGroup.classList.add("gr-nodes");

    this.viewport.appendChild(this.edgesGroup);
    this.viewport.appendChild(this.nodesGroup);
    this.svg.appendChild(this.viewport);

    this.tooltip = document.createElement("div");
    this.tooltip.className = "gr-tooltip hidden";
    container.appendChild(this.tooltip);
    container.appendChild(this.svg);

    this.createElements();
    this.positionAll();

    this.boundMouseMove = (ev: MouseEvent) => this.onMouseMove(ev);
    this.boundMouseUp = () => this.onMouseUp();
    this.boundResize = () => this.fitToView();
    this.bindEvents();
    window.addEventListener("resize", this.boundResize);

    requestAnimationFrame(() => this.fitToView());
  }

  private createElements(): void {
    const nodeMap = new Map(this.nodes.map((n) => [n.id, n]));

    for (const e of this.edges) {
      const key = `${e.source}|${e.target}`;
      const gradId = `gr-grad-${this.gradientEls.size}`;

      const src = nodeMap.get(e.source);
      const tgt = nodeMap.get(e.target);
      const grad = document.createElementNS(SVG_NS, "linearGradient");
      grad.setAttribute("id", gradId);
      grad.setAttribute("gradientUnits", "userSpaceOnUse");
      const stop1 = document.createElementNS(SVG_NS, "stop");
      stop1.setAttribute("offset", "0%");
      stop1.setAttribute("stop-color", src ? nodeColor(src) : "#888");
      const stop2 = document.createElementNS(SVG_NS, "stop");
      stop2.setAttribute("offset", "100%");
      stop2.setAttribute("stop-color", tgt ? nodeColor(tgt) : "#888");
      grad.appendChild(stop1);
      grad.appendChild(stop2);
      this.defs.appendChild(grad);
      this.gradientEls.set(key, grad);

      const line = document.createElementNS(SVG_NS, "line");
      line.classList.add("gr-edge");
      if (e.weak) line.classList.add("gr-edge--weak");
      line.setAttribute("stroke", `url(#${gradId})`);
      this.edgesGroup.appendChild(line);
      this.edgeEls.set(key, line);
    }

    for (const nd of this.nodes) {
      const g = document.createElementNS(SVG_NS, "g");
      g.classList.add("gr-node", nodeClass(nd));
      if (nd.weak) g.classList.add("gr-node--weak");
      g.dataset["id"] = nd.id;

      const circle = document.createElementNS(SVG_NS, "circle");
      circle.classList.add("gr-node-circle");
      circle.setAttribute("r", String(nd.radius));

      const text = document.createElementNS(SVG_NS, "text");
      text.classList.add("gr-node-label");
      text.setAttribute("dy", String(nd.radius + 14));
      text.textContent = nd.label;

      g.appendChild(circle);
      g.appendChild(text);
      this.nodesGroup.appendChild(g);
      this.nodeEls.set(nd.id, g);
    }
  }

  private positionAll(): void {
    const nodeMap = new Map(this.nodes.map((n) => [n.id, n]));

    for (const [key, line] of this.edgeEls) {
      const [srcId, tgtId] = key.split("|");
      const src = nodeMap.get(srcId!);
      const tgt = nodeMap.get(tgtId!);
      if (!src || !tgt) continue;
      line.setAttribute("x1", String(src.x));
      line.setAttribute("y1", String(src.y));
      line.setAttribute("x2", String(tgt.x));
      line.setAttribute("y2", String(tgt.y));

      const grad = this.gradientEls.get(key);
      if (grad) {
        grad.setAttribute("x1", String(src.x));
        grad.setAttribute("y1", String(src.y));
        grad.setAttribute("x2", String(tgt.x));
        grad.setAttribute("y2", String(tgt.y));
      }
    }

    for (const [id, g] of this.nodeEls) {
      const nd = nodeMap.get(id);
      if (!nd) continue;
      g.setAttribute("transform", `translate(${nd.x},${nd.y})`);
    }
  }

  private updateTransform(): void {
    this.viewport.setAttribute(
      "transform",
      `translate(${this.panX},${this.panY}) scale(${this.zoom})`
    );
  }

  private screenToGraph(sx: number, sy: number): { x: number; y: number } {
    return {
      x: (sx - this.panX) / this.zoom,
      y: (sy - this.panY) / this.zoom,
    };
  }

  private onMouseMove(ev: MouseEvent): void {
    if (this.dragNode) {
      const rect = this.svg.getBoundingClientRect();
      const gp = this.screenToGraph(ev.clientX - rect.left, ev.clientY - rect.top);
      this.dragNode.x = gp.x + this.dragOffsetX;
      this.dragNode.y = gp.y + this.dragOffsetY;
      this.positionAll();
    } else if (this.isPanning) {
      this.panX = this.panStartPanX + (ev.clientX - this.panStartX);
      this.panY = this.panStartPanY + (ev.clientY - this.panStartY);
      this.updateTransform();
    }
  }

  private onMouseUp(): void {
    this.dragNode = null;
    this.isPanning = false;
  }

  private bindEvents(): void {
    this.svg.addEventListener("wheel", (ev) => {
      ev.preventDefault();
      const rect = this.svg.getBoundingClientRect();
      const mx = ev.clientX - rect.left;
      const my = ev.clientY - rect.top;

      const oldZoom = this.zoom;
      const delta = ev.deltaY > 0 ? 0.9 : 1.1;
      this.zoom = Math.min(4, Math.max(0.2, this.zoom * delta));

      this.panX = mx - ((mx - this.panX) / oldZoom) * this.zoom;
      this.panY = my - ((my - this.panY) / oldZoom) * this.zoom;
      this.updateTransform();
    }, { passive: false });

    this.svg.addEventListener("mousedown", (ev) => {
      const target = (ev.target as Element).closest(".gr-node");
      if (target) {
        const id = (target as HTMLElement).dataset["id"];
        const nd = this.nodes.find((n) => n.id === id);
        if (!nd) return;
        this.cancelTooltip();
        this.dragNode = nd;
        const rect = this.svg.getBoundingClientRect();
        const gp = this.screenToGraph(ev.clientX - rect.left, ev.clientY - rect.top);
        this.dragOffsetX = nd.x - gp.x;
        this.dragOffsetY = nd.y - gp.y;
        this.selectNode(nd.id);
        ev.preventDefault();
      } else {
        this.cancelTooltip();
        this.isPanning = true;
        this.panStartX = ev.clientX;
        this.panStartY = ev.clientY;
        this.panStartPanX = this.panX;
        this.panStartPanY = this.panY;
        this.selectNode(null);
      }
    });

    window.addEventListener("mousemove", this.boundMouseMove);
    window.addEventListener("mouseup", this.boundMouseUp);

    this.nodesGroup.addEventListener("mouseenter", (ev) => {
      const target = (ev.target as Element).closest(".gr-node");
      if (!target) return;
      const id = (target as HTMLElement).dataset["id"];
      const nd = this.nodes.find((n) => n.id === id);
      if (!nd) return;
      this.scheduleTooltip(nd);
    }, true);

    this.nodesGroup.addEventListener("mouseleave", (ev) => {
      const target = (ev.target as Element).closest(".gr-node");
      if (!target) return;
      this.cancelTooltip();
    }, true);
  }

  private scheduleTooltip(nd: LayoutNode): void {
    this.cancelTooltip();
    this.tooltipNode = nd;
    this.tooltipTimer = setTimeout(() => {
      // Don't show while dragging or panning
      if (this.dragNode || this.isPanning) return;
      this.showTooltip(nd);
    }, 500);
  }

  private cancelTooltip(): void {
    if (this.tooltipTimer !== null) {
      clearTimeout(this.tooltipTimer);
      this.tooltipTimer = null;
    }
    this.tooltipNode = null;
    this.tooltip.classList.add("hidden");
  }

  private showTooltip(nd: LayoutNode): void {
    const lines: string[] = [];
    if (nd.type === "binary") {
      lines.push(`<strong>${nd.label}</strong>`);
      lines.push(`${nd.binaryType ?? "binary"}`);
    } else {
      lines.push(`<strong>${nd.id}</strong>`);
      if (nd.version) lines.push(`Version: ${nd.version}`);
      lines.push(`Type: ${nd.category ?? "unknown"}${nd.weak ? " (weak)" : ""}`);
    }
    this.tooltip.innerHTML = lines.join("<br>");
    this.tooltip.classList.remove("hidden");

    // Position tooltip near the node in screen coordinates
    const rect = this.container.getBoundingClientRect();
    const screenX = nd.x * this.zoom + this.panX;
    const screenY = nd.y * this.zoom + this.panY;

    const tipX = screenX + nd.radius * this.zoom + 10;
    const tipY = screenY - 10;

    // Clamp so the tooltip doesn't overflow the container
    const maxX = rect.width - 200;
    const maxY = rect.height - 60;
    this.tooltip.setAttribute(
      "style",
      `left:${Math.max(0, Math.min(tipX, maxX))}px;top:${Math.max(0, Math.min(tipY, maxY))}px`,
    );
  }

  private selectNode(id: string | null): void {
    if (this.selectedId) {
      this.nodeEls.get(this.selectedId)?.classList.remove("gr-node--selected");
    }
    this.selectedId = id;
    if (id) {
      this.nodeEls.get(id)?.classList.add("gr-node--selected");
    }
  }

  fitToView(): void {
    if (this.nodes.length === 0) return;
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    for (const nd of this.nodes) {
      minX = Math.min(minX, nd.x - nd.halfW);
      maxX = Math.max(maxX, nd.x + nd.halfW);
      minY = Math.min(minY, nd.y - nd.radius);
      maxY = Math.max(maxY, nd.y + nd.halfH);
    }

    const rect = this.svg.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return;
    const padding = 30;
    const w = maxX - minX + padding * 2;
    const h = maxY - minY + padding * 2;
    this.zoom = Math.min(2, Math.max(0.1, Math.min(rect.width / w, rect.height / h)));

    const cx = (minX + maxX) / 2;
    const cy = (minY + maxY) / 2;
    this.panX = rect.width / 2 - cx * this.zoom;
    this.panY = rect.height / 2 - cy * this.zoom;
    this.updateTransform();
  }

  resetLayout(): void {
    this.nodes = buildLayoutNodes(this.graphData);
    this.edges = this.graphData.edges;
    runSimulation(this.nodes, this.edges, 800);

    this.defs.innerHTML = "";
    this.edgesGroup.innerHTML = "";
    this.nodesGroup.innerHTML = "";
    this.gradientEls.clear();
    this.nodeEls.clear();
    this.edgeEls.clear();
    this.createElements();
    this.positionAll();
    this.fitToView();
  }

  /** Dim or restore nodes matching a category key (e.g. "library:system"). */
  setDimmed(dimmedKeys: Set<string>): void {
    const dimmedNodeIds = new Set<string>();
    for (const nd of this.nodes) {
      const key = nd.type === "binary"
        ? `binary:${nd.binaryType ?? "main"}`
        : `library:${nd.category ?? "system"}`;
      const dim = dimmedKeys.has(key);
      if (dim) dimmedNodeIds.add(nd.id);
      const g = this.nodeEls.get(nd.id);
      if (g) g.classList.toggle("gr-node--dimmed", dim);
    }

    for (const [key, line] of this.edgeEls) {
      const [srcId, tgtId] = key.split("|");
      const dim = dimmedNodeIds.has(srcId!) || dimmedNodeIds.has(tgtId!);
      line.classList.toggle("gr-edge--dimmed", dim);
    }
  }

  destroy(): void {
    this.cancelTooltip();
    window.removeEventListener("mousemove", this.boundMouseMove);
    window.removeEventListener("mouseup", this.boundMouseUp);
    window.removeEventListener("resize", this.boundResize);
  }
}

// ── Legend builder ──

interface LegendResult {
  element: HTMLElement;
  dimmedKeys: Set<string>;
}

function buildLegend(data: LibraryGraphData, onToggle: () => void): LegendResult {
  const legend = el("div", "gr-legend");
  const dimmedKeys = new Set<string>();

  // Only show categories that actually appear in the graph
  const hasType = new Set<string>();
  for (const n of data.nodes) {
    if (n.type === "binary") hasType.add(`binary:${n.binaryType ?? "main"}`);
    else hasType.add(`library:${n.category ?? "system"}`);
  }
  const hasWeak = data.edges.some((e) => e.weak);

  // [dotClass, label, show condition, category keys to toggle]
  const items: [string, string, () => boolean, string[]][] = [
    ["gr-legend-dot--binary-main", "Main Binary", () => hasType.has("binary:main"), ["binary:main"]],
    ["gr-legend-dot--binary-fw", "Frameworks", () => hasType.has("binary:framework") || hasType.has("binary:extension"), ["binary:framework", "binary:extension"]],
    ["gr-legend-dot--binary-tweak", "Tweaks", () => hasType.has("binary:tweak"), ["binary:tweak"]],
    ["gr-legend-dot--system", "System Libraries", () => hasType.has("library:system"), ["library:system"]],
    ["gr-legend-dot--swift", "Swift Libraries", () => hasType.has("library:swift"), ["library:swift"]],
    ["gr-legend-dot--embedded", "Embedded Libraries", () => hasType.has("library:embedded"), ["library:embedded"]],
    ["gr-legend-dot--weak", "Weak Links", () => hasWeak, []],
  ];
  for (const [cls, label, show, keys] of items) {
    if (!show()) continue;
    const item = el("div", "gr-legend-item");
    const dot = el("span", `gr-legend-dot ${cls}`);
    item.appendChild(dot);
    item.appendChild(document.createTextNode(label));

    // Make toggleable if it has category keys
    if (keys.length > 0) {
      item.classList.add("gr-legend-item--toggle");
      item.addEventListener("click", () => {
        const isActive = !item.classList.contains("gr-legend-item--off");
        item.classList.toggle("gr-legend-item--off", isActive);
        for (const k of keys) {
          if (isActive) dimmedKeys.add(k);
          else dimmedKeys.delete(k);
        }
        onToggle();
      });
    }

    legend.appendChild(item);
  }
  return { element: legend, dimmedKeys };
}

// ── Public API ──

export function mountGraphView(
  container: HTMLElement,
  sessionId: string,
): () => void {
  container.innerHTML = "";

  const wrapper = el("div", "gr-wrapper");

  const toolbar = el("div", "gr-toolbar");
  const legendContainer = el("div", "gr-legend"); // placeholder until data loads
  toolbar.appendChild(legendContainer);

  const btnGroup = el("div", "gr-toolbar-btns");

  const resetBtn = document.createElement("button");
  resetBtn.className = "gr-toolbar-btn";
  resetBtn.textContent = "Reset Layout";
  btnGroup.appendChild(resetBtn);

  const fitBtn = document.createElement("button");
  fitBtn.className = "gr-toolbar-btn";
  fitBtn.textContent = "Fit To View";
  btnGroup.appendChild(fitBtn);

  toolbar.appendChild(btnGroup);
  wrapper.appendChild(toolbar);

  const canvas = el("div", "gr-canvas");
  canvas.textContent = "Loading graph\u2026";
  wrapper.appendChild(canvas);
  container.appendChild(wrapper);

  let renderer: GraphRenderer | null = null;

  let dimmedKeys: Set<string> | null = null;

  window.api.getLibraryGraph(sessionId).then((data) => {
    canvas.textContent = "";

    if (!data.nodes.length) {
      canvas.textContent = "No dependency data available.";
      return;
    }

    const legendResult = buildLegend(data, () => {
      renderer?.setDimmed(legendResult.dimmedKeys);
    });
    dimmedKeys = legendResult.dimmedKeys;
    legendContainer.replaceWith(legendResult.element);

    renderer = new GraphRenderer(canvas, data);
  }).catch(() => {
    canvas.textContent = "Failed to load graph data.";
  });

  resetBtn.addEventListener("click", () => {
    renderer?.resetLayout();
    if (dimmedKeys) renderer?.setDimmed(dimmedKeys);
  });
  fitBtn.addEventListener("click", () => renderer?.fitToView());

  return () => renderer?.destroy();
}

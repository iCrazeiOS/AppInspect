/**
 * Horizontal drag-to-resize for a side panel.
 */

import { loadWidths, saveWidths } from "./layout-store";

interface PanelResizeOptions {
	side: "left" | "right";
	min?: number;
	max: () => number;
	storageKey: string;
	activeClass: string;
	/** Pin the width as min-width so flex siblings cannot shrink the panel. */
	pinMinWidth?: boolean;
	/** Restore the saved width immediately. */
	restore?: boolean;
}

export function initPanelResize(
	handle: HTMLElement,
	getTargetEl: () => HTMLElement,
	{
		side,
		min = 180,
		max,
		storageKey,
		activeClass,
		pinMinWidth = false,
		restore = true
	}: PanelResizeOptions
): void {
	if (restore) {
		const saved = loadWidths(storageKey);
		if (saved?.width) {
			getTargetEl().style.width = saved.width;
		}
	}

	handle.addEventListener("mousedown", (e) => {
		e.preventDefault();
		const el = getTargetEl();
		const startX = e.clientX;
		const startW = el.getBoundingClientRect().width;
		const limit = max();
		const prevSelect = document.body.style.userSelect;
		document.body.style.userSelect = "none";
		handle.classList.add(activeClass);

		const onMove = (ev: MouseEvent): void => {
			const delta = ev.clientX - startX;
			const raw = side === "left" ? startW + delta : startW - delta;
			const newW = Math.max(min, Math.min(limit, raw));
			el.style.width = `${newW}px`;
			if (pinMinWidth) el.style.minWidth = `${newW}px`;
		};

		const onUp = (): void => {
			document.removeEventListener("mousemove", onMove);
			document.removeEventListener("mouseup", onUp);
			document.body.style.userSelect = prevSelect;
			handle.classList.remove(activeClass);
			saveWidths(storageKey, { width: el.style.width });
		};

		document.addEventListener("mousemove", onMove);
		document.addEventListener("mouseup", onUp);
	});
}

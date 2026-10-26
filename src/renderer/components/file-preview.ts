/**
 * File preview pane: text/source and image previews with highlighting,
 * beautification, full-content loading and zoom controls.
 */

import {
	FILE_PREVIEW_BYTES,
	FILE_PREVIEW_FULL_BYTES,
	FILE_PREVIEW_IMAGE_BYTES
} from "../../shared/file-preview";
import type { FilePreviewContent } from "../../shared/types";
import {
	type BeautifyParser,
	beautifyParser,
	beautifyText,
	prettyPrintJson
} from "../utils/beautify";
import { copyText } from "../utils/clipboard";
import { el } from "../utils/dom";
import type { BrowserTreeNode } from "../utils/file-browser";
import { formatSize } from "../utils/format";
import {
	clampImageZoom,
	fitImageZoom,
	IMAGE_ZOOM_MAX,
	IMAGE_ZOOM_MIN,
	pinchImageZoom,
	stepImageZoom
} from "../utils/image-zoom";
import {
	HIGHLIGHT_AUTO_BYTES,
	highlightLanguage,
	highlightSource
} from "../utils/source-highlight";
import type { FilePreviewProvider } from "./file-browser";
import { showToast } from "./toast";

interface ImageZoomState {
	image: HTMLImageElement;
	width: number;
	height: number;
	scale: number;
}

interface PreviewDom {
	path: HTMLElement;
	size: HTMLElement;
	zoomControls: HTMLElement;
	zoomOut: HTMLButtonElement;
	zoomLabel: HTMLButtonElement;
	zoomIn: HTMLButtonElement;
	beautify: HTMLButtonElement;
	copy: HTMLButtonElement;
	open: HTMLButtonElement;
	notices: HTMLElement;
	body: HTMLElement;
}

interface FilePreviewPaneOptions {
	/** Read a file from the active backend for preview. */
	read: FilePreviewProvider["read"];
	/** Open the previewed file on disk. Omit for backends with no real file (e.g. ASAR). */
	onOpen?: (path: string) => void;
}

export class FilePreviewPane {
	private options: FilePreviewPaneOptions;
	private dom: PreviewDom | null = null;

	private requestId = 0;
	private currentPath: string | null = null;

	// Raw text is kept so toggling highlighting/beautifying is lossless.
	private rawText: string | null = null;
	private textParser: BeautifyParser | null = null;
	private beautified = false;
	private codeEl: HTMLElement | null = null;
	private sourceLanguage: string | null = null;
	private highlightEnabled = false;
	private highlightNotice: HTMLElement | null = null;

	private imageZoom: ImageZoomState | null = null;

	constructor(options: FilePreviewPaneOptions) {
		this.options = options;
	}

	mount(container: HTMLElement): void {
		const header = el("div", "fb-preview-header");
		const pathEl = el("span", "fb-preview-path", "Select a file to preview");
		const sizeEl = el("span", "fb-preview-size");
		const zoomControls = el("div", "fb-zoom-controls");
		const zoomOutBtn = el("button", "fb-preview-btn fb-zoom-btn", "\u2212");
		const zoomLabel = el("button", "fb-preview-btn fb-zoom-label", "100%");
		const zoomInBtn = el("button", "fb-preview-btn fb-zoom-btn", "+");
		zoomOutBtn.title = "Zoom out";
		zoomInBtn.title = "Zoom in";
		zoomLabel.title = "Reset zoom";
		zoomControls.hidden = true;
		zoomControls.appendChild(zoomOutBtn);
		zoomControls.appendChild(zoomLabel);
		zoomControls.appendChild(zoomInBtn);
		const beautifyBtn = el("button", "fb-preview-btn", "Beautify");
		beautifyBtn.title = "Beautify code";
		beautifyBtn.hidden = true;
		beautifyBtn.disabled = true;
		const copyBtn = el("button", "fb-preview-btn", "Copy path");
		copyBtn.disabled = true;
		copyBtn.addEventListener("click", () => {
			if (this.currentPath) copyText(this.currentPath, "Copied path");
		});
		const openBtn = el("button", "fb-preview-btn", "Open");
		openBtn.title = "Open with the default application";
		openBtn.disabled = true;
		openBtn.hidden = !this.options.onOpen;
		openBtn.addEventListener("click", () => {
			if (this.currentPath) this.options.onOpen?.(this.currentPath);
		});
		header.appendChild(pathEl);
		header.appendChild(openBtn);
		header.appendChild(sizeEl);
		header.appendChild(zoomControls);
		header.appendChild(beautifyBtn);
		header.appendChild(copyBtn);

		const notices = el("div", "fb-preview-notices");
		const body = el("div", "fb-preview-body");
		body.appendChild(el("div", "fb-preview-empty", "Select a file to preview."));
		container.appendChild(header);
		container.appendChild(notices);
		container.appendChild(body);

		this.dom = {
			path: pathEl,
			size: sizeEl,
			zoomControls,
			zoomOut: zoomOutBtn,
			zoomLabel,
			zoomIn: zoomInBtn,
			beautify: beautifyBtn,
			copy: copyBtn,
			open: openBtn,
			notices,
			body
		};

		zoomOutBtn.addEventListener("click", () => {
			if (this.imageZoom) this.applyImageZoom(stepImageZoom(this.imageZoom.scale, "out"));
		});
		zoomInBtn.addEventListener("click", () => {
			if (this.imageZoom) this.applyImageZoom(stepImageZoom(this.imageZoom.scale, "in"));
		});
		zoomLabel.addEventListener("click", () => this.fitImage());

		// Trackpad pinch is reported as a ctrl+wheel event. Without ctrl the
		// browser keeps its normal scroll behaviour, letting a zoomed image pan.
		body.addEventListener(
			"wheel",
			(event) => {
				if (!event.ctrlKey || !this.imageZoom) return;
				event.preventDefault();
				const rect = body.getBoundingClientRect();
				this.applyImageZoom(
					pinchImageZoom(this.imageZoom.scale, event.deltaY),
					event.clientX - rect.left,
					event.clientY - rect.top
				);
			},
			{ passive: false }
		);

		beautifyBtn.addEventListener("click", () => {
			void this.toggleBeautify();
		});
	}

	/** Preview a file. Reads are guarded so only the latest selection renders. */
	show(entry: BrowserTreeNode): void {
		void this.loadPreview(entry);
	}

	private updateBeautifyButton(): void {
		const dom = this.dom;
		if (!dom) return;
		const enabled = this.rawText !== null && this.textParser !== null;
		dom.beautify.hidden = !enabled;
		dom.beautify.disabled = !enabled;
		dom.beautify.classList.toggle("fb-preview-btn--active", this.beautified);
	}

	private resetCodePreview(): void {
		this.rawText = null;
		this.textParser = null;
		this.beautified = false;
		this.codeEl = null;
		this.sourceLanguage = null;
		this.highlightEnabled = false;
		this.highlightNotice = null;
		this.updateBeautifyButton();
	}

	private setCodeContent(text: string): boolean {
		if (!this.codeEl) return false;
		if (this.highlightEnabled && this.sourceLanguage) {
			const html = highlightSource(text, this.sourceLanguage);
			if (html !== null) {
				this.codeEl.innerHTML = html;
				return true;
			}
		}
		this.codeEl.textContent = text;
		return false;
	}

	private async toggleBeautify(): Promise<void> {
		const dom = this.dom;
		if (!dom || this.rawText === null || !this.textParser || !this.codeEl) return;
		if (this.beautified) {
			this.setCodeContent(this.rawText);
			this.beautified = false;
			this.updateBeautifyButton();
			return;
		}

		const text = this.rawText;
		const parser = this.textParser;
		const target = this.codeEl;
		dom.beautify.disabled = true;
		// Let the pending label paint before Prettier blocks the thread.
		await new Promise((resolve) => setTimeout(resolve, 0));
		const formatted = await beautifyText(text, parser);
		// A different file may have been selected while formatting.
		if (this.codeEl !== target || this.rawText !== text || this.textParser !== parser) return;
		if (formatted === null) {
			showToast("Could not beautify this file");
		} else {
			this.setCodeContent(formatted);
			this.beautified = true;
		}
		this.updateBeautifyButton();
	}

	private updateZoomControls(): void {
		const dom = this.dom;
		if (!dom || !this.imageZoom) return;
		dom.zoomLabel.textContent = `${Math.round(this.imageZoom.scale * 100)}%`;
		dom.zoomOut.disabled = this.imageZoom.scale <= IMAGE_ZOOM_MIN;
		dom.zoomIn.disabled = this.imageZoom.scale >= IMAGE_ZOOM_MAX;
	}

	/** Resize the image around an anchor point in body coordinates. */
	private applyImageZoom(scale: number, anchorX?: number, anchorY?: number): void {
		const dom = this.dom;
		const zoom = this.imageZoom;
		if (!dom || !zoom) return;
		const body = dom.body;
		const ax = anchorX ?? body.clientWidth / 2;
		const ay = anchorY ?? body.clientHeight / 2;
		const ratioX = (ax + body.scrollLeft) / Math.max(1, body.scrollWidth);
		const ratioY = (ay + body.scrollTop) / Math.max(1, body.scrollHeight);

		zoom.scale = clampImageZoom(scale);
		zoom.image.style.width = `${zoom.width * zoom.scale}px`;
		zoom.image.style.height = `${zoom.height * zoom.scale}px`;

		body.scrollLeft = ratioX * body.scrollWidth - ax;
		body.scrollTop = ratioY * body.scrollHeight - ay;
		this.updateZoomControls();
	}

	private fitImage(): void {
		const dom = this.dom;
		const zoom = this.imageZoom;
		if (!dom || !zoom) return;
		const body = dom.body;
		const fit = fitImageZoom(zoom.width, zoom.height, body.clientWidth, body.clientHeight);
		this.applyImageZoom(fit);
		body.scrollLeft = 0;
		body.scrollTop = 0;
	}

	private resetImageZoom(): void {
		this.imageZoom = null;
		if (this.dom) this.dom.zoomControls.hidden = true;
	}

	private buildHighlightNotice(size: number): HTMLElement {
		const notice = el("div", "fb-notice fb-notice--warn fb-notice--inline");
		notice.appendChild(
			el(
				"span",
				undefined,
				`Syntax highlighting is off for this large file (${formatSize(size)}).`
			)
		);
		const button = el("button", "fb-notice-action", "Highlight anyway");
		button.title = "Highlighting may take a moment for large files";
		button.addEventListener("click", () => {
			void this.enableHighlighting(button);
		});
		notice.appendChild(button);
		return notice;
	}

	private async enableHighlighting(button: HTMLButtonElement): Promise<void> {
		const target = this.codeEl;
		if (!target || !this.sourceLanguage) return;
		const requestId = this.requestId;
		button.disabled = true;
		button.textContent = "Highlighting\u2026";
		// Let the pending label paint before highlight.js blocks the thread.
		await new Promise((resolve) => setTimeout(resolve, 0));
		if (requestId !== this.requestId || this.codeEl !== target) return;

		this.highlightEnabled = true;
		if (!this.setCodeContent(target.textContent ?? "")) {
			this.highlightEnabled = false;
			button.disabled = false;
			button.textContent = "Highlight anyway";
			showToast("Could not highlight this file");
			return;
		}
		this.highlightNotice?.remove();
		this.highlightNotice = null;
	}

	private async loadFullContent(path: string, button: HTMLButtonElement): Promise<void> {
		const dom = this.dom;
		if (!dom) return;
		const requestId = this.requestId;
		button.disabled = true;
		button.textContent = "Loading full content\u2026";
		try {
			const result = await this.options.read(path, FILE_PREVIEW_FULL_BYTES, true);
			if (requestId !== this.requestId || this.currentPath !== path || !dom.body.isConnected)
				return;
			if (!result) {
				showToast("Could not load the full file");
				button.disabled = false;
				button.textContent = "Load full content";
				return;
			}
			this.renderPreviewContent(result, path, FILE_PREVIEW_FULL_BYTES);
		} catch (err) {
			if (requestId !== this.requestId || this.currentPath !== path || !dom.body.isConnected)
				return;
			showToast(
				`Could not load the full file: ${err instanceof Error ? err.message : String(err)}`
			);
			button.disabled = false;
			button.textContent = "Load full content";
		}
	}

	private buildTruncatedNotice(
		result: FilePreviewContent,
		path: string,
		limit: number
	): HTMLElement {
		const notice = el("div", "fb-notice fb-notice--warn fb-notice--inline");
		notice.appendChild(
			el(
				"span",
				undefined,
				`Showing the first ${formatSize(limit)} of ${formatSize(result.size)}.`
			)
		);
		if (limit < FILE_PREVIEW_FULL_BYTES) {
			const button = el("button", "fb-notice-action", "Load full content");
			button.title = `Load the full ${formatSize(result.size)} file`;
			button.addEventListener("click", () => {
				void this.loadFullContent(path, button);
			});
			notice.appendChild(button);
		}
		return notice;
	}

	private renderPreviewContent(
		result: FilePreviewContent,
		path: string,
		limit = FILE_PREVIEW_BYTES
	): void {
		const dom = this.dom;
		if (!dom) return;
		const body = dom.body;
		dom.notices.innerHTML = "";
		body.innerHTML = "";
		body.classList.remove("fb-preview-body--image");
		dom.size.textContent = formatSize(result.size);
		this.resetCodePreview();
		this.resetImageZoom();

		if (result.kind === "image") {
			if (result.image) {
				body.classList.add("fb-preview-body--image");
				const stage = el("div", "fb-image-stage");
				const image = el("img", "fb-image");
				image.alt = path;
				image.addEventListener("load", () => {
					if (!image.isConnected || image.naturalWidth === 0) return;
					this.imageZoom = {
						image,
						width: image.naturalWidth,
						height: image.naturalHeight,
						scale: 1
					};
					dom.zoomControls.hidden = false;
					this.fitImage();
					image.classList.add("fb-image--ready");
				});
				image.addEventListener("error", () => {
					if (!image.isConnected) return;
					this.resetImageZoom();
					body.classList.remove("fb-preview-body--image");
					body.innerHTML = "";
					body.appendChild(el("div", "fb-preview-empty", "Could not render this image."));
				});
				stage.appendChild(image);
				body.appendChild(stage);
				image.src = result.image;
				return;
			}
			dom.notices.appendChild(
				el(
					"div",
					"fb-notice fb-notice--warn",
					result.truncated
						? `Image is too large to preview (limit ${formatSize(FILE_PREVIEW_IMAGE_BYTES)}).`
						: "Image preview unavailable."
				)
			);
			return;
		}

		if (result.kind === "binary") {
			dom.notices.appendChild(
				el(
					"div",
					"fb-notice fb-notice--binary",
					`Binary file \u2014 preview not available (${formatSize(result.size)}).`
				)
			);
			return;
		}

		if (result.truncated) {
			dom.notices.appendChild(this.buildTruncatedNotice(result, path, limit));
		}

		const text = result.text ?? "";
		const pretty = result.truncated ? null : prettyPrintJson(text);
		this.rawText = text;
		this.textParser = result.truncated ? null : beautifyParser(path);
		this.beautified = pretty !== null;
		this.codeEl = el("pre", "fb-code");
		body.appendChild(this.codeEl);
		this.sourceLanguage = highlightLanguage(path);
		const displayed = pretty ?? text;
		const autoHighlight =
			this.sourceLanguage !== null && displayed.length <= HIGHLIGHT_AUTO_BYTES;
		this.highlightEnabled = autoHighlight;
		if (autoHighlight) this.highlightEnabled = this.setCodeContent(displayed);
		if (!this.highlightEnabled) {
			this.codeEl.textContent = displayed;
			if (this.sourceLanguage && !autoHighlight) {
				this.highlightNotice = this.buildHighlightNotice(displayed.length);
				dom.notices.appendChild(this.highlightNotice);
			}
		}
		this.updateBeautifyButton();
	}

	private async loadPreview(entry: BrowserTreeNode): Promise<void> {
		const dom = this.dom;
		if (!dom) return;
		const requestId = ++this.requestId;
		this.currentPath = entry.path;
		dom.path.textContent = entry.path;
		dom.size.textContent = formatSize(entry.size);
		dom.copy.disabled = false;
		dom.open.disabled = false;
		dom.notices.innerHTML = "";
		dom.body.innerHTML = "";
		dom.body.classList.remove("fb-preview-body--image");
		this.resetCodePreview();
		this.resetImageZoom();
		dom.body.appendChild(el("div", "fb-preview-loading", "Loading\u2026"));

		try {
			const result = await this.options.read(entry.path, FILE_PREVIEW_BYTES, true);
			if (requestId !== this.requestId || !dom.body.isConnected) return;
			if (!result) {
				dom.body.innerHTML = "";
				dom.body.appendChild(el("div", "fb-preview-empty", "Could not read this file."));
				return;
			}
			this.renderPreviewContent(result, entry.path);
		} catch (err) {
			if (requestId !== this.requestId || !dom.body.isConnected) return;
			dom.body.innerHTML = "";
			dom.body.appendChild(
				el(
					"div",
					"fb-preview-empty",
					`Could not read this file: ${err instanceof Error ? err.message : String(err)}`
				)
			);
		}
	}
}

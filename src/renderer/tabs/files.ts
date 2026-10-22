/**
 * Files tab: directory tree view of extracted bundle contents.
 * Thin adapter over the shared FileBrowser; this module only supplies the
 * summary strip, file-type badges and filesystem-specific actions.
 */

import type { FileEntry } from "../../shared/types";
import { FileBrowser } from "../components";
import { copyText } from "../utils/clipboard";
import { el } from "../utils/dom";
import type { FileBadge } from "../utils/file-browser";
import { treeTotals } from "../utils/file-browser";
import { formatCount, formatSize } from "../utils/format";

function classifyFile(entry: FileEntry): FileBadge[] {
	const name = entry.name;
	const path = entry.path;

	if (entry.isDirectory && name.endsWith(".framework")) {
		return [{ tone: "framework", title: "Framework" }];
	}
	if (name.endsWith(".plist")) return [{ tone: "plist", title: "Property list" }];
	if (name.endsWith(".mobileprovision")) {
		return [{ tone: "provision", title: "Provisioning profile" }];
	}

	// Mach-O heuristic: no extension in .app root or inside Frameworks/
	if (!entry.isDirectory && !name.includes(".")) {
		const normalised = path.replaceAll("\\", "/");
		if (/\.app\/[^/]*$/.test(normalised) || /Frameworks\//.test(normalised)) {
			return [{ tone: "binary", title: "Mach-O binary" }];
		}
	}

	return [];
}

function folderLabel(platform: string): string {
	if (platform === "darwin") return "Show in Finder";
	if (platform === "linux") return "Show in File Manager";
	return "Show in Explorer";
}

export function renderFiles(container: HTMLElement, data: unknown, sessionId: string = ""): void {
	container.innerHTML = "";
	container.classList.add("fb-container");

	const entries = Array.isArray(data) ? (data as FileEntry[]) : [];
	const { count, totalSize } = treeTotals(entries);

	const wrapper = el("div", "fb-wrapper");

	const summary = el("div", "fb-summary");
	const stat = el("div", "fb-stat");
	stat.appendChild(el("span", "fb-stat-value", formatCount(count, "file")));
	stat.appendChild(el("span", "fb-stat-label", formatSize(totalSize)));
	summary.appendChild(stat);
	wrapper.appendChild(summary);

	// Strip the shared extraction-root prefix so the temp cache path never
	// pollutes search results.
	const first = entries[0];
	const rootPrefix = first ? first.path.slice(0, first.path.length - first.name.length) : "";
	const searchPath = (entry: FileEntry): string => {
		const path =
			rootPrefix && entry.path.startsWith(rootPrefix)
				? entry.path.slice(rootPrefix.length)
				: entry.path;
		return path.replaceAll("\\", "/");
	};

	// Fetch once and await per menu, so the first right-click already has the
	// platform-specific folder label.
	const platform = window.api.getPlatform();

	new FileBrowser<FileEntry>({
		entries,
		sessionId,
		stateKey: "files",
		widthKey: "files-tree",
		preview: {
			read: (path, maxBytes, includeImage) =>
				window.api.readFilePreview(sessionId, path, maxBytes, includeImage)
		},
		searchPath,
		badges: classifyFile,
		contextMenu: async (entry) => {
			const p = await platform;
			const items = [
				{ label: "Copy Path", action: () => copyText(entry.path, "Copied path") },
				{ label: "Copy Name", action: () => copyText(entry.name, "Copied name") },
				{
					label: folderLabel(p),
					action: () => window.api.showItemInFolder(entry.path)
				}
			];
			if (!entry.isDirectory) {
				items.push({ label: "Open File", action: () => window.api.openFile(entry.path) });
			}
			return items;
		},
		onOpen: (entry) => window.api.openFile(entry.path),
		emptyMessage: "No files."
	}).mount(wrapper);

	container.appendChild(wrapper);
}

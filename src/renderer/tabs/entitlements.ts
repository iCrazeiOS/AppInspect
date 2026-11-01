/**
 * Entitlements tab: key-value display with dangerous entitlement highlighting.
 */

import { EmptyState, JsonTree } from "../components";
import { announce, takePendingTarget } from "../navigation";
import { copyText } from "../utils/clipboard";
import { highlightSource } from "../utils/source-highlight";

/** Entitlements that are flagged as dangerous (red). */
const RED_PATTERNS = ["com.apple.private.", "platform-application"];

/** Entitlements that are flagged as warnings (orange). */
const ORANGE_KEYS = ["get-task-allow", "com.apple.security.cs.disable-library-validation"];

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

export function renderEntitlements(
	container: HTMLElement,
	data: unknown,
	sessionId: string = ""
): void {
	container.innerHTML = "";

	// The IPC layer sends { entries, raw } for this binary.
	const payload =
		data && typeof data === "object" && !Array.isArray(data)
			? (data as { entries?: unknown; raw?: unknown })
			: null;
	const flat =
		payload?.entries && typeof payload.entries === "object"
			? (payload.entries as Record<string, unknown>)
			: null;
	const raw = typeof payload?.raw === "string" && payload.raw !== "" ? payload.raw : null;

	const entries: Record<string, unknown> = flat ?? {};
	const hasEntries = Object.keys(entries).length > 0;

	if (!hasEntries && !raw) {
		const empty = new EmptyState({
			icon: "\u{1F512}",
			message: "No entitlements found in this binary."
		});
		empty.mount(container);
		return;
	}

	// Toolbar with the parsed / raw XML toggle. With nothing parsed but the raw
	// blob present, open on the raw view so the button is not the only content.
	let showRaw = !hasEntries;
	const body = document.createElement("div");
	if (raw) {
		const toolbar = document.createElement("div");
		toolbar.className = "ent-toolbar";

		const toggle = document.createElement("button");
		toggle.className = "ent-view-btn";
		toggle.type = "button";

		const updateLabel = (): void => {
			toggle.textContent = showRaw ? "View parsed" : "View raw XML";
			toggle.title = showRaw
				? "Show the parsed entitlement keys"
				: "Show the entitlements XML embedded in the code signature";
		};
		updateLabel();

		toggle.addEventListener("click", () => {
			showRaw = !showRaw;
			updateLabel();
			renderBody();
		});

		const copy = document.createElement("button");
		copy.className = "ent-view-btn";
		copy.type = "button";
		copy.textContent = "Copy XML";
		copy.title = "Copy the raw entitlements XML to the clipboard";
		copy.addEventListener("click", () => copyText(raw, "Copied entitlements XML"));

		toolbar.appendChild(toggle);
		toolbar.appendChild(copy);
		container.appendChild(toolbar);
	}
	container.appendChild(body);

	function renderBody(): void {
		body.innerHTML = "";

		if (showRaw && raw) {
			// Reuse the file-preview code block so the highlight.js theme applies.
			const pre = document.createElement("pre");
			pre.className = "fb-code ent-raw";
			const highlighted = highlightSource(raw, "xml");
			if (highlighted !== null) {
				pre.innerHTML = highlighted;
			} else {
				pre.textContent = raw;
			}
			body.appendChild(pre);
			return;
		}

		if (!hasEntries) {
			const empty = new EmptyState({
				icon: "\u{1F512}",
				message: "The entitlements XML contained no keys."
			});
			empty.mount(body);
			return;
		}

		// Dangerous entitlements summary
		const allKeys = Object.keys(entries);
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
			body.appendChild(dangerSection);
		}

		// Source section
		const target = takePendingTarget(sessionId, "entitlements");
		const renderSource = (obj: Record<string, unknown>, field: string): void => {
			const treeContainer = document.createElement("div");
			treeContainer.className = "ent-tree";
			body.appendChild(treeContainer);

			const tree = new JsonTree({ sessionId, tabId: "entitlements", field });
			tree.mount(treeContainer);
			tree.setData(obj);

			// Reserved consumer: no producer emits entitlement findings yet.
			if (target?.kind === "entitlement") {
				tree.filter(target.key);
				requestAnimationFrame(() => {
					const highlight = treeContainer.querySelector<HTMLElement>(".jt-highlight");
					highlight?.scrollIntoView({ block: "center" });
					announce("Opened entitlement");
				});
			}
		};

		renderSource(entries, "entitlements");
	}

	renderBody();
}

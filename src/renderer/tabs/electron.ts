/**
 * Electron tab: browse the app.asar virtual filesystem and inspect the
 * package metadata, fuses and ASAR integrity recorded for the bundle.
 */

import type {
	AsarEntry,
	ElectronAsarIntegrity,
	ElectronFuse,
	ElectronFuseState,
	ElectronInfo,
	PlistValue
} from "../../shared/types";
import { EmptyState, FileBrowser } from "../components";
import { saveSearchState } from "../search-state";
import { getTabState, setTabState } from "../tab-state";
import { copyText } from "../utils/clipboard";
import { el } from "../utils/dom";
import type { FileBadge } from "../utils/file-browser";
import { ancestorPaths } from "../utils/file-browser";
import { formatCount, formatSize, plural } from "../utils/format";

type ElectronView = "files" | "package";

const FUSE_STATE_CLASS: Record<ElectronFuseState, string> = {
	enabled: "el-fuse-state--enabled",
	disabled: "el-fuse-state--disabled",
	removed: "el-fuse-state--removed"
};

const INTEGRITY_FUSE = "EnableEmbeddedAsarIntegrityValidation";

/** The hash only proves tamper-resistance when the integrity fuse enforces it. */
function integrityEnforced(info: ElectronInfo): boolean {
	return info.fuses.some((fuse) => fuse.name === INTEGRITY_FUSE && fuse.state === "enabled");
}

function integrityBadge(info: ElectronInfo): HTMLElement | null {
	if (!info.integrity) return null;
	if (!info.integrity.valid) return el("span", "el-badge el-badge--bad", "Integrity mismatch");
	return integrityEnforced(info)
		? el("span", "el-badge el-badge--ok", "Integrity verified")
		: el("span", "el-badge el-badge--warn", "Hash matches (not enforced)");
}

// ── Value formatting ──

/** Render a package.json/PlistValue scalar, including npm's object-shaped author. */
function textValue(value: PlistValue | undefined): string | undefined {
	if (value === undefined) return undefined;
	if (typeof value === "string") return value;
	if (typeof value === "number" || typeof value === "boolean") return String(value);
	if (Array.isArray(value)) {
		const parts = value.map((item) => textValue(item)).filter((item) => item !== undefined);
		return parts.length > 0 ? parts.join(", ") : undefined;
	}
	const name = value.name;
	if (typeof name === "string") {
		const email = value.email;
		return typeof email === "string" ? `${name} <${email}>` : name;
	}
	return undefined;
}

// ── Card builders ──

function buildCard(title: string, ...children: HTMLElement[]): HTMLElement {
	const card = el("div", "el-card");
	card.appendChild(el("h3", "el-card-title", title));
	const body = el("div", "el-card-body");
	for (const child of children) body.appendChild(child);
	card.appendChild(body);
	return card;
}

function buildKV(label: string, value: string, mono = false): HTMLElement {
	const row = el("div", "el-kv");
	row.appendChild(el("span", "el-kv-label", label));
	row.appendChild(el("span", mono ? "el-kv-value el-kv-value--mono" : "el-kv-value", value));
	return row;
}

function buildPackageCard(info: ElectronInfo): HTMLElement | null {
	const pkg = info.packageJson;
	if (!pkg) return null;

	const items: HTMLElement[] = [];
	const add = (label: string, value: string | undefined): void => {
		if (value !== undefined && value !== "") items.push(buildKV(label, value));
	};

	add("Name", textValue(pkg.name));
	add("Version", textValue(pkg.version));
	add("License", textValue(pkg.license));
	add("Author", textValue(pkg.author));
	add("Main", textValue(pkg.main));
	add("Description", textValue(pkg.description));
	add("Electron Version", info.electronVersion);
	add("ASAR Size", info.asarSize != null ? formatSize(info.asarSize) : undefined);
	add("Files", String(info.fileCount));

	return buildCard("Package", ...items);
}

function buildFusesCard(fuses: ElectronFuse[]): HTMLElement {
	const rows: HTMLElement[] = [];
	for (const fuse of fuses) {
		const row = el("div", "el-fuse-row");
		row.appendChild(el("span", "el-fuse-name", fuse.name));
		row.appendChild(el("span", `el-fuse-state ${FUSE_STATE_CLASS[fuse.state]}`, fuse.state));
		rows.push(row);
	}
	if (rows.length === 0) rows.push(el("p", "el-muted", "No fuse wire found."));
	return buildCard(`${plural(fuses.length, "Fuse")} (${fuses.length})`, ...rows);
}

function buildIntegrityCard(integrity: ElectronAsarIntegrity, enforced: boolean): HTMLElement {
	const status = el("div", "el-kv");
	status.appendChild(el("span", "el-kv-label", "Status"));
	status.appendChild(
		el(
			"span",
			integrity.valid ? "el-badge el-badge--ok" : "el-badge el-badge--bad",
			integrity.valid ? "Valid" : "Invalid"
		)
	);

	const enforcedRow = el("div", "el-kv");
	enforcedRow.appendChild(el("span", "el-kv-label", "Enforced"));
	enforcedRow.appendChild(
		el(
			"span",
			enforced ? "el-badge el-badge--ok" : "el-badge el-badge--warn",
			enforced ? "Yes" : "No (fuse disabled)"
		)
	);

	return buildCard(
		"ASAR Integrity",
		buildKV("Algorithm", integrity.algorithm),
		buildKV("Expected", integrity.expected, true),
		buildKV("Actual", integrity.actual, true),
		status,
		enforcedRow
	);
}

function buildDependencyCard(
	singular: string,
	pluralForm: string,
	value: PlistValue | undefined
): HTMLElement | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const entries = Object.entries(value);
	if (entries.length === 0) return null;
	const rows = entries.map(([name, version]) => buildKV(name, textValue(version) ?? "—", true));
	return buildCard(
		`${plural(entries.length, singular, pluralForm)} (${entries.length})`,
		...rows
	);
}

function buildPathCard(
	title: string,
	paths: string[],
	onOpen: (path: string) => void
): HTMLElement {
	if (paths.length === 0) return buildCard(plural(0, title), el("p", "el-muted", "None."));
	const rows = paths.map((path) => {
		const button = el("button", "el-path-btn", path);
		button.title = path;
		button.addEventListener("click", () => onOpen(path));
		return button;
	});
	return buildCard(`${plural(paths.length, title)} (${paths.length})`, ...rows);
}

function buildMissingArchive(info: ElectronInfo): HTMLElement {
	const wrap = el("div", "el-fallback");
	const empty = new EmptyState({
		icon: "\u{1F4E6}",
		message:
			"No readable app.asar was found in this Electron bundle. The archive may be missing, " +
			"unpacked as a plain resources/app directory, or malformed."
	});
	empty.mount(wrap);

	const cards = el("div", "el-cards");
	const packageCard = buildPackageCard(info);
	if (packageCard) cards.appendChild(packageCard);

	const fuses = Array.isArray(info.fuses) ? info.fuses : [];
	if (fuses.length > 0) cards.appendChild(buildFusesCard(fuses));
	if (info.integrity)
		cards.appendChild(buildIntegrityCard(info.integrity, integrityEnforced(info)));
	if (cards.childElementCount > 0) wrap.appendChild(cards);

	return wrap;
}

// ── Package view ──

function renderPackageView(
	container: HTMLElement,
	info: ElectronInfo,
	onOpenPath: (path: string) => void
): void {
	const cards = el("div", "el-cards");
	const pkg = info.packageJson;
	const packageCard = buildPackageCard(info);

	if (packageCard) {
		cards.appendChild(packageCard);
	} else {
		const empty = el("div", "el-package-empty");
		new EmptyState({
			icon: "\u{1F4E6}",
			message: "No package.json found in app.asar."
		}).mount(empty);
		cards.appendChild(empty);
	}

	if (pkg) {
		const dependencies = buildDependencyCard("Dependency", "Dependencies", pkg.dependencies);
		if (dependencies) cards.appendChild(dependencies);
		const optional = buildDependencyCard(
			"Optional Dependency",
			"Optional Dependencies",
			pkg.optionalDependencies
		);
		if (optional) cards.appendChild(optional);
		const dev = buildDependencyCard("Dev Dependency", "Dev Dependencies", pkg.devDependencies);
		if (dev) cards.appendChild(dev);
	}

	const fuses = Array.isArray(info.fuses) ? info.fuses : [];
	cards.appendChild(buildFusesCard(fuses));

	if (info.integrity)
		cards.appendChild(buildIntegrityCard(info.integrity, integrityEnforced(info)));

	const sourceMaps = Array.isArray(info.sourceMaps) ? info.sourceMaps : [];
	cards.appendChild(buildPathCard("Source Map", sourceMaps, onOpenPath));

	const nativeAddons = Array.isArray(info.nativeAddons) ? info.nativeAddons : [];
	cards.appendChild(buildPathCard("Native Addon", nativeAddons, onOpenPath));

	container.appendChild(cards);
}

// ── Main render ──

export function renderElectron(
	container: HTMLElement,
	data: { info: ElectronInfo; files: AsarEntry[] } | null,
	sessionId: string = ""
): void {
	container.innerHTML = "";
	container.classList.add("fb-container");

	if (!data?.info) {
		new EmptyState({
			icon: "\u{1F4E6}",
			message: "No Electron data available for this bundle."
		}).mount(container);
		return;
	}

	const info = data.info;
	const files = Array.isArray(data.files) ? data.files : [];
	const sourceMaps = Array.isArray(info.sourceMaps) ? info.sourceMaps : [];

	const wrapper = el("div", "fb-wrapper");

	// ── Summary strip ──
	const summary = el("div", "fb-summary");
	const stat = (value: string, label: string): HTMLElement => {
		const item = el("div", "fb-stat");
		item.appendChild(el("span", "fb-stat-value", value));
		item.appendChild(el("span", "fb-stat-label", label));
		return item;
	};

	summary.appendChild(
		stat(
			formatCount(info.fileCount, "file"),
			info.asarSize != null ? formatSize(info.asarSize) : "Archive size unknown"
		)
	);
	summary.appendChild(
		stat(String(info.unpackedCount), plural(info.unpackedCount, "Unpacked file"))
	);
	summary.appendChild(stat(String(sourceMaps.length), plural(sourceMaps.length, "Source map")));

	const badges = el("div", "fb-summary-badges");
	if (info.electronVersion) {
		badges.appendChild(
			el("span", "el-badge el-badge--version", `Electron ${info.electronVersion}`)
		);
	}
	if (info.integrity) {
		const badge = integrityBadge(info);
		if (badge) badges.appendChild(badge);
	}
	if (badges.childElementCount > 0) summary.appendChild(badges);
	wrapper.appendChild(summary);

	if (!info.asarPath) {
		wrapper.appendChild(buildMissingArchive(info));
		container.appendChild(wrapper);
		return;
	}

	// ── View toggle ──
	const toggle = el("div", "el-view-toggle");
	const filesBtn = el("button", "el-toggle-btn", "Files");
	const packageBtn = el("button", "el-toggle-btn", "Package");
	toggle.appendChild(filesBtn);
	toggle.appendChild(packageBtn);
	wrapper.appendChild(toggle);

	const content = el("div", "el-content");
	wrapper.appendChild(content);
	container.appendChild(wrapper);

	let view: ElectronView = getTabState<ElectronView>(sessionId, "electron", "view") ?? "files";

	function show(next: ElectronView): void {
		view = next;
		setTabState(sessionId, "electron", "view", next);
		filesBtn.classList.toggle("el-toggle-btn--active", next === "files");
		packageBtn.classList.toggle("el-toggle-btn--active", next === "package");
		content.innerHTML = "";
		if (next === "files") renderFilesView(content);
		else renderPackageView(content, info, openPathFromPackage);
	}

	filesBtn.addEventListener("click", () => show("files"));
	packageBtn.addEventListener("click", () => show("package"));

	function openPathFromPackage(path: string): void {
		const saved = getTabState<string[]>(sessionId, "electron", "expanded");
		const expanded = new Set<string>(Array.isArray(saved) ? saved : []);
		for (const ancestor of ancestorPaths(path)) expanded.add(ancestor);
		setTabState(sessionId, "electron", "expanded", [...expanded]);
		setTabState(sessionId, "electron", "selected", path);
		// Drop any filter so the jump target is visible in the recreated tree.
		saveSearchState(sessionId, "electron", "", false);
		show("files");
	}

	function renderFilesView(target: HTMLElement): void {
		new FileBrowser<AsarEntry>({
			entries: files,
			sessionId,
			stateKey: "electron",
			widthKey: "electron-tree",
			preview: {
				read: (path, maxBytes, includeImage) =>
					window.api.readAsarFile(sessionId, path, maxBytes, includeImage)
			},
			badges: (entry) => {
				const entryBadges: FileBadge[] = [];
				if (entry.unpacked) entryBadges.push({ label: "unpacked", tone: "unpacked" });
				if (entry.link) {
					entryBadges.push({
						label: "link",
						tone: "link",
						title: `Links to ${entry.link}`
					});
				}
				if (entry.executable) entryBadges.push({ label: "executable", tone: "exec" });
				return entryBadges;
			},
			contextMenu: (entry) => [
				{ label: "Copy Path", action: () => copyText(entry.path, "Copied path") },
				{ label: "Copy Name", action: () => copyText(entry.name, "Copied name") }
			],
			emptyMessage: "This archive is empty."
		}).mount(target);
	}

	show(view);
}

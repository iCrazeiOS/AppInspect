import path from "node:path";
import { app, BrowserWindow, Menu } from "electron";
import { pruneCache } from "./analysis/orchestrator";
import { registerIPCHandlers } from "./ipc/handlers";

const APP_ROOT = path.join(app.getAppPath());

function createWindow(): BrowserWindow {
	const win = new BrowserWindow({
		title: "AppInspect",
		width: 1200,
		height: 800,
		minWidth: 800,
		minHeight: 500,
		show: false,
		backgroundColor: "#0d1117",
		titleBarStyle: "hidden",
		trafficLightPosition: process.platform === "darwin" ? { x: 14, y: 14 } : undefined,
		titleBarOverlay:
			process.platform === "win32"
				? {
						color: "#161b22",
						symbolColor: "#e6edf3",
						height: 36
					}
				: undefined,
		webPreferences: {
			preload: path.join(APP_ROOT, "dist/preload/index.js"),
			contextIsolation: true,
			nodeIntegration: false,
			sandbox: true,
			webSecurity: true
		}
	});

	win.loadFile(path.join(APP_ROOT, "src/renderer/index.html"));

	win.webContents.setVisualZoomLevelLimits(1, 1);
	win.webContents.on("zoom-changed", (event, direction) => {
		event.preventDefault();
		stepZoom(win, direction === "in" ? ZOOM_STEP : -ZOOM_STEP);
	});
	win.webContents.on("will-navigate", (event, url) => {
		if (url !== win.webContents.getURL()) event.preventDefault();
	});
	win.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
	win.webContents.on("will-attach-webview", (event) => {
		event.preventDefault();
	});

	win.once("ready-to-show", () => {
		win.maximize();
		win.show();
	});

	if (process.platform === "darwin") {
		win.webContents.on("dom-ready", () => {
			win.webContents.executeJavaScript('document.body.classList.add("platform-darwin")');
		});
	}

	registerIPCHandlers(win);
	return win;
}

const isDev = !app.isPackaged;

// Zoom levels are logarithmic (factor 1.2^level): -2..+3 is roughly 70%..170%
const MIN_ZOOM_LEVEL = -2;
const MAX_ZOOM_LEVEL = 3;
const ZOOM_STEP = 0.5;

function stepZoom(win: Electron.BaseWindow | undefined, delta: number): void {
	if (!(win instanceof BrowserWindow)) return;
	const { webContents } = win;
	const level = webContents.getZoomLevel() + delta;
	webContents.setZoomLevel(Math.min(MAX_ZOOM_LEVEL, Math.max(MIN_ZOOM_LEVEL, level)));
}

// ── Application menu with Edit shortcuts ──
const viewSubmenu: Electron.MenuItemConstructorOptions[] = [
	{ role: "reload" },
	{ role: "forceReload" },
	...(isDev ? [{ role: "toggleDevTools" as const }] : []),
	{ type: "separator" as const },
	{
		label: "Zoom In",
		accelerator: "CmdOrCtrl+=",
		click: (_item, win) => stepZoom(win, ZOOM_STEP)
	},
	{
		label: "Zoom Out",
		accelerator: "CmdOrCtrl+-",
		click: (_item, win) => stepZoom(win, -ZOOM_STEP)
	},
	{ role: "resetZoom" as const }
];

function buildMenuTemplate(win: BrowserWindow): Electron.MenuItemConstructorOptions[] {
	return [
		{
			label: "File",
			submenu: [
				{
					label: "Open File",
					accelerator: "CmdOrCtrl+O",
					click: () => win.webContents.send("open-file-menu")
				},
				{
					label: "Open Folder",
					accelerator: "CmdOrCtrl+Shift+O",
					click: () => win.webContents.send("open-folder-menu")
				},
				{
					label: "Close Tab",
					accelerator: "CmdOrCtrl+W",
					click: () => win.webContents.send("close-active-tab")
				}
			]
		},
		{
			label: "Edit",
			submenu: [
				{ role: "undo" },
				{ role: "redo" },
				{ type: "separator" },
				{ role: "cut" },
				{ role: "copy" },
				{ role: "paste" },
				{ role: "selectAll" }
			]
		},
		{
			label: "View",
			submenu: viewSubmenu
		}
	];
}

app.whenReady().then(() => {
	pruneCache();
	const win = createWindow();

	const menuTemplate = buildMenuTemplate(win);
	if (process.platform === "darwin") {
		menuTemplate.unshift({
			label: app.getName(),
			submenu: [
				{ role: "about" },
				{ type: "separator" },
				{ role: "hide" },
				{ role: "hideOthers" },
				{ role: "unhide" },
				{ type: "separator" },
				{ role: "quit" }
			]
		});
	}
	const menu = Menu.buildFromTemplate(menuTemplate);
	Menu.setApplicationMenu(menu);

	app.on("activate", () => {
		if (BrowserWindow.getAllWindows().length === 0) {
			createWindow();
		}
	});
});

app.on("window-all-closed", () => {
	if (process.platform !== "darwin") {
		app.quit();
	}
});

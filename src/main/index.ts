import { app, BrowserWindow, Menu } from "electron";
import path from "path";
import { registerIPCHandlers } from "./ipc/handlers";

const APP_ROOT = path.join(app.getAppPath());

function createWindow(): void {
  const win = new BrowserWindow({
    title: "AppInspect",
    width: 1200,
    height: 800,
    minWidth: 800,
    minHeight: 500,
    backgroundColor: "#0d1117",
    titleBarStyle: "hidden",
    trafficLightPosition: process.platform === "darwin" ? { x: 14, y: 14 } : undefined,
    titleBarOverlay: process.platform === "win32" ? {
      color: "#161b22",
      symbolColor: "#e6edf3",
      height: 36,
    } : undefined,
    webPreferences: {
      preload: path.join(APP_ROOT, "dist/preload/index.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  win.loadFile(path.join(APP_ROOT, "src/renderer/index.html"));

  if (process.platform === "darwin") {
    win.webContents.on("dom-ready", () => {
      win.webContents.executeJavaScript('document.body.classList.add("platform-darwin")');
    });
  }

  registerIPCHandlers(win);
}

const isDev = !app.isPackaged;

// ── Application menu with Edit shortcuts ──
const viewSubmenu: Electron.MenuItemConstructorOptions[] = [
  { role: "reload" },
  { role: "forceReload" },
  ...(isDev ? [{ role: "toggleDevTools" as const }] : []),
  { type: "separator" as const },
  { role: "zoomIn" as const },
  { role: "zoomOut" as const },
  { role: "resetZoom" as const },
];

const menuTemplate: Electron.MenuItemConstructorOptions[] = [
  {
    label: "Edit",
    submenu: [
      { role: "undo" },
      { role: "redo" },
      { type: "separator" },
      { role: "cut" },
      { role: "copy" },
      { role: "paste" },
      { role: "selectAll" },
    ],
  },
  {
    label: "View",
    submenu: viewSubmenu,
  },
];

// macOS needs the app name as first menu item
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
      { role: "quit" },
    ],
  });
}

app.whenReady().then(() => {
  const menu = Menu.buildFromTemplate(menuTemplate);
  Menu.setApplicationMenu(menu);

  createWindow();

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

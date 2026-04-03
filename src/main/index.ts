import { app, BrowserWindow } from "electron";
import path from "path";

function createWindow(): void {
  const win = new BrowserWindow({
    title: "Disect",
    width: 1200,
    height: 800,
    backgroundColor: "#0d1117",
    webPreferences: {
      preload: path.join(__dirname, "../preload/index.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  win.loadFile(path.join(__dirname, "../../src/renderer/index.html"));
}

app.whenReady().then(() => {
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

// macOS takes the menu bar / Dock name from the host bundle's Info.plist, not
// package.json, so `electron .` shows "Electron". Patch the dev bundle's name.
import { existsSync } from "node:fs";
import path from "node:path";

const PLISTBUDDY = "/usr/libexec/PlistBuddy";

if (process.platform === "darwin") {
	const plist = path.join(
		import.meta.dir,
		"../node_modules/electron/dist/Electron.app/Contents/Info.plist"
	);
	if (existsSync(plist) && existsSync(PLISTBUDDY)) {
		const name = (await Bun.file(path.join(import.meta.dir, "../package.json")).json())
			.productName;
		for (const key of ["CFBundleName", "CFBundleDisplayName"]) {
			const set = Bun.spawnSync([PLISTBUDDY, "-c", `Set :${key} ${name}`, plist]);
			if (set.exitCode !== 0) {
				Bun.spawnSync([PLISTBUDDY, "-c", `Add :${key} string ${name}`, plist]);
			}
		}
	}
}

import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const base = readFileSync("src/renderer/index.css", "utf8");
const cssDir = "src/renderer/css";
const parts = readdirSync(cssDir)
	.sort()
	.map((f) => readFileSync(join(cssDir, f), "utf8"));

writeFileSync("dist/renderer/index.css", [base, ...parts].join("\n"));

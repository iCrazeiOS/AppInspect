# Electron app support

Status: implemented on `feat/electron-app-analysis`.

AppInspect already analyses the native half of a macOS Electron app (the
`.app` bundle, `Electron Framework`, helpers, plists, entitlements). This
feature adds the half that matters for reversing: `Resources/app.asar`.

## Scope

In scope:

- Detect Electron bundles and read the runtime version, fuses, ASAR integrity.
- Parse `app.asar` as a lazy, read-only virtual filesystem (never extract the
  whole archive).
- Browse and preview archive files in a dedicated **Electron** tab.
- Show Electron facts on the Overview tab.
- Split `app.asar` into its contents in the Size treemap.
- Feed archive text files into the existing secret scanner.
- Emit Electron-specific security findings (fuses, integrity, renderer
  preferences, shipped source maps, CSP meta tags).
- Run the same Electron text checks on unpacked `Resources/app` directories
  when a bundle ships no `app.asar` (the archive file browser is unavailable,
  but renderer/runtime/CSP findings are still produced).
- Expose the new data through IPC, MCP (`get_section`, `list_asar`,
  `read_asar_file`) and the CLI (`--section electron`).

Out of scope (documented, not half-built):

- PE/ELF parsing, so Windows/Linux bundles cannot be analysed end-to-end. The ASAR layer itself is platform-independent.
- Browsing unpacked `Resources/app` directories in the Electron tab (security
  checks still run; only the archive browser is unavailable).
- Runtime-fetched JavaScript.
- JS beautifying, deobfuscation, V8 bytecode or source-map reconstruction.
- Executing or extracting archive contents.

## Invariants

- Archive content is untrusted. Every read is bounds-checked and every
  `.unpacked` path is contained with `safeJoin` + `realpath` + `isInside`.
- No full-archive reads. Header is parsed once; files are read by offset.
- Bounded work: header JSON ≤ 64 MB, ≤ 200,000 entries, depth ≤ 64, preview
  reads ≤ 512 KB, scans respect the existing bundle size settings.
- Renderer text always goes through `textContent`; never `innerHTML` with
  archive content.
- No new dependencies.

## Shared contracts

`src/shared/types.ts`:

```ts
export type ElectronFuseState = "enabled" | "disabled" | "removed";

export interface ElectronFuse {
	name: string;
	state: ElectronFuseState;
}

export interface ElectronAsarIntegrity {
	algorithm: string;
	expected: string;
	actual: string;
	valid: boolean;
}

export interface AsarEntry {
	name: string;
	/** POSIX path relative to the archive root. */
	path: string;
	size: number;
	isDirectory: boolean;
	unpacked?: boolean;
	executable?: boolean;
	/** Symlink target, relative to the entry's directory. */
	link?: string;
	children?: AsarEntry[];
}

export interface ElectronInfo {
	electronVersion?: string;
	asarPath?: string;
	asarSize?: number;
	fileCount: number;
	unpackedCount: number;
	packageJson?: { [key: string]: PlistValue };
	integrity?: ElectronAsarIntegrity;
	fuses: ElectronFuse[];
	/** Archive-relative paths of shipped .map files. */
	sourceMaps: string[];
	/** Archive-relative paths of .node addons. */
	nativeAddons: string[];
}

export interface AsarFileContent {
	path: string;
	size: number;
	truncated: boolean;
	binary: boolean;
	/** Present only when `binary` is false. */
	text?: string;
}
```

- `AnalysisResult` gains `electron: ElectronInfo | null` (top level, so
  per-tab export and MCP sections map directly).
- `buildAnalysisResult` takes `opts.electron` and defaults to `null`.
- `SizeTreeKind` gains `"asar"`.
- `ElectronTabData { tab: "electron"; data: { info: ElectronInfo; files: AsarEntry[] } }`
  joins `TabData`; `TabName` therefore includes `"electron"`.
- `InvokeChannelMap` gains:

```ts
"read-asar-file": {
	params: { sessionId: string; path: string; maxBytes?: number; includeImage?: boolean };
	result: AsarFileContent | null;
};
```

- `AppInspectAPI` gains `readAsarFile(sessionId, path, maxBytes?, includeImage?)`.

## Main-process modules

### `src/main/electron/asar.ts`

ASAR is a Chromium Pickle: `u32` pickle header, `u32` header size (at offset
4), `u32` data size, `u32` JSON length, JSON header, padding to 4 bytes, then
the concatenated file data. File offsets are relative to `8 + headerSize`.
Newer archives encode `offset` as a decimal string — accept both.

```ts
export interface AsarFileRecord {
	path: string;
	size: number;
	offset: number;
	unpacked: boolean;
	executable: boolean;
	link?: string;
}

export interface AsarArchive {
	path: string;
	size: number;
	dataOffset: number;
	headerHash: string;
	entries: AsarEntry[];
	files: Map<string, AsarFileRecord>;
	fileCount: number;
	unpackedCount: number;
}

export function readAsarHeader(archivePath: string): Result<AsarArchive>;
export function readAsarFile(
	archive: AsarArchive,
	entryPath: string,
	maxBytes: number
): Result<{ data: Buffer; truncated: boolean }>;
```

Rules:

- Reject: short files, header size < 8 or > 64 MB, header beyond EOF, JSON
  length beyond the header, invalid JSON, non-object root, non-object `files`,
  data region beyond EOF.
- Entry names: non-empty, ≤ 4096 chars, no `/`, `\`, NUL, `:`, and not `.`
  or `..`. Reject duplicate paths.
- `offset`/`size`: finite safe integers ≥ 0; packed entries must satisfy
  `offset + size <= dataSize`.
- Build `entries` (directories first, `localeCompare`) and `files` in one walk.
- `readAsarFile` resolves links (≤ 8 hops, no cycles, must stay in-archive),
  reads `.unpacked` from `<archive>.unpacked/<path>` only after
  `realpathSync` + `isInside`, and reads packed data from
  `dataOffset + offset`. Clamp allocation to `min(size, maxBytes)` and never
  trust `size` for the buffer length alone.
- The header hash is SHA-256 of the JSON bytes only (verified against
  Electron's `ElectronAsarIntegrity`).

### `src/main/electron/fuses.ts`

`@electron/fuses` writes `SENTINEL = "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"`, then
one version byte (`1`), one length byte, then one ASCII state byte per fuse:
`0x30` disabled, `0x31` enabled, `0x72` removed. Order:

```
RunAsNode, EnableCookieEncryption, EnableNodeOptionsEnvironmentVariable,
EnableNodeCliInspectArguments, EnableEmbeddedAsarIntegrityValidation,
OnlyLoadAppFromAsar, LoadBrowserProcessSpecificV8Snapshot,
GrantFileProtocolExtraPrivileges, WasmTrapHandlers
```

```ts
export function readFuses(binaryPath: string): ElectronFuse[];
```

Scan in 4 MB chunks with a sentinel-length overlap (do not read a 300 MB
framework into memory). Use the first sentinel; fat binaries repeat it per
slice. Return `[]` for missing files, no sentinel, wrong version, or a length
that does not fit the remaining bytes.

### `src/main/electron/detect.ts`

```ts
export function detectElectron(appRoot: string, isMacOS: boolean): ElectronInfo | null;
```

- Resources dir: `<root>/Contents/Resources` (macOS) or `<root>/resources`.
- Framework: `<root>/Contents/Frameworks/Electron Framework.framework`, with
  `Versions/A/...` and flat layouts both tried.
- `electronVersion` from the framework's `Resources/Info.plist`
  (`CFBundleVersion`).
- Detect when `app.asar` exists, a `Resources/app` directory with a
  `package.json` exists, or the framework exists; otherwise `null`.
- Parse the archive; on failure still return info with `fileCount: 0` and no
  `asarPath` (analysis must not fail because an archive is malformed).
- `packageJson` from the archive root or unpacked app directory
  (`package.json`, ≤ 1 MB, JSON object).
- Unpacked builds set `appPath`; `fileCount`/`unpackedCount` remain archive
  statistics.
- Integrity: look in the app's `Contents/Info.plist` for
  `ElectronAsarIntegrity`; accept a key ending in `app.asar`; compare
  `algorithm` `SHA256` case-insensitively against `archive.headerHash`.
  A completely absent table is only reported as missing on Electron 30+
  (when ASAR integrity was introduced) and never when the version is unknown;
  a table that exists without an `app.asar` entry is always reported.
- `sourceMaps` = runtime `.map` files, excluding `.d.ts.map`/`.d.mts.map`/
  `.d.cts.map` declaration maps; `nativeAddons` = `.node` (archive-relative).
- `unpackedCount` from the archive header.

### `src/main/electron/scan.ts`

```ts
export function readAsarTextFiles(archive: AsarArchive): BundleFileEntry[];
export function readAsarUnpackedHtmlFiles(archive: AsarArchive): BundleFileEntry[];
export function readAppDirectoryTextFiles(appDir: string): BundleFileEntry[];
export function scanElectron(info: ElectronInfo, files: BundleFileEntry[]): SecurityFinding[];
```

- Text extraction: only `isScannableExtension`, skip `.map` (they are huge;
  runtime maps are reported separately), skip files over `maxFileSizeMB`,
  stop at `maxBundleSizeMB`, skip NUL-containing content, prefix
  `relativePath` with `app.asar/`. Unpacked `.html`/`.htm` entries are read
  from the `.unpacked` sibling with the `app.asar.unpacked/` prefix.
- `readAppDirectoryTextFiles` applies the same limits to an unpacked app
  directory, skips `node_modules` and symlinks, and uses an `app/` prefix.
- Findings are grouped into `electron-*` categories, each with an independent
  20-finding cap:
  - `electron-fuses` — `RunAsNode` enabled **warning**;
    `EnableNodeOptionsEnvironmentVariable` and
    `EnableNodeCliInspectArguments` enabled **info**; `OnlyLoadAppFromAsar`
    or `EnableEmbeddedAsarIntegrityValidation` disabled **info**.
  - `electron-integrity` — ASAR header mismatch **critical** (evidence includes
    expected/actual); shipped source maps **info** (up to 3 paths).
  - `electron-renderer` — `nodeIntegration`, `nodeIntegrationInWorker`,
    `nodeIntegrationInSubFrames`, `contextIsolation: false`, `sandbox: false`
    and `webSecurity: false` **warning**; `webviewTag: true`,
    `allowRunningInsecureContent: true`, `enableBlinkFeatures` and
    `<webview allowpopups>` **info**. `<webview webpreferences="...">` uses the
    same check names as the JS prefs.
  - `electron-runtime` — `enableRemoteModule: true` **warning** before Electron
    14 (or with an unknown version) and **info** on 14+, where the module was
    removed. Preloads forwarding a non-literal `ipcRenderer` channel are
    **warning** unless a nearby guard validates that channel or a named helper
    receives only literal channels at every call site.
  - `electron-csp` — missing or weak Content-Security-Policy meta tags in
    shipped HTML; CSP delivered by HTTP headers or set at runtime
    (`session.webRequest`) is not visible to static analysis.
- `webPreferences` values accept `true`/`false` and the minified `!0`/`!1`
  forms. Checks run only on `.js .mjs .cjs .jsbundle .json .html .htm`, skip
  matches inside line/block/HTML comments, and report the first non-commented
  match per check per file.
- Command-line switch and cleartext `loadURL` scanning runs on first-party code
  only: dependency paths (`node_modules`, `vendor`, `third_party`, `3rdparty`)
  are skipped, as are docs/tests/lockfiles. Remote-debugging ports are
  correlated with the nearest non-commented `remote-debugging-address` within
  2000 characters, so an unrelated address elsewhere in the file cannot change
  the severity.
- Same-file `nodeIntegration: true` + `contextIsolation: false` emits one
  **critical** full-RCE finding and suppresses the individual
  `nodeIntegration`/`contextIsolation`/`sandbox` findings for that file. When
  no same-file combo exists, a cross-file fallback emits one **critical** if
  both settings appear in different first-party files.
- Vendor paths (`node_modules`, `vendor`, `third_party`, `3rdparty`, except the
  app's own package) are downgraded to **info**, tagged `vendor: true`, labelled
  `(vendor code)` and capped at 5 findings total.
- Dedupe by category + source + evidence; cap 20 per category.

### Pipeline integration

- `AnalysisSession` stores `electron: ElectronInfo | null` and the parsed
  `AsarArchive`, and exposes:
  - `getAsarTree(): AsarEntry[]`
  - `readAsarFile(entryPath, maxBytes, includeImage?): AsarFileContent | null`
- `analyseApp`: after framework detection, `detectElectron`; then asar text
  scan; merge findings; pass `electron` into `buildAnalysisResult`.
  Progress: `"Scanning Electron bundle..."` around 82%.
- `buildSizeTree(..., asar?: { path: string; entries: AsarEntry[] })`: when the
  walked file is the archive, emit kind `"asar"` with packed children
  (unpacked entries excluded — they are counted under `app.asar.unpacked`
  already) plus an `overhead` child for header/padding. Leave the file leaf
  unchanged when there are no packed files.
- `getSizeTree` passes the archive path + tree.
- `getTabData("electron")` returns `{ info, files }`.
- `read-asar-file` handler: text reads default to 512 KB and are hard-capped at
  32 MB for explicit full-content loads; image reads cap at 4 MB and embed a
  data URL only when `includeImage` is true. Return `AsarFileContent` or `null`.
- Export map adds `electron: "electron"`.
- No cache changes: the header read is cheap and reads are by offset.

## Implementation notes

- Electron's patched `fs` presents an `.asar` path as a directory with size 0.
  `readAsarHeader`, `readAsarFile` and the bundle walkers (`buildFileTree`,
  `buildSizeTree`, `readBundleFiles`) run inside `withoutAsar`, which sets
  `process.noAsar` for the duration of the synchronous block and restores it.
- `ElectronInfo.fileCount` counts files and links, not directories.
- Unpacked archive entries are read from `app.asar.unpacked` for preview but are
  not re-scanned: `readBundleFiles` already walks that directory on disk.
- For `Resources/app` builds the generic bundle scan already covers secrets, so
  `loadElectron` runs only `scanElectronText`; no duplicate credential findings.
- `detectElectron` accepts a `.app`, its `Contents` directory, or an unpacked
  `resources` root, so folder analysis can find the archive too.

## Renderer

- Sidebar: hidden `Electron` tab after Info.plist (`#tab-btn-electron`,
  `#tab-electron`). Visible when `result.electron` is non-null.
  `updateTabsForSourceType` becomes result-driven; if the active tab becomes
  hidden, fall back to overview.
- `src/renderer/tabs/electron.ts`:
  - Summary strip (files · size · Electron version · integrity badge).
  - View toggle **Files** / **Package** (reuse the Size tab's toggle styling
    pattern).
  - Files view: resizable left tree (`initPanelResize`, 340px, storage key
    `electron-tree`) + preview pane.
    - Path filtering with `SearchBar`, persisted via `search-state`; matched
      ancestors auto-expand.
    - Tree rows mirror the Files tab: toggle, dir/file icon, name, size,
      badges for `unpacked`/`link`/`executable`.
    - Selection + expansions persist in `tab-state` under `electron`.
    - Preview: `readAsarFile(..., 512 KB, true)`; stale responses ignored with a
      request counter; monospace `<pre>` with syntax highlighting for source
      files and a Beautify/Raw toggle (Prettier standalone); pretty-print JSON
      when it parses. Source previews up to the 512 KB preview cap are
      highlighted automatically; larger loaded files show a **Highlight
      anyway** action. Truncated text disables Beautify and offers **Load full
      content** (32 MB cap). Raster images render from a data URL and fall back
      to a notice when larger than 4 MB or undecodable. Images open fitted to
      the viewport with zoom out / reset / zoom in header buttons, trackpad
      pinch (ctrl+wheel) anchored under the cursor, and normal two-finger
      scrolling to pan once zoomed.
    - Tree icons classify directories, images, code, data, fonts, archives,
      media, binaries and docs.
  - Package view: package.json facts, dependencies, fuses with state badges,
    integrity card, source maps and native addons lists.
  - Use `EmptyState`, `el`, `formatCount`, `formatSize`, `plural`,
    `makeCopyable`, `showToast`.
- `overview.ts`: Electron card (version, ASAR size/files, integrity badge,
  fuses enabled, source maps, native addons) when `data.electron`.
- `size-treemap.ts`: map kind `"asar"` → file role, describe as
  "app.asar archive"; no new colour role.
- `css/electron.css` (`el-` prefix, tab indentation not required in CSS —
  match existing 2-space style): summary, split panes, tree rows, badges,
  preview code block, package cards. Reuse existing CSS variables.

## MCP / CLI

- `SECTION_NAMES` gains `"electron"` (both MCP and CLI).
- `get_section("electron")` returns `ElectronInfo`.
- New tools:
  - `list_asar`: `{ filter?, offset?, limit?, path? }` → `{ total, offset,
    limit, files: { path, size, unpacked }[] }` (files only, flat, sorted).
  - `read_asar_file`: `{ file, maxBytes?, path? }` → `AsarFileContent`.
- Update `analyse_file` / `get_section` descriptions and the README tool
  table.

## Tests

- `asar.test.ts`: fixture builder (header + data + `.unpacked`), nested dirs,
  string offsets, tree order, reads, truncation, links, unpacked reads,
  escaping unpacked link rejected, malformed header/JSON/offset/data region,
  duplicate and traversal names, header hash.
- `fuses.test.ts`: sentinel at a chunk boundary, all three states, short wire,
  missing sentinel, missing file.
- `detect.test.ts`: temp `.app` layout with framework plist, asar, package.json,
  integrity match/mismatch, source maps, native addons, unreadable asar.
- `scan.test.ts`: fuse/integrity/source-map findings and the category
  taxonomy, minified `!0`/`!1` values, comment and extension filtering, vendor
  classification/cap, `<webview>` markup, the combined critical and cross-file
  fallback, webPreferences patterns, scan budgets, `.map` skipped.
- `size-tree.test.ts`: asar split, unpacked exclusion, overhead child, no
  packed files falls back to a file leaf.
- `asar-preview.test.ts`: raster MIME detection and unsupported extensions.
- `beautify.test.ts`: parser detection, JSON/JS/TS/CSS/HTML formatting and
  invalid input.
- Existing tests must keep passing.

## Acceptance

- `bun run typecheck`, `bun run check`, `bun test`, `bun run build` pass.
- CLI against `/Applications/vesktop.app`:
  - `--section electron` reports Electron 40.4.0, 39 files, integrity hash
    matching, 8 fuses, 7 source maps.
  - SARIF includes Electron findings.
- MCP: `get_section electron`, `list_asar`, `read_asar_file` work.
- Desktop: Electron tab appears for Vesktop, tree/preview/package views work,
  Size treemap splits `app.asar`, Overview shows the Electron card, Security
  lists Electron findings. Non-Electron apps are unchanged.

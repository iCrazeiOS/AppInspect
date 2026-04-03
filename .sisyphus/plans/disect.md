# Disect — IPA Reverse Engineering Scanner

## TL;DR

> **Quick Summary**: Build "Disect", a cross-platform desktop app (Electron + Bun + TypeScript) that lets users drop/open a decrypted IPA file and instantly browse 10 tabs of reverse engineering analysis — strings, Mach-O headers, linked libraries, ObjC classes, entitlements, security findings, and more.
> 
> **Deliverables**:
> - Working Electron app with drag-drop + file picker for IPA loading
> - Pure TypeScript Mach-O parser (headers, load commands, chained fixups, sections)
> - 10 analysis tabs with regex search/filter and JSON export
> - Dark-only UI with clean tabbed interface and subtle animations
> - Unit tests for Mach-O parser via `bun test`
> 
> **Estimated Effort**: Large
> **Parallel Execution**: YES — 7 waves
> **Critical Path**: Scaffold → Fat/Header parser → Load commands → Chained fixups → String/ObjC extraction → RPC integration → UI tabs

---

## Context

### Original Request
Build an app that allows a user to drag-drop a decrypted IPA file into the window, extract it, and display useful reverse engineering info in different tabs. Use Electron with TypeScript (Bun as runtime). Codebase should be minimal, non-bloated, fast, with a nice-looking dark UI and basic animations.

### Interview Summary
**Key Discussions**:
- **All 10 tabs selected**: Overview, Strings, Headers, Libraries, Symbols, Classes & Protocols, Entitlements, Info.plist, Security Scan, File Browser
- **UI**: Vanilla HTML/CSS/TS — no framework. Dark-only theme.
- **Search**: Regex-capable filter on all data lists
- **Export**: JSON (per-tab or full analysis)
- **Mach-O parser**: Pure TypeScript, referencing macmade/macho (C++) as implementation guide
- **CFStrings**: Yes — resolve `__DATA.__cfstring` structs pointing into `__TEXT.__cstring`
- **Security tab**: Flag leaked API keys, DB creds, hardcoded URLs/tokens, insecure API imports, binary hardening checks
- **Multi-binary**: Analyze all binaries in IPA (main + embedded frameworks) with binary selector
- **Name**: "Disect"
- **Platforms**: macOS, Windows, Linux

**Research Findings**:
- **Electron IPC**: Type-safe main↔renderer communication via `ipcMain.handle()` / `ipcRenderer.invoke()` through a preload script with `contextBridge.exposeInMainWorld()`
- **Electron project layout**: `src/main/` (main process), `src/renderer/` (UI), `src/preload/` (bridge), `src/shared/` (types)
- **IPA structure**: ZIP → `Payload/*.app/` containing Mach-O binary, Info.plist, Frameworks/, embedded.mobileprovision
- **Mach-O format**: header → load commands → segments → sections, all parseable via DataView on ArrayBuffer
- **Chained fixups**: iOS 14+ uses `LC_DYLD_CHAINED_FIXUPS` — every pointer in `__DATA` is encoded, not a real address. Must resolve before any data section parsing.

### Metis Review
**Critical Findings** (addressed):
- **`Bun.Archive` is TAR-only** — cannot extract IPAs. Mitigation: Use `fflate` (zero-dep, TS-native ZIP library).
- **Chained fixups are a prerequisite dependency** — blocks CFString resolution, ObjC class parsing, symbol resolution. Mitigation: Build fixup resolver as first parser milestone after load commands.
- **Encrypted IPA detection** — App Store IPAs have FairPlay DRM. User said "already decrypted" but we still detect `cryptid != 0` and warn prominently.
- **Electron + Bun runtime**: Electron is mature and well-supported across macOS/Windows/Linux. Use `electron-forge` or manual setup with Bun as the build tool. Drag-drop and file dialogs are first-class Electron features.

**Scope Locks** (from Metis):
- Swift metadata: `__swift5_reflstr` plain strings ONLY. No type descriptors, no demangling.
- ObjC depth: Class names + method name strings. No ivar types, no protocol recursion, no category merging.
- Chained fixup format: `DYLD_CHAINED_PTR_64_OFFSET` (format 6) only — covers standard iOS device binaries.
- arm64e PAC: Strip high bits universally. No PAC verification.
- One IPA at a time. "Open new" replaces current.
- Export: JSON only. No CSV, no PDF.
- Electron renderer: `nodeIntegration: false`, `contextIsolation: true` — all main-process access via preload bridge only.

---

## Work Objectives

### Core Objective
Build a cross-platform desktop IPA analyzer that parses Mach-O binaries in pure TypeScript and displays comprehensive reverse engineering data across 10 tabbed views, with regex search and JSON export.

### Concrete Deliverables
- Electron desktop app (macOS/Windows/Linux)
- Pure TypeScript Mach-O parser with fat binary support
- 10 analysis tabs: Overview, Strings, Headers, Libraries, Symbols, Classes, Entitlements, Info.plist, Security Scan, File Browser
- Regex search/filter on all data lists
- JSON export (per-tab and full analysis)
- Unit test suite for Mach-O parser

### Definition of Done
- [ ] `bun run start` launches the Electron app, window renders with dark theme
- [ ] Opening a test IPA populates all 10 tabs with correct data
- [ ] Regex search filters results correctly across all data tabs
- [ ] JSON export produces valid, complete JSON files
- [ ] `bun test` passes all parser unit tests
- [ ] Encrypted IPA shows detection warning, partial data in parseable tabs

### Must Have
- File picker via Electron `dialog.showOpenDialog()` (native, works across all platforms)
- Drag-drop via Electron's native file drop support (full drag-drop with file paths)
- Pure TypeScript Mach-O parser — no native dependencies, no shelling out to otool/class-dump
- `fflate` for ZIP extraction (not Bun.Archive which is TAR-only)
- `bplist-parser` for binary plist parsing
- Chained fixups resolver before any `__DATA` section parsing
- Fat/universal binary support (0xCAFEBABE detection, slice extraction)
- Encryption detection (`LC_ENCRYPTION_INFO_64.cryptid`) with prominent UI warning
- Big-endian handling for code signature blobs
- Binary selector for choosing which binary to analyze (main app vs embedded frameworks)
- Lazy tab loading — only request data from main process when tab is activated
- DataView for binary parsing, BigInt for 64-bit values
- Load command iteration by `cmdsize`, never by struct size
- Pin Electron to exact version in package.json
- Preload script with `contextBridge` for secure main↔renderer IPC
- `contextIsolation: true` and `nodeIntegration: false` on all BrowserWindows

### Must NOT Have (Guardrails)
- No UI framework (React, Vue, Svelte, etc.) — vanilla HTML/CSS/TS only
- No Swift name demangling (multi-week rabbit hole)
- No Swift type descriptors beyond `__swift5_reflstr` reflection strings
- No ObjC protocol recursive traversal, ivar type parsing, or category merging
- No multiple simultaneous IPA sessions — one at a time
- No streaming ZIP extraction complexity — `fflate.unzipSync` is sufficient
- No export formats beyond JSON
- No disassembly, no dynamic analysis
- No `Bun.Archive` usage (TAR-only, cannot handle ZIP)
- No `nodeIntegration: true` in renderer — all IPC through preload bridge
- No `remote` module usage — deprecated and insecure
- No over-abstraction or premature generalization — minimal, direct code
- No bloated animations — limit to: tab transitions, loading spinners, list fade-in, drop zone pulse
- No assumption that `__DATA` pointers are valid addresses (chained fixups!)
- No parsing `embedded.mobileprovision` as binary plist (it's CMS/DER wrapping XML)
- No Electrobun — switched to Electron for maturity, drag-drop support, and cross-platform stability

---

## Verification Strategy

> **ZERO HUMAN INTERVENTION** — ALL verification is agent-executed. No exceptions.

### Test Decision
- **Infrastructure exists**: NO (greenfield)
- **Automated tests**: YES — parser only (bun test)
- **Framework**: `bun test` (built-in)
- **Test fixtures**: Minimal Mach-O binaries with known contents, created as part of test setup

### QA Policy
Every task MUST include agent-executed QA scenarios.
Evidence saved to `.sisyphus/evidence/task-{N}-{scenario-slug}.{ext}`.

- **Desktop App UI**: Use Playwright — launch Electron app, interact, assert DOM, screenshot
- **Mach-O Parser**: Use Bash (`bun test`) — run tests, assert pass counts
- **IPC Integration**: Use Bash (bun REPL or test script) — call IPC handlers, verify responses
- **File Operations**: Use Bash — verify files created, check JSON validity

---

## Execution Strategy

### Parallel Execution Waves

```
Wave 1 (Foundation — start immediately):
├── Task 1:  Electron project scaffold + config + build verification [quick]
├── Task 2:  Shared TypeScript types (RPC schema, analysis data types) [quick]
├── Task 3:  Fat binary + Mach-O header parser + tests [deep]
└── Task 4:  IPA extraction module (fflate + app bundle discovery) + tests [quick]

Wave 2 (Core Parser — after Wave 1):
├── Task 5:  Load command parser + segment/section enumeration + tests (depends: 3) [deep]
├── Task 6:  Info.plist + mobileprovision parser + tests (depends: 4) [unspecified-high]
└── Task 7:  App shell UI — window, dark theme, tab navigation, drop zone, file picker (depends: 1, 2) [visual-engineering]

Wave 3 (Deep Parser — after Wave 2):
├── Task 8:  Chained fixups resolver (LC_DYLD_CHAINED_FIXUPS) + tests (depends: 5) [ultrabrain]
├── Task 9:  Code signature + entitlements parser + tests (depends: 5) [deep]
├── Task 10: Symbol table + export trie parser + tests (depends: 5) [deep]
└── Task 11: Shared UI components — data table, search bar, JSON tree, loading states (depends: 7) [visual-engineering]

Wave 4 (Section Parsers — after Wave 3):
├── Task 12: String extraction (__cstring, __cfstring, __objc_methname, __swift5_reflstr) + tests (depends: 8) [deep]
├── Task 13: ObjC class + method name extraction + tests (depends: 8) [deep]
├── Task 14: Security scan engine (pattern matching + binary hardening checks) + tests (depends: 5, 10, 12) [deep]
└── Task 15: RPC integration — analysis orchestrator + per-tab data handlers (depends: 2, 4, 5, 6, 8, 9, 10, 12, 13) [unspecified-high]

Wave 5 (UI Tabs — after Wave 4):
├── Task 16: Overview tab + Libraries tab + Headers tab (depends: 7, 11, 15) [visual-engineering]
├── Task 17: Strings tab + Symbols tab (depends: 11, 15) [visual-engineering]
├── Task 18: Classes tab + Entitlements tab + Info.plist tab (depends: 11, 15) [visual-engineering]
├── Task 19: Security Scan tab (depends: 11, 14, 15) [visual-engineering]
└── Task 20: File Browser tab (depends: 11, 15) [visual-engineering]

Wave 6 (Features — after Wave 5):
├── Task 21: Regex search/filter across all data tabs (depends: 16-20) [unspecified-high]
├── Task 22: JSON export — per-tab and full analysis (depends: 15, 16-20) [unspecified-high]
├── Task 23: Binary selector — choose main app vs embedded frameworks (depends: 15, 16) [unspecified-high]
└── Task 24: Error handling + encrypted IPA detection UI (depends: 7, 15) [unspecified-high]

Wave FINAL (After ALL tasks — 4 parallel reviews, then user okay):
├── Task F1: Plan compliance audit (oracle)
├── Task F2: Code quality review (unspecified-high)
├── Task F3: Real manual QA (unspecified-high)
└── Task F4: Scope fidelity check (deep)
-> Present results -> Get explicit user okay

Critical Path: T1 → T3 → T5 → T8 → T12/T13 → T15 → T16-T20 → T21-T24 → F1-F4 → user okay
Parallel Speedup: ~65% faster than sequential
Max Concurrent: 5 (Waves 4 & 5)
```

### Dependency Matrix

| Task | Depends On | Blocks | Wave |
|------|-----------|--------|------|
| 1 | — | 7 | 1 |
| 2 | — | 7, 15 | 1 |
| 3 | — | 5 | 1 |
| 4 | — | 6, 15 | 1 |
| 5 | 3 | 8, 9, 10, 14 | 2 |
| 6 | 4 | 15 | 2 |
| 7 | 1, 2 | 11, 16-20, 24 | 2 |
| 8 | 5 | 12, 13, 15 | 3 |
| 9 | 5 | 15 | 3 |
| 10 | 5 | 14, 15 | 3 |
| 11 | 7 | 16-20 | 3 |
| 12 | 8 | 14, 15 | 4 |
| 13 | 8 | 15 | 4 |
| 14 | 5, 10, 12 | 19 | 4 |
| 15 | 2, 4, 5, 6, 8, 9, 10, 12, 13 | 16-24 | 4 |
| 16 | 7, 11, 15 | 21, 22 | 5 |
| 17 | 11, 15 | 21, 22 | 5 |
| 18 | 11, 15 | 21, 22 | 5 |
| 19 | 11, 14, 15 | 21, 22 | 5 |
| 20 | 11, 15 | 21, 22 | 5 |
| 21 | 16-20 | — | 6 |
| 22 | 15, 16-20 | — | 6 |
| 23 | 15, 16 | — | 6 |
| 24 | 7, 15 | — | 6 |

### Agent Dispatch Summary

- **Wave 1**: **4** — T1 → `quick`, T2 → `quick`, T3 → `deep`, T4 → `quick`
- **Wave 2**: **3** — T5 → `deep`, T6 → `unspecified-high`, T7 → `visual-engineering`
- **Wave 3**: **4** — T8 → `ultrabrain`, T9 → `deep`, T10 → `deep`, T11 → `visual-engineering`
- **Wave 4**: **4** — T12 → `deep`, T13 → `deep`, T14 → `deep`, T15 → `unspecified-high`
- **Wave 5**: **5** — T16-T20 → `visual-engineering`
- **Wave 6**: **4** — T21-T24 → `unspecified-high`
- **FINAL**: **4** — F1 → `oracle`, F2 → `unspecified-high`, F3 → `unspecified-high`, F4 → `deep`

---

## TODOs

- [ ] 1. Electron Project Scaffold + Config + Build Verification

  **What to do**:
  - Set up the project directory structure:
    - `src/main/index.ts` — Electron main process entry
    - `src/preload/index.ts` — preload script with `contextBridge`
    - `src/renderer/index.html` — renderer HTML
    - `src/renderer/index.ts` — renderer entry script
    - `src/renderer/index.css` — renderer styles (placeholder)
    - `src/shared/` — shared types (created in Task 2)
  - Install dependencies: `bun add electron fflate bplist-parser plist` + `bun add -d electron-builder` (for future packaging)
  - Create `src/main/index.ts` with:
    - `app.whenReady()` → create BrowserWindow (title "Disect", 1200x800, `backgroundColor: '#0d1117'`)
    - BrowserWindow options: `webPreferences: { preload: path.join(__dirname, '../preload/index.js'), contextIsolation: true, nodeIntegration: false }`
    - Load `src/renderer/index.html` via `win.loadFile()` or `win.loadURL()` with file:// protocol
    - Handle `app.on('window-all-closed')` for proper quit on macOS
  - Create `src/preload/index.ts` with a minimal `contextBridge.exposeInMainWorld('api', {})` stub (fleshed out in Task 15)
  - Create minimal `src/renderer/index.html` with dark background placeholder
  - Create `src/renderer/index.ts` — empty for now (wired in Task 7)
  - Set up `package.json` with:
    - `"main": "dist/main/index.js"` — Electron entry point
    - Scripts: `"start": "bun run build && electron ."`, `"build": "bun build src/main/index.ts --outdir dist/main --target node && bun build src/preload/index.ts --outdir dist/preload --target node && bun build src/renderer/index.ts --outdir dist/renderer --target browser"`, `"dev": "bun run build && electron ."`
    - Alternatively: use a simple build script that compiles all three entry points
  - Create `tsconfig.json` with strict mode, ES2022 target, moduleResolution node
  - Pin Electron to exact version in package.json
  - Verify `bun run start` launches the app and a window appears with the dark background

  **Must NOT do**:
  - Do not add any UI framework dependencies
  - Do not set up IPC handlers yet (that's Task 15)
  - Do not use `nodeIntegration: true` — security risk
  - Do not use `@electron-forge` — keep the build simple with direct `bun build` + `electron .`

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Scaffold task — follow Electron docs, create files, verify build. Electron is well-documented.
  - **Skills**: []
  - **Skills Evaluated but Omitted**:
    - `playwright`: Not needed — just verify app launches via `bun run start`

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 2, 3, 4)
  - **Blocks**: Task 7 (app shell UI)
  - **Blocked By**: None (can start immediately)

  **References**:

  **External References**:
  - Electron Quick Start: `https://www.electronjs.org/docs/latest/tutorial/quick-start` — project structure, main + renderer + preload setup
  - Electron BrowserWindow API: `https://www.electronjs.org/docs/latest/api/browser-window` — constructor options (title, frame, webPreferences, backgroundColor)
  - Electron contextBridge: `https://www.electronjs.org/docs/latest/api/context-bridge` — `contextBridge.exposeInMainWorld()` for secure IPC
  - Electron Process Model: `https://www.electronjs.org/docs/latest/tutorial/process-model` — main vs renderer vs preload architecture
  - Electron Security: `https://www.electronjs.org/docs/latest/tutorial/security` — why `contextIsolation: true` and `nodeIntegration: false`

  **WHY Each Reference Matters**:
  - Quick Start: Follow the exact init sequence — Electron requires main/preload/renderer separation
  - BrowserWindow: Constructor options for initial window (dark theme via backgroundColor, frame size, webPreferences)
  - contextBridge: The ONLY safe way to expose main-process APIs to renderer — misconfigure this and IPC breaks or is insecure
  - Process Model: Understanding the 3-process architecture is essential for all downstream tasks
  - Security: `contextIsolation` and `nodeIntegration` settings are non-negotiable for a safe Electron app

  **Acceptance Criteria**:

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: App launches and window appears
    Tool: Bash
    Preconditions: Project initialized, dependencies installed
    Steps:
      1. Run `bun run start`
      2. Wait up to 15 seconds for process to start
      3. Check process is running (no crash/exit)
    Expected Result: Process starts without errors, Electron window opens with dark background
    Failure Indicators: Non-zero exit code, "Error" in stdout/stderr, process exits immediately
    Evidence: .sisyphus/evidence/task-1-app-launches.txt

  Scenario: Project structure is correct
    Tool: Bash
    Preconditions: Project initialized
    Steps:
      1. Verify `src/main/index.ts` exists and imports from "electron"
      2. Verify `src/preload/index.ts` exists and uses contextBridge
      3. Verify `src/renderer/index.html` exists
      4. Verify `src/renderer/index.ts` exists
      5. Verify `package.json` has electron, fflate, bplist-parser, plist as dependencies
      6. Verify `package.json` has `"main"` pointing to dist/main entry
    Expected Result: All files exist with correct content
    Failure Indicators: Missing files, missing dependencies, wrong import paths
    Evidence: .sisyphus/evidence/task-1-project-structure.txt
  ```

  **Commit**: YES
  - Message: `chore(scaffold): init Electron project with main/preload/renderer setup`
  - Files: `package.json`, `tsconfig.json`, `src/main/index.ts`, `src/preload/index.ts`, `src/renderer/index.html`, `src/renderer/index.ts`, `src/renderer/index.css`
  - Pre-commit: `bun run build`

- [ ] 2. Shared TypeScript Types (RPC Schema + Analysis Data Types)

  **What to do**:
  - Create `src/shared/types.ts` with all analysis data interfaces:
    - `IPAInfo`: bundle path, app name, binaries list
    - `MachOHeader`: magic, cputype, cpusubtype, filetype, flags, ncmds
    - `LoadCommand`: cmd type, cmdsize, parsed data union
    - `Segment`: name, vmaddr, vmsize, fileoff, filesize, sections list
    - `Section`: sectname, segname, addr, size, offset, flags
    - `StringEntry`: value, section source, offset
    - `LinkedLibrary`: name, version, weak flag
    - `Symbol`: name, type (exported/imported), address
    - `ObjCClass`: name, superclass, methods list
    - `Entitlement`: key, value
    - `SecurityFinding`: severity (info/warning/critical), category, message, evidence
    - `BinaryHardening`: pie, arc, stackCanaries, encrypted, stripped
    - `FileEntry`: name, path, size, isDirectory
    - `AnalysisResult`: top-level container with all tab data
  - Create `src/shared/ipc-types.ts` with IPC channel definitions and payload types:
    - **Invoke channels** (renderer → main, request/response via `ipcRenderer.invoke`):
      - `'analyze-ipa'`: `{ path: string }` → `AnalysisResult`
      - `'get-tab-data'`: `{ tab: string, binaryIndex: number }` → `TabData`
      - `'export-json'`: `{ tabs?: string[] }` → `string`
      - `'open-file-picker'`: `void` → `string | null`
      - `'analyze-binary'`: `{ binaryIndex: number }` → `AnalysisResult`
    - **Send channels** (main → renderer, one-way via `webContents.send`):
      - `'update-progress'`: `{ phase: string, percent: number, message: string }`
      - `'analysis-complete'`: `void`
      - `'analysis-error'`: `{ message: string }`
    - Export typed channel maps: `type InvokeChannelMap = { 'analyze-ipa': { params: {...}, result: ... }, ... }`
    - This enables typed IPC wrappers in the preload script
  - Use discriminated unions where appropriate (e.g., LoadCommand variants)
  - Keep types strict — no `any`, no optional where data is always present

  **Must NOT do**:
  - Do not implement any logic — types only
  - Do not add runtime code to these files
  - Do not use `any` or `unknown` as escape hatches

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Pure type definitions — no logic, just interfaces
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 1, 3, 4)
  - **Blocks**: Tasks 7, 15
  - **Blocked By**: None

  **References**:

  **External References**:
  - Electron IPC: `https://www.electronjs.org/docs/latest/tutorial/ipc` — ipcMain.handle / ipcRenderer.invoke pattern for request-response, webContents.send / ipcRenderer.on for one-way messages
  - Electron contextBridge: `https://www.electronjs.org/docs/latest/api/context-bridge` — `exposeInMainWorld()` to create typed API object in renderer
  - Mach-O header struct: Reference `mach_header_64` fields — `magic` (0xFEEDFACF), `cputype` (ARM64=0x0100000C), `filetype` (MH_EXECUTE=2, MH_DYLIB=6), `flags` (MH_PIE=0x200000)
  - Load command types: `LC_SEGMENT_64`, `LC_LOAD_DYLIB`, `LC_ENCRYPTION_INFO_64`, `LC_CODE_SIGNATURE`, `LC_DYLD_CHAINED_FIXUPS`, `LC_SYMTAB`, `LC_BUILD_VERSION`, `LC_UUID`, `LC_MAIN`

  **WHY Each Reference Matters**:
  - Electron IPC: The typed channel maps must match between `ipcMain.handle(channel)` and `ipcRenderer.invoke(channel)` — the preload script bridges them
  - contextBridge: The renderer accesses main-process functionality ONLY through the exposed API object — type it correctly here for downstream safety
  - Mach-O structs: The parser types must map 1:1 to the C struct fields to ensure correct binary parsing downstream

  **Acceptance Criteria**:
  - [ ] `src/shared/types.ts` compiles with no errors under strict TypeScript
  - [ ] `src/shared/ipc-types.ts` compiles and exports typed IPC channel maps
  - [ ] Zero uses of `any` or `unknown` in type definitions

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Types compile cleanly
    Tool: Bash
    Preconditions: Files created
    Steps:
      1. Run `bunx tsc --noEmit src/shared/types.ts src/shared/ipc-types.ts`
      2. Check exit code is 0
    Expected Result: No type errors, exit code 0
    Failure Indicators: Type errors in output, non-zero exit code
    Evidence: .sisyphus/evidence/task-2-types-compile.txt

  Scenario: No `any` usage in type files
    Tool: Bash
    Preconditions: Files created
    Steps:
      1. Search for `: any` or `as any` in src/shared/types.ts and src/shared/ipc-types.ts
    Expected Result: Zero matches
    Failure Indicators: Any match found
    Evidence: .sisyphus/evidence/task-2-no-any.txt
  ```

  **Commit**: YES
  - Message: `feat(types): add shared IPC channel types and analysis data types`
  - Files: `src/shared/types.ts`, `src/shared/ipc-types.ts`

- [ ] 3. Fat Binary + Mach-O Header Parser + Tests

  **What to do**:
  - Create `src/main/parser/macho.ts`:
    - `parseFatHeader(buffer: ArrayBuffer)`: Detect fat magic (`0xCAFEBABE` big-endian / `0xBEBAFECA` little-endian), read `fat_arch` entries (cputype, cpusubtype, offset, size), return slice descriptors. For non-fat files, return single slice covering entire buffer.
    - `parseMachOHeader(buffer: ArrayBuffer, offset: number)`: Read `mach_header_64` at offset — magic (`0xFEEDFACF`/`0xCFFAEDFE`), cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags. Detect endianness from magic. Also handle 32-bit headers (`0xFEEDFACE`) with a clear "32-bit not supported" indication.
    - Export a `MachOFile` type that contains the header + base offset for downstream parsing
  - Use `DataView` for all binary reads, respecting endianness from magic value
  - Use `BigInt` for any 64-bit values
  - Create `src/main/parser/__tests__/macho.test.ts`:
    - Test fat binary detection (craft a minimal fat header in a Uint8Array)
    - Test single-arch passthrough (non-fat Mach-O goes through as single slice)
    - Test header field extraction (magic, cputype, filetype, flags)
    - Test endianness handling
    - Test invalid/corrupted magic detection (returns error, doesn't crash)
  - Create a test helper `src/main/parser/__tests__/fixtures.ts` that builds minimal Mach-O byte arrays in memory (no external files needed)

  **Must NOT do**:
  - Do not parse load commands (that's Task 5)
  - Do not read files from disk in the parser — it takes ArrayBuffer input
  - Do not handle compressed slices in fat binaries (iOS IPAs don't use them)

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: Binary format parsing requires precision — endianness, struct offsets, BigInt. TDD workflow.
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 1, 2, 4)
  - **Blocks**: Task 5 (load commands)
  - **Blocked By**: None

  **References**:

  **External References**:
  - macmade/macho C++ reference: `https://github.com/macmade/macho` → `lib-macho/` directory — the C++ parser's fat header and Mach-O header parsing logic
  - Apple Mach-O Reference: `mach_header_64` struct layout — magic (4 bytes), cputype (4), cpusubtype (4), filetype (4), ncmds (4), sizeofcmds (4), flags (4), reserved (4) = 32 bytes total
  - Fat header: `fat_header` is 8 bytes (magic + nfat_arch), each `fat_arch` is 20 bytes (cputype, cpusubtype, offset, size, align) — ALL big-endian regardless of slice endianness
  - Constants: `MH_MAGIC_64=0xFEEDFACF`, `MH_CIGAM_64=0xCFFAEDFE`, `FAT_MAGIC=0xCAFEBABE`, `FAT_CIGAM=0xBEBAFECA`, `CPU_TYPE_ARM64=0x0100000C`, `MH_EXECUTE=2`, `MH_DYLIB=6`

  **WHY Each Reference Matters**:
  - macmade/macho: Provides verified C++ implementation to cross-reference our TS parser logic against
  - Struct layouts: Exact byte offsets are critical — off by one byte and everything downstream is garbage
  - Fat header endianness: Fat headers are ALWAYS big-endian even when slices are little-endian — must use `getUint32(offset, false)` for fat, `getUint32(offset, true)` for arm64 Mach-O

  **Acceptance Criteria**:
  - [ ] `bun test src/main/parser/__tests__/macho.test.ts` → all tests pass
  - [ ] Fat binary with multiple slices parsed correctly
  - [ ] Single-arch binary returns one slice
  - [ ] Invalid magic returns descriptive error

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Parser tests all pass
    Tool: Bash
    Preconditions: Parser and test files created
    Steps:
      1. Run `bun test src/main/parser/__tests__/macho.test.ts`
      2. Check all tests pass
    Expected Result: 0 failures, ≥4 tests pass
    Failure Indicators: Any test failure, crash, or timeout
    Evidence: .sisyphus/evidence/task-3-parser-tests.txt

  Scenario: Corrupted input doesn't crash
    Tool: Bash
    Preconditions: Parser created
    Steps:
      1. In test file, pass a 4-byte buffer with random bytes to parseFatHeader
      2. Verify it returns an error result, not an exception
    Expected Result: Graceful error handling, no uncaught exceptions
    Failure Indicators: Uncaught exception, process crash
    Evidence: .sisyphus/evidence/task-3-corrupt-input.txt
  ```

  **Commit**: YES
  - Message: `feat(parser): fat binary and Mach-O header parser with tests`
  - Files: `src/main/parser/macho.ts`, `src/main/parser/__tests__/macho.test.ts`, `src/main/parser/__tests__/fixtures.ts`
  - Pre-commit: `bun test`

- [ ] 4. IPA Extraction Module + App Bundle Discovery + Tests

  **What to do**:
  - Create `src/main/ipa/extractor.ts`:
    - `extractIPA(ipaPath: string, destDir: string)`: Read IPA file as ArrayBuffer via `Bun.file().arrayBuffer()`, use `fflate.unzipSync()` to extract. Write extracted files to destDir preserving directory structure.
    - `discoverAppBundle(extractedDir: string)`: Glob `Payload/*.app/` to find the `.app` directory (name varies per app). Return the path.
    - `discoverBinaries(appBundlePath: string)`: Find the main executable (same name as .app folder, or from Info.plist `CFBundleExecutable`), plus all `.framework/` and `.dylib` files in `Frameworks/` and `PlugIns/*.appex/`. Return list of `{ name, path, type: 'main' | 'framework' | 'extension' }`.
    - `cleanupExtracted(destDir: string)`: Remove the temp extraction directory
  - Use `fflate.unzipSync()` with a filter callback to skip unnecessary large files (e.g., `Assets.car`, `*.storyboardc`) during extraction for performance. Or extract everything if simpler — IPAs are typically under 200MB extracted.
  - Create `src/main/ipa/__tests__/extractor.test.ts`:
    - Test extraction of a minimal ZIP fixture (create programmatically with `fflate.zipSync()`)
    - Test app bundle discovery with `Payload/TestApp.app/` structure
    - Test binary discovery (main binary + framework)
    - Test non-IPA file handling (not a valid ZIP)

  **Must NOT do**:
  - Do not use `Bun.Archive` — it's TAR-only, cannot handle ZIP
  - Do not implement streaming extraction — `unzipSync` is sufficient
  - Do not parse any Mach-O data here — extraction only

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: File I/O + fflate usage — straightforward, well-documented APIs
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 1, 2, 3)
  - **Blocks**: Tasks 6, 15
  - **Blocked By**: None

  **References**:

  **External References**:
  - fflate docs: `https://github.com/101arrowz/fflate` — `unzipSync(data)` takes `Uint8Array`, returns `{ [filename]: Uint8Array }`. `zipSync(data)` for creating test fixtures.
  - IPA structure: `Payload/<AppName>.app/` contains main binary (name from `CFBundleExecutable` in Info.plist), `Frameworks/` (embedded dylibs), `PlugIns/` (app extensions)

  **WHY Each Reference Matters**:
  - fflate: Must use `unzipSync` not `Bun.Archive` — this is the critical dependency fix from Metis review
  - IPA structure: The `.app` bundle name varies — must glob `Payload/*.app/`, never hardcode

  **Acceptance Criteria**:
  - [ ] `bun test src/main/ipa/__tests__/extractor.test.ts` → all tests pass
  - [ ] ZIP extraction works with fflate
  - [ ] App bundle discovered dynamically (not hardcoded name)
  - [ ] Non-ZIP file returns error gracefully

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Extract and discover test IPA
    Tool: Bash
    Preconditions: Test creates a minimal ZIP with Payload/TestApp.app/TestApp and Payload/TestApp.app/Info.plist
    Steps:
      1. Run `bun test src/main/ipa/__tests__/extractor.test.ts`
      2. Verify extraction produces correct directory structure
      3. Verify binary discovery finds the main binary
    Expected Result: All tests pass, correct files discovered
    Failure Indicators: Test failures, missing files in extraction
    Evidence: .sisyphus/evidence/task-4-extraction-tests.txt

  Scenario: Non-ZIP file handled gracefully
    Tool: Bash
    Preconditions: Test passes a PNG or random bytes to extractIPA
    Steps:
      1. Run the error-handling test
      2. Verify descriptive error returned
    Expected Result: Error with message like "Invalid IPA file" — no crash
    Failure Indicators: Uncaught exception, crash
    Evidence: .sisyphus/evidence/task-4-invalid-file.txt
  ```

  **Commit**: YES
  - Message: `feat(ipa): IPA extraction and app bundle discovery with fflate`
  - Files: `src/main/ipa/extractor.ts`, `src/main/ipa/__tests__/extractor.test.ts`
  - Pre-commit: `bun test`

- [ ] 5. Load Command Parser + Segment/Section Enumeration + Tests

  **What to do**:
  - Create `src/main/parser/load-commands.ts`:
    - `parseLoadCommands(buffer: ArrayBuffer, offset: number, ncmds: number, sizeofcmds: number, littleEndian: boolean)`: Walk load commands starting after the header. For each command, read `cmd` (4 bytes) and `cmdsize` (4 bytes), then parse based on cmd type. ALWAYS advance by `cmdsize`, never by struct size.
    - Parse these load command types (return typed objects):
      - `LC_SEGMENT_64` (0x19): segname, vmaddr (BigInt), vmsize, fileoff, filesize, maxprot, initprot, nsects, flags. Then parse each section_64 (68 bytes each): sectname, segname, addr, size, offset, align, reloff, nreloc, flags, reserved1/2/3.
      - `LC_LOAD_DYLIB` (0xC) and `LC_LOAD_WEAK_DYLIB` (0x18000000D): dylib name (offset into cmd + read string), current_version, compat_version, mark weak flag.
      - `LC_ENCRYPTION_INFO_64` (0x2C): cryptoff, cryptsize, cryptid.
      - `LC_UUID` (0x1B): 16-byte UUID.
      - `LC_BUILD_VERSION` (0x32): platform, minos, sdk, ntools.
      - `LC_MAIN` (0x80000028): entryoff, stacksize.
      - `LC_SYMTAB` (0x2): symoff, nsyms, stroff, strsize.
      - `LC_DYSYMTAB` (0xB): key index fields.
      - `LC_CODE_SIGNATURE` (0x1D): dataoff, datasize.
      - `LC_DYLD_CHAINED_FIXUPS` (0x80000034): dataoff, datasize.
      - `LC_RPATH` (0x8000001C): path string.
      - `LC_FUNCTION_STARTS` (0x26): dataoff, datasize.
      - `LC_SOURCE_VERSION` (0x2A): version as packed uint64.
      - All other commands: store as `{ cmd, cmdsize, raw: Uint8Array }` for future extensibility.
    - Return `{ segments: Segment[], loadCommands: LoadCommand[], libraries: LinkedLibrary[], encryption: EncryptionInfo | null, uuid: string | null, buildVersion: BuildVersion | null, symtabInfo: SymtabInfo | null, codeSignatureInfo: { offset: number, size: number } | null, chainedFixupsInfo: { offset: number, size: number } | null }`
  - Create `src/main/parser/__tests__/load-commands.test.ts`:
    - Test with crafted byte arrays containing known load commands
    - Test segment with multiple sections
    - Test dylib name string extraction
    - Test encryption info parsing
    - Test unknown command type falls through gracefully
    - Test iteration always advances by cmdsize (not struct size)

  **Must NOT do**:
  - Do not parse the data pointed to by load commands (code signature blob, symtab entries, etc.) — that's Tasks 8-10
  - Do not resolve any pointers — just record offsets and sizes

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: Many load command variants with precise byte layouts. TDD with crafted fixtures.
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2 (with Tasks 6, 7)
  - **Blocks**: Tasks 8, 9, 10, 14
  - **Blocked By**: Task 3 (needs MachOHeader parsing)

  **References**:

  **External References**:
  - macmade/macho: `https://github.com/macmade/macho` → `lib-macho/` — load command parsing logic, especially `LC_SEGMENT_64` section iteration
  - Load command constants: `LC_SEGMENT_64=0x19`, `LC_LOAD_DYLIB=0xC`, `LC_SYMTAB=0x2`, `LC_CODE_SIGNATURE=0x1D`, `LC_DYLD_CHAINED_FIXUPS=0x80000034`, `LC_ENCRYPTION_INFO_64=0x2C`, `LC_UUID=0x1B`, `LC_BUILD_VERSION=0x32`, `LC_MAIN=0x80000028`
  - Section_64 struct: 68 bytes — sectname(16) + segname(16) + addr(8) + size(8) + offset(4) + align(4) + reloff(4) + nreloc(4) + flags(4) = 68 total. Follow Mach-O ABI docs.
  - Dylib name: `lc_str` union uses an `offset` field relative to the start of the load command, then read null-terminated string at that offset

  **WHY Each Reference Matters**:
  - macmade/macho: Verified implementation to cross-check our load command iteration logic
  - Constants: Exact hex values are critical — one wrong constant and the parser silently skips important commands
  - Section struct: 68-byte struct — wrong size means every subsequent section is misaligned
  - Dylib name offset: Relative to load command start, NOT to section or buffer start

  **Acceptance Criteria**:
  - [ ] `bun test src/main/parser/__tests__/load-commands.test.ts` → all tests pass
  - [ ] All listed LC types parsed correctly
  - [ ] Unknown commands don't cause errors
  - [ ] Segment sections extracted with correct field values

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Load command tests all pass
    Tool: Bash
    Preconditions: Parser and test files created
    Steps:
      1. Run `bun test src/main/parser/__tests__/load-commands.test.ts`
    Expected Result: 0 failures, ≥6 tests pass
    Failure Indicators: Any test failure
    Evidence: .sisyphus/evidence/task-5-loadcmd-tests.txt

  Scenario: Segment with sections parsed correctly
    Tool: Bash
    Preconditions: Test fixture with LC_SEGMENT_64 containing 3 sections
    Steps:
      1. Parse fixture
      2. Assert segment name, vmaddr, vmsize match expected
      3. Assert 3 sections with correct names, offsets, sizes
    Expected Result: All fields match handcrafted fixture values
    Failure Indicators: Wrong values, missing sections
    Evidence: .sisyphus/evidence/task-5-segment-sections.txt
  ```

  **Commit**: YES
  - Message: `feat(parser): load command parser and segment/section enumeration`
  - Files: `src/main/parser/load-commands.ts`, `src/main/parser/__tests__/load-commands.test.ts`
  - Pre-commit: `bun test`

- [ ] 6. Info.plist + Mobileprovision Parser + Tests

  **What to do**:
  - Create `src/main/parser/plist.ts`:
    - `parseInfoPlist(appBundlePath: string)`: Read `Info.plist` from the app bundle. Try binary plist first (`bplist-parser.parseBuffer()`), fall back to XML plist (`plist.parse()`). Extract and return structured data: `CFBundleIdentifier`, `CFBundleName`, `CFBundleDisplayName`, `CFBundleShortVersionString`, `CFBundleVersion`, `CFBundleExecutable`, `MinimumOSVersion`, `LSRequiresIPhoneOS`, `UIRequiredDeviceCapabilities`, `CFBundleURLTypes` (URL schemes), `NSAppTransportSecurity`, `UIBackgroundModes`, privacy usage strings (`NS*UsageDescription`), plus the full raw plist object for the Info.plist tab.
    - `parseMobileprovision(appBundlePath: string)`: Read `embedded.mobileprovision` if it exists. This is a CMS/DER envelope — do NOT parse as binary plist. Extract the XML by finding `<?xml` ... `</plist>` boundaries within the raw bytes. Parse the extracted XML with `plist.parse()`. Return: `TeamIdentifier`, `TeamName`, `ExpirationDate`, `CreationDate`, `Entitlements` (from the provisioning profile), `ProvisionedDevices` (UDIDs list), `ProvisionsAllDevices` flag.
  - Create `src/main/parser/__tests__/plist.test.ts`:
    - Test binary plist parsing with a minimal bplist fixture
    - Test mobileprovision XML extraction from a DER envelope mock
    - Test missing file handling (no embedded.mobileprovision → return null)

  **Must NOT do**:
  - Do NOT parse `embedded.mobileprovision` with `bplist-parser` — it's CMS/DER wrapping XML
  - Do not validate certificate chains in the provisioning profile
  - Do not attempt full DER/ASN.1 parsing — just find the XML boundaries

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: Two distinct parsing formats (binary plist + CMS envelope XML extraction). Moderate complexity.
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2 (with Tasks 5, 7)
  - **Blocks**: Task 15 (RPC integration needs plist data)
  - **Blocked By**: Task 4 (needs extracted IPA bundle path)

  **References**:

  **External References**:
  - bplist-parser: `https://github.com/nicolo-ribaudo/bplist-parser` — `parseBuffer(buffer)` returns parsed object. Handles all binary plist types.
  - plist npm: `https://www.npmjs.com/package/plist` — `plist.parse(xmlString)` for XML plist parsing
  - Mobileprovision format: CMS (Cryptographic Message Syntax) envelope. The XML plist is embedded verbatim inside the DER-encoded CMS structure. Find it with `buffer.indexOf('<?xml')` and `buffer.indexOf('</plist>')`.
  - Info.plist keys: `CFBundleIdentifier`, `CFBundleExecutable`, `MinimumOSVersion`, `CFBundleURLTypes`, `NSAppTransportSecurity`, `UIBackgroundModes`, `NS*UsageDescription` privacy strings

  **WHY Each Reference Matters**:
  - bplist-parser: Info.plist in compiled apps is binary format, not XML — must use this library
  - Mobileprovision: CRITICAL — must NOT use bplist-parser on this file. It's a CMS envelope. Extract XML by string search.
  - Info.plist keys: These specific keys are what RE analysts look for — URL schemes reveal deep link attack surface, ATS exceptions reveal insecure network config

  **Acceptance Criteria**:
  - [ ] `bun test` for plist tests → all pass
  - [ ] Binary plist parsed correctly
  - [ ] Mobileprovision XML extracted from DER envelope
  - [ ] Missing mobileprovision returns null, not error

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Plist parser tests pass
    Tool: Bash
    Preconditions: Parser and tests created
    Steps:
      1. Run `bun test src/main/parser/__tests__/plist.test.ts`
    Expected Result: All tests pass
    Failure Indicators: Any failure
    Evidence: .sisyphus/evidence/task-6-plist-tests.txt

  Scenario: Missing mobileprovision handled gracefully
    Tool: Bash
    Preconditions: Test with app bundle path that has no embedded.mobileprovision
    Steps:
      1. Call parseMobileprovision with path to directory without the file
    Expected Result: Returns null, no exception
    Failure Indicators: Exception thrown
    Evidence: .sisyphus/evidence/task-6-missing-provision.txt
  ```

  **Commit**: YES
  - Message: `feat(parser): Info.plist and mobileprovision parser`
  - Files: `src/main/parser/plist.ts`, `src/main/parser/__tests__/plist.test.ts`
  - Pre-commit: `bun test`

- [ ] 7. App Shell UI — Window, Dark Theme, Tab Navigation, Drop Zone, File Picker

  **What to do**:
  - Update `src/renderer/index.html` with the full app shell layout:
    - Custom titlebar with CSS `-webkit-app-region: drag` on the titlebar div, app name "Disect", window controls (minimize, maximize, close) with `-webkit-app-region: no-drag` on interactive elements
    - Left sidebar with 10 tab buttons (icons + labels): Overview, Strings, Headers, Libraries, Symbols, Classes, Entitlements, Info.plist, Security, Files
    - Main content area with placeholder for tab content
    - "Open IPA" button prominently in sidebar header
    - Drop zone overlay — full-window overlay that appears on dragenter, shows "Drop IPA file here" message with a subtle pulse animation
    - Initial empty state: centered message "Open or drop an IPA file to begin analysis" with the file picker button
    - Loading state: progress bar + phase text (e.g., "Extracting IPA...", "Parsing Mach-O...")
    - Binary selector dropdown (initially hidden, appears when IPA has multiple binaries)
  - Create `src/renderer/index.css` with:
    - Dark theme: background `#0d1117` (GitHub dark), surfaces `#161b22`, borders `#30363d`, text `#e6edf3`, accent color (pick a good one — maybe `#58a6ff` blue or `#7ee787` green)
    - Sidebar: fixed left, ~220px wide, scrollable if many tabs
    - Tab buttons: hover/active states with smooth 150ms transitions
    - Content area: flex, takes remaining width, scrollable
    - Drop zone overlay: position fixed, backdrop-filter blur, fade-in animation (200ms)
    - Loading bar: thin accent-colored bar with indeterminate animation
    - Typography: system font stack, clear hierarchy
    - Animations: tab switch fade (150ms), loading spinner (CSS-only), drop zone pulse (2s ease-in-out), list item stagger fade-in (50ms per item, capped at 500ms total)
  - Update `src/renderer/index.ts`:
    - Tab switching logic: click tab → hide all tab content divs, show selected, update active tab styling
    - Drop zone: `dragenter`/`dragover`/`dragleave`/`drop` event handlers on document. On drop, get file path from `e.dataTransfer.files[0].path` (Electron provides `.path` on dropped files). Send to main process via the preload-exposed `window.api.analyzeIPA(path)` (wired in Task 15). Also wire "Open IPA" button to call `window.api.openFilePicker()`.
    - Empty state / loading state / content state transitions
    - Listen for main→renderer messages (progress, completion, error) via `window.api.on*` callbacks (wired in Task 15)
  - Update `src/main/index.ts`:
    - Configure BrowserWindow with: `titleBarStyle: "hiddenInset"`, `backgroundColor: '#0d1117'`, width 1200, height 800
    - `webPreferences: { preload, contextIsolation: true, nodeIntegration: false }`
    - Set up `Menu.setApplicationMenu()` with Edit menu (undo, redo, cut, copy, paste, selectAll) for keyboard shortcuts
    - macOS-specific: `app.on('activate')` to recreate window if dock icon clicked

  **Must NOT do**:
  - Do not implement actual tab content rendering (that's Tasks 16-20)
  - Do not implement actual IPA analysis logic
  - Do not add any CSS framework or UI library
  - Do not add complex animations beyond what's specified (no particle effects, no spring physics)
  - Do not use `nodeIntegration: true` or `remote` module

  **Recommended Agent Profile**:
  - **Category**: `visual-engineering`
    - Reason: Core UI layout, CSS theming, animations, interactive drag-drop. Visual-heavy task.
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2 (with Tasks 5, 6)
  - **Blocks**: Tasks 11, 16-20, 24
  - **Blocked By**: Tasks 1, 2 (needs project scaffold and type definitions)

  **References**:

  **External References**:
  - Electron BrowserWindow: `https://www.electronjs.org/docs/latest/api/browser-window` — `titleBarStyle: "hiddenInset"` for traffic lights on macOS, `backgroundColor` for dark theme
  - Electron Draggable Regions: `-webkit-app-region: drag` CSS property — standard Chromium feature. Apply to titlebar div, use `no-drag` on interactive elements within it. See `https://www.electronjs.org/docs/latest/tutorial/window-customization#set-custom-draggable-region`
  - Electron Menu: `https://www.electronjs.org/docs/latest/api/menu` — `Menu.setApplicationMenu()` with roles for edit operations (undo, redo, cut, copy, paste, selectAll)
  - Electron File Drop: In Electron, `event.dataTransfer.files[0].path` provides the real filesystem path — this is Electron-specific (browsers don't expose `.path`). See `https://www.electronjs.org/docs/latest/tutorial/native-file-drag-drop`

  **WHY Each Reference Matters**:
  - titleBarStyle hiddenInset: Gives the native macOS traffic lights overlaid on content — polished look. On Windows/Linux, enables custom titlebar.
  - Draggable regions: CSS `-webkit-app-region: drag` makes the custom titlebar draggable — without it, the window can't be moved
  - Menu: Without the Edit menu with roles, Cmd+C/V/X won't work — critical UX issue
  - File Drop: Electron's `.path` property on dropped files is what makes drag-drop actually useful — gives real file paths, not blob URLs

  **Acceptance Criteria**:
  - [ ] App launches with dark themed window, sidebar with 10 tab buttons, empty state message
  - [ ] Clicking tabs switches active tab highlighting (content area shows tab name placeholder)
  - [ ] Drag-over shows the drop zone overlay with animation
  - [ ] "Open IPA" button is visible and clickable (doesn't need to work yet — just wired to a no-op or alert)
  - [ ] Window titlebar is draggable, window controls (close/minimize/maximize) work

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: App shell renders correctly
    Tool: Playwright
    Preconditions: App built and running
    Steps:
      1. Launch app
      2. Assert sidebar element exists with 10 tab buttons
      3. Assert initial empty state message "Open or drop an IPA" is visible
      4. Assert dark background color is approximately #0d1117
      5. Screenshot the initial state
    Expected Result: Dark themed app with sidebar, empty state, correct layout
    Failure Indicators: White/light background, missing sidebar, missing tabs
    Evidence: .sisyphus/evidence/task-7-app-shell.png

  Scenario: Tab switching works
    Tool: Playwright
    Preconditions: App running
    Steps:
      1. Click "Strings" tab button in sidebar
      2. Assert "Strings" tab button has active styling
      3. Assert content area shows Strings placeholder
      4. Click "Security" tab button
      5. Assert "Security" tab is now active, "Strings" is not
    Expected Result: Tab switching updates active state and content
    Failure Indicators: Multiple tabs active, content doesn't change
    Evidence: .sisyphus/evidence/task-7-tab-switching.png

  Scenario: Drop zone overlay appears on drag
    Tool: Playwright
    Preconditions: App running
    Steps:
      1. Simulate dragenter event on the document
      2. Assert drop zone overlay element is visible
      3. Assert overlay contains text "Drop IPA file here"
      4. Simulate dragleave event
      5. Assert overlay is hidden
    Expected Result: Overlay appears/disappears on drag events
    Failure Indicators: Overlay doesn't appear, or doesn't disappear
    Evidence: .sisyphus/evidence/task-7-drop-zone.png
  ```

  **Commit**: YES
  - Message: `feat(ui): app shell with dark theme, tab navigation, drop zone`
  - Files: `src/renderer/index.html`, `src/renderer/index.css`, `src/renderer/index.ts`, `src/main/index.ts`

- [ ] 8. Chained Fixups Resolver (LC_DYLD_CHAINED_FIXUPS) + Tests

  **What to do**:
  - Create `src/main/parser/chained-fixups.ts`:
    - `buildFixupMap(buffer: ArrayBuffer, chainedFixupsOffset: number, chainedFixupsSize: number, segments: Segment[], littleEndian: boolean)`: Parse the chained fixups data and return a `Map<number, bigint>` mapping file offsets to resolved pointer values.
    - Parse `dyld_chained_fixups_header`: fixups_version, starts_offset, imports_offset, symbols_offset, imports_count, imports_format, symbols_format.
    - Parse `dyld_chained_starts_in_image`: seg_count, then per-segment `dyld_chained_starts_in_segment`: size, page_size, pointer_format, segment_offset, max_valid_pointer, page_count, page_starts array.
    - Focus on `DYLD_CHAINED_PTR_64_OFFSET` (pointer_format = 6) — the standard format for iOS device arm64 binaries. This format uses: bit 63 = bind flag, if rebase: bits 0-35 = target offset, bits 36-51 = high8, bits 52-62 = next pointer offset in chain. If bind: bits 0-23 = ordinal, bits 24 = addend sign, bits 25-42 = addend, bits 43-51 = reserved, bits 52-62 = next.
    - Walk each page's chain: start at page_starts[i] offset within the segment, read 8-byte value, extract next pointer delta (×4 for stride), follow chain until next=0.
    - For rebase entries: resolved_value = target + image_base_address (for on-disk analysis, use segment vmaddr as base).
    - For bind entries: record the ordinal for symbol resolution (store as a separate bind map).
    - Parse imports table for bind resolution: `dyld_chained_import` (lib_ordinal + name_offset).
    - Use `BigInt` for ALL 64-bit pointer arithmetic and bit manipulation.
  - Also handle the fallback case: if `LC_DYLD_CHAINED_FIXUPS` is absent (older binaries), return an empty map — downstream parsers should handle raw pointers directly.
  - Create `src/main/parser/__tests__/chained-fixups.test.ts`:
    - Test with a crafted fixture containing a minimal chained fixups structure
    - Test rebase entry resolution
    - Test chain walking across a page
    - Test empty fixups (no LC_DYLD_CHAINED_FIXUPS) returns empty map
    - Test malformed fixups data returns error, not crash

  **Must NOT do**:
  - Do not implement pointer formats other than `DYLD_CHAINED_PTR_64_OFFSET` (format 6) — skip kernel cache formats, DYLD_CHAINED_PTR_ARM64E, etc.
  - Do not verify PAC signatures — just strip high bits for arm64e
  - Do not resolve bind symbols to actual names here (that's done in symbol parsing)

  **Recommended Agent Profile**:
  - **Category**: `ultrabrain`
    - Reason: This is the hardest task in the entire plan. BigInt bit manipulation, page-walking algorithms, multiple struct formats. Must be precisely correct or everything downstream breaks.
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 3 (with Tasks 9, 10, 11)
  - **Blocks**: Tasks 12, 13, 15 (everything that reads __DATA pointers)
  - **Blocked By**: Task 5 (needs segment layout and chainedFixupsInfo offset)

  **References**:

  **External References**:
  - Apple dyld source: `https://github.com/apple-oss-distributions/dyld` → `include/mach-o/fixup-chains.h` — canonical struct definitions for `dyld_chained_fixups_header`, `dyld_chained_starts_in_image`, `dyld_chained_starts_in_segment`, pointer format constants
  - DYLD_CHAINED_PTR_64_OFFSET format: pointer_format=6, stride=4, bit layout: [63]=bind, [62:52]=next, [51:36]=high8 (rebase only), [35:0]=target (rebase) or [23:0]=ordinal (bind)
  - dyld_chained_import struct: 4 bytes — lib_ordinal (8 bits), weak_import (1 bit), name_offset (23 bits)

  **WHY Each Reference Matters**:
  - fixup-chains.h: The ONLY authoritative source for the bit layouts. Get one bit wrong and pointers resolve to garbage.
  - Pointer format 6: This is the format used by 99%+ of iOS arm64 device binaries. Supporting only this one covers the real-world use case.
  - Chain walking: Each entry's `next` field is ×4 (stride), and 0 means end of chain. Miss this and you walk off the page.

  **Acceptance Criteria**:
  - [ ] `bun test` chained fixups tests → all pass
  - [ ] Rebase entries resolve to correct target addresses
  - [ ] Chain walking follows next pointers correctly until terminator
  - [ ] Missing LC_DYLD_CHAINED_FIXUPS returns empty map
  - [ ] Malformed data returns error gracefully

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Chained fixups resolver tests pass
    Tool: Bash
    Preconditions: Parser and tests created
    Steps:
      1. Run `bun test src/main/parser/__tests__/chained-fixups.test.ts`
    Expected Result: All tests pass
    Failure Indicators: Any failure — this is the critical path
    Evidence: .sisyphus/evidence/task-8-fixups-tests.txt

  Scenario: Empty fixups map for older binaries
    Tool: Bash
    Preconditions: Test with no chained fixups info
    Steps:
      1. Call buildFixupMap with null chainedFixupsInfo
    Expected Result: Returns empty Map, no error
    Failure Indicators: Exception, non-empty map
    Evidence: .sisyphus/evidence/task-8-no-fixups.txt
  ```

  **Commit**: YES
  - Message: `feat(parser): chained fixups resolver for LC_DYLD_CHAINED_FIXUPS`
  - Files: `src/main/parser/chained-fixups.ts`, `src/main/parser/__tests__/chained-fixups.test.ts`
  - Pre-commit: `bun test`

- [ ] 9. Code Signature + Entitlements Parser + Tests

  **What to do**:
  - Create `src/main/parser/codesign.ts`:
    - `parseCodeSignature(buffer: ArrayBuffer, csOffset: number, csSize: number)`: Parse the code signature SuperBlob at the given offset. The SuperBlob and all sub-blobs use BIG-ENDIAN byte order (unlike the rest of the little-endian Mach-O).
    - Parse `CS_SuperBlob`: magic (`0xFADE0CC0`), length, count, then `CS_BlobIndex` entries (type + offset pairs).
    - For each blob, check type:
      - `0x00005` = entitlements (magic `0xFADE7171`) — extract the XML plist string that follows the 8-byte blob header. Parse with `plist.parse()`. Return as key-value pairs.
      - `0x00000` = code directory — extract `teamID` (null-terminated string at teamOffset within the blob), `hashType`, `codeLimit`, `flags`.
    - `extractEntitlements(buffer, csOffset, csSize)`: Convenience wrapper that returns just the entitlements object.
    - Handle missing code signature gracefully (return null).
  - Create `src/main/parser/__tests__/codesign.test.ts`:
    - Test SuperBlob parsing with crafted big-endian fixture
    - Test entitlements XML extraction
    - Test team ID extraction from code directory
    - Test missing/empty code signature returns null

  **Must NOT do**:
  - Do not verify code signatures (we're analyzing, not validating)
  - Do not parse DER-encoded entitlements (some binaries have both XML and DER — just use XML)
  - Do not validate certificate chains

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: Big-endian blob parsing within a little-endian file. Must handle endianness switch correctly.
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 3 (with Tasks 8, 10, 11)
  - **Blocks**: Task 15
  - **Blocked By**: Task 5 (needs codeSignatureInfo offset from load commands)

  **References**:

  **External References**:
  - Apple codesign source: `CS_SuperBlob` magic = `0xFADE0CC0`, `CS_CodeDirectory` magic = `0xFADE0C02`, entitlements blob magic = `0xFADE7171`
  - All code signature blob fields are BIG-ENDIAN — use `dataView.getUint32(offset, false)`
  - Entitlements blob: 8-byte header (magic + length), then raw XML plist string for the remaining bytes
  - Code directory: fixed-size header with `teamOffset` field pointing to null-terminated team ID string within the blob

  **WHY Each Reference Matters**:
  - Endianness: The code signature is the ONE part of an arm64 Mach-O that's big-endian. Get this wrong and magic values won't match.
  - Blob structure: SuperBlob contains indexed sub-blobs — must iterate by index, not just scan for magic values

  **Acceptance Criteria**:
  - [ ] `bun test` codesign tests → all pass
  - [ ] Entitlements extracted as parsed key-value object
  - [ ] Team ID extracted from code directory
  - [ ] Big-endian handling correct

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Codesign parser tests pass
    Tool: Bash
    Steps:
      1. Run `bun test src/main/parser/__tests__/codesign.test.ts`
    Expected Result: All tests pass
    Evidence: .sisyphus/evidence/task-9-codesign-tests.txt

  Scenario: Missing code signature returns null
    Tool: Bash
    Steps:
      1. Call parseCodeSignature with null offset
    Expected Result: Returns null, no crash
    Evidence: .sisyphus/evidence/task-9-no-codesign.txt
  ```

  **Commit**: YES
  - Message: `feat(parser): code signature and entitlements extraction`
  - Files: `src/main/parser/codesign.ts`, `src/main/parser/__tests__/codesign.test.ts`
  - Pre-commit: `bun test`

- [ ] 10. Symbol Table + Export Trie Parser + Tests

  **What to do**:
  - Create `src/main/parser/symbols.ts`:
    - `parseSymbolTable(buffer: ArrayBuffer, symtabInfo: SymtabInfo, littleEndian: boolean)`: Parse `LC_SYMTAB` data. Read `nlist_64` entries (16 bytes each: n_strx(4) + n_type(1) + n_sect(1) + n_desc(2) + n_value(8)). For each entry, read the symbol name from the string table at `stroff + n_strx`. Classify as exported (n_type & N_EXT), imported (n_type & N_EXT && n_type & N_UNDF), or local.
    - `parseExportTrie(buffer: ArrayBuffer, exportOffset: number, exportSize: number)`: Parse the export trie from `LC_DYLD_EXPORTS_TRIE` or the export info in `LC_DYLD_INFO`. The trie is ULEB128-encoded: each node has a terminal size, then children (count, edge label bytes, child offset as ULEB128). Walk recursively, accumulate edge labels to form symbol names, extract flags + address from terminal nodes.
    - Helper: `readULEB128(dataView: DataView, offset: number)`: Read ULEB128 encoded integer, return value and bytes consumed.
    - Return `Symbol[]` with: name, address (BigInt), type ('exported' | 'imported' | 'local'), section index.

  **Must NOT do**:
  - Do not implement full dyld bind info parsing (opcodes) — chained fixups handles this for modern binaries
  - Do not attempt to demangle Swift names
  - Do not include debug symbols (STABS entries — n_type values 0x20-0xFF)

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: ULEB128 decoding + recursive trie walking — algorithmic complexity
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 3 (with Tasks 8, 9, 11)
  - **Blocks**: Tasks 14, 15
  - **Blocked By**: Task 5 (needs symtabInfo from load commands)

  **References**:

  **External References**:
  - nlist_64 struct: 16 bytes — `n_strx` (uint32, offset into string table), `n_type` (uint8), `n_sect` (uint8), `n_desc` (int16), `n_value` (uint64)
  - N_EXT = 0x01, N_UNDF = 0x0, N_TYPE mask = 0x0E. Imported = (n_type & N_EXT) && ((n_type & N_TYPE) == N_UNDF). Exported = (n_type & N_EXT) && section != 0.
  - Export trie format: Each node starts with terminal_size (ULEB128). If >0, read flags (ULEB128) + address (ULEB128). Then children_count (byte), for each child: null-terminated edge string, child_offset (ULEB128 relative to trie start).
  - ULEB128: Little-endian base-128. Read byte, if high bit set, continue. Value = accumulate 7 bits per byte.

  **WHY Each Reference Matters**:
  - nlist_64: Exact struct layout for symbol table entries — wrong size or field order = misaligned reads
  - N_TYPE flags: Classification logic determines imported vs exported — critical for Symbols tab
  - Export trie: ULEB128 + recursive walk is the most algorithmically complex parser piece

  **Acceptance Criteria**:
  - [ ] `bun test` symbol tests → all pass
  - [ ] Symbols classified correctly as exported/imported
  - [ ] ULEB128 decoder handles multi-byte values
  - [ ] Export trie walks correctly and accumulates full symbol names

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Symbol parser tests pass
    Tool: Bash
    Steps:
      1. Run `bun test src/main/parser/__tests__/symbols.test.ts`
    Expected Result: All tests pass
    Evidence: .sisyphus/evidence/task-10-symbol-tests.txt

  Scenario: ULEB128 edge cases
    Tool: Bash
    Steps:
      1. Test readULEB128 with single-byte value (0x05 → 5)
      2. Test multi-byte value (0x80 0x01 → 128)
      3. Test large value (5 bytes)
    Expected Result: All decode correctly
    Evidence: .sisyphus/evidence/task-10-uleb128.txt
  ```

  **Commit**: YES
  - Message: `feat(parser): symbol table and export trie parser`
  - Files: `src/main/parser/symbols.ts`, `src/main/parser/__tests__/symbols.test.ts`
  - Pre-commit: `bun test`

- [ ] 11. Shared UI Components — Data Table, Search Bar, JSON Tree, Loading States

  **What to do**:
  - Create `src/renderer/components/data-table.ts`:
    - Reusable virtualized table component for large data sets (strings can have 100k+ rows). Use a simple virtual scroll: render only visible rows + buffer. Takes `columns: {key, label, width?}[]`, `data: any[]`, `rowHeight: number`. Renders into a container div. Handles scroll events to update visible range.
    - Sorting: click column header to sort asc/desc
    - Row click callback for selection
  - Create `src/renderer/components/search-bar.ts`:
    - Reusable search input with regex toggle button. Emits `onFilter(term: string, isRegex: boolean)` callback.
    - Debounced input (200ms) to avoid filtering on every keystroke
    - Visual indicator when regex is invalid (red border)
    - Result count display ("Showing N of M")
  - Create `src/renderer/components/json-tree.ts`:
    - Collapsible tree view for JSON/plist data. Recursively render objects with expand/collapse toggles. Show key: value with syntax coloring (strings=green, numbers=blue, booleans=orange, null=gray).
    - Copy value on click
  - Create `src/renderer/components/loading.ts`:
    - Loading spinner (CSS-only animation)
    - Progress bar component (determinate + indeterminate modes)
    - Phase text display (e.g., "Parsing headers...")
  - Create `src/renderer/components/empty-state.ts`:
    - Reusable empty state with icon + message + optional action button
  - All components are plain TypeScript classes that create/manage DOM elements. No framework. Each component:
    - Has a `mount(container: HTMLElement)` method
    - Has an `update(data)` method for re-rendering
    - Has a `destroy()` method for cleanup
    - Uses CSS classes from the shared stylesheet

  **Must NOT do**:
  - Do not use any UI framework (React, Lit, etc.)
  - Do not implement full-featured virtual scrolling library — keep it simple (fixed row height, overflow scroll)
  - Do not add complex animation beyond list fade-in

  **Recommended Agent Profile**:
  - **Category**: `visual-engineering`
    - Reason: Interactive UI components, virtual scrolling, animations — visual engineering domain
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 3 (with Tasks 8, 9, 10)
  - **Blocks**: Tasks 16-20 (all tab implementations use these components)
  - **Blocked By**: Task 7 (needs app shell and CSS theme)

  **References**:

  **Pattern References**:
  - `src/renderer/index.css` (Task 7) — CSS variables, color scheme, typography to match
  - `src/renderer/index.ts` (Task 7) — component mounting pattern, DOM creation style

  **WHY Each Reference Matters**:
  - CSS theme: Components must use the same CSS variables and class naming conventions as the shell
  - Mount pattern: All tab implementations will use these components — consistent API is critical for code reuse

  **Acceptance Criteria**:
  - [ ] Data table renders with columns and rows
  - [ ] Virtual scrolling works for 10k+ rows without lag
  - [ ] Search bar with regex toggle filters data correctly
  - [ ] JSON tree renders nested objects with expand/collapse
  - [ ] All components follow mount/update/destroy pattern

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Data table handles large dataset
    Tool: Playwright
    Preconditions: App running with test data
    Steps:
      1. Create a data table with 50,000 rows of test data
      2. Verify only ~50 visible rows are in the DOM (virtual scrolling)
      3. Scroll to bottom, verify last rows render
      4. Measure scroll performance — no visible jank
    Expected Result: Table renders, scrolls smoothly, DOM has limited rows
    Failure Indicators: All 50k rows in DOM, scroll lag, blank rows
    Evidence: .sisyphus/evidence/task-11-virtual-scroll.png

  Scenario: Search bar filters with regex
    Tool: Playwright
    Preconditions: Data table with known test strings
    Steps:
      1. Type "api.*key" in search bar with regex toggle ON
      2. Verify result count shows filtered number
      3. Verify displayed rows match regex
      4. Toggle regex OFF, verify search becomes literal
    Expected Result: Regex filtering works, count updates, toggle switches mode
    Failure Indicators: No filtering, wrong count, regex toggle does nothing
    Evidence: .sisyphus/evidence/task-11-search-regex.png
  ```

  **Commit**: YES
  - Message: `feat(ui): shared components — data table, search, tree viewer, loading`
  - Files: `src/renderer/components/data-table.ts`, `src/renderer/components/search-bar.ts`, `src/renderer/components/json-tree.ts`, `src/renderer/components/loading.ts`, `src/renderer/components/empty-state.ts`

- [ ] 12. String Extraction (All Mach-O Sections) + Tests

  **What to do**:
  - Create `src/main/parser/strings.ts`:
    - `extractStrings(buffer: ArrayBuffer, sections: Section[], fixupMap: Map<number, bigint>, littleEndian: boolean)`: Extract strings from multiple section types. Return `StringEntry[]` with: value, source section name, file offset.
    - `__TEXT.__cstring`: Null-terminated C strings. Walk bytes, collect until null. Filter strings ≥4 chars.
    - `__TEXT.__objc_methname`: Null-terminated ObjC method name strings. Same parsing as __cstring.
    - `__TEXT.__objc_classname`: Null-terminated ObjC class name strings.
    - `__TEXT.__objc_methtype`: Null-terminated ObjC type encoding strings.
    - `__TEXT.__swift5_reflstr`: Null-terminated Swift reflection strings.
    - `__TEXT.__oslogstring`: Null-terminated os_log format strings.
    - `__TEXT.__ustring`: UTF-16 encoded strings (read as 2-byte code units until double null).
    - `__DATA.__cfstring` (or `__DATA_CONST.__cfstring`): Each entry is 32 bytes on 64-bit: [isa(8) + flags(8) + data_ptr(8) + length(8)]. The `data_ptr` may be a chained fixup — use `fixupMap` to resolve. Then read `length` bytes from the resolved pointer address (convert vmaddr to file offset using segment info). Deduplicate against __cstring entries.
    - Deduplicate strings across sections (same string in __cstring and __cfstring → keep one, note both sources).
  - Create `src/main/parser/__tests__/strings.test.ts`:
    - Test __cstring extraction from crafted section data
    - Test __cfstring resolution with mock fixup map
    - Test deduplication
    - Test UTF-16 __ustring extraction
    - Test empty sections return empty array

  **Must NOT do**:
  - Do not implement string encoding detection beyond UTF-8 and UTF-16
  - Do not filter/classify strings (security scan does that in Task 14)

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: Multiple section formats, pointer resolution through fixup map, deduplication logic
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 4 (with Tasks 13, 14, 15)
  - **Blocks**: Tasks 14, 15
  - **Blocked By**: Task 8 (needs fixup map for __cfstring resolution)

  **References**:

  **External References**:
  - __cfstring struct (64-bit): 32 bytes — isa (8, always kCFConstantStringTypeID), flags (8), data (8, pointer to UTF8 string), length (8). The `data` pointer is a vmaddr that must be resolved to a file offset.
  - vmaddr to file offset: `file_offset = (vmaddr - segment.vmaddr) + segment.fileoff` for the segment containing the target address

  **WHY Each Reference Matters**:
  - __cfstring: This is NOT just a string pointer — it's a 32-byte struct. Must parse the struct to get the actual string data pointer and length.
  - vmaddr conversion: Pointers in Mach-O reference virtual memory addresses, not file offsets. Must convert using segment info.

  **Acceptance Criteria**:
  - [ ] `bun test` string extraction tests → all pass
  - [ ] __cstring null-terminated strings extracted correctly
  - [ ] __cfstring pointers resolved through fixup map
  - [ ] Deduplication removes exact duplicates

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: String extraction tests pass
    Tool: Bash
    Steps:
      1. Run `bun test src/main/parser/__tests__/strings.test.ts`
    Expected Result: All tests pass
    Evidence: .sisyphus/evidence/task-12-string-tests.txt
  ```

  **Commit**: YES
  - Message: `feat(parser): string extraction from all Mach-O sections`
  - Files: `src/main/parser/strings.ts`, `src/main/parser/__tests__/strings.test.ts`
  - Pre-commit: `bun test`

- [ ] 13. ObjC Class + Method Name Extraction + Tests

  **What to do**:
  - Create `src/main/parser/objc.ts`:
    - `extractObjCMetadata(buffer: ArrayBuffer, sections: Section[], segments: Segment[], fixupMap: Map<number, bigint>, littleEndian: boolean)`: Parse `__DATA.__objc_classlist` (or `__DATA_CONST.__objc_classlist`) to extract class names and method names.
    - `__objc_classlist`: Array of pointers to `class_t` structs. Each pointer may be a chained fixup — resolve through `fixupMap`. Also apply `& ~0x7` mask (low 3 bits are flags, not part of address).
    - For each `class_t`: read `data` pointer (offset 32 in struct, 8 bytes), resolve through fixup map, mask low bits (`data & ~0x7`). This gives `class_ro_t` address.
    - For each `class_ro_t`: read `name` pointer (offset 24, 8 bytes) → resolve → read null-terminated string = class name. Read `baseMethods` pointer (offset 32, 8 bytes) → if non-null, resolve → points to `method_list_t`.
    - `method_list_t`: Read `count` (uint32 at offset 4, after entsizeAndFlags). For each method, check if relative methods (flag in entsizeAndFlags bit 31): if relative, each entry is 12 bytes (name_offset(4) + types_offset(4) + imp_offset(4), all relative int32 from their own position); if absolute, each entry is 24 bytes (name_ptr(8) + types_ptr(8) + imp_ptr(8)).
    - Return `ObjCClass[]` with: `{ name, methods: string[] }`. For MVP, just extract method name strings — don't decode type encodings.
    - Also extract protocol names from `__objc_protolist` if straightforward (pointer → protocol_t → name pointer → string).

  **Must NOT do**:
  - Do not parse ivar types, property attributes, or category merging
  - Do not do recursive protocol traversal (protocols conforming to protocols)
  - Do not parse metaclass methods separately (class methods)
  - Do not decode ObjC type encodings into readable signatures

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: Multi-level pointer chasing through fixup map, two different method list formats (relative vs absolute). Requires precision.
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 4 (with Tasks 12, 14, 15)
  - **Blocks**: Task 15
  - **Blocked By**: Task 8 (needs fixup map)

  **References**:

  **External References**:
  - ObjC runtime structs: `class_t` = 40 bytes (isa(8) + superclass(8) + cache(8) + vtable(8) + data(8)). `class_ro_t` has `name` at offset 24 and `baseMethods` at offset 32 on 64-bit.
  - Relative method lists: Introduced in iOS 14. Flag is bit 31 of `method_list_t.entsizeAndFlags`. Each relative method is 12 bytes with int32 offsets from their own address.
  - Pointer masking: `class_t.data & ~0x7` strips runtime flags from the data pointer. `class_t` pointers from __objc_classlist also need `& ~0x7` in some cases.

  **WHY Each Reference Matters**:
  - Struct offsets: Off by 8 bytes on any struct field = reading wrong pointer = garbage class names
  - Relative methods: Modern iOS binaries use relative method lists — without this, method extraction returns garbage
  - Pointer masking: Apple stores runtime flags in low bits of pointers — must mask before dereferencing

  **Acceptance Criteria**:
  - [ ] `bun test` ObjC parser tests → all pass
  - [ ] Class names extracted correctly
  - [ ] Method names extracted for each class
  - [ ] Both relative and absolute method list formats handled

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: ObjC parser tests pass
    Tool: Bash
    Steps:
      1. Run `bun test src/main/parser/__tests__/objc.test.ts`
    Expected Result: All tests pass
    Evidence: .sisyphus/evidence/task-13-objc-tests.txt
  ```

  **Commit**: YES
  - Message: `feat(parser): ObjC class and method name extraction`
  - Files: `src/main/parser/objc.ts`, `src/main/parser/__tests__/objc.test.ts`
  - Pre-commit: `bun test`

- [ ] 14. Security Scan Engine (Pattern Matching + Binary Hardening) + Tests

  **What to do**:
  - Create `src/main/analysis/security.ts`:
    - `runSecurityScan(strings: StringEntry[], symbols: Symbol[], header: MachOHeader, loadCommands: LoadCommand[], encryption: EncryptionInfo | null)`: Run all security checks and return `SecurityFinding[]`.
    - **Binary hardening checks** (from Mach-O header + symbols):
      - PIE: Check `MH_PIE` flag (0x200000) in header flags → "ASLR enabled/disabled"
      - Stack canaries: Search symbol table for `___stack_chk_guard` and `___stack_chk_fail` → "Stack canaries present/absent"
      - ARC: Search symbol table for `_objc_release`, `_objc_autorelease`, `_objc_storeStrong` → "ARC enabled/absent"
      - Encryption: Check `cryptid` from `LC_ENCRYPTION_INFO_64` → "Encrypted (cannot analyze)/Decrypted"
      - Symbols stripped: Check if symbol table is empty or very small → "Symbols stripped/present"
      - Rpath: Check for `LC_RPATH` load commands → "Rpath present (potential hijack vector)"
    - **Secret/credential pattern matching** (scan extracted strings):
      - AWS keys: `/AKIA[0-9A-Z]{16}/`
      - API keys: `/[aA][pP][iI][-_]?[kK][eE][yY]\s*[:=]\s*['"][^'"]{8,}/`
      - Bearer tokens: `/[Bb]earer\s+[A-Za-z0-9\-._~+\/]{20,}/`
      - Database URIs: `/mongodb(\+srv)?:\/\/[^\s'"]+/`, `/postgres(ql)?:\/\/[^\s'"]+/`, `/mysql:\/\/[^\s'"]+/`
      - Private keys: `/-----BEGIN (RSA |EC )?PRIVATE KEY-----/`
      - Generic secrets: `/[sS]ecret[-_]?[kK]ey\s*[:=]\s*['"][^'"]{8,}/`, `/[pP]assword\s*[:=]\s*['"][^'"]{4,}/`
      - Hardcoded URLs with credentials: `/https?:\/\/[^:]+:[^@]+@[^\s'"]+/`
      - Firebase: `/AIza[0-9A-Za-z\-_]{35}/`
      - Slack tokens: `/xox[bpas]-[0-9A-Za-z\-]+/`
    - **Insecure API detection** (scan imported symbols):
      - Memory-unsafe: `strcpy`, `strcat`, `sprintf`, `gets`, `scanf`, `vsprintf`
      - Weak crypto: `CC_MD5`, `CC_SHA1`, `MD5_Init`, `SHA1_Init`
      - System calls: `_system`, `_popen`, `_fork`, `_execve`
      - Dynamic loading: `_dlopen`, `_dlsym` (jailbreak detection bypass vector)
    - **Jailbreak detection strings** (scan strings):
      - `/cydia:\/\//`, `/\/Applications\/Cydia\.app/`, `/frida/i`, `/substrate/`, `/MobileSubstrate/`
    - Each finding: `{ severity: 'critical' | 'warning' | 'info', category: string, message: string, evidence: string, location?: string }`
  - Create `src/main/analysis/__tests__/security.test.ts`:
    - Test each pattern category with known matching strings
    - Test binary hardening detection with mock header flags
    - Test no false positives on clean strings
    - Test severity classification

  **Must NOT do**:
  - No ML or heuristic detection — regex patterns only
  - No false-positive tuning beyond reasonable regex specificity
  - No network requests or VirusTotal integration

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: Many regex patterns to get right, binary flag inspection, clear severity classification
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 4 (with Tasks 12, 13, 15)
  - **Blocks**: Task 19
  - **Blocked By**: Tasks 5 (header flags), 10 (symbols), 12 (strings)

  **References**:

  **External References**:
  - MobSF binary analysis checks: PIE, ARC, stack canaries, encryption — the standard mobile security assessment checklist
  - AWS key format: AKIA prefix + 16 alphanumeric characters
  - Common secret patterns from tools like TruffleHog, detect-secrets

  **Acceptance Criteria**:
  - [ ] `bun test` security scan tests → all pass
  - [ ] AWS key pattern matches "AKIA1234567890ABCDEF"
  - [ ] PIE/ARC/canary checks correctly read header flags and symbols
  - [ ] No false positives on common English words

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Security scan tests pass
    Tool: Bash
    Steps:
      1. Run `bun test src/main/analysis/__tests__/security.test.ts`
    Expected Result: All tests pass
    Evidence: .sisyphus/evidence/task-14-security-tests.txt

  Scenario: Known patterns detected
    Tool: Bash
    Steps:
      1. Feed strings containing "AKIA1234567890ABCDEF" and "mongodb://user:pass@host"
      2. Verify both are flagged as critical findings
    Expected Result: Both detected with correct severity
    Evidence: .sisyphus/evidence/task-14-pattern-detection.txt
  ```

  **Commit**: YES
  - Message: `feat(analysis): security scan engine with pattern matching and hardening checks`
  - Files: `src/main/analysis/security.ts`, `src/main/analysis/__tests__/security.test.ts`
  - Pre-commit: `bun test`

- [ ] 15. Electron IPC Integration — Analysis Orchestrator + Per-Tab Data Handlers

  **What to do**:
  - Create `src/main/analysis/orchestrator.ts`:
    - `analyzeIPA(ipaPath: string, progressCallback: (phase: string, percent: number) => void)`: The main analysis pipeline. Sequentially:
      1. Extract IPA to temp dir (fflate) → progress "Extracting IPA..." 0-15%
      2. Discover app bundle and binaries → progress "Discovering binaries..." 15-20%
      3. Parse Info.plist + mobileprovision → progress "Parsing plists..." 20-25%
      4. For main binary: read file as ArrayBuffer → progress "Reading binary..." 25-30%
      5. Parse fat header / Mach-O header → 30-35%
      6. Parse load commands → 35-45%
      7. Build chained fixup map → 45-55%
      8. Extract strings → 55-65%
      9. Parse symbols → 65-70%
      10. Extract ObjC metadata → 70-80%
      11. Parse code signature + entitlements → 80-85%
      12. Run security scan → 85-95%
      13. Build file tree → 95-100%
    - Cache results in memory. Return `AnalysisResult` containing all tab data.
    - Support analyzing a specific binary (for binary selector): re-run steps 4-12 for the selected binary, keep IPA extraction and file tree.
  - Create `src/main/ipc/handlers.ts` to register all IPC handlers:
    - Use `ipcMain.handle(channel, handler)` for request/response channels:
      - `'analyze-ipa'`: Call orchestrator, send progress via `win.webContents.send('update-progress', ...)`, return AnalysisResult
      - `'analyze-binary'`: Re-analyze specific binary from current IPA
      - `'get-tab-data'`: Return cached data for specific tab (lazy loading)
      - `'export-json'`: Serialize specified tab data (or all) as JSON string
      - `'open-file-picker'`: Use `dialog.showOpenDialog(win, { filters: [{ name: 'IPA Files', extensions: ['ipa'] }] })` — return selected file path or null
    - Use `win.webContents.send()` for main→renderer messages:
      - `'update-progress'`: `{ phase, percent, message }`
      - `'analysis-complete'`: void
      - `'analysis-error'`: `{ message }`
  - Update `src/preload/index.ts` to expose typed IPC bridge:
    - `contextBridge.exposeInMainWorld('api', { ... })` with:
      - `analyzeIPA(path)`: wraps `ipcRenderer.invoke('analyze-ipa', { path })`
      - `analyzeBinary(binaryIndex)`: wraps `ipcRenderer.invoke('analyze-binary', { binaryIndex })`
      - `getTabData(tab, binaryIndex)`: wraps `ipcRenderer.invoke('get-tab-data', { tab, binaryIndex })`
      - `exportJSON(tabs?)`: wraps `ipcRenderer.invoke('export-json', { tabs })`
      - `openFilePicker()`: wraps `ipcRenderer.invoke('open-file-picker')`
      - `onProgress(callback)`: wraps `ipcRenderer.on('update-progress', (_, data) => callback(data))`
      - `onComplete(callback)`: wraps `ipcRenderer.on('analysis-complete', () => callback())`
      - `onError(callback)`: wraps `ipcRenderer.on('analysis-error', (_, data) => callback(data))`
    - Also declare `window.api` type in a `src/renderer/global.d.ts` for TypeScript
  - Update `src/renderer/index.ts` to wire renderer-side IPC:
    - On file drop/pick: call `window.api.analyzeIPA(path)`
    - On tab switch: call `window.api.getTabData(tab)` if data not already loaded (lazy)
    - Register progress listener: `window.api.onProgress(({ phase, percent, message }) => { /* update UI */ })`
    - Register completion listener: `window.api.onComplete(() => { /* switch to data view */ })`
    - Register error listener: `window.api.onError(({ message }) => { /* show error toast */ })`

  **Must NOT do**:
  - Do not implement any tab rendering here (that's Tasks 16-20)
  - Do not add multi-IPA session support
  - Do not add caching to disk — in-memory only

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: Integration task wiring many modules together. Requires understanding all parser outputs and RPC schema.
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES (with Tasks 12, 13, 14 — but realistically starts after most are done)
  - **Parallel Group**: Wave 4
  - **Blocks**: Tasks 16-24 (all UI tabs and features need RPC)
  - **Blocked By**: Tasks 2, 4, 5, 6, 8, 9, 10, 12, 13

  **References**:

  **Pattern References**:
  - `src/shared/ipc-types.ts` (Task 2) — IPC channel type definitions that main, preload, and renderer all share
  - All parser modules from Tasks 3-13 — import and call in sequence from orchestrator

  **External References**:
  - Electron IPC Tutorial: `https://www.electronjs.org/docs/latest/tutorial/ipc` — `ipcMain.handle()` + `ipcRenderer.invoke()` pattern, and `webContents.send()` + `ipcRenderer.on()` for one-way messages
  - Electron contextBridge: `https://www.electronjs.org/docs/latest/api/context-bridge` — `contextBridge.exposeInMainWorld()` for secure API exposure to renderer
  - Electron dialog: `https://www.electronjs.org/docs/latest/api/dialog` — `dialog.showOpenDialog()` with file filters for IPA selection
  - Electron webContents: `https://www.electronjs.org/docs/latest/api/web-contents` — `webContents.send()` for main→renderer messages

  **WHY Each Reference Matters**:
  - IPC Tutorial: The handle/invoke pattern is the correct way to do request/response IPC in Electron — do NOT use `ipcRenderer.sendSync`
  - contextBridge: The preload script is the ONLY safe bridge between main and renderer — must expose exactly the right methods
  - dialog: Native file picker for IPA selection — Electron's dialog API gives real file paths, unlike HTML file input
  - webContents.send: Progress updates flow from main to renderer via this one-way channel

  **Acceptance Criteria**:
  - [ ] Main-process IPC handlers registered via `ipcMain.handle()` and callable
  - [ ] Preload script exposes typed `window.api` object to renderer
  - [ ] Renderer receives progress messages via `window.api.onProgress()`
  - [ ] Full analysis pipeline runs without errors on valid input
  - [ ] Progress updates flow from main → renderer during analysis
  - [ ] `dialog.showOpenDialog()` opens native file picker filtered to .ipa files

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: RPC wiring works end-to-end
    Tool: Playwright
    Preconditions: App running
    Steps:
      1. Open app
      2. Trigger file picker (click "Open IPA" button)
      3. Select a test IPA file
      4. Verify progress bar appears and updates
      5. Verify analysis completes (progress reaches 100%)
      6. Verify at least one tab shows data (e.g., Overview tab)
    Expected Result: Full pipeline from file selection to data display works
    Failure Indicators: No progress, stuck at 0%, crash, empty tabs after completion
    Evidence: .sisyphus/evidence/task-15-rpc-e2e.png

  Scenario: Error handling for invalid file
    Tool: Playwright
    Preconditions: App running
    Steps:
      1. Select a non-IPA file (e.g., a text file)
      2. Verify error message appears in UI
      3. Verify app doesn't crash, remains functional
    Expected Result: Graceful error message, app still usable
    Failure Indicators: Crash, hang, no error feedback
    Evidence: .sisyphus/evidence/task-15-rpc-error.png
  ```

  **Commit**: YES
  - Message: `feat(ipc): analysis orchestrator and per-tab IPC data handlers`
  - Files: `src/main/analysis/orchestrator.ts`, `src/main/ipc/handlers.ts`, `src/preload/index.ts`, `src/renderer/index.ts`, `src/renderer/global.d.ts`

- [ ] 16. Overview Tab + Libraries Tab + Headers Tab

  **What to do**:
  - Create `src/renderer/tabs/overview.ts`:
    - Render app summary card: app icon (if extractable from Assets.car — skip if complex, just show placeholder), bundle ID, display name, version, build number, minimum iOS version, architectures (from Mach-O header cputype/cpusubtype), UUID, encryption status (with red warning if encrypted), team ID (from code signature).
    - Binary hardening summary: PIE ✓/✗, ARC ✓/✗, Stack Canaries ✓/✗, Stripped ✓/✗ — each with green check or red X.
    - Provisioning info (if available): team name, expiration date, provisioned devices count.
    - Use the shared empty-state component if no IPA loaded.
  - Create `src/renderer/tabs/libraries.ts`:
    - Data table (from shared component) with columns: Name, Version, Type (strong/weak), Path.
    - Populate from `LinkedLibrary[]` data.
    - Highlight `@rpath` entries with a subtle warning icon (potential hijack).
    - Group by: System frameworks (`/System/Library/`), Swift runtime (`/usr/lib/swift/`), Embedded (`@rpath/`).
  - Create `src/renderer/tabs/headers.ts`:
    - Top section: Mach-O header summary — Magic, CPU Type, File Type, Flags (decoded as named flags like "MH_PIE", "MH_TWOLEVEL").
    - Load commands table: Type, Size, and key details per command (e.g., LC_SEGMENT_64 shows segment name, LC_UUID shows UUID, LC_BUILD_VERSION shows platform+version).
    - Segments/sections tree: Expandable tree showing each segment with its sections. Each section shows: name, size (human-readable), file offset, permissions.
  - Each tab: lazy-loaded (request data from RPC when first activated), show loading spinner during fetch, then render.
  - Integrate with tab switching from Task 7.

  **Must NOT do**:
  - Do not attempt to decode Assets.car for app icon (it's a compiled asset catalog — extremely complex format). Use a generic app placeholder icon.
  - Do not add sorting to Overview (it's a card layout, not a table)

  **Recommended Agent Profile**:
  - **Category**: `visual-engineering`
    - Reason: Three tab layouts — card layout (Overview), data table (Libraries), tree view (Headers). Visual design work.
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 5 (with Tasks 17, 18, 19, 20)
  - **Blocks**: Tasks 21, 22
  - **Blocked By**: Tasks 7, 11, 15

  **References**:

  **Pattern References**:
  - `src/renderer/components/data-table.ts` (Task 11) — use for Libraries tab
  - `src/renderer/components/json-tree.ts` (Task 11) — base pattern for Headers segments tree

  **Acceptance Criteria**:
  - [ ] Overview tab shows app info card with all fields populated
  - [ ] Libraries tab shows sortable/searchable table of dylibs
  - [ ] Headers tab shows Mach-O header, load commands, and segment tree
  - [ ] All three tabs lazy-load data on first activation

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Overview tab displays app info
    Tool: Playwright
    Preconditions: App running with test IPA loaded
    Steps:
      1. Click "Overview" tab
      2. Assert bundle ID field contains a reverse-DNS string (e.g., "com.example")
      3. Assert architecture field shows "arm64"
      4. Assert binary hardening section shows PIE/ARC/Canaries indicators
      5. Screenshot
    Expected Result: All fields populated with real data from test IPA
    Evidence: .sisyphus/evidence/task-16-overview.png

  Scenario: Libraries tab renders dylib list
    Tool: Playwright
    Steps:
      1. Click "Libraries" tab
      2. Assert table has rows
      3. Assert at least one row contains "/usr/lib/" (system library)
    Expected Result: Table populated with linked libraries
    Evidence: .sisyphus/evidence/task-16-libraries.png
  ```

  **Commit**: YES
  - Message: `feat(ui): Overview, Libraries, and Headers tabs`
  - Files: `src/renderer/tabs/overview.ts`, `src/renderer/tabs/libraries.ts`, `src/renderer/tabs/headers.ts`

- [ ] 17. Strings Tab + Symbols Tab

  **What to do**:
  - Create `src/renderer/tabs/strings.ts`:
    - Data table with columns: String Value, Source Section, Offset (hex).
    - Search bar with regex toggle (from shared component) wired to filter the table.
    - Source section filter: dropdown/chips to filter by section type (__cstring, __cfstring, __objc_methname, etc.).
    - Row count display: "Showing N of M strings"
    - Virtual scrolling essential — strings can be 50k+ rows.
  - Create `src/renderer/tabs/symbols.ts`:
    - Data table with columns: Symbol Name, Type (exported/imported), Address (hex).
    - Search bar with regex toggle.
    - Filter by type: exported only, imported only, all.
    - Virtual scrolling for large symbol tables.

  **Must NOT do**:
  - Do not attempt to demangle Swift symbol names
  - Do not add hex viewer or binary view for string offsets

  **Recommended Agent Profile**:
  - **Category**: `visual-engineering`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 5
  - **Blocks**: Tasks 21, 22
  - **Blocked By**: Tasks 11, 15

  **References**:

  **Pattern References**:
  - `src/renderer/components/data-table.ts` (Task 11) — virtual scrolling table
  - `src/renderer/components/search-bar.ts` (Task 11) — regex search

  **Acceptance Criteria**:
  - [ ] Strings tab shows all extracted strings with section source labels
  - [ ] Symbols tab shows exported/imported symbols with addresses
  - [ ] Search filters work on both tabs
  - [ ] Virtual scrolling handles 50k+ rows without lag

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Strings tab with search
    Tool: Playwright
    Steps:
      1. Click "Strings" tab, verify rows appear
      2. Type "http" in search bar
      3. Verify result count decreases
      4. Verify all visible rows contain "http"
    Expected Result: Search filters strings correctly
    Evidence: .sisyphus/evidence/task-17-strings-search.png
  ```

  **Commit**: YES
  - Message: `feat(ui): Strings and Symbols tabs`
  - Files: `src/renderer/tabs/strings.ts`, `src/renderer/tabs/symbols.ts`

- [ ] 18. Classes Tab + Entitlements Tab + Info.plist Tab

  **What to do**:
  - Create `src/renderer/tabs/classes.ts`:
    - Two-panel layout: left panel shows class list (searchable), right panel shows selected class details (method names).
    - Class list as a virtual-scrolled list with search bar.
    - Click a class → right panel shows its method names as a simple list.
    - Protocol names shown in a separate section below classes (simple list).
  - Create `src/renderer/tabs/entitlements.ts`:
    - Key-value display using the JSON tree component.
    - Highlight dangerous entitlements with orange/red badges: `com.apple.private.*`, `get-task-allow`, `com.apple.security.cs.disable-library-validation`, `platform-application`.
    - Show source (embedded entitlements vs provisioning profile entitlements) if both available.
  - Create `src/renderer/tabs/plist.ts`:
    - Full Info.plist rendered as collapsible JSON tree (shared component).
    - Quick-info section at top highlighting key fields: URL schemes, background modes, privacy strings, ATS exceptions.
    - Searchable — filter tree nodes by key name.

  **Must NOT do**:
  - Do not render ObjC type encodings as readable types
  - Do not attempt to reconstruct full @interface declarations

  **Recommended Agent Profile**:
  - **Category**: `visual-engineering`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 5
  - **Blocks**: Tasks 21, 22
  - **Blocked By**: Tasks 11, 15

  **References**:

  **Pattern References**:
  - `src/renderer/components/json-tree.ts` (Task 11) — for Entitlements and Info.plist tree views

  **Acceptance Criteria**:
  - [ ] Classes tab shows searchable class list + method details panel
  - [ ] Entitlements tab highlights dangerous entitlements
  - [ ] Info.plist tab shows full plist with collapsible tree

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Classes tab master-detail works
    Tool: Playwright
    Steps:
      1. Click "Classes" tab
      2. Click on a class name in the list
      3. Assert right panel shows method names for that class
    Expected Result: Class selection shows methods
    Evidence: .sisyphus/evidence/task-18-classes.png

  Scenario: Entitlements highlights dangerous keys
    Tool: Playwright
    Steps:
      1. Click "Entitlements" tab
      2. If "get-task-allow" exists, verify it has a warning badge
    Expected Result: Dangerous entitlements visually highlighted
    Evidence: .sisyphus/evidence/task-18-entitlements.png
  ```

  **Commit**: YES
  - Message: `feat(ui): Classes, Entitlements, and Info.plist tabs`
  - Files: `src/renderer/tabs/classes.ts`, `src/renderer/tabs/entitlements.ts`, `src/renderer/tabs/plist.ts`

- [ ] 19. Security Scan Tab

  **What to do**:
  - Create `src/renderer/tabs/security.ts`:
    - Top summary: count of critical/warning/info findings, with colored badges (red/orange/blue).
    - Binary hardening section: compact grid showing PIE, ARC, Stack Canaries, Encryption, Stripped — each with pass/fail indicator and short description.
    - Findings list: each finding as a card with: severity badge, category label, message, evidence string (the matched text), and source location if available.
    - Filter by severity: buttons for Critical/Warning/Info, toggleable.
    - Search within findings.
    - Sort by severity (critical first, then warning, then info).

  **Must NOT do**:
  - Do not add remediation advice (out of scope — this is an analysis tool, not a fixer)

  **Recommended Agent Profile**:
  - **Category**: `visual-engineering`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 5
  - **Blocks**: Tasks 21, 22
  - **Blocked By**: Tasks 11, 14, 15

  **Acceptance Criteria**:
  - [ ] Security tab shows summary counts
  - [ ] Binary hardening grid displays pass/fail for each check
  - [ ] Findings list shows all detected issues with severity badges
  - [ ] Severity filter works

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Security tab displays findings
    Tool: Playwright
    Steps:
      1. Click "Security" tab with test IPA loaded
      2. Assert summary section shows finding counts
      3. Assert hardening section shows PIE/ARC/etc indicators
      4. Assert at least one finding card is visible
    Expected Result: Security analysis rendered with all sections
    Evidence: .sisyphus/evidence/task-19-security.png
  ```

  **Commit**: YES
  - Message: `feat(ui): Security Scan tab`
  - Files: `src/renderer/tabs/security.ts`

- [ ] 20. File Browser Tab

  **What to do**:
  - Create `src/renderer/tabs/files.ts`:
    - Directory tree view of the extracted IPA contents.
    - Each entry shows: icon (folder/file), name, size (human-readable), file type indicator.
    - Folders expandable/collapsible with smooth animation.
    - File count and total size at top.
    - Search/filter by filename.
    - Highlight interesting files: binaries (Mach-O executables), plists, provisioning profiles, frameworks.

  **Must NOT do**:
  - Do not implement file preview or hex viewer
  - Do not allow file extraction/save from the browser

  **Recommended Agent Profile**:
  - **Category**: `visual-engineering`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 5
  - **Blocks**: Tasks 21, 22
  - **Blocked By**: Tasks 11, 15

  **Acceptance Criteria**:
  - [ ] File tree renders the IPA directory structure
  - [ ] Folders expand/collapse
  - [ ] File sizes displayed in human-readable format

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: File browser shows IPA contents
    Tool: Playwright
    Steps:
      1. Click "Files" tab
      2. Assert "Payload" folder is visible
      3. Expand "Payload" folder, verify .app directory appears
      4. Verify file sizes are shown
    Expected Result: Directory tree of IPA contents rendered
    Evidence: .sisyphus/evidence/task-20-files.png
  ```

  **Commit**: YES
  - Message: `feat(ui): File Browser tab`
  - Files: `src/renderer/tabs/files.ts`

- [ ] 21. Regex Search/Filter Across All Data Tabs

  **What to do**:
  - Ensure every data tab (Strings, Symbols, Classes, Libraries, Security findings, Files) has the search bar component integrated and wired to its data table.
  - The search bar (from Task 11) already supports regex toggle. This task ensures:
    - Search state persists per tab (switching tabs and back preserves the search term)
    - Regex errors show inline feedback (red border + "Invalid regex" message)
    - Search is debounced (200ms)
    - Result count updates: "Showing N of M" or "No matches" state
    - Keyboard shortcut: Cmd/Ctrl+F focuses the search bar of the active tab
  - Wire Cmd/Ctrl+F via a keydown listener on the document, prevent default browser find, focus the active tab's search input.

  **Must NOT do**:
  - Do not implement cross-tab search (search one tab at a time)
  - Do not add search history or saved searches

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: Integration task — wiring existing component across multiple tabs. Keyboard shortcut handling.
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 6 (with Tasks 22, 23, 24)
  - **Blocks**: None
  - **Blocked By**: Tasks 16-20 (all tabs must exist)

  **Acceptance Criteria**:
  - [ ] Every data tab has working search
  - [ ] Regex mode works (toggle on → regex matching)
  - [ ] Search state persists per tab
  - [ ] Cmd/Ctrl+F focuses search bar

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Regex search across tabs
    Tool: Playwright
    Steps:
      1. Go to Strings tab, type "https?://" with regex on
      2. Verify only URL-like strings shown
      3. Switch to Symbols tab, type "_objc" with regex off
      4. Verify matching symbols shown
      5. Switch back to Strings — verify "https?://" still in search bar
    Expected Result: Search works on all tabs, state persists
    Evidence: .sisyphus/evidence/task-21-search.png
  ```

  **Commit**: YES
  - Message: `feat(search): regex search/filter across all data tabs`
  - Files: updates to `src/renderer/tabs/*.ts`, `src/renderer/index.ts`

- [ ] 22. JSON Export — Per-Tab and Full Analysis

  **What to do**:
  - Create `src/main/export/json.ts`:
    - `exportAnalysis(result: AnalysisResult, tabs?: string[])`: Serialize analysis data as JSON. If `tabs` specified, include only those tabs' data. If omitted, export everything.
    - Use `JSON.stringify` with 2-space indent for readability.
    - Include metadata: export timestamp, app name, Disect version.
  - Add export button to UI:
    - In the app shell (sidebar or toolbar), add an "Export JSON" button (visible only when IPA is loaded).
    - Clicking it triggers `window.api.exportJSON()` which calls `dialog.showSaveDialog()` in the main process to pick save location, then writes the JSON.
    - Per-tab export: each tab gets a small export icon button in its header that exports just that tab's data.
  - Wire via IPC: renderer calls `window.api.exportJSON({ tabs })` → main process serializes + uses `dialog.showSaveDialog()` → writes file to disk → returns success/path.

  **Must NOT do**:
  - No CSV, PDF, or HTML export formats
  - No export customization options (what you see is what you export)

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 6
  - **Blocks**: None
  - **Blocked By**: Tasks 15, 16-20

  **Acceptance Criteria**:
  - [ ] Full export produces valid JSON with all analysis data
  - [ ] Per-tab export includes only selected tab data
  - [ ] JSON includes metadata (timestamp, app name)

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Full JSON export
    Tool: Bash
    Steps:
      1. Load test IPA, trigger full export
      2. Read exported JSON file
      3. Verify valid JSON (JSON.parse succeeds)
      4. Verify it contains keys for all 10 tabs
    Expected Result: Valid, complete JSON export
    Evidence: .sisyphus/evidence/task-22-export.json
  ```

  **Commit**: YES
  - Message: `feat(export): JSON export per-tab and full analysis`
  - Files: `src/main/export/json.ts`, UI updates

- [ ] 23. Binary Selector — Choose Main App vs Embedded Frameworks

  **What to do**:
  - In the app shell (Task 7 created a hidden binary selector dropdown), make it functional:
    - After IPA analysis, populate the dropdown with discovered binaries: main binary (default selected) + all embedded frameworks and extensions.
    - Selecting a different binary triggers re-analysis of that binary (call `analyzeBinary({ binaryIndex })` via RPC).
    - Show loading state during re-analysis.
    - All tabs update with the new binary's data.
  - The dropdown should show: binary name, type badge (Main/Framework/Extension), file size.

  **Must NOT do**:
  - Do not show simultaneous analysis of multiple binaries (one at a time)
  - Do not cache analysis for all binaries upfront (analyze on demand)

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 6
  - **Blocks**: None
  - **Blocked By**: Tasks 15, 16

  **Acceptance Criteria**:
  - [ ] Binary selector shows all discovered binaries
  - [ ] Selecting a framework triggers re-analysis
  - [ ] All tabs update with new binary data
  - [ ] Main binary is default selected

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Binary selector switches analysis target
    Tool: Playwright
    Steps:
      1. Load IPA with embedded frameworks
      2. Verify binary selector dropdown appears with multiple entries
      3. Select a framework
      4. Verify loading state appears
      5. Verify tab data changes after re-analysis
    Expected Result: Binary switch works, data updates
    Evidence: .sisyphus/evidence/task-23-binary-selector.png
  ```

  **Commit**: YES
  - Message: `feat(ui): binary selector for analyzing embedded frameworks`
  - Files: `src/renderer/components/binary-selector.ts`, RPC handler updates

- [ ] 24. Error Handling + Encrypted IPA Detection UI

  **What to do**:
  - Add comprehensive error handling throughout:
    - **Invalid file**: Drop/pick a non-IPA file → show error toast: "Not a valid IPA file. Expected a ZIP archive containing Payload/*.app/"
    - **Corrupted IPA**: ZIP extraction fails → error toast with fflate error message
    - **No Mach-O binary**: App bundle found but no valid Mach-O → error toast
    - **Parse failures**: Any parser throws → catch, show error toast for that specific phase, continue with available data
    - **Encrypted binary**: `cryptid != 0` → show persistent warning banner at top of content area: "⚠ This binary is FairPlay encrypted. Strings, classes, and symbols data may be incomplete. Use a decrypted IPA for full analysis." Banner stays visible across all tabs. Partial data (headers, load commands, libraries, Info.plist, entitlements) still shown.
  - Error toast component: slide-in from top-right, auto-dismiss after 5 seconds, closeable. Red for errors, orange for warnings.
  - Ensure no unhandled promise rejections — wrap all async RPC handlers in try/catch.
  - Add `window.onerror` and `window.onunhandledrejection` handlers in browser to catch unexpected errors.

  **Must NOT do**:
  - Do not add retry logic
  - Do not attempt to decrypt encrypted binaries

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: Cross-cutting concern touching many files. Error boundaries, toast system, encrypted state management.
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 6
  - **Blocks**: None
  - **Blocked By**: Tasks 7, 15

  **Acceptance Criteria**:
  - [ ] Non-IPA file shows clear error message
  - [ ] Encrypted IPA shows persistent warning banner
  - [ ] Parseable data still shown for encrypted IPAs (headers, libs, plist, entitlements)
  - [ ] No unhandled exceptions in any error path

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Non-IPA file error
    Tool: Playwright
    Steps:
      1. Open a .txt or .png file via file picker
      2. Assert error toast appears with "Not a valid IPA" message
      3. Assert app remains functional (can open another file)
    Expected Result: Graceful error, app still usable
    Evidence: .sisyphus/evidence/task-24-invalid-file.png

  Scenario: Encrypted IPA warning
    Tool: Playwright
    Steps:
      1. Open an IPA with encrypted binary (cryptid=1 in fixture)
      2. Assert warning banner appears with encryption message
      3. Navigate to Overview tab — verify header data still shown
      4. Navigate to Strings tab — verify it shows warning or limited data
    Expected Result: Warning banner visible, partial data available
    Evidence: .sisyphus/evidence/task-24-encrypted.png
  ```

  **Commit**: YES
  - Message: `feat(ux): error handling, toast notifications, encrypted IPA detection`
  - Files: `src/renderer/components/error.ts`, `src/renderer/components/toast.ts`, updates to orchestrator and RPC handlers

---

## Final Verification Wave (MANDATORY — after ALL implementation tasks)

> 4 review agents run in PARALLEL. ALL must APPROVE. Present consolidated results to user and get explicit "okay" before completing.

- [ ] F1. **Plan Compliance Audit** — `oracle`
  Read the plan end-to-end. For each "Must Have": verify implementation exists (read file, run command). For each "Must NOT Have": search codebase for forbidden patterns — reject with file:line if found. Check evidence files exist in .sisyphus/evidence/. Compare deliverables against plan.
  Output: `Must Have [N/N] | Must NOT Have [N/N] | Tasks [N/N] | VERDICT: APPROVE/REJECT`

- [ ] F2. **Code Quality Review** — `unspecified-high`
  Run `bun test` + check TypeScript strictness. Review all changed files for: `as any`/`@ts-ignore`, empty catches, console.log in prod, commented-out code, unused imports. Check AI slop: excessive comments, over-abstraction, generic names (data/result/item/temp). Verify codebase is "minimal, non-bloated" per user requirement.
  Output: `Build [PASS/FAIL] | Tests [N pass/N fail] | Files [N clean/N issues] | VERDICT`

- [ ] F3. **Real Manual QA** — `unspecified-high` (+ `playwright` skill if needed)
  Start from clean state. Launch app with `bun run start`. Open a test IPA via file picker. Navigate every tab, verify data appears. Test regex search on Strings tab. Export JSON and validate. Test error case (open a non-IPA file). Test encrypted IPA detection. Save evidence to `.sisyphus/evidence/final-qa/`.
  Output: `Scenarios [N/N pass] | Integration [N/N] | Edge Cases [N tested] | VERDICT`

- [ ] F4. **Scope Fidelity Check** — `deep`
  For each task: read "What to do", read actual implementation. Verify 1:1 — everything in spec was built, nothing beyond spec was added. Check "Must NOT do" compliance (no React, no Swift demangling, no streaming ZIP, etc.). Detect cross-task contamination. Flag unaccounted changes.
  Output: `Tasks [N/N compliant] | Contamination [CLEAN/N issues] | Unaccounted [CLEAN/N files] | VERDICT`

---

## Commit Strategy

| Task | Commit Message | Key Files |
|------|---------------|-----------|
| 1 | `chore(scaffold): init Electron project with main/preload/renderer setup` | `package.json`, `tsconfig.json`, `src/main/index.ts`, `src/preload/index.ts` |
| 2 | `feat(types): add shared IPC channel types and analysis data types` | `src/shared/types.ts`, `src/shared/ipc-types.ts` |
| 3 | `feat(parser): fat binary and Mach-O header parser with tests` | `src/main/parser/macho.ts`, `src/main/parser/__tests__/` |
| 4 | `feat(ipa): IPA extraction and app bundle discovery` | `src/main/ipa/extractor.ts` |
| 5 | `feat(parser): load command parser and section enumeration` | `src/main/parser/load-commands.ts` |
| 6 | `feat(parser): Info.plist and mobileprovision parser` | `src/main/parser/plist.ts` |
| 7 | `feat(ui): app shell with dark theme, tab nav, drop zone` | `src/renderer/` |
| 8 | `feat(parser): chained fixups resolver` | `src/main/parser/chained-fixups.ts` |
| 9 | `feat(parser): code signature and entitlements extraction` | `src/main/parser/codesign.ts` |
| 10 | `feat(parser): symbol table and export trie` | `src/main/parser/symbols.ts` |
| 11 | `feat(ui): shared components — data table, search, tree viewer` | `src/renderer/components/` |
| 12 | `feat(parser): string extraction from all Mach-O sections` | `src/main/parser/strings.ts` |
| 13 | `feat(parser): ObjC class and method name extraction` | `src/main/parser/objc.ts` |
| 14 | `feat(analysis): security scan engine with pattern matching` | `src/main/analysis/security.ts` |
| 15 | `feat(ipc): analysis orchestrator and per-tab IPC data handlers` | `src/main/ipc/handlers.ts`, `src/main/analysis/orchestrator.ts`, `src/preload/index.ts` |
| 16 | `feat(ui): Overview, Libraries, and Headers tabs` | `src/renderer/tabs/` |
| 17 | `feat(ui): Strings and Symbols tabs` | `src/renderer/tabs/` |
| 18 | `feat(ui): Classes, Entitlements, and Info.plist tabs` | `src/renderer/tabs/` |
| 19 | `feat(ui): Security Scan tab` | `src/renderer/tabs/security.ts` |
| 20 | `feat(ui): File Browser tab` | `src/renderer/tabs/files.ts` |
| 21 | `feat(search): regex search/filter across all data tabs` | `src/renderer/components/search.ts` |
| 22 | `feat(export): JSON export per-tab and full analysis` | `src/main/export/json.ts`, `src/renderer/components/export.ts` |
| 23 | `feat(ui): binary selector for frameworks` | `src/renderer/components/binary-selector.ts` |
| 24 | `feat(ux): error handling and encrypted IPA detection` | `src/main/analysis/errors.ts`, `src/renderer/components/error.ts` |

---

## Success Criteria

### Verification Commands
```bash
bun test                              # Expected: all parser tests pass
bun run start                         # Expected: Electron app launches, window renders
# Open test IPA → all 10 tabs populated with correct data
# Regex search on Strings tab → filters correctly
# JSON export → valid JSON file with analysis data
# Open encrypted IPA → warning displayed, partial data shown
# Open non-IPA file → graceful error message
```

### Final Checklist
- [ ] All "Must Have" present
- [ ] All "Must NOT Have" absent
- [ ] All parser tests pass
- [ ] App launches on dev machine
- [ ] All 10 tabs render correctly with test IPA data
- [ ] Search/filter works with regex
- [ ] JSON export produces valid output
- [ ] Error states handled gracefully

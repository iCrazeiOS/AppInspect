# AppInspect

A desktop app for analysing iOS and macOS binaries. Open an IPA, DEB, macOS .app bundle, .xcframework, bare Mach-O/dylib, or a folder and inspect its internals — headers, strings, classes, symbols, entitlements, security findings, and more.

Cross-platform for macOS, Windows, and Linux. Built with Electron and TypeScript. All analysis runs locally, offline, with no network requests.

## Features

### File format support

- **IPA** — extracts the app bundle, discovers the main executable plus embedded frameworks and app extensions
- **macOS .app** — supports macOS app bundles (`.app/Contents/MacOS/` layout), discovers main executable, helper binaries, versioned frameworks, and plugins
- **Electron .app** — parses the bundled `Resources/app.asar` as a read-only virtual filesystem: browse and preview archive files, read `package.json`, fuses, ASAR integrity and shipped source maps, split the archive in the Size treemap, and scan archive text files for secrets. Full analysis currently needs a macOS `.app` bundle; the ASAR, fuse and metadata layers are platform-independent, but PE/ELF executables are not parsed. Runtime-fetched JavaScript is not covered
- **DEB** — extracts Debian packages (jailbreak tweaks), parses package metadata, discovers dylibs and bundle binaries
- **Mach-O / dylib** — analyses bare binaries directly (32-bit and 64-bit, fat/universal)
- **XCFramework** — opens `.xcframework` directories or zipped ones (e.g. SwiftPM binary targets), lists every platform slice from `Info.plist`, and lets you switch between the dynamic slices (static-library slices are listed but not analysed)
- **Folder** — scans any directory for Mach-O binaries (extensionless executables, dylibs, and binaries inside `.app`/`.framework` bundles) and extracts any `.deb` packages found inside; every discovered binary is selectable

File type is detected automatically by magic bytes.

### Analysis tabs

| Tab | Description |
|-----|-------------|
| **Overview** | Mach-O header summary, binary hardening status (PIE, ARC, stack canaries, encryption, stripped), build version, UUID, team ID, detected frameworks |
| **Strings** | All embedded strings with section attribution and file offsets |
| **Headers** | Mach-O header fields, fat architecture list, full load command dump |
| **Libraries** | Linked frameworks and dylibs with version info and weak-linking flags. Interactive force-directed dependency graph view showing inter-binary relationships, with pan/zoom, node dragging, and category filtering |
| **Symbols** | Exported, imported, and local symbols with addresses. Swift symbols are demangled for display; the raw name stays searchable |
| **Classes** | ObjC class names and methods with decoded type signatures, syntax-highlighted methods and Logos hooks, protocol conformances per class, protocol detail view (required/optional instance/class methods), Logos hook generation, back/forward navigation history |
| **Swift** | Swift 5 runtime metadata: nominal types (classes, structs, enums) with their source module and nesting, stored properties and enum cases with demangled types (including symbolic field-type references and generics), superclasses, protocols defined in the binary, and protocol conformances (including Swift-standard-library conformances resolved through chained-fixup binds and rebases). Enum cases without a stored type, accessor-only references, and existential-shape-only references remain untyped. Filter by kind or module, and inspect protocol requirement counts and conforming types |
| **Entitlements** | Code signature entitlements or provisioning profile fallback |
| **Localisation** | Localisation strings from `.lproj` bundles with `.strings` file parsing |
| **Info.plist** | Key-facts summary at the top (bundle metadata, device family, supported platforms, privacy strings, ATS exceptions) above the full searchable key/value tree |
| **Electron** | Electron-only, shown when the bundle ships an `app.asar`: archive file tree with path filter and previews for text and images (zoomable, with a Beautify toggle for code), plus package facts — Electron version, fuses, ASAR integrity, `package.json`, shipped source maps and native addons |
| **Hooks** | Jailbreak hook framework detection — Substrate, Libhooker, fishhook, Substitute, ObjC swizzling (Mach-O/DEB only) |
| **Security** | Credential leak scanning, weak crypto, unsafe APIs, dangerous syscalls, jailbreak detection strings, binary hardening assessment (issues only), leaked debug artifacts (DWARF, debug symbols, developer source paths, shipped source maps / Swift module interfaces / symbol maps), bundle file scanning (JS bundles, configs), and Electron findings (fuses, ASAR integrity, shipped source maps, unsafe `webPreferences`) |
| **Hex** | Raw hex viewer with virtual scrolling for large binaries. Segment/section region picker, go-to offset, hex/decimal offset toggle. Dual-mode search (hex bytes or text) with match highlighting and navigation |
| **Files** | Bundle file tree with sizes, context menu (copy path, open file, show in explorer/finder), double-click to open (IPA/DEB) |
| **Size** | Where the binary's bytes go, as **Modules** (Swift modules, ObjC prefixes, C++ namespaces, Kotlin packages, well-known C libs, expandable to largest functions), **Sections** (per-segment, `__LINKEDIT` split into tables/signature/fixups/export trie), and **Blocks**, a treemap of every bundle file with the active binary broken into modules and overhead. Export PNG saves the view at 6000×4000 with every block labelled. Attribution is heuristic, based on symbol table, export trie, ObjC methods, and function starts |

### Other capabilities

- **Tabbed multi-file sessions** — open multiple files simultaneously in separate tabs, each with independent analysis state (scroll position, filters, search, and tree expansions are per tab)
- **Multi-binary switching** — select between main app, frameworks, extensions, multiple dylibs in a DEB, or every binary found in a folder
- **Cross-binary search** — search classes, strings, symbols, or libraries across all binaries in a container at once
- **Fat binary architecture selector** — choose which slice to analyse in universal binaries
- **Jailbreak tweak detection** — identifies binaries linking hooking frameworks (Substrate, Libhooker, Substitute, ElleKit) and marks them as tweaks in the dependency graph
- **FairPlay encryption detection** — warns when a binary is still encrypted (App Store builds)
- **App framework detection** — identifies cross-platform frameworks (React Native, Expo, Flutter, Cordova, Capacitor, Xamarin/.NET MAUI, Kotlin Multiplatform, NativeScript, Titanium, Qt, Electron) and game engines (Unity, Unreal Engine, Godot, Cocos2d, GameMaker, Solar2D), plus linked system frameworks (SwiftUI, UIKit, ARKit, Metal, SceneKit, SpriteKit, RealityKit, GameKit, AppKit)
- **Security scan** — 14 credential/secret patterns (AWS, Google/Firebase, OpenAI, Anthropic, Slack, bearer tokens, private keys, database URIs, hardcoded passwords), also checks base64-encoded strings and scans bundle files (JS bundles, JSON configs, plists). Flags leaked build artifacts: DWARF debug info and retained debug symbols, developer source paths embedded in strings, and shipped source maps / Swift module interfaces / bitcode symbol maps
- **Function attribution** — security findings show which function references the flagged string (xref analysis for ARM64, ARM32/THUMB, x86_64, and x86, runs lazily only when needed)
- **JSON export** — export all analysis data or individual tabs, filename derived from the analysed app
- **Drag-and-drop** — drop files or folders onto the window to start analysis
- **Search** — per-tab search with regex support and case-sensitivity toggle (Ctrl+F / Cmd+F)
- **Settings** — configurable options including multi-binary scanning, plus cache size and a **Clear cache** button (entries used by open files are kept)
- **Keyboard navigation** — Ctrl/Cmd+F for search, Ctrl+Tab to cycle file tabs, Alt+1-9 for section tabs, arrow keys in sidebar and lists
- **Copy on double-click** — double-click a table cell, JSON tree value, or key/value row to copy it; Classes buttons copy on click. Every copy shows a confirmation toast

## Setup & Building

### Prerequisites

- [Bun](https://bun.sh) (v1.0+) — JavaScript runtime and package manager
- [Node.js](https://nodejs.org) (v18+) — required by Electron

### Install dependencies

```bash
bun install
```

### Run in development

```bash
bun start
```

This builds all sources and launches the Electron app.

### Build steps (manual)

```bash
# Build everything
bun run build

# Or individually:
bun run build:main       # Main process (TypeScript → dist/main/)
bun run build:preload    # Preload script (TypeScript → dist/preload/)
bun run build:renderer   # Renderer bundle (TypeScript → dist/renderer/)
bun run build:css        # Copy stylesheets to dist/renderer/
bun run build:mcp        # MCP server (TypeScript → dist/mcp/)
bun run build:cli        # Standalone CLI (TypeScript → dist/cli/)
```

### Package for distribution

```bash
bun run dist            # Build for current platform
bun run dist:mac        # macOS (universal DMG)
bun run dist:win        # Windows (NSIS installer)
bun run dist:win:portable  # Windows (portable exe, no install)
bun run dist:linux      # Linux (AppImage + deb)
```

Output goes to `release/`. Uses [electron-builder](https://www.electron.build/) with configuration in the `"build"` field of `package.json`.

## MCP Server

AppInspect includes a standalone [Model Context Protocol](https://modelcontextprotocol.io) server that exposes the full analysis engine to AI agents. No GUI or Electron needed — it runs as a plain process over stdio.

### Setup

```bash
bun install
bun run build:mcp
```

### Configure your MCP client

Add the server to your client's MCP configuration.

#### Claude Code

Add to `.mcp.json` in a project root (project-scoped) or `~/.claude.json` (global):
```json
{
  "mcpServers": {
    "appinspect": {
      "command": "bun",
      "args": ["/absolute/path/to/AppInspect/dist/mcp/server.js"]
    }
  }
}
```

**Claude Desktop** (`claude_desktop_config.json`), **Cursor**, **VS Code** — same `command` + `args` shape in their respective MCP settings.

#### OpenCode

Add to `~/.config/opencode/opencode.json` (or `opencode.json` in a project root):
```json
{
  "mcp": {
    "appinspect": {
      "type": "local",
      "command": ["bun", "/absolute/path/to/AppInspect/dist/mcp/server.js"],
      "enabled": true
    }
  }
}
```

Verify with `opencode mcp list` — the server should show as **connected**.

### Available tools

| Tool | Description |
|------|-------------|
| `analyse_file` | Analyse a file (IPA, Mach-O, DEB, .app, .xcframework) or folder. Must be called first. |
| `get_overview` | Analysis summary — header, hardening, build version, hooks, frameworks |
| `get_section` | Detailed data for a section (see below). Supports `filter`, `offset`, `limit` for large datasets. |
| `get_size_tree` | Bundle files as a size tree (what the Blocks treemap shows), with the active binary split into modules and an Electron `app.asar` split into its packed contents. Optional `maxDepth` (default 3). |
| `list_asar` | List files inside an Electron `app.asar` (flat, sorted by path). Optional `filter`, `offset`, `limit` |
| `read_asar_file` | Read a file from `app.asar` by archive-relative path (text up to 512 KB; images and other binary content return metadata only). Optional `maxBytes` |
| `search` | Cross-binary search across all binaries in the loaded container. `tab`: `classes`, `strings`, `symbols`, `libraries`, `swift` (Swift type full names) |
| `get_library_graph` | Dependency graph across all binaries (nodes + edges). Optional `category` (`system`, `framework`, `swift`, `embedded`) |
| `search_hex` | Find a byte pattern (hex, or `text:` prefix for a string) in a binary; returns file offsets. Optional `regionOffset`, `regionSize`, `caseInsensitive`, `binary` |
| `read_hex` | Read raw hex bytes from the binary. Supports offset, length, and hexdump or raw output format. |
| `switch_binary` | Change the active binary (framework/extension) so later calls default to it |

**`get_section` sections:** `strings`, `headers`, `libraries`, `symbols`, `classes`, `swift`, `entitlements`, `infoPlist`, `electron`, `security`, `files`, `hooks`, `size`

All query tools (`get_overview`, `get_section`, `search`, `get_library_graph`, `search_hex`, `switch_binary`) accept an optional `path` parameter to target a specific analysis session. When omitted, they default to the last analysed file.

`get_overview`, `get_section`, `read_hex`, and `search_hex` also accept an optional `binary` index (from `overview.ipa.binaries`) to query any binary in the container directly, without `switch_binary` changing the active one.

### Example workflow

1. Agent calls `analyse_file` with a path to an IPA → gets an overview summary
2. Agent calls `get_section` with `section: "security"` → sees security findings
3. Agent calls `get_section` with `section: "strings", filter: "api.example.com"` → finds matching strings
4. Agent calls `search` with `query: "UIWebView", tab: "classes"` → searches across all binaries

### Parallel analysis

Multiple files can be analysed concurrently (e.g. by subagents). Each `analyse_file` call creates an isolated session keyed by file path. Query tools target the correct session via the optional `path` parameter:

```
Subagent A: analyse_file({ path: "/tmp/App1.ipa" })
Subagent B: analyse_file({ path: "/tmp/App2.ipa" })
Subagent A: get_section({ section: "security", path: "/tmp/App1.ipa" })
Subagent B: get_section({ section: "symbols", path: "/tmp/App2.ipa" })
```

### Notes

- All analysis runs locally, offline, with no network requests
- The app does not need to be open — the MCP server is fully standalone
- The server reads whatever local path you ask it to analyse, running with your privileges. To confine `analyse_file` to a directory tree, start it with `APPINSPECT_ALLOW_ROOT=/path/to/root`.
- Large sections (strings, symbols, classes, libraries) support pagination via `offset` and `limit` (default: 200 items) and text filtering via `filter`
- Symbol entries include a `demangled` field with the readable name for Swift symbols; the original `name` is preserved as-is
- Extracted IPA/DEB content is cached in `~/.appinspect/cache/` so re-analysing the same file skips extraction
- Settings are shared with the desktop app (`~/.appinspect/appinspect-settings.json`), with sensible defaults if no settings file exists

## CLI

AppInspect also ships a standalone command-line entry point for headless and scripted use (CI, batch triage). It runs under Bun with no GUI or Electron, and emits either the full analysis as JSON or the security findings as a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) report.

### Build

```bash
bun install
bun run build:cli        # or: bun run build (builds everything)
```

### Usage

```bash
bun run cli -- /path/App.ipa --sarif --out report.sarif --fail-on warning
bun run cli -- /path/App.ipa --json --section security
bun run cli -- /path/App.ipa --json --section security --section strings
bun run cli -- /path/App.ipa --json --no-pretty --out analysis.json
bun run cli -- /path/App.ipa --binary 1 --json        # analyse a specific binary
```

`appinspect <file> [options]`

| Flag | Description |
|------|-------------|
| `--json` | Emit the full analysis as JSON (default) |
| `--sarif` | Emit a SARIF 2.1.0 report of the security findings |
| `--section <name>` | Limit `--json` output to a section (repeatable): `overview`, `strings`, `headers`, `libraries`, `symbols`, `classes`, `swift`, `entitlements`, `infoPlist`, `electron`, `hooks`, `security`, `files`, `size` |
| `--binary <index>` | Analyse a specific binary index instead of the main one |
| `--out <path>` | Write output to a file (overwrites an existing file; default: stdout) |
| `--no-clobber` | Refuse to overwrite an existing `--out` file (exits 1) |
| `--pretty` / `--no-pretty` | Pretty-print or minify JSON (default: pretty) |
| `--fail-on <level>` | Exit 3 when a finding at/above this severity exists: `critical`, `warning`, `info`, or `none` (default: `none`) |
| `--quiet` | Suppress progress output on stderr |
| `--version` / `--help` | Print version / usage |

### Output & exit codes

The machine-readable payload goes to stdout (or `--out <path>`); progress goes to stderr and is suppressed by `--quiet`.

| Exit code | Meaning |
|-----------|---------|
| `0` | Success, or no findings at/above `--fail-on` |
| `1` | Analysis failure |
| `2` | Usage error (unknown flags, missing file) |
| `3` | A finding at/above `--fail-on` exists |

## Project structure

```
src/
  main/              # Electron main process
    analysis/        # Orchestrator, security scan engine
    deb/             # DEB archive extraction
    electron/        # Electron detection, ASAR parsing, fuse + archive scanning
    ipc/             # IPC handlers
    ipa/             # IPA extraction
    xcframework/     # XCFramework slice discovery
    parser/          # Mach-O parsing (headers, load commands, strings,
                     #   symbols, ObjC + Swift metadata, code signatures, xrefs,
                     #   chained fixups, plists)
  mcp/               # Standalone MCP server (no Electron dependency)
  preload/           # Electron preload bridge
  renderer/          # UI
    components/      # Reusable UI components (tables, search, JSON tree, toast)
    tabs/            # Tab renderers (one per analysis tab)
    utils/           # Shared helpers (DOM utilities, Mach-O decoders)
  shared/            # Types and IPC channel definitions
```

## Development

### Linting & Formatting

We use [Biome](https://biomejs.dev) for linting and formatting. Configuration is in `biome.json`.

```bash
bun run check       # Lint + format check
bun run check:fix   # Auto-fix issues
```

A pre-commit hook automatically runs `check:fix`, TypeScript type checking, and tests before each commit.

### Testing

```bash
bun test            # Run all tests
bun run typecheck   # TypeScript type check only
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed development guidelines.

## Tech stack

- **Electron** — desktop shell
- **TypeScript** — full codebase, strict mode
- **Bun** — bundler and package manager
- **Biome** — linting and formatting
- **fflate** — ZIP decompression (IPA extraction)
- **bplist-parser** / **plist** — binary and XML plist parsing
- **@modelcontextprotocol/sdk** — MCP server for AI agent integration
- **swift-demangle-wasm** — Swift symbol demangling (WebAssembly)

# AppInspect

A desktop app for analysing iOS and macOS binaries. Open an IPA, DEB, macOS .app bundle, or bare Mach-O/dylib and inspect its internals — headers, strings, classes, symbols, entitlements, security findings, and more.

Built with Electron and TypeScript. All analysis runs locally, offline, with no network requests.

## Features

### File format support

- **IPA** — extracts the app bundle, discovers the main executable plus embedded frameworks and app extensions
- **macOS .app** — supports macOS app bundles (`Contents/MacOS/` layout), discovers main executable, helper binaries, versioned frameworks, and plugins
- **DEB** — extracts Debian packages (jailbreak tweaks), parses package metadata, discovers dylibs and bundle binaries
- **Mach-O / dylib** — analyses bare binaries directly (64-bit, fat/universal)

File type is detected automatically by magic bytes.

### Analysis tabs

| Tab | Description |
|-----|-------------|
| **Overview** | Mach-O header summary, binary hardening status (PIE, ARC, stack canaries, encryption, stripped), build version, UUID, team ID, detected frameworks |
| **Strings** | All embedded strings with section attribution and file offsets |
| **Headers** | Mach-O header fields, fat architecture list, full load command dump |
| **Libraries** | Linked frameworks and dylibs with version info and weak-linking flags |
| **Symbols** | Exported, imported, and local symbols with addresses |
| **Classes** | ObjC class names, instance and class methods with decoded type signatures, protocols, Logos hook generation |
| **Entitlements** | Code signature entitlements or provisioning profile fallback |
| **Localisation** | Localisation strings from `.lproj` bundles with `.strings` file parsing |
| **Info.plist** | Full Info.plist contents (IPA only) |
| **Hooks** | Jailbreak hook framework detection — Substrate, Libhooker, fishhook, Substitute, ObjC swizzling (Mach-O/DEB only) |
| **Security** | Credential leak scanning, weak crypto, unsafe APIs, dangerous syscalls, jailbreak detection strings, binary hardening assessment, bundle file scanning (JS bundles, configs) |
| **Files** | Bundle file tree with sizes, context menu (copy path, open file, show in explorer/finder), double-click to open (IPA/DEB) |

### Other capabilities

- **Multi-binary switching** — select between main app, frameworks, extensions, or multiple dylibs in a DEB
- **Fat binary architecture selector** — choose which slice to analyse in universal binaries
- **FairPlay encryption detection** — warns when a binary is still encrypted (App Store builds)
- **App framework detection** — identifies cross-platform frameworks (React Native, Expo, Flutter, Cordova, Capacitor, Xamarin/.NET MAUI, Kotlin Multiplatform, NativeScript, Titanium, Qt, Electron) and game engines (Unity, Unreal Engine, Godot, Cocos2d, GameMaker, Solar2D), plus linked system frameworks (SwiftUI, UIKit, ARKit, Metal, SceneKit, SpriteKit, RealityKit, GameKit, AppKit)
- **Security scan** — 14 credential/secret patterns (AWS, Google/Firebase, OpenAI, Anthropic, Slack, bearer tokens, private keys, database URIs, hardcoded passwords), also checks base64-encoded strings and scans bundle files (JS bundles, JSON configs, plists)
- **Function attribution** — security findings show which function references the flagged string (arm64 xref analysis, runs lazily only when needed)
- **JSON export** — export all analysis data or individual tabs, filename derived from the analysed app
- **Drag-and-drop** — drop files onto the window to start analysis
- **Search** — per-tab search with regex support and case-sensitivity toggle (Ctrl+F / Cmd+F)
- **Settings** — configurable options including multi-binary scanning
- **Copy on double-click** — double-click any table cell to copy its contents

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

## Project structure

```
src/
  main/              # Electron main process
    analysis/        # Orchestrator, security scan engine
    deb/             # DEB archive extraction
    ipc/             # IPC handlers
    ipa/             # IPA extraction
    parser/          # Mach-O parsing (headers, load commands, strings,
                     #   symbols, ObjC metadata, code signatures, xrefs,
                     #   chained fixups, plists)
  preload/           # Electron preload bridge
  renderer/          # UI
    components/      # Reusable UI components (tables, search, JSON tree, toast)
    tabs/            # Tab renderers (one per analysis tab)
    utils/           # Shared helpers (DOM utilities, Mach-O decoders)
  shared/            # Types and IPC channel definitions
```

## Tech stack

- **Electron** — desktop shell
- **TypeScript** — full codebase
- **Bun** — bundler and package manager
- **fflate** — ZIP decompression (IPA extraction)
- **bplist-parser** / **plist** — binary and XML plist parsing

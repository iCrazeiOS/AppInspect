# AppInspect

Desktop binary analysis tool for iOS/macOS apps. Built with Electron + TypeScript, vanilla DOM renderer (no framework). All analysis runs locally.

## Commands

```bash
bun install          # Install deps (also sets up Husky hooks via prepare)
bun run build        # Build all targets (main, preload, renderer, css, mcp)
bun run start        # Build + launch Electron
bun run typecheck    # tsc --noEmit
bun test             # Run all tests (bun:test)
bun run dist         # Build + package with electron-builder
```

## Architecture

Three Electron processes with strict context isolation:

- **Main** (`src/main/`) — analysis orchestrator, file I/O, IPC handlers
- **Renderer** (`src/renderer/`) — vanilla TypeScript DOM manipulation, no framework
- **Preload** (`src/preload/`) — typed `window.api` bridge via contextBridge
- **MCP** (`src/mcp/`) — standalone MCP server for AI agents (runs under Bun, no Electron)
- **Shared** (`src/shared/`) — types shared across all processes (`types.ts`, `ipc-types.ts`)

IPC: renderer invokes main via typed channels defined in `src/shared/ipc-types.ts`. Main sends progress/completion/error events back. All IPC types are in `InvokeChannelMap` and `SendChannelMap`.

### Analysis pipeline

`src/main/analysis/orchestrator.ts` runs a multi-step pipeline: extract container → discover binaries → parse Mach-O headers → load commands → chained fixups → strings → symbols → ObjC metadata → code signature → security scan → hook detection → framework detection → bundle file scan → file tree + localisation.

Each step yields to the event loop (`setImmediate`) and reports progress via callback.

### Parsers (`src/main/parser/`)

Each parser is a self-contained module: `macho.ts`, `load-commands.ts`, `symbols.ts`, `strings.ts`, `objc.ts`, `codesign.ts`, `chained-fixups.ts`, `plist.ts`, `xrefs.ts`. They operate on `DataView` with explicit endianness and use `BigInt` for addresses/offsets.

### Caching

Extracted containers cached in `~/.appinspect/cache/` keyed by MD5(path+size+mtime). Cache mtime is touched on access for LRU-style pruning (7-day expiry).

## Code style

- **Files:** kebab-case (`load-commands.ts`, `data-table.ts`)
- **Types/interfaces:** PascalCase. Use `import type` for type-only imports
- **Functions:** camelCase. **Constants:** UPPER_SNAKE_CASE
- **Exports:** named exports, no default exports
- **Error handling:** result types (`{ ok, data/error }`) for parsers, try-catch with informative messages at boundaries. Parsers continue gracefully on individual failures
- **BigInt:** used internally for addresses, converted to number/string before IPC serialisation (see `bigintReplacer` in MCP server)
- **No linter configured** — TypeScript strict mode is the only enforcement
- Keep implementations minimal. No unnecessary abstractions, helpers, or wrapper functions
- Follow existing patterns in the file you're editing

## TypeScript config

Strict mode enabled. Key flags: `noUncheckedIndexedAccess`, `noFallthroughCasesInSwitch`, `noImplicitOverride`. Target ES2022. `skipLibCheck: true`.

## Testing

Framework: `bun:test` (`describe`, `it`, `expect`). Tests live in `__tests__/` directories next to the code they test.

- `src/main/parser/__tests__/` — parser unit tests (fixtures in `fixtures.ts`)
- `src/main/analysis/__tests__/` — security scan tests
- `src/main/ipa/__tests__/` — IPA extraction tests

When adding new features or modifying analysis logic, add or update corresponding tests.

## Pre-commit hook

Husky runs `bun run typecheck && bun test` before every commit. Both must pass. Do not bypass with `--no-verify`.

## Cross-platform

Must work on macOS, Windows, and Linux.

- macOS: traffic light buttons, `.app` bundle directory support in file picker
- Windows: title bar overlay, PowerShell for IPA extraction
- Linux: standard unzip

Use `process.platform` checks when platform-specific behaviour is needed. Never assume Unix-only APIs.

## Key dependencies

- `electron` — desktop framework
- `@modelcontextprotocol/sdk` — MCP server (AI agent integration)
- `bplist-parser` + `plist` — binary/XML plist parsing
- `fflate` — ZIP compression/decompression (dev dependency, used in tests)
- `electron-builder` — packaging
- `husky` — git hooks

## Build targets

Each process builds separately with Bun. Main and preload target Node (CJS, `--external electron`). Renderer targets browser. MCP targets Bun. CSS is a plain copy.

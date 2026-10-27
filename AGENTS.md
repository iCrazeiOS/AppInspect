# AppInspect

Desktop binary analysis tool for iOS/macOS apps. Built with Electron + TypeScript, vanilla DOM renderer (no framework). All analysis runs locally.

## Commands

```bash
bun install          # Install deps (also sets up Husky hooks via prepare)
bun run build        # Build all targets (main, preload, renderer, css, mcp)
bun run start        # Build + launch Electron
bun run typecheck    # tsc --noEmit
bun test             # Run all tests (bun:test)
bun run check        # Lint + format check
bun run check:fix    # Lint + format with auto-fix
bun run dist         # Build + package with electron-builder
```

## Architecture

Three Electron processes with strict context isolation:

- **Main** (`src/main/`) — analysis orchestrator, file I/O, IPC handlers
- **Renderer** (`src/renderer/`) — vanilla TypeScript DOM manipulation, no framework
- **Preload** (`src/preload/`) — typed `window.api` bridge via contextBridge
- **MCP** (`src/mcp/`) — standalone MCP server for AI agents (runs under Bun, no Electron). **Important:** After running `bun run build:mcp`, you must restart Claude Code (or the MCP client) to pick up changes — the server process keeps running old code until restarted. If MCP tool results don't reflect your code changes, this is likely why.
- **Shared** (`src/shared/`) — types shared across all processes (`types.ts`, `ipc-types.ts`)

IPC: renderer invokes main via typed channels defined in `src/shared/ipc-types.ts`. Main sends progress/completion/error events back. All IPC types are in `InvokeChannelMap` and `SendChannelMap`.

### Analysis pipeline

`src/main/analysis/orchestrator.ts` runs a multi-step pipeline: extract container → discover binaries → parse Mach-O headers → load commands → chained fixups → strings → symbols → ObjC metadata → code signature → security scan → hook detection → framework detection → bundle file scan → file tree + localisation.

Each step yields to the event loop (`setImmediate`) and reports progress via callback.

### Parsers (`src/main/parser/`)

Each parser is a self-contained module: `macho.ts`, `load-commands.ts`, `symbols.ts`, `strings.ts`, `objc.ts`, `codesign.ts`, `chained-fixups.ts`, `plist.ts`, `xrefs.ts`. They operate on `DataView` with explicit endianness and use `BigInt` for addresses/offsets.

### Caching

Extracted containers cached in `~/.appinspect/cache/` keyed by MD5(path+size+mtime). Cache mtime is touched on access for LRU-style pruning (7-day expiry). The Settings panel can clear the cache on demand; entries used by open sessions and fresh `-tmp-` dirs are kept.

## Code style

- **Files:** kebab-case (`load-commands.ts`, `data-table.ts`)
- **Types/interfaces:** PascalCase. Use `import type` for type-only imports
- **Functions:** camelCase. **Constants:** UPPER_SNAKE_CASE
- **Exports:** named exports, no default exports
- **Error handling:** parsers with a hard-failure mode (input is either valid and fully parseable or not — `macho.ts`, `plist.ts`, `codesign.ts`) return the shared `Result<T>` from `src/main/parser/result.ts` (`{ ok, data } | { ok, error }`) and never throw for malformed-but-expected input. Collection extractors (`strings`, `symbols`, `load-commands`, `objc`, `chained-fixups`, `xrefs`) return partial data best-effort, skipping malformed entries — an empty result is meaningful, not a failure. Use try-catch with informative messages at boundaries
- **BigInt:** used internally for addresses, converted to number/string before IPC serialisation (see `bigintReplacer` in MCP server)
- **Counts and units:** use the shared helpers in `src/shared/format.ts` (`formatCount()`, `plural()`, `formatSize()`) instead of hardcoding plurals or units — e.g. `plural(n, "source map")`, not `` `${n} source map${n === 1 ? "" : "s"}` `` or a fixed `"Source Maps (1)"`. Supply an explicit plural when the default `+s` is wrong (`plural(n, "Dependency", "Dependencies")`). UI labels use sentence case
- **Linter:** Biome (see "Linting & Formatting" section)
- Keep implementations minimal. No unnecessary abstractions, helpers, or wrapper functions - unless it will sufficiently improve readability, or reduce code duplication
- Follow existing patterns in the file you're editing

## Linting & Formatting

Biome handles linting and formatting. Configuration in `biome.json`.

```bash
bun run lint        # Run linter only
bun run format      # Format files in place
bun run format:check # Check formatting (CI mode)
bun run check       # Lint + format check (unused symbols are errors, not warnings)
bun run check:fix   # Lint + format with auto-fix
```

**Style rules:**
- Indentation: Tabs
- Line width: 100 characters
- Semicolons: Always
- Quotes: Double quotes
- Trailing commas: None
- Arrow function parens: Always
- Bracket spacing: Yes

VS Code users: Install the recommended Biome extension for format-on-save.

## TypeScript config

Strict mode enabled. Key flags: `noUncheckedIndexedAccess`, `noFallthroughCasesInSwitch`, `noImplicitOverride`. Target ES2022. `skipLibCheck: true`.

## Testing

Framework: `bun:test` (`describe`, `it`, `expect`). Tests live in `__tests__/` directories next to the code they test.

`bunfig.toml` sets `[test] root = "src"`. Without it `bun test` walks the whole tree and also picks up the compiled `*.test.js` files that `bun run build` leaves in `dist/` — stale copies that keep passing long after their TypeScript sources have changed.

- `src/main/parser/__tests__/` — parser unit tests (fixtures in `fixtures.ts`)
- `src/main/analysis/__tests__/` — security scan tests
- `src/main/ipa/__tests__/` — IPA extraction tests

When adding new features or modifying analysis logic, add or update corresponding tests. New scan/analysis features must also be exposed via the MCP server (`src/mcp/`) so AI agents can access them.

## README

When adding a significant user-facing feature (new tab, new MCP tool, major capability), update `README.md` to document it. Small additions that most users wouldn't care about should not be in the README just for the sake of it.

## Pre-commit hook

Husky runs Biome auto-fix, re-stages changes, then runs `bun run check && bun run typecheck && bun test` before every commit. Auto-fixable issues are corrected automatically; unfixable lint errors will fail the commit. Do not bypass with `--no-verify`.

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

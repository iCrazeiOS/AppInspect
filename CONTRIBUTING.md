# Contributing to AppInspect

Thanks for your interest in contributing to AppInspect! This document outlines how to get started.

## Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/iCrazeiOS/AppInspect.git
   cd AppInspect
   ```

2. **Install dependencies**
   ```bash
   bun install
   ```
   This also sets up Husky git hooks via the `prepare` script.

3. **Run the app**
   ```bash
   bun run start
   ```

## Code Style

We use [Biome](https://biomejs.dev) for linting and formatting. The configuration is in `biome.json`.

### Style Rules

| Setting | Value |
|---------|-------|
| Indentation | Tabs |
| Line width | 100 characters |
| Semicolons | Always |
| Quotes | Double quotes |
| Trailing commas | None |
| Arrow function parens | Always |
| Bracket spacing | Yes |

### Commands

```bash
bun run check       # Lint + format check
bun run check:fix   # Auto-fix lint/format issues
bun run format      # Format files in place
bun run lint        # Lint only
```

### VS Code

Install the recommended [Biome extension](https://marketplace.visualstudio.com/items?itemName=biomejs.biome) for format-on-save. Settings are in `.vscode/settings.json`.

## Pre-commit Hook

Every commit runs through a pre-commit hook that:

1. Auto-fixes lint/format issues (`bun run check:fix`)
2. Re-stages modified files
3. Runs lint check (`bun run check`)
4. Runs TypeScript type check (`bun run typecheck`)
5. Runs tests (`bun test`)

If any step fails, the commit is aborted. Do not bypass with `--no-verify`.

## Testing

Tests use `bun:test`. Run all tests with:

```bash
bun test
```

Test files live in `__tests__/` directories next to the code they test:

- `src/main/parser/__tests__/` — parser unit tests
- `src/main/analysis/__tests__/` — security scan tests
- `src/main/ipa/__tests__/` — IPA extraction tests

When adding new features or fixing bugs, add or update corresponding tests.

## Pull Request Guidelines

1. **Branch from `master`** and give your branch a descriptive name
2. **Keep changes focused** — one feature or fix per PR
3. **Write clear commit messages** — describe what and why
4. **Add tests** for new functionality
5. **Update documentation** if adding user-facing features (README.md, CLAUDE.md)
6. **Ensure all checks pass** — the pre-commit hook runs automatically

## Architecture Overview

AppInspect is an Electron app with three processes:

- **Main** (`src/main/`) — file I/O, binary parsing, analysis orchestration
- **Renderer** (`src/renderer/`) — vanilla TypeScript DOM manipulation
- **Preload** (`src/preload/`) — typed IPC bridge via `window.api`

Additionally:

- **MCP** (`src/mcp/`) — standalone MCP server for AI agents
- **Shared** (`src/shared/`) — types shared across processes

See `CLAUDE.md` for detailed architecture documentation.

## Reporting Issues

Please open an issue on GitHub with:

- A clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- App version and OS

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.

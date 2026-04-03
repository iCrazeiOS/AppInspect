# Learnings — Disect

## Electrobun
- RPC: Type-safe via shared RPCSchema<T>, BrowserView.defineRPC on bun side, Electroview.defineRPC on browser side
- Views: src/views/<name>/index.ts → transpiled to views://<name>/index.js, HTML must be in copy rules
- Draggable regions: CSS class `electrobun-webkit-app-region-drag` for titlebar drag
- Native file drag-drop NOT supported (Issue #63) — use file picker + HTML5 drop events
- ApplicationMenu with Edit roles needed for Cmd+C/V/X to work

## Mach-O Parsing
- Fat headers are ALWAYS big-endian, even for LE slices
- Code signature blobs are BIG-ENDIAN (unlike rest of arm64 LE binary)
- Load commands: iterate by cmdsize, NEVER by struct size
- Chained fixups: pointers in __DATA are encoded, must resolve before reading
- __cfstring is a 32-byte struct, not a string pointer
- mobileprovision is CMS/DER wrapping XML — NOT binary plist

## Dependencies
- fflate: ZIP extraction (NOT Bun.Archive which is TAR-only)
- bplist-parser: Binary plist parsing
- plist: XML plist parsing

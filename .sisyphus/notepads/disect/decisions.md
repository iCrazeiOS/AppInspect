# Decisions — Disect

## Architecture
- Pure TypeScript Mach-O parser — no native deps, no otool/class-dump
- Heavy analysis in Bun main process, results sent to UI via typed RPC
- Lazy tab loading — only fetch data when tab activated
- One IPA at a time, "Open new" replaces current

## Scope Locks
- Swift: __swift5_reflstr only. No demangling, no type descriptors.
- ObjC: Class names + method names. No ivars, no protocol recursion.
- Chained fixups: DYLD_CHAINED_PTR_64_OFFSET (format 6) only.
- Export: JSON only. No CSV/PDF.
- No app icon extraction from Assets.car.

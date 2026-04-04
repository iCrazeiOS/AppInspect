/**
 * ObjC Class + Method Name Extraction
 *
 * Parses __DATA.__objc_classlist (or __DATA_CONST.__objc_classlist) to
 * extract Objective-C class names and their method selectors from a
 * Mach-O 64-bit binary.
 *
 * All pointer reads check the rebaseMap first (chained fixups may have
 * replaced raw pointer values), then fall back to reading the raw
 * BigUint64 from the buffer. Low 3 bits are stripped from data pointers
 * (Apple stores runtime flags there).
 *
 * Does NOT parse ivar types, property attributes, or category merging.
 */

import type { Section64, Segment64 } from "./load-commands";
import { readCString } from "./load-commands";

// ── Types ────────────────────────────────────────────────────────────

export interface ObjCMethod {
  selector: string;
  signature: string;
  /** @internal Set for metaclass (class-level) methods during parsing; used by enrichment. */
  _isClassMethod?: boolean;
}

export interface ObjCClass {
  name: string;
  methods: ObjCMethod[];
}

export interface ObjCMetadata {
  classes: ObjCClass[];
  protocols: string[];
}

// ── Pointer mask ─────────────────────────────────────────────────────

/** Mask to strip low 3 flag bits from ObjC data pointers. */
const POINTER_MASK = ~0x7n;

// ── Helpers ──────────────────────────────────────────────────────────

/**
 * Convert a virtual memory address to a file offset using segment
 * mappings. Returns null if the vmaddr doesn't fall within any segment.
 */
export function vmaddrToFileOffset(
  vmaddr: bigint,
  segments: Segment64[],
): number | null {
  for (const seg of segments) {
    if (vmaddr >= seg.vmaddr && vmaddr < seg.vmaddr + seg.vmsize) {
      const offset = Number(vmaddr - seg.vmaddr) + Number(seg.fileoff);
      return offset;
    }
  }
  return null;
}

/**
 * For dyld_shared_cache extracted binaries, pointers may have auth/tag bits
 * in the upper bytes and a rebased target that doesn't directly match
 * segment vmaddrs. This function detects and caches the slide base.
 */
let cachedSlideBase: bigint | null = null;
let slideBaseComputed = false;

function resolveSharedCachePointer(
  raw: bigint,
  segments: Segment64[],
): bigint {
  // For arm64e shared cache extracted binaries, pointers have PAC/auth bits
  // in the upper bytes. The actual target offset may be in the lower 36 bits
  // (non-auth) or lower 32 bits (auth, where bits 32-47 hold PAC metadata).
  // Try both masks to handle both cases.
  const targets = [
    raw & 0xFFFFFFFFFn, // lower 36 bits (non-auth / general case)
    raw & 0xFFFFFFFFn,  // lower 32 bits (auth pointers with PAC in bits 32-47)
  ];

  for (const target of targets) {
    if (target === 0n) continue;

    // Use cached base if already found
    if (slideBaseComputed && cachedSlideBase !== null) {
      const candidate = target + cachedSlideBase;
      if (vmaddrToFileOffset(candidate, segments) !== null) {
        return candidate;
      }
    }

    // Probe common shared cache base addresses
    for (const base of [0x180000000n, 0x200000000n, 0x100000000n, 0x0n]) {
      const c = target + base;
      if (vmaddrToFileOffset(c, segments) !== null) {
        cachedSlideBase = base;
        slideBaseComputed = true;
        return c;
      }
    }
  }

  return raw;
}

/**
 * Resolve an 8-byte pointer at the given file offset.
 *
 * If the rebaseMap contains a resolved value for this file offset, use
 * that (chained fixups). Otherwise read the raw BigUint64 from the
 * buffer. For dyld_shared_cache extracted binaries, attempts slide-base
 * correction when the raw pointer doesn't resolve to any segment.
 */
export function resolvePointer(
  view: DataView,
  fileOffset: number,
  rebaseMap: Map<number, bigint>,
  littleEndian: boolean,
  segments?: Segment64[],
): bigint {
  const resolved = rebaseMap.get(fileOffset);
  if (resolved !== undefined) return resolved;
  if (fileOffset + 8 > view.byteLength) return 0n;
  const raw = view.getBigUint64(fileOffset, littleEndian);

  // If segments provided and raw pointer doesn't resolve, try shared cache fixup
  if (segments && raw !== 0n && vmaddrToFileOffset(raw & POINTER_MASK, segments) === null) {
    return resolveSharedCachePointer(raw, segments);
  }

  return raw;
}

/**
 * Read a null-terminated C string from a DataView.
 * Delegates to readCString from load-commands with a 4096-byte limit.
 */
function readString(view: DataView, offset: number): string {
  if (offset < 0 || offset >= view.byteLength) return "";
  const maxLen = Math.min(4096, view.byteLength - offset);
  return readCString(view, offset, maxLen);
}

// ── ObjC Type Encoding Decoder ───────────────────────────────────────

const TYPE_MAP: Record<string, string> = {
  v: "void", "@": "id", "#": "Class", ":": "SEL",
  c: "char", C: "unsigned char", s: "short", S: "unsigned short",
  i: "int", I: "unsigned int", l: "long", L: "unsigned long",
  q: "long long", Q: "unsigned long long",
  f: "float", d: "double", B: "BOOL",
  "*": "char *", "?": "unknown",
};

/**
 * Find the matching closing delimiter for nested bracket-like pairs.
 * Handles {}, (), and [] with proper nesting.
 */
function findMatchingClose(enc: string, pos: number, open: string, close: string): number {
  let depth = 1;
  let i = pos + 1;
  while (i < enc.length && depth > 0) {
    if (enc[i] === open) depth++;
    else if (enc[i] === close) depth--;
    i++;
  }
  return depth === 0 ? i - 1 : -1;
}

/**
 * Decode a single ObjC type encoding token starting at `pos`.
 * Returns the decoded type string and the new position after the token.
 */
function decodeType(enc: string, pos: number): { type: string; next: number } {
  if (pos >= enc.length) return { type: "?", next: pos };

  let ch = enc[pos];

  // Skip qualifiers: r(const) n(in) N(inout) o(out) O(bycopy) R(byref) V(oneway)
  while (pos < enc.length && "rnNoORV".includes(enc[pos]!)) {
    pos++;
    ch = enc[pos]!;
  }

  if (ch === "^") {
    const inner = decodeType(enc, pos + 1);
    return { type: inner.type + " *", next: inner.next };
  }

  if (ch === "@") {
    // Check for @"ClassName"
    if (pos + 1 < enc.length && enc[pos + 1] === '"') {
      const end = enc.indexOf('"', pos + 2);
      if (end !== -1) {
        return { type: enc.slice(pos + 2, end) + " *", next: end + 1 };
      }
    }
    return { type: "id", next: pos + 1 };
  }

  if (ch === "{") {
    // Struct: {Name=...} — extract just the name, handle nested braces
    const eq = enc.indexOf("=", pos);
    const close = findMatchingClose(enc, pos, "{", "}");
    if (eq !== -1 && (close === -1 || eq < close)) {
      return { type: enc.slice(pos + 1, eq), next: close !== -1 ? close + 1 : pos + 1 };
    }
    if (close !== -1) {
      return { type: enc.slice(pos + 1, close), next: close + 1 };
    }
    return { type: "struct", next: pos + 1 };
  }

  if (ch === "(") {
    const close = findMatchingClose(enc, pos, "(", ")");
    return { type: "union", next: close !== -1 ? close + 1 : pos + 1 };
  }

  if (ch === "[") {
    const close = findMatchingClose(enc, pos, "[", "]");
    return { type: "array", next: close !== -1 ? close + 1 : pos + 1 };
  }

  if (ch === "b") {
    // Bitfield: bN
    let next = pos + 1;
    while (next < enc.length && enc[next]! >= "0" && enc[next]! <= "9") next++;
    return { type: "bitfield", next };
  }

  const mapped = TYPE_MAP[ch!];
  if (mapped) return { type: mapped, next: pos + 1 };

  return { type: String(ch), next: pos + 1 };
}

/**
 * Skip a stack offset number in the encoding string.
 */
function skipOffset(enc: string, pos: number): number {
  while (pos < enc.length && ((enc[pos]! >= "0" && enc[pos]! <= "9") || enc[pos] === "-")) pos++;
  return pos;
}

/**
 * Parse a full ObjC method type encoding string into [returnType, ...argTypes].
 * The encoding format is: returnType offset argType1 offset argType2 offset ...
 */
function parseTypeEncoding(enc: string): string[] {
  if (!enc) return [];
  const types: string[] = [];
  let pos = 0;
  while (pos < enc.length) {
    const { type, next } = decodeType(enc, pos);
    types.push(type);
    pos = skipOffset(enc, next);
  }
  return types;
}

/**
 * Build a full ObjC method signature string from selector and type encoding.
 * e.g. "-(void)initWithFrame:(CGRect)frame style:(NSInteger)style"
 */
export function buildMethodSignature(selector: string, typeEncoding: string, isInstance = true): string {
  const types = parseTypeEncoding(typeEncoding);
  const prefix = isInstance ? "-" : "+";

  if (types.length === 0) {
    return `${prefix}${selector}`;
  }

  const returnType = types[0];
  // types[1] = self (id), types[2] = _cmd (SEL), types[3..] = actual args
  const argTypes = types.slice(3);

  const parts = selector.split(":");

  if (argTypes.length === 0 || !selector.includes(":")) {
    return `${prefix}(${returnType})${selector}`;
  }

  let sig = `${prefix}(${returnType})`;
  for (let i = 0; i < parts.length; i++) {
    if (parts[i] === "" && i === parts.length - 1) break; // trailing colon
    if (i > 0) sig += " ";
    sig += parts[i];
    if (i < argTypes.length) {
      sig += `:(${argTypes[i]})arg${i}`;
    }
  }

  return sig;
}

// ── Section Finders ──────────────────────────────────────────────────

/**
 * Find a section by segment + section name pair across all segments.
 * Checks both __DATA and __DATA_CONST for ObjC sections.
 */
function findSection(
  sections: Section64[],
  segname: string,
  sectname: string,
): Section64 | null {
  for (const sect of sections) {
    if (sect.segname.trim() === segname && sect.sectname.trim() === sectname) {
      return sect;
    }
  }
  return null;
}

function findObjCSection(
  sections: Section64[],
  sectname: string,
): Section64 | null {
  // Check all segments that can contain ObjC metadata, including
  // __AUTH_CONST, __AUTH, __DATA_DIRTY (dyld_shared_cache binaries).
  for (const seg of ["__DATA", "__DATA_CONST", "__AUTH_CONST", "__AUTH", "__DATA_DIRTY"]) {
    const found = findSection(sections, seg, sectname);
    if (found) return found;
  }
  return null;
}

// ── Method List Parsing ──────────────────────────────────────────────

/** Bit 31 of entsizeAndFlags indicates relative method selectors. */
const METHOD_LIST_FLAG_RELATIVE = 0x80000000;

/**
 * Parse a method_list_t and return an array of ObjCMethod with selector and signature.
 */
function parseMethodList(
  view: DataView,
  methodListFileOffset: number,
  segments: Segment64[],
  rebaseMap: Map<number, bigint>,
  le: boolean,
  methodListVmaddr: bigint | null = null,
  isInstance = true,
): ObjCMethod[] {
  if (
    methodListFileOffset < 0 ||
    methodListFileOffset + 8 > view.byteLength
  ) {
    return [];
  }

  const entsizeAndFlags = view.getUint32(methodListFileOffset, le);
  const count = view.getUint32(methodListFileOffset + 4, le);

  if (count === 0 || count > 100_000) return [];

  const isRelative = (entsizeAndFlags & METHOD_LIST_FLAG_RELATIVE) !== 0;
  const methods: ObjCMethod[] = [];

  const entriesStart = methodListFileOffset + 8;

  if (isRelative) {
    // Relative method entries: 12 bytes each
    // name_offset(int32) + types_offset(int32) + imp_offset(int32)
    const entrySize = 12;

    for (let i = 0; i < count; i++) {
      const entryOffset = entriesStart + i * entrySize;
      if (entryOffset + entrySize > view.byteLength) break;

      // name_offset is a signed 32-bit relative offset from its own position
      const nameRelOffset = view.getInt32(entryOffset, le);
      const selectorRefFileOffset = entryOffset + nameRelOffset;

      let name = "";

      if (
        selectorRefFileOffset >= 0 &&
        selectorRefFileOffset + 8 <= view.byteLength
      ) {
        // Normal case: selref is within the file
        const selectorVmaddr = resolvePointer(
          view, selectorRefFileOffset, rebaseMap, le, segments,
        );
        if (selectorVmaddr !== 0n) {
          const selectorFileOffset = vmaddrToFileOffset(selectorVmaddr, segments);
          if (selectorFileOffset !== null) {
            name = readString(view, selectorFileOffset);
          }
        }
      }

      // Shared cache fallback: the relative offset targets a selref outside
      // this extracted file. Compute the selref's vmaddr from the method
      // entry's vmaddr and try to resolve the selector string directly.
      if (name.length === 0 && methodListVmaddr !== null) {
        const entryVmaddr = methodListVmaddr + BigInt(8 + i * entrySize);
        const selrefVmaddr = entryVmaddr + BigInt(nameRelOffset);
        // The selref vmaddr may be outside our segments (in another cache image),
        // but sometimes the selector string vmaddr can be found in __objc_selrefs
        // within our file. Try looking up the selref in our local selrefs.
        const localSelrefOff = vmaddrToFileOffset(selrefVmaddr, segments);
        if (localSelrefOff !== null) {
          const selVmaddr = resolvePointer(view, localSelrefOff, rebaseMap, le, segments);
          if (selVmaddr !== 0n) {
            const selOff = vmaddrToFileOffset(selVmaddr, segments);
            if (selOff !== null) name = readString(view, selOff);
          }
        }
      }

      // types_offset is a signed 32-bit relative offset from its own position
      const typesRelOffset = view.getInt32(entryOffset + 4, le);
      const typesFileOffset = entryOffset + 4 + typesRelOffset;
      const typeEncoding = (typesFileOffset >= 0 && typesFileOffset < view.byteLength)
        ? readString(view, typesFileOffset) : "";

      // Keep entry even with empty name — the orchestrator can fill it
      // from symbol table data for shared cache binaries.
      methods.push({
        selector: name,
        signature: name.length > 0 ? buildMethodSignature(name, typeEncoding, isInstance) : typeEncoding,
        ...(!isInstance && { _isClassMethod: true }),
      });
    }
  } else {
    // Absolute method entries: 24 bytes each
    // name_ptr(8) + types_ptr(8) + imp_ptr(8)
    const entrySize = 24;

    for (let i = 0; i < count; i++) {
      const entryOffset = entriesStart + i * entrySize;
      if (entryOffset + 16 > view.byteLength) break;

      const nameVmaddr = resolvePointer(view, entryOffset, rebaseMap, le, segments);
      if (nameVmaddr === 0n) continue;

      const nameFileOffset = vmaddrToFileOffset(nameVmaddr, segments);
      if (nameFileOffset === null) continue;

      const name = readString(view, nameFileOffset);
      if (name.length === 0) continue;

      // types pointer at offset 8 within the entry
      const typesVmaddr = resolvePointer(view, entryOffset + 8, rebaseMap, le, segments);
      let typeEncoding = "";
      if (typesVmaddr !== 0n) {
        const typesFileOffset = vmaddrToFileOffset(typesVmaddr, segments);
        if (typesFileOffset !== null) {
          typeEncoding = readString(view, typesFileOffset);
        }
      }

      methods.push({
        selector: name,
        signature: buildMethodSignature(name, typeEncoding, isInstance),
        ...(!isInstance && { _isClassMethod: true }),
      });
    }
  }

  return methods;
}

// ── Class Parsing ────────────────────────────────────────────────────

/**
 * Parse a single class from its class_t file offset.
 * Returns null if the class cannot be parsed.
 *
 * class_t layout (64-bit):
 *   isa(8) + superclass(8) + cache(8) + vtable(8) + data(8) = 40 bytes
 *
 * class_ro_t layout:
 *   flags(4) + instanceStart(4) + instanceSize(4) + reserved(4) +
 *   ivarLayout(8) + name(8) + baseMethods(8) + baseProtocols(8) +
 *   ivars(8) + weakIvarLayout(8) + baseProperties(8)
 */
function parseClass(
  view: DataView,
  classFileOffset: number,
  segments: Segment64[],
  rebaseMap: Map<number, bigint>,
  le: boolean,
): ObjCClass | null {
  // Read class_t.data pointer at offset 32
  if (classFileOffset + 40 > view.byteLength) return null;

  const dataFieldOffset = classFileOffset + 32;
  let dataVmaddr = resolvePointer(view, dataFieldOffset, rebaseMap, le, segments);
  dataVmaddr = dataVmaddr & POINTER_MASK; // strip low 3 flag bits

  if (dataVmaddr === 0n) return null;

  const roFileOffset = vmaddrToFileOffset(dataVmaddr, segments);
  if (roFileOffset === null) return null;

  // class_ro_t: need at least up to baseMethods (offset 32 + 8 = 40 bytes)
  if (roFileOffset + 40 > view.byteLength) return null;

  // name pointer at offset 24 within class_ro_t
  const nameFieldOffset = roFileOffset + 24;
  const nameVmaddr = resolvePointer(view, nameFieldOffset, rebaseMap, le, segments);
  if (nameVmaddr === 0n) return null;

  const nameFileOffset = vmaddrToFileOffset(nameVmaddr, segments);
  if (nameFileOffset === null) return null;

  const className = readString(view, nameFileOffset);
  if (className.length === 0) return null;

  // baseMethods pointer at offset 32 within class_ro_t
  const baseMethodsFieldOffset = roFileOffset + 32;
  const baseMethodsVmaddr = resolvePointer(
    view,
    baseMethodsFieldOffset,
    rebaseMap,
    le,
    segments,
  );

  let methods: ObjCMethod[] = [];
  if (baseMethodsVmaddr !== 0n) {
    const methodsFileOffset = vmaddrToFileOffset(baseMethodsVmaddr, segments);
    if (methodsFileOffset !== null) {
      methods = parseMethodList(view, methodsFileOffset, segments, rebaseMap, le, baseMethodsVmaddr);
    }
  }

  // Class methods from metaclass (isa pointer at offset 0)
  let isaVmaddr = resolvePointer(view, classFileOffset, rebaseMap, le, segments);
  isaVmaddr = isaVmaddr & POINTER_MASK;
  if (isaVmaddr !== 0n) {
    const metaclassOff = vmaddrToFileOffset(isaVmaddr, segments);
    if (metaclassOff !== null && metaclassOff + 40 <= view.byteLength) {
      let metaDataVmaddr = resolvePointer(view, metaclassOff + 32, rebaseMap, le, segments);
      metaDataVmaddr = metaDataVmaddr & POINTER_MASK;
      if (metaDataVmaddr !== 0n) {
        const metaRoOff = vmaddrToFileOffset(metaDataVmaddr, segments);
        if (metaRoOff !== null && metaRoOff + 40 <= view.byteLength) {
          const metaMethodsVmaddr = resolvePointer(view, metaRoOff + 32, rebaseMap, le, segments);
          if (metaMethodsVmaddr !== 0n) {
            const metaMethodsOff = vmaddrToFileOffset(metaMethodsVmaddr, segments);
            if (metaMethodsOff !== null) {
              const classMethods = parseMethodList(
                view, metaMethodsOff, segments, rebaseMap, le, metaMethodsVmaddr, false,
              );
              methods.push(...classMethods);
            }
          }
        }
      }
    }
  }

  return { name: className, methods };
}

// ── Protocol Parsing ─────────────────────────────────────────────────

/**
 * Parse __objc_protolist to extract protocol names.
 *
 * protocol_t layout (simplified, 64-bit):
 *   isa(8) + mangledName(8) + ...
 *
 * We only read the name pointer at offset 8.
 */
function parseProtocols(
  view: DataView,
  sections: Section64[],
  segments: Segment64[],
  rebaseMap: Map<number, bigint>,
  le: boolean,
): string[] {
  const protolistSection = findObjCSection(sections, "__objc_protolist");
  if (!protolistSection) return [];

  const sectionOffset = vmaddrToFileOffset(protolistSection.addr, segments) ?? protolistSection.offset;
  const sectionSize = Number(protolistSection.size);
  const pointerCount = Math.floor(sectionSize / 8);
  const protocols: string[] = [];

  for (let i = 0; i < pointerCount; i++) {
    const ptrFileOffset = sectionOffset + i * 8;
    if (ptrFileOffset + 8 > view.byteLength) break;

    let protoVmaddr = resolvePointer(view, ptrFileOffset, rebaseMap, le, segments);
    protoVmaddr = protoVmaddr & POINTER_MASK;
    if (protoVmaddr === 0n) continue;

    const protoFileOffset = vmaddrToFileOffset(protoVmaddr, segments);
    if (protoFileOffset === null) continue;

    // protocol_t.mangledName at offset 8
    if (protoFileOffset + 16 > view.byteLength) continue;

    const nameVmaddr = resolvePointer(
      view,
      protoFileOffset + 8,
      rebaseMap,
      le,
      segments,
    );
    if (nameVmaddr === 0n) continue;

    const nameFileOffset = vmaddrToFileOffset(nameVmaddr, segments);
    if (nameFileOffset === null) continue;

    const name = readString(view, nameFileOffset);
    if (name.length > 0) protocols.push(name);
  }

  return protocols;
}

// ── Main Entry Point ─────────────────────────────────────────────────

/**
 * Extract Objective-C class names, method selectors, and protocol names
 * from a Mach-O 64-bit binary.
 *
 * @param buffer       The raw Mach-O file buffer
 * @param sections     All Section64 entries from parsed segments
 * @param segments     All Segment64 entries from load commands
 * @param rebaseMap    Chained fixups rebase map (file offset → resolved vmaddr)
 * @param littleEndian Byte order of the binary
 */
export function extractObjCMetadata(
  buffer: ArrayBuffer,
  sections: Section64[],
  segments: Segment64[],
  rebaseMap: Map<number, bigint>,
  littleEndian: boolean,
): ObjCMetadata {
  const view = new DataView(buffer);
  const le = littleEndian;

  // Reset shared cache slide base detection for each new binary
  cachedSlideBase = null;
  slideBaseComputed = false;

  const result: ObjCMetadata = {
    classes: [],
    protocols: [],
  };

  // Step 1: Find __objc_classlist section
  const classlistSection = findObjCSection(sections, "__objc_classlist");

  if (classlistSection) {
    // Use vmaddr→fileoff mapping instead of section.offset, because
    // dyld_shared_cache extracted binaries have stale section offsets.
    const sectionOffset = vmaddrToFileOffset(classlistSection.addr, segments) ?? classlistSection.offset;
    const sectionSize = Number(classlistSection.size);
    const pointerCount = Math.floor(sectionSize / 8);

    // Step 2: For each pointer in __objc_classlist
    for (let i = 0; i < pointerCount; i++) {
      const ptrFileOffset = sectionOffset + i * 8;
      if (ptrFileOffset + 8 > view.byteLength) break;

      // Resolve the pointer (may be a chained fixup)
      let classVmaddr = resolvePointer(view, ptrFileOffset, rebaseMap, le, segments);
      classVmaddr = classVmaddr & POINTER_MASK; // strip low 3 flag bits

      if (classVmaddr === 0n) continue;

      // Convert vmaddr to file offset
      const classFileOffset = vmaddrToFileOffset(classVmaddr, segments);
      if (classFileOffset === null) continue;

      // Steps 3-5: Parse the class
      const cls = parseClass(view, classFileOffset, segments, rebaseMap, le);
      if (cls) {
        result.classes.push(cls);
      }
    }
  }

  // Step 6: Parse protocols
  result.protocols = parseProtocols(view, sections, segments, rebaseMap, le);

  return result;
}

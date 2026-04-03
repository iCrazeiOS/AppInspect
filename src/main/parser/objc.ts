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
 * Does NOT parse ivar types, property attributes, category merging,
 * metaclass methods, or ObjC type encodings.
 */

import type { Section64, Segment64 } from "./load-commands";
import { readCString } from "./load-commands";

// ── Types ────────────────────────────────────────────────────────────

export interface ObjCClass {
  name: string;
  methods: string[];
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
 * Resolve an 8-byte pointer at the given file offset.
 *
 * If the rebaseMap contains a resolved value for this file offset, use
 * that (chained fixups). Otherwise read the raw BigUint64 from the
 * buffer.
 */
export function resolvePointer(
  view: DataView,
  fileOffset: number,
  rebaseMap: Map<number, bigint>,
  littleEndian: boolean,
): bigint {
  const resolved = rebaseMap.get(fileOffset);
  if (resolved !== undefined) return resolved;
  if (fileOffset + 8 > view.byteLength) return 0n;
  return view.getBigUint64(fileOffset, littleEndian);
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
  return (
    findSection(sections, "__DATA", sectname) ??
    findSection(sections, "__DATA_CONST", sectname) ??
    null
  );
}

// ── Method List Parsing ──────────────────────────────────────────────

/** Bit 31 of entsizeAndFlags indicates relative method selectors. */
const METHOD_LIST_FLAG_RELATIVE = 0x80000000;

/**
 * Parse a method_list_t and return an array of method name strings.
 */
function parseMethodList(
  view: DataView,
  methodListFileOffset: number,
  segments: Segment64[],
  rebaseMap: Map<number, bigint>,
  le: boolean,
): string[] {
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
  const methods: string[] = [];

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
      // This points to a selector reference (pointer to the actual string)
      const selectorRefFileOffset = entryOffset + nameRelOffset;

      if (
        selectorRefFileOffset < 0 ||
        selectorRefFileOffset + 8 > view.byteLength
      ) {
        continue;
      }

      // Read the selector reference pointer (may be in rebaseMap)
      const selectorVmaddr = resolvePointer(
        view,
        selectorRefFileOffset,
        rebaseMap,
        le,
      );
      if (selectorVmaddr === 0n) continue;

      const selectorFileOffset = vmaddrToFileOffset(selectorVmaddr, segments);
      if (selectorFileOffset === null) continue;

      const name = readString(view, selectorFileOffset);
      if (name.length > 0) methods.push(name);
    }
  } else {
    // Absolute method entries: 24 bytes each
    // name_ptr(8) + types_ptr(8) + imp_ptr(8)
    const entrySize = 24;

    for (let i = 0; i < count; i++) {
      const entryOffset = entriesStart + i * entrySize;
      if (entryOffset + 8 > view.byteLength) break;

      const nameVmaddr = resolvePointer(view, entryOffset, rebaseMap, le);
      if (nameVmaddr === 0n) continue;

      const nameFileOffset = vmaddrToFileOffset(nameVmaddr, segments);
      if (nameFileOffset === null) continue;

      const name = readString(view, nameFileOffset);
      if (name.length > 0) methods.push(name);
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
  let dataVmaddr = resolvePointer(view, dataFieldOffset, rebaseMap, le);
  dataVmaddr = dataVmaddr & POINTER_MASK; // strip low 3 flag bits

  if (dataVmaddr === 0n) return null;

  const roFileOffset = vmaddrToFileOffset(dataVmaddr, segments);
  if (roFileOffset === null) return null;

  // class_ro_t: need at least up to baseMethods (offset 32 + 8 = 40 bytes)
  if (roFileOffset + 40 > view.byteLength) return null;

  // name pointer at offset 24 within class_ro_t
  const nameFieldOffset = roFileOffset + 24;
  const nameVmaddr = resolvePointer(view, nameFieldOffset, rebaseMap, le);
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
  );

  let methods: string[] = [];
  if (baseMethodsVmaddr !== 0n) {
    const methodsFileOffset = vmaddrToFileOffset(baseMethodsVmaddr, segments);
    if (methodsFileOffset !== null) {
      methods = parseMethodList(view, methodsFileOffset, segments, rebaseMap, le);
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

  const sectionOffset = protolistSection.offset;
  const sectionSize = Number(protolistSection.size);
  const pointerCount = Math.floor(sectionSize / 8);
  const protocols: string[] = [];

  for (let i = 0; i < pointerCount; i++) {
    const ptrFileOffset = sectionOffset + i * 8;
    if (ptrFileOffset + 8 > view.byteLength) break;

    let protoVmaddr = resolvePointer(view, ptrFileOffset, rebaseMap, le);
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

  const result: ObjCMetadata = {
    classes: [],
    protocols: [],
  };

  // Step 1: Find __objc_classlist section
  const classlistSection = findObjCSection(sections, "__objc_classlist");

  if (classlistSection) {
    const sectionOffset = classlistSection.offset;
    const sectionSize = Number(classlistSection.size);
    const pointerCount = Math.floor(sectionSize / 8);

    // Step 2: For each pointer in __objc_classlist
    for (let i = 0; i < pointerCount; i++) {
      const ptrFileOffset = sectionOffset + i * 8;
      if (ptrFileOffset + 8 > view.byteLength) break;

      // Resolve the pointer (may be a chained fixup)
      let classVmaddr = resolvePointer(view, ptrFileOffset, rebaseMap, le);
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

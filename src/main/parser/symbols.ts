/**
 * Symbol Table + Export Trie Parser
 *
 * Parses LC_SYMTAB nlist_64 entries and LC_DYLD_EXPORTS_TRIE / LC_DYLD_INFO
 * export trie structures from a Mach-O binary buffer.
 *
 * Does NOT demangle Swift/C++ names or parse dyld bind opcodes.
 */

// ── Types ─────────────────────────────────────────────────────────────

export interface Symbol {
  name: string;
  address: bigint;
  type: "exported" | "imported" | "local";
  sectionIndex: number;
}

export interface SymtabInfo {
  symoff: number;
  nsyms: number;
  stroff: number;
  strsize: number;
}

// ── Constants ─────────────────────────────────────────────────────────

const NLIST_64_SIZE = 16; // n_strx(4) + n_type(1) + n_sect(1) + n_desc(2) + n_value(8)
const N_EXT = 0x01;
const N_TYPE_MASK = 0x0e;
const N_STAB_MASK = 0xe0;

// ── ULEB128 ───────────────────────────────────────────────────────────

/**
 * Read a ULEB128-encoded unsigned integer from a DataView.
 * Returns the decoded value and number of bytes consumed.
 */
export function readULEB128(
  dataView: DataView,
  offset: number,
): { value: number; bytesRead: number } {
  let value = 0;
  let shift = 0;
  let bytesRead = 0;

  while (offset + bytesRead < dataView.byteLength) {
    const byte = dataView.getUint8(offset + bytesRead);
    bytesRead++;
    value |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7;
  }

  return { value, bytesRead };
}

// ── Helpers ───────────────────────────────────────────────────────────

/**
 * Read a null-terminated C string from a DataView starting at `offset`.
 * Returns an empty string if offset is out of bounds.
 */
function readStringFromTable(
  dataView: DataView,
  strTableOffset: number,
  n_strx: number,
): string {
  const start = strTableOffset + n_strx;
  if (start >= dataView.byteLength) return "";

  const bytes: number[] = [];
  for (let i = start; i < dataView.byteLength; i++) {
    const b = dataView.getUint8(i);
    if (b === 0) break;
    bytes.push(b);
  }
  return String.fromCharCode(...bytes);
}

// ── Symbol Table Parser ───────────────────────────────────────────────

/**
 * Parse the LC_SYMTAB symbol table: reads nlist_64 entries and their
 * associated string table names. Skips STABS debug symbols.
 *
 * @param buffer       The full Mach-O file buffer
 * @param symtabInfo   Offsets / sizes from the LC_SYMTAB load command
 * @param littleEndian Endianness of the binary
 * @returns            Array of parsed Symbol entries (no STABS)
 */
export function parseSymbolTable(
  buffer: ArrayBuffer,
  symtabInfo: SymtabInfo | null,
  littleEndian: boolean,
): Symbol[] {
  if (!symtabInfo) return [];

  const { symoff, nsyms, stroff, strsize } = symtabInfo;
  if (nsyms === 0) return [];

  const view = new DataView(buffer);
  const le = littleEndian;
  const symbols: Symbol[] = [];

  for (let i = 0; i < nsyms; i++) {
    const entryOffset = symoff + i * NLIST_64_SIZE;

    // Bounds check
    if (entryOffset + NLIST_64_SIZE > buffer.byteLength) break;

    const n_strx = view.getUint32(entryOffset, le);
    const n_type = view.getUint8(entryOffset + 4);
    const n_sect = view.getUint8(entryOffset + 5);
    const n_desc = view.getInt16(entryOffset + 6, le);
    const n_value = view.getBigUint64(entryOffset + 8, le);

    // Skip STABS debug symbols
    if ((n_type & N_STAB_MASK) !== 0) continue;

    const name = readStringFromTable(view, stroff, n_strx);

    // Classify symbol
    const isExternal = (n_type & N_EXT) !== 0;
    const typeBits = n_type & N_TYPE_MASK;

    let symType: Symbol["type"];
    if (isExternal && typeBits !== 0) {
      symType = "exported";
    } else if (isExternal && typeBits === 0) {
      symType = "imported";
    } else {
      symType = "local";
    }

    symbols.push({
      name,
      address: n_value,
      type: symType,
      sectionIndex: n_sect,
    });
  }

  return symbols;
}

// ── Export Trie Parser ────────────────────────────────────────────────

/**
 * Parse the export trie (from LC_DYLD_EXPORTS_TRIE or LC_DYLD_INFO).
 * Walks the trie recursively, accumulating edge labels to reconstruct
 * full symbol names.
 *
 * @param buffer       The full Mach-O file buffer
 * @param exportOffset Byte offset of the trie within the buffer
 * @param exportSize   Size of the trie in bytes
 * @returns            Array of exported Symbol entries
 */
export function parseExportTrie(
  buffer: ArrayBuffer,
  exportOffset: number,
  exportSize: number,
): Symbol[] {
  if (exportSize === 0) return [];
  if (exportOffset + exportSize > buffer.byteLength) return [];

  const view = new DataView(buffer);
  const symbols: Symbol[] = [];

  function walkNode(nodeOffset: number, prefix: string): void {
    const absOffset = exportOffset + nodeOffset;
    if (absOffset >= exportOffset + exportSize) return;

    // Read terminal size
    const term = readULEB128(view, absOffset);
    let cursor = absOffset + term.bytesRead;

    if (term.value > 0) {
      // This is a terminal node — read flags and address
      const flags = readULEB128(view, cursor);
      cursor += flags.bytesRead;
      const addr = readULEB128(view, cursor);
      cursor += addr.bytesRead;

      symbols.push({
        name: prefix,
        address: BigInt(addr.value),
        type: "exported",
        sectionIndex: 0,
      });
    }

    // Read children
    const childrenStart = absOffset + term.bytesRead + term.value;
    if (childrenStart >= exportOffset + exportSize) return;

    const childCount = view.getUint8(childrenStart);
    let childCursor = childrenStart + 1;

    for (let i = 0; i < childCount; i++) {
      // Read null-terminated edge string
      const edgeChars: number[] = [];
      while (childCursor < exportOffset + exportSize) {
        const b = view.getUint8(childCursor);
        childCursor++;
        if (b === 0) break;
        edgeChars.push(b);
      }
      const edge = String.fromCharCode(...edgeChars);

      // Read child node offset (ULEB128, relative to trie start)
      const childOff = readULEB128(view, childCursor);
      childCursor += childOff.bytesRead;

      walkNode(childOff.value, prefix + edge);
    }
  }

  walkNode(0, "");
  return symbols;
}

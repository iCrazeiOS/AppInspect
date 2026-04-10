import { describe, expect, it } from "bun:test";
import {
  readULEB128,
  parseSymbolTable,
  parseExportTrie,
  type SymtabInfo,
} from "../symbols";

// ── Helpers ───────────────────────────────────────────────────────────

/** Build a DataView from raw byte values. */
function dvFrom(bytes: number[]): DataView {
  return new DataView(new Uint8Array(bytes).buffer);
}

/**
 * Build an ArrayBuffer containing nlist_64 entries + a string table.
 *
 * Layout:
 *   [0 .. nlist_64 entries] [string table]
 *
 * Each nlist_64 = 16 bytes (little-endian):
 *   n_strx  (uint32)  — byte offset into string table
 *   n_type  (uint8)
 *   n_sect  (uint8)
 *   n_desc  (int16)
 *   n_value (uint64)
 */
function buildSymtabBuffer64(
  entries: Array<{
    n_strx: number;
    n_type: number;
    n_sect: number;
    n_desc: number;
    n_value: bigint;
  }>,
  stringTable: string[], // null-terminated strings concatenated
): { buffer: ArrayBuffer; symtabInfo: SymtabInfo } {
  // Build string table bytes: each string followed by a null byte
  const strBytes: number[] = [0]; // index 0 = empty string (null byte)
  const strOffsets: number[] = [0];
  for (const s of stringTable) {
    strOffsets.push(strBytes.length);
    for (let i = 0; i < s.length; i++) strBytes.push(s.charCodeAt(i));
    strBytes.push(0);
  }

  const symoff = 0;
  const nsyms = entries.length;
  const stroff = nsyms * 16;
  const strsize = strBytes.length;

  const totalSize = stroff + strsize;
  const buf = new ArrayBuffer(totalSize);
  const view = new DataView(buf);

  // Write nlist_64 entries
  for (let i = 0; i < nsyms; i++) {
    const base = i * 16;
    const e = entries[i]!;
    view.setUint32(base, e.n_strx, true);
    view.setUint8(base + 4, e.n_type);
    view.setUint8(base + 5, e.n_sect);
    view.setInt16(base + 6, e.n_desc, true);
    view.setBigUint64(base + 8, e.n_value, true);
  }

  // Write string table
  const u8 = new Uint8Array(buf);
  for (let i = 0; i < strBytes.length; i++) {
    u8[stroff + i] = strBytes[i]!;
  }

  return { buffer: buf, symtabInfo: { symoff, nsyms, stroff, strsize } };
}

/** Alias for backward compatibility */
const buildSymtabBuffer = buildSymtabBuffer64;

/**
 * Build an ArrayBuffer containing nlist (32-bit) entries + a string table.
 *
 * Each nlist = 12 bytes (little-endian):
 *   n_strx  (uint32)  — byte offset into string table
 *   n_type  (uint8)
 *   n_sect  (uint8)
 *   n_desc  (int16)
 *   n_value (uint32)
 */
function buildSymtabBuffer32(
  entries: Array<{
    n_strx: number;
    n_type: number;
    n_sect: number;
    n_desc: number;
    n_value: number;
  }>,
  stringTable: string[],
): { buffer: ArrayBuffer; symtabInfo: SymtabInfo } {
  const strBytes: number[] = [0];
  for (const s of stringTable) {
    for (let i = 0; i < s.length; i++) strBytes.push(s.charCodeAt(i));
    strBytes.push(0);
  }

  const symoff = 0;
  const nsyms = entries.length;
  const stroff = nsyms * 12; // 12 bytes per nlist (32-bit)
  const strsize = strBytes.length;

  const totalSize = stroff + strsize;
  const buf = new ArrayBuffer(totalSize);
  const view = new DataView(buf);

  // Write nlist entries (32-bit)
  for (let i = 0; i < nsyms; i++) {
    const base = i * 12;
    const e = entries[i]!;
    view.setUint32(base, e.n_strx, true);
    view.setUint8(base + 4, e.n_type);
    view.setUint8(base + 5, e.n_sect);
    view.setInt16(base + 6, e.n_desc, true);
    view.setUint32(base + 8, e.n_value, true);
  }

  // Write string table
  const u8 = new Uint8Array(buf);
  for (let i = 0; i < strBytes.length; i++) {
    u8[stroff + i] = strBytes[i]!;
  }

  return { buffer: buf, symtabInfo: { symoff, nsyms, stroff, strsize } };
}

// ── ULEB128 Tests ─────────────────────────────────────────────────────

describe("readULEB128", () => {
  it("decodes single byte value", () => {
    const result = readULEB128(dvFrom([0x05]), 0);
    expect(result.value).toBe(5);
    expect(result.bytesRead).toBe(1);
  });

  it("decodes zero", () => {
    const result = readULEB128(dvFrom([0x00]), 0);
    expect(result.value).toBe(0);
    expect(result.bytesRead).toBe(1);
  });

  it("decodes two-byte value (128)", () => {
    const result = readULEB128(dvFrom([0x80, 0x01]), 0);
    expect(result.value).toBe(128);
    expect(result.bytesRead).toBe(2);
  });

  it("decodes multi-byte value (624485)", () => {
    const result = readULEB128(dvFrom([0xe5, 0x8e, 0x26]), 0);
    expect(result.value).toBe(624485);
    expect(result.bytesRead).toBe(3);
  });

  it("respects offset parameter", () => {
    const result = readULEB128(dvFrom([0xff, 0xff, 0x05]), 2);
    expect(result.value).toBe(5);
    expect(result.bytesRead).toBe(1);
  });
});

// ── Symbol Table Tests ────────────────────────────────────────────────

describe("parseSymbolTable", () => {
  it("returns empty array when symtabInfo is null", () => {
    const buf = new ArrayBuffer(64);
    expect(parseSymbolTable(buf, null, true)).toEqual([]);
  });

  it("returns empty array when nsyms is 0", () => {
    const buf = new ArrayBuffer(64);
    const info: SymtabInfo = { symoff: 0, nsyms: 0, stroff: 0, strsize: 0 };
    expect(parseSymbolTable(buf, info, true)).toEqual([]);
  });

  it("classifies exported symbol (N_EXT + defined type)", () => {
    // n_type = 0x0F => N_EXT(0x01) | N_SECT(0x0E) — external, defined in section
    const { buffer, symtabInfo } = buildSymtabBuffer(
      [{ n_strx: 1, n_type: 0x0f, n_sect: 1, n_desc: 0, n_value: 0x1000n }],
      ["_main"],
    );
    const symbols = parseSymbolTable(buffer, symtabInfo, true);
    expect(symbols).toHaveLength(1);
    expect(symbols[0]!.name).toBe("_main");
    expect(symbols[0]!.type).toBe("exported");
    expect(symbols[0]!.address).toBe(0x1000n);
    expect(symbols[0]!.sectionIndex).toBe(1);
  });

  it("classifies imported symbol (N_EXT + N_UNDF)", () => {
    // n_type = 0x01 => N_EXT only, type bits = 0 (N_UNDF)
    const { buffer, symtabInfo } = buildSymtabBuffer(
      [{ n_strx: 1, n_type: 0x01, n_sect: 0, n_desc: 0, n_value: 0n }],
      ["_objc_msgSend"],
    );
    const symbols = parseSymbolTable(buffer, symtabInfo, true);
    expect(symbols).toHaveLength(1);
    expect(symbols[0]!.name).toBe("_objc_msgSend");
    expect(symbols[0]!.type).toBe("imported");
  });

  it("classifies local symbol", () => {
    // n_type = 0x0E => N_SECT but no N_EXT — local, defined
    const { buffer, symtabInfo } = buildSymtabBuffer(
      [{ n_strx: 1, n_type: 0x0e, n_sect: 2, n_desc: 0, n_value: 0x2000n }],
      ["_helper"],
    );
    const symbols = parseSymbolTable(buffer, symtabInfo, true);
    expect(symbols).toHaveLength(1);
    expect(symbols[0]!.name).toBe("_helper");
    expect(symbols[0]!.type).toBe("local");
  });

  it("skips STABS debug symbols", () => {
    // n_type = 0x24 (N_FUN) has STAB bits set (0xE0 mask)
    // n_type = 0x0F is a normal exported symbol
    const { buffer, symtabInfo } = buildSymtabBuffer(
      [
        { n_strx: 1, n_type: 0x24, n_sect: 1, n_desc: 0, n_value: 0x1000n },
        { n_strx: 1, n_type: 0x0f, n_sect: 1, n_desc: 0, n_value: 0x2000n },
      ],
      ["_func"],
    );
    const symbols = parseSymbolTable(buffer, symtabInfo, true);
    expect(symbols).toHaveLength(1);
    expect(symbols[0]!.address).toBe(0x2000n);
    expect(symbols[0]!.type).toBe("exported");
  });

  it("parses multiple symbols of different types", () => {
    const { buffer, symtabInfo } = buildSymtabBuffer(
      [
        { n_strx: 1, n_type: 0x0f, n_sect: 1, n_desc: 0, n_value: 0x1000n }, // exported
        { n_strx: 7, n_type: 0x01, n_sect: 0, n_desc: 0, n_value: 0n },       // imported
        { n_strx: 15, n_type: 0x0e, n_sect: 2, n_desc: 0, n_value: 0x3000n }, // local
        { n_strx: 1, n_type: 0x64, n_sect: 0, n_desc: 0, n_value: 0n },       // STABS (skipped)
      ],
      ["_start", "_scanf", "_private"],
    );
    const symbols = parseSymbolTable(buffer, symtabInfo, true);
    expect(symbols).toHaveLength(3);
    expect(symbols[0]!.type).toBe("exported");
    expect(symbols[1]!.type).toBe("imported");
    expect(symbols[2]!.type).toBe("local");
  });
});

// ── Export Trie Tests ─────────────────────────────────────────────────

describe("parseExportTrie", () => {
  it("returns empty array for zero-size trie", () => {
    const buf = new ArrayBuffer(64);
    expect(parseExportTrie(buf, 0, 0)).toEqual([]);
  });

  it("parses a single terminal node", () => {
    // Build a minimal trie: root node with terminal info, no children
    // terminal_size = 2 (flags ULEB + addr ULEB)
    // flags = 0x00 (regular)
    // address = 0x1000 (ULEB128: 0x80, 0x20)
    // children_count = 0
    const bytes = [
      0x02, // terminal_size = 2
      0x00, // flags = 0
      0x80, 0x20, // address = 0x1000 (ULEB128) -- wait, let me recalc
    ];
    // Actually ULEB128 for 0x1000 = 4096:
    // 4096 = 0x1000, in ULEB128: byte0 = 0x80 (0 + continue), byte1 = 0x20 (0x20 << 7 = 4096) -- 0x80, 0x20
    // Hmm: 4096 / 128 = 32, so byte0 = 0x00 | 0x80 = 0x80, byte1 = 0x20. Value = 0 + (0x20 << 7) = 4096. Correct.

    // But terminal_size = 2 means 2 bytes of terminal data AFTER terminal_size field.
    // Actually terminal_size says how many bytes of payload follow (flags + addr).
    // flags(1 byte: 0x00) + addr(1 byte... no, addr = 0x80,0x20 is 2 bytes). That's 3 bytes, not 2.
    // Let me use a simpler address: 5 (single byte ULEB = 0x05).

    // terminal_size = 2 (flags=1byte + addr=1byte)
    // flags = 0x00
    // addr = 0x05
    // then children_count = 0
    const trieBytes = [
      0x02, // terminal_size = 2
      0x00, // flags
      0x05, // addr = 5
      0x00, // children_count = 0
    ];

    const buf = new ArrayBuffer(trieBytes.length);
    const u8 = new Uint8Array(buf);
    u8.set(trieBytes);

    const symbols = parseExportTrie(buf, 0, trieBytes.length);
    // Root node with empty prefix is terminal — but name would be ""
    // This is valid, though unusual. The name is the accumulated prefix.
    expect(symbols).toHaveLength(1);
    expect(symbols[0]!.address).toBe(5n);
    expect(symbols[0]!.type).toBe("exported");
  });

  it("reconstructs symbol names from edge labels", () => {
    // Build a trie with structure:
    //   root (non-terminal) -> child "_f" -> terminal node (addr=100)
    //                       -> child "_g" -> terminal node (addr=200)
    //
    // Root node (offset 0):
    //   terminal_size = 0
    //   children_count = 2
    //   child 1: edge "_f\0", offset -> node A
    //   child 2: edge "_g\0", offset -> node B
    // Node A (terminal, addr=100):
    //   terminal_size = 2, flags=0, addr=100(0x64)
    //   children_count = 0
    // Node B (terminal, addr=200):
    //   terminal_size = 2, flags=0, addr=200(0xC8,0x01)

    // Let's lay this out byte by byte:
    // Root at offset 0:
    const trie: number[] = [];

    // Root: terminal_size=0, children_count=2
    trie.push(0x00); // terminal_size = 0
    trie.push(0x02); // children_count = 2

    // Child 1 edge: "_f\0"
    trie.push(0x5f); // '_'
    trie.push(0x66); // 'f'
    trie.push(0x00); // null terminator
    // Child 1 offset: will be filled after we know node A position
    const child1OffsetPos = trie.length;
    trie.push(0x00); // placeholder for node A offset (ULEB128, 1 byte)

    // Child 2 edge: "_g\0"
    trie.push(0x5f); // '_'
    trie.push(0x67); // 'g'
    trie.push(0x00); // null terminator
    const child2OffsetPos = trie.length;
    trie.push(0x00); // placeholder for node B offset (ULEB128, 1 byte)

    // Node A at current position
    const nodeAOffset = trie.length;
    trie.push(0x02); // terminal_size = 2
    trie.push(0x00); // flags = 0
    trie.push(0x64); // addr = 100
    trie.push(0x00); // children_count = 0

    // Node B at current position
    const nodeBOffset = trie.length;
    trie.push(0x03); // terminal_size = 3 (flags=1byte + addr=2bytes)
    trie.push(0x00); // flags = 0
    trie.push(0xc8); // addr = 200 ULEB128: 0xC8 & 0x7F = 0x48, continue
    trie.push(0x01); // 0x01 << 7 = 128; 128 + 72 = 200
    trie.push(0x00); // children_count = 0

    // Patch child offsets
    trie[child1OffsetPos] = nodeAOffset;
    trie[child2OffsetPos] = nodeBOffset;

    const buf = new ArrayBuffer(trie.length);
    new Uint8Array(buf).set(trie);

    const symbols = parseExportTrie(buf, 0, trie.length);
    expect(symbols).toHaveLength(2);

    const byName = new Map(symbols.map((s) => [s.name, s]));
    expect(byName.get("_f")!.address).toBe(100n);
    expect(byName.get("_g")!.address).toBe(200n);
    expect(byName.get("_f")!.type).toBe("exported");
    expect(byName.get("_g")!.type).toBe("exported");
  });
});

// ── 32-bit Symbol Table Tests ─────────────────────────────────────────

describe("parseSymbolTable (32-bit)", () => {
  it("parses nlist (32-bit) with 4-byte n_value", () => {
    const { buffer, symtabInfo } = buildSymtabBuffer32(
      [{ n_strx: 1, n_type: 0x0f, n_sect: 1, n_desc: 0, n_value: 0x1000 }],
      ["_main"],
    );
    const symbols = parseSymbolTable(buffer, symtabInfo, true, false);
    expect(symbols).toHaveLength(1);
    expect(symbols[0]!.name).toBe("_main");
    expect(symbols[0]!.type).toBe("exported");
    expect(symbols[0]!.address).toBe(0x1000n);
    expect(symbols[0]!.sectionIndex).toBe(1);
  });

  it("classifies imported symbol (32-bit)", () => {
    const { buffer, symtabInfo } = buildSymtabBuffer32(
      [{ n_strx: 1, n_type: 0x01, n_sect: 0, n_desc: 0, n_value: 0 }],
      ["_objc_msgSend"],
    );
    const symbols = parseSymbolTable(buffer, symtabInfo, true, false);
    expect(symbols).toHaveLength(1);
    expect(symbols[0]!.name).toBe("_objc_msgSend");
    expect(symbols[0]!.type).toBe("imported");
  });

  it("classifies local symbol (32-bit)", () => {
    const { buffer, symtabInfo } = buildSymtabBuffer32(
      [{ n_strx: 1, n_type: 0x0e, n_sect: 2, n_desc: 0, n_value: 0x2000 }],
      ["_helper"],
    );
    const symbols = parseSymbolTable(buffer, symtabInfo, true, false);
    expect(symbols).toHaveLength(1);
    expect(symbols[0]!.name).toBe("_helper");
    expect(symbols[0]!.type).toBe("local");
  });

  it("skips STABS debug symbols (32-bit)", () => {
    const { buffer, symtabInfo } = buildSymtabBuffer32(
      [
        { n_strx: 1, n_type: 0x24, n_sect: 1, n_desc: 0, n_value: 0x1000 },
        { n_strx: 1, n_type: 0x0f, n_sect: 1, n_desc: 0, n_value: 0x2000 },
      ],
      ["_func"],
    );
    const symbols = parseSymbolTable(buffer, symtabInfo, true, false);
    expect(symbols).toHaveLength(1);
    expect(symbols[0]!.address).toBe(0x2000n);
    expect(symbols[0]!.type).toBe("exported");
  });

  it("parses multiple symbols of different types (32-bit)", () => {
    const { buffer, symtabInfo } = buildSymtabBuffer32(
      [
        { n_strx: 1, n_type: 0x0f, n_sect: 1, n_desc: 0, n_value: 0x1000 },  // exported
        { n_strx: 7, n_type: 0x01, n_sect: 0, n_desc: 0, n_value: 0 },       // imported
        { n_strx: 15, n_type: 0x0e, n_sect: 2, n_desc: 0, n_value: 0x3000 }, // local
      ],
      ["_start", "_scanf", "_private"],
    );
    const symbols = parseSymbolTable(buffer, symtabInfo, true, false);
    expect(symbols).toHaveLength(3);
    expect(symbols[0]!.type).toBe("exported");
    expect(symbols[1]!.type).toBe("imported");
    expect(symbols[2]!.type).toBe("local");
  });
});

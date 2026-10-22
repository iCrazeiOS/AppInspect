/**
 * Swift 5 runtime metadata extraction.
 *
 * Walks the Swift read-only metadata sections emitted by the compiler:
 *
 *   __swift5_types      nominal type context descriptors (class/struct/enum)
 *   __swift5_types2     additional nominal type descriptors
 *   __swift5_fieldmd    stored property / enum case names and mangled types
 *   __swift5_protos     protocol descriptors
 *   __swift5_proto      protocol conformance descriptors
 *
 * All references between these structures are 32-bit relative pointers based
 * on the referencing field's virtual address, so targets are resolved through
 * the segment table rather than assumed to be file-offset relative.
 *
 * Field type names may be symbolic manglings: inline Swift manglings containing
 * references to context descriptors. A reference is a kind byte followed by a
 * 4-byte relative or pointer-sized absolute offset; relative offsets are based
 * on the offset field itself and may contain NUL bytes. Indirect references are
 * resolved through chained-fixup binds/rebases, then reconstructed into a
 * nominal mangling and demangled. Accessor (0x09), existential-shape (0x0A/0x0B),
 * and demangler-unsupported manglings are left untyped rather than guessed.
 *
 * Collection extractor: malformed entries are skipped best-effort.
 */

import type {
	SwiftConformance,
	SwiftField,
	SwiftMetadata,
	SwiftProtocol,
	SwiftType,
	SwiftTypeKind
} from "../../shared/types";
import { vmaddrToFileOffset } from "./address";
import type { ChainedFixupsResult } from "./chained-fixups";
import type { Section64, Segment64 } from "./load-commands";
import { readCString } from "./load-commands";
import { demangleSwiftSymbol } from "./swift-demangle";

type BindMap = ChainedFixupsResult["bindMap"];

const CONTEXT_KIND_MODULE = 0;
const CONTEXT_KIND_EXTENSION = 1;
const CONTEXT_KIND_ANONYMOUS = 2;
const CONTEXT_KIND_PROTOCOL = 3;
const CONTEXT_KIND_CLASS = 16;
const CONTEXT_KIND_STRUCT = 17;
const CONTEXT_KIND_ENUM = 18;

const CONTEXT_FLAG_GENERIC = 0x80;

const MAX_NAME_LENGTH = 1024;
const MAX_FIELDS_PER_TYPE = 4096;
const MAX_TOTAL_FIELDS = 200_000;
const MAX_TYPES = 100_000;
const MAX_PROTOCOLS = 100_000;
const MAX_CONFORMANCES = 200_000;
const MAX_CONTEXT_DEPTH = 8;
const MAX_SYMBOLIC_BLOB_LENGTH = 8192;
const MAX_SYMBOLIC_REFERENCES = 64;

interface ContextPath {
	module: string;
	path: string[];
}

interface ParsedFields {
	fields: SwiftField[];
	declared: number;
}

function isTypeContextKind(kind: number): boolean {
	return (
		kind === CONTEXT_KIND_CLASS || kind === CONTEXT_KIND_STRUCT || kind === CONTEXT_KIND_ENUM
	);
}

function typeKindFor(kind: number): SwiftTypeKind | null {
	switch (kind) {
		case CONTEXT_KIND_CLASS:
			return "class";
		case CONTEXT_KIND_STRUCT:
			return "struct";
		case CONTEXT_KIND_ENUM:
			return "enum";
		default:
			return null;
	}
}

/** Extract the protocol name from a demangled protocol descriptor symbol. */
function protocolNameFromSymbol(symbol: string): string | null {
	const demangled = demangleSwiftSymbol(symbol);
	if (!demangled) return null;
	const marker = "protocol descriptor for ";
	const index = demangled.indexOf(marker);
	if (index === -1) return null;
	const name = demangled.slice(index + marker.length).trim();
	return name.length > 0 ? name : null;
}

/** Mangled type names are plain identifier-ish strings in __TEXT.__const. */
function isMangledTypeName(value: string): boolean {
	if (value.length === 0 || value.length > 512) return false;
	for (let i = 0; i < value.length; i++) {
		const code = value.charCodeAt(i);
		const isAlphaNum =
			(code >= 0x30 && code <= 0x39) ||
			(code >= 0x41 && code <= 0x5a) ||
			(code >= 0x61 && code <= 0x7a);
		if (!isAlphaNum && code !== 0x5f && code !== 0x24) return false;
	}
	return true;
}

class SwiftMetadataReader {
	private readonly view: DataView;
	private readonly segments: Segment64[];
	private readonly le: boolean;
	private readonly is64Bit: boolean;
	private readonly bindMap: BindMap;
	private readonly rebaseMap: Map<number, bigint>;
	private readonly typeByFullName = new Map<string, SwiftType>();
	private readonly protocolByFullName = new Map<string, SwiftProtocol>();
	private readonly demangleCache = new Map<string, string | null>();
	private readonly typeBodyCache = new Map<number, string | null>();
	private readonly contextFragmentCache = new Map<number, string>();
	private readonly contextResolving = new Set<number>();
	private fieldBudget = MAX_TOTAL_FIELDS;

	constructor(
		buffer: ArrayBuffer,
		segments: Segment64[],
		littleEndian: boolean,
		is64Bit: boolean,
		bindMap: BindMap,
		rebaseMap: Map<number, bigint>
	) {
		this.view = new DataView(buffer);
		this.segments = segments;
		this.le = littleEndian;
		this.is64Bit = is64Bit;
		this.bindMap = bindMap;
		this.rebaseMap = rebaseMap;
	}

	extract(): SwiftMetadata {
		const present = this.hasSection(
			"__swift5_types",
			"__swift5_types2",
			"__swift5_protos",
			"__swift5_proto",
			"__swift5_fieldmd"
		);
		const types = present ? this.extractTypes() : [];
		const protocols = this.extractProtocols();
		const { conformances, unresolved } = this.extractConformances();

		types.sort((a, b) => a.fullName.localeCompare(b.fullName));
		protocols.sort((a, b) => a.fullName.localeCompare(b.fullName));
		conformances.sort(
			(a, b) =>
				a.typeName.localeCompare(b.typeName) || a.protocolName.localeCompare(b.protocolName)
		);
		for (const type of types) type.protocols.sort();
		for (const protocol of protocols) protocol.conformingTypes.sort();

		return {
			types,
			protocols,
			conformances,
			present,
			unresolvedConformances: unresolved
		};
	}

	private u16(offset: number): number {
		return this.view.getUint16(offset, this.le);
	}

	private u32(offset: number): number {
		return this.view.getUint32(offset, this.le);
	}

	private int32(offset: number): number {
		return this.view.getInt32(offset, this.le);
	}

	private readPointer(fileOffset: number): bigint {
		return this.is64Bit
			? this.view.getBigUint64(fileOffset, this.le)
			: BigInt(this.view.getUint32(fileOffset, this.le));
	}

	private fileOffsetToVmaddr(fileOffset: number): bigint | null {
		for (const seg of this.segments) {
			const start = Number(seg.fileoff);
			const end = start + Number(seg.filesize);
			if (fileOffset >= start && fileOffset < end) {
				return seg.vmaddr + BigInt(fileOffset - start);
			}
		}
		return null;
	}

	/**
	 * Resolve a 32-bit relative pointer stored at `fieldOffset`.
	 * When `indirectable` is set, bit 0 marks a pointer-to-pointer.
	 */
	private relativeTarget(fieldOffset: number, indirectable = false): number | null {
		if (fieldOffset < 0 || fieldOffset + 4 > this.view.byteLength) return null;
		const fieldVm = this.fileOffsetToVmaddr(fieldOffset);
		if (fieldVm === null) return null;

		const relative = this.int32(fieldOffset);
		let targetVm = fieldVm + BigInt(relative);

		if (indirectable && (relative & 1) !== 0) {
			targetVm = fieldVm + BigInt(relative & ~1);
			const pointerOffset = vmaddrToFileOffset(targetVm, this.segments);
			const pointerSize = this.is64Bit ? 8 : 4;
			if (pointerOffset === null || pointerOffset + pointerSize > this.view.byteLength) {
				return null;
			}

			// In a chained-fixup binary the slot holds an encoded rebase, not a
			// usable pointer. Prefer the rebased target when we have it.
			const rebased = this.rebaseMap.get(pointerOffset);
			if (rebased !== undefined) {
				targetVm = rebased;
			} else {
				const pointer = this.readPointer(pointerOffset);
				if (pointer === 0n) return null;
				targetVm = pointer;
			}
		}

		return vmaddrToFileOffset(targetVm, this.segments);
	}

	private readStringAt(fileOffset: number): string | null {
		if (fileOffset < 0 || fileOffset >= this.view.byteLength) return null;
		const maxLength = Math.min(MAX_NAME_LENGTH, this.view.byteLength - fileOffset);
		const value = readCString(this.view, fileOffset, maxLength);
		if (value.length === 0) return null;
		for (let i = 0; i < value.length; i++) {
			const code = value.charCodeAt(i);
			if (code < 0x20 || code === 0x7f) return null;
		}
		return value;
	}

	private relativeString(fieldOffset: number, indirectable = false): string | null {
		const target = this.relativeTarget(fieldOffset, indirectable);
		return target === null ? null : this.readStringAt(target);
	}

	private fileOffsetForVmaddr(vmaddr: bigint): number | null {
		for (const seg of this.segments) {
			const filesize = Number(seg.filesize);
			if (filesize === 0) continue;
			if (vmaddr < seg.vmaddr || vmaddr >= seg.vmaddr + seg.vmsize) continue;
			const delta = Number(vmaddr - seg.vmaddr);
			if (delta >= filesize) return null;
			const offset = Number(seg.fileoff) + delta;
			return offset >= 0 && offset < this.view.byteLength ? offset : null;
		}
		return null;
	}

	private typeAtPointer(pointerOffset: number): string | null {
		const body = this.mangledTypeBodyAtPointer(pointerOffset);
		return body === null ? null : this.demangleType(body);
	}

	private mangledTypeBodyAtPointer(pointerOffset: number): string | null {
		if (pointerOffset < 0 || pointerOffset + 4 > this.view.byteLength) return null;
		if (this.int32(pointerOffset) === 0) return null;

		const blobOffset = this.relativeTarget(pointerOffset);
		if (blobOffset === null) return null;

		const cached = this.typeBodyCache.get(blobOffset);
		if (cached !== undefined) return cached;

		const plain = this.readStringAt(blobOffset);
		const body =
			plain && isMangledTypeName(plain) ? plain : this.parseSymbolicMangling(blobOffset);
		this.typeBodyCache.set(blobOffset, body);
		return body;
	}

	/** Expand a symbolic mangling blob into a plain mangling body. */
	private parseSymbolicMangling(blobOffset: number): string | null {
		if (blobOffset < 0 || blobOffset >= this.view.byteLength) return null;
		const limit = Math.min(this.view.byteLength, blobOffset + MAX_SYMBOLIC_BLOB_LENGTH);
		let body = "";
		let references = 0;

		for (let offset = blobOffset; offset < limit; ) {
			const byte = this.view.getUint8(offset);
			if (byte === 0) return body.length > 0 ? body : null;
			if (byte === 0xff) {
				offset++;
				continue;
			}

			if (byte >= 0x01 && byte <= 0x17) {
				if (offset + 5 > limit || ++references > MAX_SYMBOLIC_REFERENCES) return null;
				const fragment = this.resolveSymbolicReference(byte, offset);
				if (fragment === null) return null;
				body += fragment;
				offset += 5;
			} else if (byte >= 0x18 && byte <= 0x1f) {
				const pointerSize = this.is64Bit ? 8 : 4;
				if (offset + 1 + pointerSize > limit || ++references > MAX_SYMBOLIC_REFERENCES) {
					return null;
				}
				const fragment = this.resolveSymbolicReference(byte, offset);
				if (fragment === null) return null;
				body += fragment;
				offset += 1 + pointerSize;
			} else {
				if (byte < 0x20 || byte > 0x7e) return null;
				body += String.fromCharCode(byte);
				offset++;
			}

			if (body.length > MAX_SYMBOLIC_BLOB_LENGTH) return null;
		}

		return null;
	}

	private resolveSymbolicReference(kind: number, kindOffset: number): string | null {
		if (kind === 0x01 || kind === 0x18) {
			const target = this.symbolicTarget(kind, kindOffset);
			return target === null ? null : this.contextFragment(target);
		}
		if (kind === 0x02 || kind === 0x19) {
			const slot = this.symbolicTarget(kind, kindOffset);
			return slot === null ? null : this.indirectContextFragment(slot);
		}
		return null;
	}

	private symbolicTarget(kind: number, kindOffset: number): number | null {
		if (kind <= 0x17) {
			const offsetField = kindOffset + 1;
			if (offsetField + 4 > this.view.byteLength) return null;
			const base = this.fileOffsetToVmaddr(offsetField);
			if (base === null) return null;
			return this.fileOffsetForVmaddr(base + BigInt(this.int32(offsetField)));
		}

		const pointerSize = this.is64Bit ? 8 : 4;
		if (kindOffset + 1 + pointerSize > this.view.byteLength) return null;
		return this.fileOffsetForVmaddr(this.readPointer(kindOffset + 1));
	}

	private indirectContextFragment(slotOffset: number): string | null {
		const bind = this.bindMap.get(slotOffset);
		if (bind) return this.bindSymbolToMangling(bind.symbolName);

		const rebased = this.rebaseMap.get(slotOffset);
		if (rebased !== undefined) {
			const target = this.fileOffsetForVmaddr(rebased);
			return target === null ? null : this.contextFragment(target);
		}

		const pointerSize = this.is64Bit ? 8 : 4;
		if (slotOffset + pointerSize > this.view.byteLength) return null;
		const pointer = this.readPointer(slotOffset);
		if (pointer === 0n) return null;
		const target = this.fileOffsetForVmaddr(pointer);
		return target === null ? null : this.contextFragment(target);
	}

	private bindSymbolToMangling(symbol: string): string | null {
		let mangled = symbol.startsWith("_") ? symbol.slice(1) : symbol;
		if (mangled.startsWith("$s")) mangled = mangled.slice(2);
		else if (mangled.startsWith("$S")) mangled = mangled.slice(2);
		else return null;

		if (mangled.endsWith("Mn")) {
			const body = mangled.slice(0, -2);
			return body.length > 0 ? body : null;
		}
		if (mangled.endsWith("Mp")) {
			const body = mangled.slice(0, -2);
			return body.length > 0 ? `${body}P` : null;
		}
		if (mangled.endsWith("Ma")) {
			const body = mangled.slice(0, -2);
			return body.length > 0 ? body : null;
		}
		return null;
	}

	private mangleIdentifier(name: string | null): string | null {
		if (name === null || name.length === 0 || name.length > MAX_NAME_LENGTH) return null;
		return `${name.length}${name}`;
	}

	/** Build the nominal mangling fragment for a context descriptor. */
	private contextFragment(descriptorOffset: number, depth = 0): string | null {
		if (
			depth > MAX_CONTEXT_DEPTH ||
			descriptorOffset < 0 ||
			descriptorOffset + 12 > this.view.byteLength ||
			this.contextResolving.has(descriptorOffset)
		) {
			return null;
		}

		const cached = this.contextFragmentCache.get(descriptorOffset);
		if (cached !== undefined) return cached;

		this.contextResolving.add(descriptorOffset);
		const kind = this.descriptorKind(descriptorOffset);
		let fragment: string | null = null;

		if (kind === CONTEXT_KIND_MODULE) {
			fragment = this.mangleIdentifier(this.descriptorName(descriptorOffset));
		} else if (kind === CONTEXT_KIND_EXTENSION) {
			fragment = this.mangledTypeBodyAtPointer(descriptorOffset + 8);
		} else if (kind === CONTEXT_KIND_ANONYMOUS) {
			const parentOffset = this.relativeTarget(descriptorOffset + 4, true);
			fragment = parentOffset === null ? null : this.contextFragment(parentOffset, depth + 1);
		} else if (
			kind === CONTEXT_KIND_PROTOCOL ||
			kind === CONTEXT_KIND_CLASS ||
			kind === CONTEXT_KIND_STRUCT ||
			kind === CONTEXT_KIND_ENUM
		) {
			const name = this.mangleIdentifier(this.descriptorName(descriptorOffset));
			const parentOffset = this.relativeTarget(descriptorOffset + 4, true);
			const parent =
				parentOffset === null ? null : this.contextFragment(parentOffset, depth + 1);
			if (name !== null && parent !== null) {
				const suffix =
					kind === CONTEXT_KIND_PROTOCOL
						? "P"
						: kind === CONTEXT_KIND_CLASS
							? "C"
							: kind === CONTEXT_KIND_STRUCT
								? "V"
								: "O";
				fragment = `${parent}${name}${suffix}`;
			}
		}

		this.contextResolving.delete(descriptorOffset);
		if (fragment !== null) this.contextFragmentCache.set(descriptorOffset, fragment);
		return fragment;
	}

	private descriptorKind(offset: number): number {
		if (offset < 0 || offset + 4 > this.view.byteLength) return -1;
		return this.u32(offset) & 0x1f;
	}

	private descriptorName(offset: number): string | null {
		return this.relativeString(offset + 8);
	}

	private findSections(...names: string[]): Section64[] {
		const wanted = new Set(names);
		const found: Section64[] = [];
		for (const seg of this.segments) {
			for (const sect of seg.sections) {
				if (wanted.has(sect.sectname.trim())) found.push(sect);
			}
		}
		return found;
	}

	private hasSection(...names: string[]): boolean {
		return this.findSections(...names).length > 0;
	}

	private sectionEntries(section: Section64): { base: number; count: number } {
		const base = vmaddrToFileOffset(section.addr, this.segments) ?? section.offset;
		const count = Math.floor(Number(section.size) / 4);
		return { base, count };
	}

	private contextFullName(context: ContextPath): string {
		return [...(context.module ? [context.module] : []), ...context.path].join(".");
	}

	/**
	 * Walk a context descriptor's parent chain. Module descriptors terminate the
	 * chain; extensions and anonymous contexts are transparent.
	 */
	private resolveOwner(
		descriptorOffset: number,
		depth = 0,
		seen = new Set<number>()
	): ContextPath {
		if (
			depth > MAX_CONTEXT_DEPTH ||
			seen.has(descriptorOffset) ||
			descriptorOffset < 0 ||
			descriptorOffset + 12 > this.view.byteLength
		) {
			return { module: "", path: [] };
		}
		seen.add(descriptorOffset);

		const kind = this.descriptorKind(descriptorOffset);
		if (kind === CONTEXT_KIND_MODULE) {
			return { module: this.descriptorName(descriptorOffset) ?? "", path: [] };
		}

		if (isTypeContextKind(kind)) {
			const name = this.descriptorName(descriptorOffset);
			if (!name) return { module: "", path: [] };
			const parentOffset = this.relativeTarget(descriptorOffset + 4, true);
			const parent =
				parentOffset === null ? null : this.resolveOwner(parentOffset, depth + 1, seen);
			return {
				module: parent?.module ?? "",
				path: [...(parent?.path ?? []), name]
			};
		}

		if (kind === CONTEXT_KIND_EXTENSION) {
			// An extension's parent is the module it is declared in; offset +8
			// is the mangled name of the extended type, not a context
			// descriptor. Use the mangled name to preserve nesting for types
			// declared inside the extension.
			const parentOffset = this.relativeTarget(descriptorOffset + 4, true);
			const parent =
				parentOffset === null
					? { module: "", path: [] }
					: this.resolveOwner(parentOffset, depth + 1, seen);
			const extended = this.typeAtPointer(descriptorOffset + 8);
			if (!extended) return parent;

			const prefix = parent.module ? `${parent.module}.` : "";
			const relative = extended.startsWith(prefix) ? extended.slice(prefix.length) : extended;
			return { module: parent.module, path: [...parent.path, ...relative.split(".")] };
		}

		if (kind === CONTEXT_KIND_ANONYMOUS) {
			const parentOffset = this.relativeTarget(descriptorOffset + 4, true);
			return parentOffset === null
				? { module: "", path: [] }
				: this.resolveOwner(parentOffset, depth + 1, seen);
		}

		return { module: "", path: [] };
	}

	private typeFullName(descriptorOffset: number): string {
		const context = this.resolveOwner(descriptorOffset);
		return this.contextFullName(context) || (this.descriptorName(descriptorOffset) ?? "");
	}

	private protocolNameAndOwner(
		descriptorOffset: number
	): { name: string; fullName: string; module: string } | null {
		const name = this.descriptorName(descriptorOffset);
		if (!name) return null;
		const parentOffset = this.relativeTarget(descriptorOffset + 4, true);
		const owner =
			parentOffset === null ? { module: "", path: [] } : this.resolveOwner(parentOffset);
		return {
			name,
			fullName: this.contextFullName({ module: owner.module, path: [...owner.path, name] }),
			module: owner.module
		};
	}

	private demangleType(mangled: string): string | null {
		const cached = this.demangleCache.get(mangled);
		if (cached !== undefined) return cached;
		const demangled = demangleSwiftSymbol(`$s${mangled}`);
		this.demangleCache.set(mangled, demangled);
		return demangled;
	}

	private parseFields(descriptorOffset: number): ParsedFields {
		const fieldDescriptor = this.relativeTarget(descriptorOffset + 16);
		if (
			fieldDescriptor === null ||
			fieldDescriptor + 16 > this.view.byteLength ||
			this.fieldBudget <= 0
		) {
			return { fields: [], declared: 0 };
		}

		const recordSize = this.u16(fieldDescriptor + 10);
		const declared = this.u32(fieldDescriptor + 12);
		if (recordSize < 8 || recordSize > 256 || recordSize % 4 !== 0 || declared === 0) {
			return { fields: [], declared: 0 };
		}

		const count = Math.min(declared, MAX_FIELDS_PER_TYPE, this.fieldBudget);
		const fields: SwiftField[] = [];

		for (let i = 0; i < count; i++) {
			const record = fieldDescriptor + 16 + i * recordSize;
			if (record + 12 > this.view.byteLength) break;

			const name = this.relativeString(record + 8);
			if (!name) continue;

			const flags = this.u32(record);
			const type = this.typeAtPointer(record + 4);

			fields.push({
				name,
				...(type ? { type } : {}),
				...(flags & 1 ? { indirect: true } : {})
			});
		}

		this.fieldBudget -= fields.length;
		return { fields, declared };
	}

	private buildType(descriptorOffset: number, kind: SwiftTypeKind): SwiftType | null {
		const name = this.descriptorName(descriptorOffset);
		if (!name) return null;

		const context = this.resolveOwner(descriptorOffset);
		const fields = this.parseFields(descriptorOffset);
		const type: SwiftType = {
			name,
			fullName: this.contextFullName(context) || name,
			module: context.module,
			kind,
			protocols: [],
			fields: fields.fields,
			generic: (this.u32(descriptorOffset) & CONTEXT_FLAG_GENERIC) !== 0,
			fieldCount: fields.declared
		};

		if (kind === "class") {
			const superclass = this.typeAtPointer(descriptorOffset + 20);
			if (superclass) type.superclass = superclass;
		}

		return type;
	}

	private extractTypes(): SwiftType[] {
		const types: SwiftType[] = [];

		for (const section of this.findSections("__swift5_types", "__swift5_types2")) {
			const { base, count } = this.sectionEntries(section);
			for (let i = 0; i < count; i++) {
				if (types.length >= MAX_TYPES) return types;
				const entry = base + i * 4;
				if (entry + 4 > this.view.byteLength) break;

				let descriptorOffset = this.relativeTarget(entry);
				if (
					descriptorOffset === null ||
					!isTypeContextKind(this.descriptorKind(descriptorOffset))
				) {
					descriptorOffset = this.relativeTarget(entry, true);
				}
				if (
					descriptorOffset === null ||
					!isTypeContextKind(this.descriptorKind(descriptorOffset))
				) {
					continue;
				}

				const kind = typeKindFor(this.descriptorKind(descriptorOffset));
				if (!kind) continue;

				const type = this.buildType(descriptorOffset, kind);
				if (!type) continue;

				const existing = this.typeByFullName.get(type.fullName);
				if (existing) {
					if (type.fields.length > existing.fields.length) {
						existing.fields = type.fields;
						existing.fieldCount = type.fieldCount;
					}
					if (type.superclass && !existing.superclass) {
						existing.superclass = type.superclass;
					}
					if (type.generic) existing.generic = true;
					continue;
				}

				this.typeByFullName.set(type.fullName, type);
				types.push(type);
			}
		}

		return types;
	}

	private extractProtocols(): SwiftProtocol[] {
		const protocols: SwiftProtocol[] = [];

		for (const section of this.findSections("__swift5_protos")) {
			const { base, count } = this.sectionEntries(section);
			for (let i = 0; i < count; i++) {
				if (protocols.length >= MAX_PROTOCOLS) return protocols;
				const entry = base + i * 4;
				if (entry + 4 > this.view.byteLength) break;

				let descriptorOffset = this.relativeTarget(entry);
				if (
					descriptorOffset === null ||
					this.descriptorKind(descriptorOffset) !== CONTEXT_KIND_PROTOCOL
				) {
					descriptorOffset = this.relativeTarget(entry, true);
				}
				if (
					descriptorOffset === null ||
					this.descriptorKind(descriptorOffset) !== CONTEXT_KIND_PROTOCOL
				) {
					continue;
				}

				const parsed = this.protocolNameAndOwner(descriptorOffset);
				if (!parsed || descriptorOffset + 20 > this.view.byteLength) continue;

				const requirementCount = this.u32(descriptorOffset + 16);
				const protocol: SwiftProtocol = {
					name: parsed.name,
					fullName: parsed.fullName,
					module: parsed.module,
					requirementCount:
						requirementCount > 0 && requirementCount <= 10_000 ? requirementCount : 0,
					conformingTypes: []
				};

				if (this.protocolByFullName.has(protocol.fullName)) continue;

				this.protocolByFullName.set(protocol.fullName, protocol);
				protocols.push(protocol);
			}
		}

		return protocols;
	}

	private resolveConformanceProtocol(descriptorOffset: number): string | null {
		const fieldVm = this.fileOffsetToVmaddr(descriptorOffset);
		if (fieldVm === null) return null;

		const relative = this.int32(descriptorOffset);
		let protocolVm = fieldVm + BigInt(relative & ~1);

		if ((relative & 1) !== 0) {
			const pointerOffset = vmaddrToFileOffset(protocolVm, this.segments);
			const pointerSize = this.is64Bit ? 8 : 4;
			if (pointerOffset === null || pointerOffset + pointerSize > this.view.byteLength) {
				return null;
			}

			// External protocol descriptors are bound at load time. The chained
			// fixup import table carries the protocol descriptor symbol name.
			const bind = this.bindMap.get(pointerOffset);
			if (bind) return protocolNameFromSymbol(bind.symbolName);

			const rebased = this.rebaseMap.get(pointerOffset);
			if (rebased !== undefined) {
				protocolVm = rebased;
			} else {
				const pointer = this.readPointer(pointerOffset);
				if (pointer === 0n) return null;
				protocolVm = pointer;
			}
		}

		const protocolOffset = vmaddrToFileOffset(protocolVm, this.segments);
		if (
			protocolOffset === null ||
			this.descriptorKind(protocolOffset) !== CONTEXT_KIND_PROTOCOL
		) {
			return null;
		}

		return this.protocolNameAndOwner(protocolOffset)?.fullName ?? null;
	}

	private resolveConformanceType(descriptorOffset: number): string | null {
		if (descriptorOffset + 16 > this.view.byteLength) return null;
		const flags = this.u32(descriptorOffset + 12);
		const typeReferenceKind = (flags >>> 3) & 0x7;

		if (typeReferenceKind === 0 || typeReferenceKind === 1) {
			const typeOffset = this.relativeTarget(descriptorOffset + 4, true);
			if (typeOffset === null) return null;
			if (!isTypeContextKind(this.descriptorKind(typeOffset))) return null;
			return this.typeFullName(typeOffset) || null;
		}

		if (typeReferenceKind === 2) {
			return this.relativeString(descriptorOffset + 4);
		}

		// IndirectObjCClass points at a variable holding the ObjC class object,
		// not at a C string. Resolving its name needs ObjC class metadata, so
		// leave the conformance unresolved rather than reading the class object
		// as a string.
		return null;
	}

	private extractConformances(): { conformances: SwiftConformance[]; unresolved: number } {
		const conformances: SwiftConformance[] = [];
		const seen = new Set<string>();
		let unresolved = 0;

		for (const section of this.findSections("__swift5_proto")) {
			const { base, count } = this.sectionEntries(section);
			for (let i = 0; i < count; i++) {
				if (conformances.length >= MAX_CONFORMANCES) {
					return { conformances, unresolved };
				}
				const entry = base + i * 4;
				if (entry + 4 > this.view.byteLength) break;

				const descriptorOffset = this.relativeTarget(entry);
				if (descriptorOffset === null || descriptorOffset + 16 > this.view.byteLength) {
					continue;
				}

				const protocolName = this.resolveConformanceProtocol(descriptorOffset);
				const typeName = this.resolveConformanceType(descriptorOffset);
				if (!protocolName || !typeName) {
					unresolved++;
					continue;
				}

				const key = `${typeName}\u0000${protocolName}`;
				if (seen.has(key)) continue;
				seen.add(key);
				conformances.push({ typeName, protocolName });

				const type = this.typeByFullName.get(typeName);
				if (type) type.protocols.push(protocolName);
				const protocol = this.protocolByFullName.get(protocolName);
				if (protocol) protocol.conformingTypes.push(typeName);
			}
		}

		return { conformances, unresolved };
	}
}

/**
 * Extract Swift nominal types, stored properties, protocols, and conformances.
 *
 * @param buffer       Raw Mach-O file buffer (already sliced to the target arch)
 * @param segments     Parsed segment load commands
 * @param littleEndian Byte order of the binary
 * @param is64Bit      Whether this is a 64-bit Mach-O
 * @param bindMap      Chained-fixup bind map, used to name external protocols
 * @param rebaseMap    Chained-fixup rebase map, used to resolve indirect
 *                     context/type pointers in `__DATA_CONST`
 */
export function extractSwiftMetadata(
	buffer: ArrayBuffer,
	segments: Segment64[],
	littleEndian: boolean,
	is64Bit: boolean = true,
	bindMap: BindMap = new Map(),
	rebaseMap: Map<number, bigint> = new Map()
): SwiftMetadata {
	return new SwiftMetadataReader(
		buffer,
		segments,
		littleEndian,
		is64Bit,
		bindMap,
		rebaseMap
	).extract();
}

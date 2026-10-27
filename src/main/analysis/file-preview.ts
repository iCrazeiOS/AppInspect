/**
 * Safe workspace-file preview reader.
 *
 * Produces the same `FilePreviewContent` shape as ASAR previews so the renderer
 * can share one preview pane. Paths are confined to the session's allowed roots
 * before anything is read.
 */

import * as fs from "node:fs";
import * as path from "node:path";

import {
	FILE_PREVIEW_BYTES,
	FILE_PREVIEW_FULL_BYTES,
	FILE_PREVIEW_IMAGE_BYTES,
	imageMimeType
} from "../../shared/file-preview";
import type { FilePreviewContent } from "../../shared/types";
import { binaryPlistToXml } from "../parser/plist";
import { convertCgbiPng } from "../util/cgbi-png";
import { withoutAsar } from "../util/no-asar";
import { isInsideAny } from "../util/safe-path";

/** Bytes inspected for a NUL byte to tell text from binary. */
const BINARY_SNIFF_BYTES = 8 * 1024;

/** Resolve through symlinks, falling back to an absolute path if the path is missing. */
function realPath(filePath: string): string {
	try {
		return fs.realpathSync(filePath);
	} catch {
		return path.resolve(filePath);
	}
}

/** Sniff preview data into the shared preview shape. */
export function buildFilePreview(
	filePath: string,
	data: Buffer,
	totalSize: number,
	truncated: boolean,
	includeImage: boolean
): FilePreviewContent {
	const mime = imageMimeType(filePath);
	const content: FilePreviewContent = {
		path: filePath,
		size: truncated ? totalSize : data.length,
		truncated,
		kind: mime ? "image" : "binary"
	};
	if (mime) {
		if (includeImage && !truncated) {
			// Chromium cannot decode Xcode's CgBI PNG variant; transcode it first.
			const preview = mime === "image/png" ? (convertCgbiPng(data) ?? data) : data;
			content.image = `data:${mime};base64,${preview.toString("base64")}`;
		}
	} else if (!data.subarray(0, BINARY_SNIFF_BYTES).includes(0)) {
		content.kind = "text";
		content.text = data.toString("utf8");
	} else if (!truncated) {
		// Binary plists are common in iOS bundles; show them as XML, not binary.
		const xml = binaryPlistToXml(data);
		if (xml !== null) {
			content.kind = "text";
			content.text = xml;
		}
	}
	return content;
}

/**
 * Read a filesystem file for preview, rejecting anything outside `allowedRoots`.
 * Images read up to `FILE_PREVIEW_IMAGE_BYTES`, everything else up to
 * `maxBytes` (1..`FILE_PREVIEW_FULL_BYTES`). Returns null on any filesystem
 * error or when the path is a directory.
 */
export function readFilePreview(
	filePath: string,
	allowedRoots: readonly string[],
	maxBytes: number,
	includeImage = false
): FilePreviewContent | null {
	const target = realPath(filePath);
	if (!isInsideAny(allowedRoots.map(realPath), target)) return null;

	try {
		return withoutAsar(() => {
			const stat = fs.statSync(target);
			if (!stat.isFile()) return null;

			const requested = Number.isFinite(maxBytes) ? Math.floor(maxBytes) : FILE_PREVIEW_BYTES;
			const limit = imageMimeType(filePath)
				? FILE_PREVIEW_IMAGE_BYTES
				: Math.min(FILE_PREVIEW_FULL_BYTES, Math.max(1, requested));
			const truncated = stat.size > limit;

			const data = Buffer.alloc(Math.min(limit, stat.size));
			const fd = fs.openSync(target, "r");
			try {
				const read = fs.readSync(fd, data, 0, data.length, 0);
				return buildFilePreview(
					filePath,
					data.subarray(0, read),
					stat.size,
					truncated,
					includeImage
				);
			} finally {
				fs.closeSync(fd);
			}
		});
	} catch {
		return null;
	}
}

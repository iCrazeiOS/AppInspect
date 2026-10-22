/**
 * ASAR preview helpers shared by main and the renderer.
 */

/** Default text preview cap. */
export const ASAR_PREVIEW_BYTES = 512 * 1024;

/** Hard cap for an explicit full-content read. */
export const ASAR_FULL_BYTES = 32 * 1024 * 1024;

/** Raster image preview cap. */
export const ASAR_IMAGE_BYTES = 4 * 1024 * 1024;

/** MIME type for raster image extensions that can be shown in an `<img>`, or null. */
export function imageMimeType(filePath: string): string | null {
	const name = filePath.slice(filePath.lastIndexOf("/") + 1);
	const dot = name.lastIndexOf(".");
	if (dot <= 0) return null;
	switch (name.slice(dot + 1).toLowerCase()) {
		case "png":
			return "image/png";
		case "jpg":
		case "jpeg":
			return "image/jpeg";
		case "gif":
			return "image/gif";
		case "webp":
			return "image/webp";
		case "bmp":
			return "image/bmp";
		case "ico":
			return "image/x-icon";
		case "avif":
			return "image/avif";
		case "tif":
		case "tiff":
			return "image/tiff";
		default:
			return null;
	}
}

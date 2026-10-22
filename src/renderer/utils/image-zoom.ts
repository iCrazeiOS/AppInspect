/** Zoom limits and math for the image preview. */

export const IMAGE_ZOOM_MIN = 0.02;
export const IMAGE_ZOOM_MAX = 16;

/** Padding around a fitted image, matching `.fb-image-stage`. */
export const IMAGE_STAGE_PADDING = 16;

/** Trackpad pinch sensitivity; higher zooms faster for the same wheel delta. */
const PINCH_ZOOM_SENSITIVITY = 0.00375;

export function clampImageZoom(scale: number): number {
	return Math.min(IMAGE_ZOOM_MAX, Math.max(IMAGE_ZOOM_MIN, scale));
}

/** Scale that fits an image inside the viewport without upscaling past 100%. */
export function fitImageZoom(
	width: number,
	height: number,
	viewportWidth: number,
	viewportHeight: number
): number {
	if (width <= 0 || height <= 0) return 1;
	const availableWidth = Math.max(1, viewportWidth - IMAGE_STAGE_PADDING * 2);
	const availableHeight = Math.max(1, viewportHeight - IMAGE_STAGE_PADDING * 2);
	return clampImageZoom(Math.min(availableWidth / width, availableHeight / height, 1));
}

export function stepImageZoom(scale: number, direction: "in" | "out"): number {
	return clampImageZoom(direction === "in" ? scale * 1.25 : scale / 1.25);
}

/** Trackpad pinch arrives as ctrl+wheel; zoom out on positive delta. */
export function pinchImageZoom(scale: number, deltaY: number): number {
	return clampImageZoom(scale * Math.exp(-deltaY * PINCH_ZOOM_SENSITIVITY));
}

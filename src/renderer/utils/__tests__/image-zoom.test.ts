import { describe, expect, it } from "bun:test";
import {
	clampImageZoom,
	fitImageZoom,
	IMAGE_ZOOM_MAX,
	IMAGE_ZOOM_MIN,
	pinchImageZoom,
	stepImageZoom
} from "../image-zoom";

describe("clampImageZoom", () => {
	it("keeps zoom inside the supported range", () => {
		expect(clampImageZoom(1)).toBe(1);
		expect(clampImageZoom(0)).toBe(IMAGE_ZOOM_MIN);
		expect(clampImageZoom(100)).toBe(IMAGE_ZOOM_MAX);
	});
});

describe("fitImageZoom", () => {
	it("fits large images inside the padded viewport", () => {
		expect(fitImageZoom(2000, 1000, 1000, 800)).toBe(0.484);
		expect(fitImageZoom(1000, 2000, 1000, 800)).toBe(0.384);
	});

	it("never upscales images smaller than the viewport", () => {
		expect(fitImageZoom(64, 64, 1000, 800)).toBe(1);
	});

	it("falls back to 100% for empty dimensions", () => {
		expect(fitImageZoom(0, 0, 1000, 800)).toBe(1);
	});
});

describe("stepImageZoom", () => {
	it("steps by 25% and clamps at the limits", () => {
		expect(stepImageZoom(1, "in")).toBe(1.25);
		expect(stepImageZoom(1, "out")).toBe(0.8);
		expect(stepImageZoom(IMAGE_ZOOM_MAX, "in")).toBe(IMAGE_ZOOM_MAX);
		expect(stepImageZoom(IMAGE_ZOOM_MIN, "out")).toBe(IMAGE_ZOOM_MIN);
	});
});

describe("pinchImageZoom", () => {
	it("zooms in for a negative delta and out for a positive delta", () => {
		expect(pinchImageZoom(1, -100)).toBeGreaterThan(1);
		expect(pinchImageZoom(1, 100)).toBeLessThan(1);
	});

	it("clamps at the limits", () => {
		expect(pinchImageZoom(1, -100000)).toBe(IMAGE_ZOOM_MAX);
		expect(pinchImageZoom(1, 100000)).toBe(IMAGE_ZOOM_MIN);
	});
});

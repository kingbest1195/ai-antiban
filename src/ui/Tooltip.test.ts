import { describe, expect, it } from "vitest";
import { clampTooltipPosition } from "./Tooltip";

describe("clampTooltipPosition", () => {
  it("центрирует подсказку под якорем, когда она помещается в окно", () => {
    const pos = clampTooltipPosition({
      anchorLeft: 200,
      anchorTop: 100,
      anchorWidth: 20,
      anchorBottom: 120,
      popWidth: 160,
      popHeight: 60,
      viewportWidth: 460,
      viewportHeight: 660,
    });

    expect(pos).toEqual({ left: 130, top: 128 });
  });

  it("прижимает подсказку к левому и правому краю с отступом margin", () => {
    const leftEdge = clampTooltipPosition({
      anchorLeft: 4,
      anchorTop: 40,
      anchorWidth: 16,
      anchorBottom: 56,
      popWidth: 240,
      popHeight: 64,
      viewportWidth: 440,
      viewportHeight: 470,
    });
    expect(leftEdge.left).toBe(8);

    const rightEdge = clampTooltipPosition({
      anchorLeft: 416,
      anchorTop: 40,
      anchorWidth: 16,
      anchorBottom: 56,
      popWidth: 240,
      popHeight: 64,
      viewportWidth: 440,
      viewportHeight: 470,
    });
    expect(rightEdge.left).toBe(440 - 240 - 8);
  });

  it("переносит подсказку над якорем, если снизу не хватает места (окно 440x470)", () => {
    const pos = clampTooltipPosition({
      anchorLeft: 200,
      anchorTop: 420,
      anchorWidth: 16,
      anchorBottom: 436,
      popWidth: 200,
      popHeight: 72,
      viewportWidth: 440,
      viewportHeight: 470,
    });

    expect(pos.top).toBe(420 - 8 - 72);
    expect(pos.top).toBeGreaterThanOrEqual(8);
  });

  it("не уводит подсказку выше верхнего отступа на слишком низких окнах", () => {
    const pos = clampTooltipPosition({
      anchorLeft: 100,
      anchorTop: 20,
      anchorWidth: 16,
      anchorBottom: 36,
      popWidth: 180,
      popHeight: 100,
      viewportWidth: 440,
      viewportHeight: 120,
    });

    expect(pos.top).toBe(12);
    expect(pos.top).toBeGreaterThanOrEqual(8);
  });
});

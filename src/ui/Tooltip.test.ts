import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import {
  INITIAL_TOOLTIP_STATE,
  InfoTip,
  Tip,
  clampTooltipPosition,
  isTooltipVisible,
  reduceTooltipState,
} from "./Tooltip";

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

describe("Tooltip interaction state (hover + focus + click toggle + Escape + outsideClick)", () => {
  it("открывается при hover/focus и закрывается при уходе", () => {
    const hovered = reduceTooltipState(INITIAL_TOOLTIP_STATE, "hoverStart");
    expect(isTooltipVisible(hovered)).toBe(true);
    expect(isTooltipVisible(reduceTooltipState(hovered, "hoverEnd"))).toBe(false);

    const focused = reduceTooltipState(INITIAL_TOOLTIP_STATE, "focus");
    expect(isTooltipVisible(focused)).toBe(true);
    expect(isTooltipVisible(reduceTooltipState(focused, "blur"))).toBe(false);
  });

  it("clickToggle фиксирует подсказку даже после ухода курсора и закрывает при повторном клике", () => {
    let s = reduceTooltipState(INITIAL_TOOLTIP_STATE, "hoverStart");
    s = reduceTooltipState(s, "clickToggle");
    expect(s.pinned).toBe(true);
    expect(isTooltipVisible(s)).toBe(true);

    // Курсор ушёл, но подсказка остаётся открытой, пока не кликнут снова или снаружи
    s = reduceTooltipState(s, "hoverEnd");
    expect(isTooltipVisible(s)).toBe(true);

    // Навели и кликнули второй раз — закрывается сразу, даже при hover=true
    s = reduceTooltipState(s, "hoverStart");
    s = reduceTooltipState(s, "clickToggle");
    expect(s.pinned).toBe(false);
    expect(isTooltipVisible(s)).toBe(false);
  });

  it("закрывается по Escape и клику снаружи", () => {
    const pinned = reduceTooltipState(INITIAL_TOOLTIP_STATE, "clickToggle");
    expect(isTooltipVisible(pinned)).toBe(true);

    const afterEsc = reduceTooltipState(pinned, "escape");
    expect(isTooltipVisible(afterEsc)).toBe(false);

    const afterOutside = reduceTooltipState(pinned, "outsideClick");
    expect(isTooltipVisible(afterOutside)).toBe(false);
  });

  it("InfoTip рендерит доступную кнопку с aria-expanded и классом zs-info-i", () => {
    const html = renderToStaticMarkup(createElement(InfoTip, { title: "ASN", text: "Номер провайдера" }));
    expect(html).toContain("<button");
    expect(html).toContain('class="zs-info-i"');
    expect(html).toContain('aria-expanded="false"');
    expect(html).toContain('aria-label="Пояснение"');

    const tipHtml = renderToStaticMarkup(
      createElement(Tip, { text: "Текст", children: createElement("span", null, "Якорь") }),
    );
    expect(tipHtml).toContain('class="zs-tip"');
    expect(tipHtml).toContain("Якорь");
  });
});

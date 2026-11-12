import { describe, expect, it } from "vitest";
import { tabAriaLabel } from "./Tabs";

describe("tabAriaLabel", () => {
  const bad = ", есть проблема";
  const notice = ", есть замечание";
  it("без бейджа подписи нет", () => {
    expect(tabAriaLabel({ label: "Обзор" }, bad, notice)).toBeUndefined();
  });
  it("красная точка и число получают «есть проблема»", () => {
    expect(tabAriaLabel({ label: "Обзор", badge: "danger" }, bad, notice)).toBe("Обзор, есть проблема");
    expect(tabAriaLabel({ label: "Проверки", badge: 3 }, bad, notice)).toBe("Проверки, есть проблема");
  });
  it("жёлтая точка получает «есть замечание»", () => {
    expect(tabAriaLabel({ label: "Обзор", badge: "warn" }, bad, notice)).toBe("Обзор, есть замечание");
  });
  it("без отдельного текста для жёлтой берётся общий; без текстов подписи нет", () => {
    expect(tabAriaLabel({ label: "Обзор", badge: "warn" }, bad)).toBe("Обзор, есть проблема");
    expect(tabAriaLabel({ label: "Обзор", badge: "warn" })).toBeUndefined();
  });
});

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  CleanRoomRadarAnim,
  KillSwitchAnim,
  SmartScreenGuide,
  SplitRoutingAnim,
  WatchdogMascot,
  shouldPauseMascot,
  useMascotPause,
} from "./index";
import type { MascotState } from "./index";

describe("WatchdogMascot 5-state FSM", () => {
  const states: MascotState[] = ["protected", "scanning", "alert", "sleep", "warmup"];

  it.each(states)("рендерит состояние %s с корректным CSS-классом и без сырых цветов", (state) => {
    const html = renderToStaticMarkup(createElement(WatchdogMascot, { state }));
    expect(html).toContain(`zs-mascot--${state}`);
    expect(html).toContain(`data-mascot-state="${state}"`);
    expect(html).toContain('role="img"');
    expect(html).toContain("aria-label=");
    expect(html).not.toMatch(/#(?:[0-9a-fA-F]{3,8})\b/);
    expect(html).not.toMatch(/\brgba?\s*\(/i);
  });

  it("поддерживает размеры 48, 64, 96 и декоративный режим aria-hidden", () => {
    for (const size of [48, 64, 96] as const) {
      const html = renderToStaticMarkup(createElement(WatchdogMascot, { state: "protected", size, decorative: true }));
      expect(html).toContain(`width:${size}px;height:${size}px`);
      expect(html).toContain('aria-hidden="true"');
      expect(html).not.toContain('role="img"');
    }
  });

  it("добавляет .zs-mascot--paused при явной паузе", () => {
    const html = renderToStaticMarkup(createElement(WatchdogMascot, { state: "scanning", paused: true }));
    expect(html).toContain("zs-mascot--paused");
    expect(html).toContain('data-mascot-paused="true"');
  });
});

describe("useMascotPause и auto-pause логика", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("ставит анимацию на паузу при hidden, blur, reduced-motion и forcePaused", () => {
    expect(
      shouldPauseMascot({ visibilityState: "visible", windowFocused: true, reducedMotion: false }),
    ).toBe(false);
    expect(
      shouldPauseMascot({ visibilityState: "hidden", windowFocused: true, reducedMotion: false }),
    ).toBe(true);
    expect(
      shouldPauseMascot({ visibilityState: "visible", windowFocused: false, reducedMotion: false }),
    ).toBe(true);
    expect(
      shouldPauseMascot({ visibilityState: "visible", windowFocused: true, reducedMotion: true }),
    ).toBe(true);
    expect(
      shouldPauseMascot({ visibilityState: "visible", windowFocused: true, reducedMotion: false, forcePaused: true }),
    ).toBe(true);
  });

  it("хук useMascotPause считывает document.visibilityState === 'hidden' и prefers-reduced-motion", () => {
    function Probe({ forcePaused = false }: { forcePaused?: boolean }) {
      const { paused, pauseClassName } = useMascotPause(forcePaused);
      return createElement("div", { className: pauseClassName, "data-paused": String(paused) });
    }

    vi.stubGlobal("document", {
      visibilityState: "hidden",
      hasFocus: () => true,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    });
    vi.stubGlobal("window", {
      matchMedia: () => ({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() }),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    });

    const hiddenHtml = renderToStaticMarkup(createElement(Probe));
    expect(hiddenHtml).toContain('data-paused="true"');
    expect(hiddenHtml).toContain("zs-mascot--paused");

    vi.stubGlobal("document", {
      visibilityState: "visible",
      hasFocus: () => true,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    });
    vi.stubGlobal("window", {
      matchMedia: (q: string) => ({
        matches: q.includes("prefers-reduced-motion"),
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
      }),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    });

    const reducedHtml = renderToStaticMarkup(createElement(Probe));
    expect(reducedHtml).toContain('data-paused="true"');
    expect(reducedHtml).toContain("zs-mascot--paused");
  });
});

describe("Функциональные анимации Заставы", () => {
  it("SplitRoutingAnim показывает два потока: AI через щит и обычные сайты напрямую", () => {
    const html = renderToStaticMarkup(createElement(SplitRoutingAnim, { active: true }));
    expect(html).toContain("zs-anim-split--active");
    expect(html).toContain("Claude");
    expect(html).toContain("Сбербанк");
    expect(html).toContain("Щит Заставы");
    expect(html).toContain("Напрямую");
  });

  it("KillSwitchAnim отображает мгновенный перехват 0.04 мс", () => {
    const html = renderToStaticMarkup(createElement(KillSwitchAnim, { triggered: true, compact: true }));
    expect(html).toContain("zs-anim-ks--triggered");
    expect(html).toContain("zs-anim-ks--compact");
    expect(html).toContain("0.04 мс");
  });

  it("CleanRoomRadarAnim рендерит 4 локализованных слоя аудита (без MSIX на macOS)", () => {
    const html = renderToStaticMarkup(createElement(CleanRoomRadarAnim, { scanning: true, activeLayerIndex: 1 }));
    expect(html).toContain("zs-anim-radar--scanning");
    expect(html).toContain("Браузеры");
    expect(html).toContain("Приложения ИИ");
    expect(html).toContain("IP и DNS");
    expect(html).toContain("Время и язык");
    expect(html).not.toContain("MSIX");
  });

  it("SmartScreenGuide рендерит 2 кадра для Windows и macOS и поддерживает сворачивание", () => {
    const winHtml = renderToStaticMarkup(createElement(SmartScreenGuide, { platform: "windows" }));
    expect(winHtml).toContain("Подробнее");
    expect(winHtml).toContain("Выполнить в любом случае");

    const macHtml = renderToStaticMarkup(createElement(SmartScreenGuide, { platform: "macos" }));
    expect(macHtml).toContain("Всё равно открыть");
    expect(macHtml).toContain("Открыть");

    const collapsedHtml = renderToStaticMarkup(
      createElement(SmartScreenGuide, { collapsible: true, defaultExpanded: false }),
    );
    expect(collapsedHtml).toContain('aria-expanded="false"');
    expect(collapsedHtml).not.toContain("Выполнить в любом случае");
  });
});

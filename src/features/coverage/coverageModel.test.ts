import { describe, expect, it } from "vitest";
import type { AppCoverageItem, AppCoverageStatus } from "../../types";
import { POLL_FAST_MS, POLL_SLOW_MS, WAIT_TIMEOUT_MS, isListed, pollInterval, resolveWaiting, sinceLastSeen, startWaiting, viewOf } from "./coverageModel";

const app = (id: string, status: AppCoverageStatus, over: Partial<AppCoverageItem> = {}): AppCoverageItem => ({
  id,
  name: id,
  category: "ide",
  installed: status !== "not_installed",
  status,
  requests_seen: 0,
  ai_requests: 0,
  pac_fetches: 0,
  last_seen_ms: null,
  manual_steps: [],
  detail: "",
  ...over,
});

describe("pollInterval", () => {
  it("при скрытом окне таймер не тикает", () => {
    expect(pollInterval(false, [app("a", "unknown")])).toBe(0);
    expect(pollInterval(false, [])).toBe(0);
  });
  it("5 с пока есть неподтверждённые, 30 с когда все подтверждены или не установлены", () => {
    expect(pollInterval(true, [app("a", "confirmed"), app("b", "configured")])).toBe(POLL_FAST_MS);
    expect(pollInterval(true, [app("a", "off")])).toBe(POLL_FAST_MS);
    expect(pollInterval(true, [app("a", "confirmed"), app("b", "not_installed")])).toBe(POLL_SLOW_MS);
    expect(pollInterval(true, undefined)).toBe(POLL_SLOW_MS);
  });
});

describe("isListed", () => {
  it("«Не установлено» скрыто везде; в «Обзоре» только установленные или с трафиком", () => {
    const missing = app("x", "not_installed");
    expect(isListed(missing, "checks")).toBe(false);
    expect(isListed(missing, "overview")).toBe(false);
    const dynamic = app("d", "confirmed", { installed: false, ai_requests: 3, requests_seen: 3 });
    expect(isListed(dynamic, "overview")).toBe(true);
    expect(isListed(app("i", "off", { installed: false }), "overview")).toBe(false);
    expect(isListed(app("i", "off", { installed: false }), "checks")).toBe(true);
  });
});

describe("waiting", () => {
  const apps = [app("a", "configured"), app("b", "unknown"), app("c", "confirmed"), app("d", "off")];

  it("«Проверить снова» ставит ожидание только приложениям в статусе «Настроено»", () => {
    expect(Object.keys(startWaiting({}, apps, "configured", 1000))).toEqual(["a"]);
  });
  it("«Я настроил» ставит ожидание выбранному, кроме подтверждённых", () => {
    expect(Object.keys(startWaiting({}, apps, ["b", "c"], 1000))).toEqual(["b"]);
  });
  it("до 60 с — «ожидаем», после — «не подтверждено»", () => {
    const w = { a: 1000 };
    expect(viewOf(apps[0], w, 1000 + WAIT_TIMEOUT_MS - 1)).toBe("waiting");
    expect(viewOf(apps[0], w, 1000 + WAIT_TIMEOUT_MS)).toBe("waiting_timeout");
  });
  it("без ожидания виден статус шлюза", () => {
    expect(viewOf(apps[0], {}, 5)).toBe("configured");
    expect(viewOf(apps[2], { c: 1 }, 5)).toBe("confirmed");
  });
  it("подтверждение завершает ожидание: переход configured → waiting → confirmed", () => {
    const w1 = startWaiting({}, apps, "configured", 1000);
    expect(viewOf(apps[0], w1, 2000)).toBe("waiting");
    const next = [app("a", "confirmed", { ai_requests: 1, last_seen_ms: 3000 }), ...apps.slice(1)];
    const w2 = resolveWaiting(w1, next);
    expect(w2).toEqual({});
    expect(viewOf(next[0], w2, 4000)).toBe("confirmed");
  });
  it("статус off или исчезновение приложения тоже снимают ожидание; истёкшее остаётся", () => {
    expect(resolveWaiting({ a: 1 }, [app("a", "off")])).toEqual({});
    expect(resolveWaiting({ a: 1 }, [])).toEqual({});
    expect(resolveWaiting({ a: 1 }, [app("a", "configured")])).toEqual({ a: 1 });
  });
  it("подтверждение откатывается: confirmed → configured без ожидания показывает «Настроено»", () => {
    expect(viewOf(app("a", "configured"), {}, 9)).toBe("configured");
  });
});

describe("sinceLastSeen", () => {
  it("давность в мс или null", () => {
    expect(sinceLastSeen(app("a", "confirmed", { last_seen_ms: 1000 }), 4000)).toBe(3000);
    expect(sinceLastSeen(app("a", "configured"), 4000)).toBeNull();
  });
});

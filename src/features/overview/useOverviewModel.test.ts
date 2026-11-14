import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { CheckResult, RiskReport } from "../../types";
import { overview as copy } from "../../shared/copy/ru";
import { parseAdminAuthError, parseTempDnsDeferredError } from "../../shared/hooks/useProtectionToggles";
import { fetchAppState, setMockScenario, toggleSysproxyPrivileged, verifyAndUnblockProvider } from "../../utils/api";
import { useOverviewModel } from "./useOverviewModel";
import type { OverviewModel } from "./useOverviewModel";

const ok = (code: string): CheckResult => ({ status: "ok", code, message: "ok" });
const crit = (): CheckResult => ({ status: "critical", code: "C", message: "c" });

function report(over: Partial<RiskReport> = {}): RiskReport {
  const checks = Array.from({ length: 13 }, (_, i) => ok(`C${i}`));
  return {
    provider: "anthropic",
    overall_status: "green",
    trust_score: 100,
    telemetry: { ip: "1.1.1.1", country_code: "NL", resolved_at: 1 },
    geo_result: checks[0],
    pinning_result: checks[1],
    travel_result: checks[2],
    dnsbl_result: checks[3],
    dnsbl_clean_count: "",
    asn_result: checks[4],
    ipv6_result: checks[5],
    timezone_result: checks[7],
    checks,
    ...over,
  };
}

/** Хук нельзя вызвать вне React: рендерим пробный компонент на сервере и забираем результат. */
function model(input: Partial<Parameters<typeof useOverviewModel>[0]>): OverviewModel {
  let out: OverviewModel | null = null;
  const Probe = () => {
    out = useOverviewModel({
      reports: {},
      activeReport: null,
      state: null,
      currentIp: "--",
      sysproxyActive: false,
      killswitchFrozen: false,
      updateInfo: null,
      refreshing: false,
      ...input,
    });
    return null;
  };
  renderToStaticMarkup(createElement(Probe));
  return out as unknown as OverviewModel;
}

describe("Обзор: запуск и ожидание", () => {
  it("пока шлюз запускается, нет ни «Вы защищены», ни «Защита выключена», ни красного", () => {
    const r = report();
    const m = model({ reports: { anthropic: r }, activeReport: r, currentIp: "1.1.1.1", sysproxyActive: false, startupPending: true });
    expect(m.verdict).toBe(copy.verdict.starting);
    expect(m.verdict).not.toBe(copy.verdict.ok);
    expect(m.verdict).not.toBe(copy.verdict.off);
    expect(m.banner).toBeNull();
  });

  it("красный отчёт до конца запуска не открывает баннер «Доступ остановлен»", () => {
    const r = report({ overall_status: "red", geo_result: crit(), checks: [crit(), ...report().checks.slice(1)] });
    const m = model({ reports: { anthropic: r }, activeReport: r, sysproxyActive: false, startupPending: true });
    expect(m.banner).toBeNull();
    expect(m.tone).not.toBe("danger");
  });

  it("ручной СТОП СЕТИ показывается и во время запуска: это известное состояние", () => {
    const m = model({ killswitchFrozen: true, startupPending: true });
    expect(m.banner).toBe("frozen");
    expect(m.tone).toBe("danger");
  });

  it("после запуска вердикты прежние", () => {
    const r = report();
    expect(model({ reports: { anthropic: r }, activeReport: r, sysproxyActive: true }).verdict).toBe(copy.verdict.ok);
    expect(model({ reports: { anthropic: r }, activeReport: r, sysproxyActive: false }).verdict).toBe(copy.verdict.off);
  });

  it("сервис без отчёта при идущей проверке — «Проверяем», а не «Нужна проверка»", () => {
    const m = model({ refreshing: true });
    expect(m.services.every((s) => s.status === "checking")).toBe(true);
  });
});

describe("ADMIN_AUTH_REQUIRED и умное снятие блока", () => {
  it("parseAdminAuthError снимает префикс ADMIN_AUTH_REQUIRED:", () => {
    expect(parseAdminAuthError("ADMIN_AUTH_REQUIRED:Нужен пароль администратора")).toBe("Нужен пароль администратора");
    expect(parseAdminAuthError(new Error("ADMIN_AUTH_REQUIRED:Требуются права"))).toBe("Требуются права");
    expect(parseAdminAuthError("ADMIN_AUTH_REQUIRED:")).toBeTruthy();
    expect(parseAdminAuthError(new Error("Обычная ошибка"))).toBeNull();
    expect(parseAdminAuthError(null)).toBeNull();
  });

  it("parseTempDnsDeferredError снимает префикс TEMP_DNS_DEFERRED:", () => {
    expect(parseTempDnsDeferredError("TEMP_DNS_DEFERRED:Прокси выключен, DNS ждёт VPN")).toBe(
      "Прокси выключен, DNS ждёт VPN",
    );
    expect(parseTempDnsDeferredError(new Error("TEMP_DNS_DEFERRED:"))).toBeTruthy();
    expect(parseTempDnsDeferredError(new Error("Обычная ошибка"))).toBeNull();
  });

  it("verifyAndUnblockProvider в чистом сценарии возвращает true без session_allowed_providers, а в RU — false", async () => {
    setMockScenario("clean");
    expect(await verifyAndUnblockProvider("anthropic")).toBe(true);
    const st = await fetchAppState();
    expect(st.session_allowed_providers).not.toContain("anthropic");

    setMockScenario("ru");
    expect(await verifyAndUnblockProvider("anthropic")).toBe(false);
    setMockScenario("clean");
  });

  it("toggleSysproxyPrivileged в браузерном моке включает защиту", async () => {
    expect(await toggleSysproxyPrivileged()).toBe(true);
  });
});

describe("Обзор: неизвестный DNS-резолвер не красит главный экран в жёлтый", () => {
  const unknown = (code: string): CheckResult => ({
    status: "unknown",
    code,
    message: "u",
    reason: "timeout",
  });

  it("когда unknown только в проверках DNS (6 и 10), вердикт и сервисы остаются зелёными", () => {
    const r = report({ overall_status: "green", trust_score: 100, incomplete: false });
    r.checks[6] = unknown("DNS_WHOAMI_TIMEOUT");
    r.checks[10] = unknown("DNS_WHOAMI_DISAGREE");

    const m = model({
      reports: { anthropic: r, openai: r, gemini: r },
      activeReport: r,
      sysproxyActive: true,
    });
    expect(m.tone).toBe("ok");
    expect(m.verdict).toBe(copy.verdict.ok);
    expect(m.banner).toBeNull();
    expect(m.services.every((s) => s.status === "ok")).toBe(true);
  });

  it("когда unknown в другой проверке (например, UDP STUN на 12), экран остаётся жёлтым", () => {
    const r = report({ overall_status: "green", trust_score: 94 });
    r.checks[12] = unknown("UDP_STUN_TIMEOUT");

    const m = model({
      reports: { anthropic: r },
      activeReport: r,
      sysproxyActive: true,
    });
    expect(m.tone).toBe("warn");
    expect(m.verdict).toBe(copy.verdict.partial);
    expect(m.banner).toBe("incomplete");
    expect(m.services.find((s) => s.id === "anthropic")?.status).toBe("warn");
  });
});

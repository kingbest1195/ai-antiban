import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { CheckResult, RiskReport } from "../../types";
import { overview as copy } from "../../shared/copy/ru";
import { parseAdminAuthError, parseTempDnsDeferredError } from "../../shared/hooks/useProtectionToggles";
import {
  allowProviderSession,
  clearTrustedExceptions,
  fetchAppState,
  removeTrustedException,
  setMockScenario,
  setProviderMonitoring,
  toggleSysproxyPrivileged,
  verifyAndUnblockProvider,
} from "../../utils/api";
import { tabBadges, useOverviewModel } from "./useOverviewModel";
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

  it("попровайдерный пин в state.pinned_ips определяет pinState для активного сервиса", () => {
    const gpt = report({ provider: "openai", telemetry: { ip: "3.3.3.3", country_code: "NL", resolved_at: 1 } });
    const m = model({
      reports: { openai: gpt },
      activeReport: gpt,
      currentIp: "3.3.3.3",
      sysproxyActive: true,
      state: {
        pinned_ip: "1.1.1.1",
        pinned_ips: { default: "1.1.1.1", openai: "3.3.3.3" },
        strict_pinning_enabled: true,
        ip_history: {},
        session_allowed_providers: [],
        blocked_providers: [],
      },
    });
    expect(m.pinState).toBe("pinned");
  });
});

describe("Wave 2: disabled_providers, trusted_exceptions и API-моки", () => {
  it("отключённый сервис получает status='disabled' и не вызывает ложный red/yellow вердикт или бейдж вкладки", () => {
    const full14 = Array.from({ length: 14 }, (_, i) => ok(`C${i}`));
    const green = report({ provider: "anthropic", overall_status: "green", checks: full14 });
    const greenGpt = report({ provider: "openai", overall_status: "green", checks: full14 });
    const redGemini = report({
      provider: "gemini",
      overall_status: "red",
      geo_result: crit(),
      checks: [crit(), ...full14.slice(1)],
    });
    const state = {
      pinned_ip: null,
      strict_pinning_enabled: false,
      ip_history: {},
      session_allowed_providers: [],
      blocked_providers: ["gemini"],
      disabled_providers: ["gemini"],
    };

    const m = model({
      reports: { anthropic: green, openai: greenGpt, gemini: redGemini },
      activeReport: green,
      state,
      sysproxyActive: true,
    });

    expect(m.tone).toBe("ok");
    expect(m.verdict).toBe(copy.verdict.ok);
    expect(m.banner).toBeNull();
    expect(m.services.find((s) => s.id === "gemini")?.status).toBe("disabled");
    expect(m.services.find((s) => s.id === "anthropic")?.status).toBe("ok");

    const badges = tabBadges(m.banner, { anthropic: green, openai: greenGpt, gemini: redGemini }, state);
    expect(badges.overview).toBeUndefined();
    expect(badges.checks).toBeUndefined();
  });

  it("когда активный отчёт относится к отключённому сервису, метрики берутся из включённого сервиса", () => {
    const redClaude = report({
      provider: "anthropic",
      overall_status: "red",
      geo_result: crit(),
      checks: [crit(), ...report().checks.slice(1)],
    });
    const greenGpt = report({ provider: "openai", overall_status: "green" });
    const m = model({
      reports: { anthropic: redClaude, openai: greenGpt },
      activeReport: redClaude,
      sysproxyActive: true,
      state: {
        pinned_ip: null,
        strict_pinning_enabled: false,
        ip_history: {},
        session_allowed_providers: [],
        blocked_providers: [],
        disabled_providers: ["anthropic"],
      },
    });
    expect(m.tone).toBe("ok");
    expect(m.services.find((s) => s.id === "anthropic")?.status).toBe("disabled");
    expect(m.services.find((s) => s.id === "openai")?.status).toBe("ok");
  });

  it("trusted_exceptions для текущего IP выхода разрешает сервис без красного баннера", () => {
    const redGpt = report({
      provider: "openai",
      overall_status: "red",
      telemetry: { ip: "185.220.101.5", country_code: "TR", resolved_at: 1 },
      geo_result: crit(),
      checks: [crit(), ...report().checks.slice(1)],
    });
    const m = model({
      reports: { openai: redGpt },
      activeReport: redGpt,
      currentIp: "185.220.101.5",
      sysproxyActive: true,
      state: {
        pinned_ip: null,
        strict_pinning_enabled: false,
        ip_history: {},
        session_allowed_providers: [],
        blocked_providers: [],
        trusted_exceptions: { openai: ["185.220.101.5"] },
      },
    });
    expect(m.banner).toBeNull();
    expect(m.services.find((s) => s.id === "openai")?.status).toBe("allowed");
  });

  it("совпадающий pinned_ip/pinned_ips перекрывает IMPOSSIBLE_TRAVEL_CRITICAL без красной карточки «Доступ к ИИ остановлен»", () => {
    const travelCrit: CheckResult = { code: "IMPOSSIBLE_TRAVEL_CRITICAL", status: "critical", message: "hop" };
    const redClaude = report({
      provider: "anthropic",
      overall_status: "red",
      telemetry: { ip: "198.51.100.245", country_code: "GB", resolved_at: 1 },
      travel_result: travelCrit,
      checks: [ok("GEO"), travelCrit],
    });
    const m = model({
      reports: { anthropic: redClaude },
      activeReport: redClaude,
      currentIp: "198.51.100.245",
      sysproxyActive: true,
      state: {
        pinned_ip: "198.51.100.245",
        pinned_ips: { default: "198.51.100.245", anthropic: "198.51.100.245" },
        strict_pinning_enabled: true,
        ip_history: {},
        session_allowed_providers: [],
        blocked_providers: [],
      },
    });
    expect(m.tone).toBe("ok");
    expect(m.verdict).toBe(copy.verdict.ok);
    expect(m.banner).toBeNull();
    expect(m.services.find((s) => s.id === "anthropic")?.status).toBe("allowed");

    // Если вместе с IMPOSSIBLE_TRAVEL_CRITICAL есть реальный критичный блок (например, DNSBL), pinned_ip не перекрывает его.
    const dnsblCrit: CheckResult = { code: "DNSBL_LISTED_CRITICAL", status: "critical", message: "listed" };
    const redBoth = report({
      provider: "anthropic",
      overall_status: "red",
      telemetry: { ip: "198.51.100.245", country_code: "GB", resolved_at: 1 },
      travel_result: travelCrit,
      dnsbl_result: dnsblCrit,
      checks: [travelCrit, dnsblCrit],
    });
    const mBlocked = model({
      reports: { anthropic: redBoth },
      activeReport: redBoth,
      currentIp: "198.51.100.245",
      sysproxyActive: true,
      state: {
        pinned_ip: "198.51.100.245",
        pinned_ips: { default: "198.51.100.245", anthropic: "198.51.100.245" },
        strict_pinning_enabled: true,
        ip_history: {},
        session_allowed_providers: [],
        blocked_providers: [],
      },
    });
    expect(mBlocked.tone).toBe("danger");
    expect(mBlocked.verdict).toBe(copy.verdict.stopped);
    expect(mBlocked.banner).toBe("stopped");
  });

  it("API моки setProviderMonitoring, removeTrustedException и clearTrustedExceptions обновляют состояние", async () => {
    const off = await setProviderMonitoring("gemini", false);
    expect(off.disabled_providers).toContain("gemini");

    const on = await setProviderMonitoring("gemini", true);
    expect(on.disabled_providers).not.toContain("gemini");

    await allowProviderSession("openai");
    const afterAllow = await fetchAppState();
    expect(afterAllow.trusted_exceptions?.openai?.length).toBeGreaterThan(0);

    const ip = afterAllow.trusted_exceptions!.openai[0];
    const afterRemove = await removeTrustedException("openai", ip);
    expect(afterRemove.trusted_exceptions?.openai).toBeUndefined();

    await allowProviderSession("anthropic");
    await allowProviderSession("gemini");
    const afterClear = await clearTrustedExceptions();
    expect(afterClear.trusted_exceptions).toEqual({});
  });
});

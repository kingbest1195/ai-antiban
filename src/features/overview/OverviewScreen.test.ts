import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { CheckResult, CoverageSnapshot, RiskReport } from "../../types";
import { overview as copy, status as words, toast as toastCopy } from "../../shared/copy/ru";
import { checkCliProtectionStatus, toggleSysproxy, toggleSysproxyPrivileged } from "../../utils/api";
import { CoverageSection } from "../coverage/CoverageSection";
import { executeAllowSequence, OverviewScreen } from "./OverviewScreen";
import type { OverviewScreenProps } from "./OverviewScreen";

const ok = (code: string): CheckResult => ({ status: "ok", code, message: "ok" });

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

const noop = () => {};

function baseProps(over: Partial<OverviewScreenProps> = {}): OverviewScreenProps {
  const active = report();
  return {
    reports: { anthropic: active, openai: report({ provider: "openai" }) },
    activeReport: active,
    state: {
      pinned_ip: null,
      strict_pinning_enabled: false,
      ip_history: {},
      session_allowed_providers: [],
      blocked_providers: [],
    },
    refreshing: false,
    auditError: null,
    currentIp: "1.1.1.1",
    trustScore: 100,
    gatewayStats: null,
    updateInfo: null,
    sysproxyActive: true,
    cliProtected: true,
    killswitchFrozen: false,
    onToggleSysproxy: noop,
    onToggleCli: noop,
    onToggleKillswitch: noop,
    onCopyIp: noop,
    onPinIp: noop,
    onUnpinIp: noop,
    onToggleStrict: noop,
    onAllowProvider: noop,
    onUnblockProvider: noop,
    onRetry: noop,
    onFixService: noop,
    onOpenChecks: noop,
    onOpenTimezone: noop,
    onOpenUpdate: noop,
    onOpenCrashTest: noop,
    ...over,
  };
}

describe("WP-4 & WP-5: OverviewScreen, CoverageSection и CLI sync", () => {
  it("при выключенной защите показывает нейтральное «Без защиты» вместо устаревших статусов провайдеров", () => {
    const html = renderToStaticMarkup(
      createElement(OverviewScreen, baseProps({ sysproxyActive: false, cliProtected: false })),
    );

    expect(html).toContain(copy.service.unprotected);
    expect(html).toContain(copy.service.unprotectedNote);
    expect(html).not.toContain(words.available);
    expect(html).not.toContain("zs-badge--danger");
  });

  it("держит «Браузеры» и «Десктопные приложения» раздельными строками внутри общей группы прокси", () => {
    const html = renderToStaticMarkup(createElement(OverviewScreen, baseProps()));

    expect(html).toContain("zs-linked-group");
    expect(html).toContain(copy.linkedProxy.label);
    expect(html).toContain(copy.browsers.title);
    expect(html).toContain(copy.desktopApps.title);
    expect(html).toContain(copy.editors.title);
    expect(html).toContain('class="zs-info-i"');
  });

  it("выключение и включение системного прокси синхронизирует статус CLI-защиты", async () => {
    await toggleSysproxy(false);
    expect(await checkCliProtectionStatus()).toBe(false);

    await toggleSysproxy(true);
    expect(await checkCliProtectionStatus()).toBe(true);

    await toggleSysproxy(false);
    await toggleSysproxyPrivileged();
    expect(await checkCliProtectionStatus()).toBe(true);
  });

  it("использует понятные тосты включения и выключения защиты", () => {
    expect(toastCopy.guard.onText).toContain("Браузеры, приложения, редакторы кода и терминал");
    expect(toastCopy.guard.offText).toContain("напрямую");
  });

  it("в CoverageSection показывает сворачиваемую расшифровку «Что значат статусы»", () => {
    const snapshot: CoverageSnapshot = {
      sysproxy_enabled: true,
      cli_protection_enabled: true,
      gateway_addr: "127.0.0.1:18080",
      pac_url: "http://127.0.0.1:18080/proxy.pac",
      generated_at_ms: 1,
      cli_mode: "ai_only",
      apps: [],
    };
    const html = renderToStaticMarkup(
      createElement(CoverageSection, { variant: "overview", initialSnapshot: snapshot }),
    );

    expect(html).toContain("Что значат статусы");
    expect(html).toContain("zs-cov__legend-toggle");
    expect(html).toContain('aria-expanded="false"');
  });

  it("для отключённого в Настройках провайдера показывает нейтральный статус «Мониторинг отключён» без ложной тревоги и CTA", () => {
    const redGemini = report({
      provider: "gemini",
      overall_status: "red",
      geo_result: { status: "critical", code: "GEMINI_GEO_BLOCKED", message: "blocked" },
    });
    const html = renderToStaticMarkup(
      createElement(
        OverviewScreen,
        baseProps({
          reports: { anthropic: report(), openai: report({ provider: "openai" }), gemini: redGemini },
          state: {
            pinned_ip: null,
            strict_pinning_enabled: false,
            ip_history: {},
            session_allowed_providers: [],
            blocked_providers: [],
            disabled_providers: ["gemini"],
          },
        }),
      ),
    );

    expect(html).toContain(copy.service.monitoringDisabled);
    expect(html).toContain(copy.service.monitoringDisabledNote);
    expect(html).not.toContain(words.blocked);
    expect(html).not.toContain(copy.service.forceAllow);
  });

  it("для жёлтых предупреждений мягко пишет «Есть замечания» без утверждения о блокировке", () => {
    const warnGpt = report({
      provider: "openai",
      overall_status: "yellow",
      asn_result: { status: "warning", code: "ASN_WARN", message: "shared pool" },
    });
    warnGpt.checks[4] = { status: "warning", code: "ASN_WARN", message: "shared pool" };

    const html = renderToStaticMarkup(
      createElement(
        OverviewScreen,
        baseProps({
          reports: { anthropic: report(), openai: warnGpt },
        }),
      ),
    );

    expect(html).toContain(copy.service.warnBadge);
    expect(html).toContain(copy.service.warnNote);
    expect(html).not.toContain(words.blocked);
  });

  it("executeAllowSequence ждёт завершения unblock строго перед вызовом allow", async () => {
    const order: string[] = [];
    let releaseUnblock!: () => void;
    const unblockGate = new Promise<void>((resolve) => {
      releaseUnblock = resolve;
    });

    const p = executeAllowSequence(
      "anthropic",
      true,
      async () => {
        order.push("unblock:start");
        await unblockGate;
        order.push("unblock:done");
      },
      async () => {
        order.push("allow:start");
        order.push("allow:done");
      },
    );

    await Promise.resolve();
    expect(order).toEqual(["unblock:start"]);
    releaseUnblock();
    await p;
    expect(order).toEqual(["unblock:start", "unblock:done", "allow:start", "allow:done"]);
  });

  it("копирайт «Разрешить принудительно» объясняет постоянное исключение для сервиса и текущего IP выхода", () => {
    expect(copy.service.forceHint).toContain("постоянное исключение");
    expect(copy.service.forceHint).toContain("Настройках");
    expect(copy.service.confirm.text("Claude")).toContain("Настройках");
  });
});

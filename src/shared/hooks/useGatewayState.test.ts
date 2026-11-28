import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { AppStateData, AuditProgressEvent, CheckResult, OverallStatus, ProviderId, RiskReport, RoutesSnapshot } from "../../types";

const hookRt = vi.hoisted(() => {
  type Slot = { kind: string; value?: unknown; deps?: unknown[]; cleanup?: () => void };
  let active = false, cursor = 0;
  let slots: Slot[] = [];
  let pending: Array<{ idx: number; fn: () => void | (() => void); deps?: unknown[] }> = [];
  let onRender: (() => void) | null = null;
  const changed = (a?: unknown[], b?: unknown[]) => !a || !b || a.length !== b.length || a.some((v, i) => !Object.is(v, b[i]));
  const flush = () => {
    for (const item of pending.splice(0)) {
      const s = slots[item.idx];
      s.cleanup?.();
      s.deps = item.deps;
      const c = item.fn();
      s.cleanup = typeof c === "function" ? c : undefined;
    }
  };
  return {
    isActive: () => active,
    mount(fn: () => void) { active = true; slots = []; cursor = 0; pending = []; onRender = fn; fn(); flush(); },
    unmount() { for (const s of slots) if (s.kind === "effect") s.cleanup?.(); active = false; slots = []; pending = []; onRender = null; },
    beginRender() { cursor = 0; },
    useState<T>(init: T | (() => T)): [T, (next: T | ((p: T) => T)) => void] {
      const idx = cursor++;
      if (idx >= slots.length) slots.push({ kind: "state", value: typeof init === "function" ? (init as () => T)() : init });
      const s = slots[idx];
      return [s.value as T, (next) => {
        const val = typeof next === "function" ? (next as (p: T) => T)(s.value as T) : next;
        if (!Object.is(s.value, val)) { s.value = val; if (onRender) { onRender(); flush(); } }
      }];
    },
    useRef<T>(init: T) { const i = cursor++; if (i >= slots.length) slots.push({ kind: "ref", value: { current: init } }); return slots[i].value as { current: T }; },
    useMemo<T>(f: () => T, deps: unknown[]) {
      const i = cursor++;
      if (i >= slots.length) { const value = f(); slots.push({ kind: "memo", deps, value }); return value; }
      const s = slots[i];
      if (changed(s.deps, deps)) { s.deps = deps; s.value = f(); }
      return s.value as T;
    },
    useEffect(fn: () => void | (() => void), deps?: unknown[]) {
      const idx = cursor++;
      if (idx >= slots.length) { slots.push({ kind: "effect" }); pending.push({ idx, fn, deps }); }
      else if (changed(slots[idx].deps, deps)) pending.push({ idx, fn, deps });
    },
  };
});

vi.mock("react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react")>();
  return {
    ...actual,
    useState: ((i: unknown) => (hookRt.isActive() ? hookRt.useState(i) : actual.useState(i))) as typeof actual.useState,
    useRef: ((i: unknown) => (hookRt.isActive() ? hookRt.useRef(i) : actual.useRef(i))) as typeof actual.useRef,
    useMemo: ((f: () => unknown, d: unknown[]) => (hookRt.isActive() ? hookRt.useMemo(f, d) : actual.useMemo(f, d))) as typeof actual.useMemo,
    useCallback: ((f: unknown, d: unknown[]) => (hookRt.isActive() ? hookRt.useMemo(() => f, d) : actual.useCallback(f as never, d))) as typeof actual.useCallback,
    useEffect: ((f: () => void | (() => void), d?: unknown[]) => (hookRt.isActive() ? hookRt.useEffect(f, d) : actual.useEffect(f, d))) as typeof actual.useEffect,
  };
});

const apiMocks = vi.hoisted(() => ({
  auditImpl: null as ((p: ProviderId, force: boolean, runId?: string) => Promise<RiskReport>) | null,
  onProgress: null as ((e: AuditProgressEvent) => void) | null,
}));

vi.mock("../../utils/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../utils/api")>();
  const noop = async () => () => {};
  return {
    ...actual,
    auditConnection: vi.fn((p: ProviderId, f: boolean, r?: string) => apiMocks.auditImpl ? apiMocks.auditImpl(p, f, r) : Promise.reject(new Error("no mock"))),
    fetchAppState: vi.fn(async () => ({ pinned_ip: null, strict_pinning_enabled: true, ip_history: {}, session_allowed_providers: [], blocked_providers: [], auto_update_enabled: true })),
    getCoverageSnapshot: vi.fn(async () => ({ items: [] })),
    getGuardPauseStatus: vi.fn(async () => ({ paused: false, mode: "none", gate: "open", manual_killswitch: false })),
    getRoutesSnapshot: vi.fn(async () => ({ routes: [], provider_routes: {}, effective: {}, dangling: [] })),
    getStartupState: vi.fn(async () => ({ phase: "ready" })),
    getSysproxyStatus: vi.fn(async () => true),
    onAuditProgress: vi.fn(async (cb: (e: AuditProgressEvent) => void) => { apiMocks.onProgress = cb; return () => {}; }),
    onAuditRefreshed: vi.fn(noop), onGuardPauseStatusChanged: vi.fn(noop), onStartupChanged: vi.fn(noop),
  };
});
import { HomeHub, resolveMascotState } from "../../features/shell-v3/HomeHub";
import { ServicesPage } from "../../features/shell-v3/ServicesPage";
import type { OverviewView } from "../../features/shell-v3/types";
import type { OverviewScreenProps } from "../../features/overview/OverviewScreen";
import { ServiceRow } from "../../features/overview/ServiceRow";
import { useOverviewModel } from "../../features/overview/useOverviewModel";
import { progressOf, buildPendingChecks } from "../../features/checks/checksModel";
import {
  invalidateStaleReports,
  mergeProviderReport,
  shouldInvalidateOnPauseStatus,
  shouldSuppressSelfHeal,
  useGatewayState,
} from "./useGatewayState";
import {
  findMissingEnabledProviders,
  isConfirmedIpChange,
  isRedundantNetworkAudit,
  mergeBatchReports,
  needsStartupSelfHeal,
  pickActiveReport,
  runConcurrentFullAudit,
  shouldRefreshOnFocus,
} from "./gatewayReports";

const okCheck: CheckResult = {
  status: "ok",
  code: "OK",
  message: "ok",
};

function makeReport(provider: ProviderId, status: OverallStatus, ip: string): RiskReport {
  return {
    provider,
    overall_status: status,
    trust_score: status === "green" ? 100 : 60,
    telemetry: {
      ip,
      country_code: "NL",
      resolved_at: 1,
    },
    geo_result: okCheck,
    pinning_result: okCheck,
    travel_result: okCheck,
    dnsbl_result: okCheck,
    dnsbl_clean_count: "4/4",
    asn_result: okCheck,
    ipv6_result: okCheck,
    timezone_result: okCheck,
    checks: [],
  };
}

describe("mergeProviderReport", () => {
  it("обновляет только выбранный сервис, не сбрасывая и не перезаписывая здоровые отчёты других", () => {
    const anthropicOk = makeReport("anthropic", "green", "1.1.1.1");
    const openaiOk = makeReport("openai", "green", "2.2.2.2");
    const geminiOld = makeReport("gemini", "yellow", "3.3.3.3");
    const geminiNew = makeReport("gemini", "green", "4.4.4.4");

    const prev: Partial<Record<ProviderId, RiskReport>> = {
      anthropic: anthropicOk,
      openai: openaiOk,
      gemini: geminiOld,
    };

    const next = mergeProviderReport(prev, "gemini", geminiNew);

    expect(next.anthropic).toBe(anthropicOk);
    expect(next.openai).toBe(openaiOk);
    expect(next.gemini).toBe(geminiNew);
    expect(prev.gemini).toBe(geminiOld);
  });
});

describe("invalidateStaleReports", () => {
  const routesSnapshot: RoutesSnapshot = {
    routes: [],
    provider_routes: { openai: "route-1" },
    effective: { anthropic: null, openai: "route-1", gemini: null },
    dangling: [],
  };

  it("сбрасывает только unrouted-сервисы при смене сети и сохраняет привязанный к ключу", () => {
    const prev = {
      anthropic: makeReport("anthropic", "green", "1.1.1.1"),
      openai: makeReport("openai", "green", "9.9.9.9"),
      gemini: makeReport("gemini", "green", "1.1.1.1"),
    };
    const next = invalidateStaleReports(prev, routesSnapshot);
    expect(next.anthropic).toBeUndefined();
    expect(next.gemini).toBeUndefined();
    expect(next.openai).toEqual(prev.openai);
  });

  it("при includeAll сбрасывает все отчёты, а при onlyProviders — только перечисленные", () => {
    const prev = {
      anthropic: makeReport("anthropic", "green", "1.1.1.1"),
      openai: makeReport("openai", "green", "9.9.9.9"),
    };
    const targeted = invalidateStaleReports(prev, routesSnapshot, ["openai"]);
    expect(targeted.openai).toBeUndefined();
    expect(targeted.anthropic).toEqual(prev.anthropic);

    const allDropped = invalidateStaleReports(prev, routesSnapshot, undefined, true);
    expect(allDropped).toEqual({});
  });
});

describe("shouldInvalidateOnPauseStatus", () => {
  it("не сбрасывает отчёты при paused === true или gate === 'blocked'", () => {
    expect(
      shouldInvalidateOnPauseStatus({
        paused: true,
        mode: "until_network_change",
        gate: "blocked",
        manual_killswitch: false,
        blocked_providers: ["anthropic"],
      }).invalidate,
    ).toBe(false);

    expect(
      shouldInvalidateOnPauseStatus({
        paused: false,
        mode: "none",
        gate: "blocked",
        manual_killswitch: false,
        blocked_providers: ["anthropic"],
      }).invalidate,
    ).toBe(false);
  });

  it("НЕ сбрасывает отчёты при транзиентном gate === 'pending' (устраняет шторм 11 из 11 -> 0 из 14)", () => {
    expect(
      shouldInvalidateOnPauseStatus({
        paused: false,
        mode: "none",
        gate: "pending",
        manual_killswitch: false,
        pending_providers: ["anthropic"],
      }),
    ).toEqual({ invalidate: false, includeAll: false });

    expect(
      shouldInvalidateOnPauseStatus({
        paused: false,
        mode: "none",
        gate: "open",
        manual_killswitch: false,
        pending_providers: [],
        blocked_providers: [],
      }).invalidate,
    ).toBe(false);
  });

  it("сбрасывает отчёты при включённом ручном kill-switch", () => {
    expect(
      shouldInvalidateOnPauseStatus({
        paused: false,
        mode: "manual",
        gate: "blocked",
        manual_killswitch: true,
        pending_providers: [],
      }).invalidate,
    ).toBe(false);

    expect(
      shouldInvalidateOnPauseStatus({
        paused: false,
        mode: "manual",
        gate: "open",
        manual_killswitch: true,
        pending_providers: ["anthropic"],
      }),
    ).toEqual({ invalidate: true, onlyProviders: ["anthropic"], includeAll: true });
  });
});

describe("isRedundantNetworkAudit & isConfirmedIpChange", () => {
  it("считает network://changed избыточным, если audit://refreshed недавно пришёл для того же IP", () => {
    const now = 100_000;
    expect(isRedundantNetworkAudit({ ip: "178.168.12.86", at: now - 500 }, "178.168.12.86", now)).toBe(true);
    expect(isRedundantNetworkAudit({ ip: "178.168.12.86", at: now - 6000 }, "178.168.12.86", now)).toBe(false);
    expect(isRedundantNetworkAudit({ ip: "178.168.12.86", at: now - 500 }, "185.212.102.40", now)).toBe(false);
    expect(isRedundantNetworkAudit({ ip: "178.168.12.86", at: now - 500 }, null, now)).toBe(false);
  });

  it("распознаёт подтверждённую смену IP только при двух разных валидных IP", () => {
    expect(isConfirmedIpChange("1.1.1.1", "2.2.2.2")).toBe(true);
    expect(isConfirmedIpChange("1.1.1.1", "1.1.1.1")).toBe(false);
    expect(isConfirmedIpChange("--", "2.2.2.2")).toBe(false);
    expect(isConfirmedIpChange("1.1.1.1", null)).toBe(false);
  });
});

describe("shouldSuppressSelfHeal", () => {
  it("подавляет 1.5с self-heal при gate === 'pending' или paused === true", () => {
    expect(shouldSuppressSelfHeal({ paused: true, mode: "until_network_change", gate: "open", manual_killswitch: false })).toBe(true);
    expect(shouldSuppressSelfHeal({ paused: false, mode: "none", gate: "pending", manual_killswitch: false })).toBe(true);
    expect(shouldSuppressSelfHeal({ paused: false, mode: "none", gate: "open", manual_killswitch: false })).toBe(false);
    expect(shouldSuppressSelfHeal(null)).toBe(false);
  });
});

describe("startup/visibility self-heal для всех включённых провайдеров (устранение «Проверить: Gemini»)", () => {
  it("выявляет отсутствующий отчёт у любого включённого провайдера, даже когда activeReport здоров", () => {
    const anthropicOk = {
      ...makeReport("anthropic", "green", "1.1.1.1"),
      telemetry: { ip: "1.1.1.1", country_code: "NL", asn: 13335, resolved_at: 1 },
    };
    const openaiOk = {
      ...makeReport("openai", "green", "1.1.1.1"),
      telemetry: { ip: "1.1.1.1", country_code: "NL", asn: 13335, resolved_at: 1 },
    };

    const reports = { anthropic: anthropicOk, openai: openaiOk };
    expect(findMissingEnabledProviders(reports)).toEqual(["gemini"]);

    const plan = needsStartupSelfHeal(anthropicOk, reports, []);
    expect(plan).toEqual({
      needed: true,
      missingIpOrProvider: false,
      missingProviders: ["gemini"],
    });

    // Отключённый пользователем провайдер не триггерит self-heal.
    expect(findMissingEnabledProviders(reports, ["gemini"])).toEqual([]);
    expect(needsStartupSelfHeal(anthropicOk, reports, ["gemini"])).toEqual({
      needed: false,
      missingIpOrProvider: false,
      missingProviders: [],
    });

    // При наличии всех трёх отчётов self-heal не требуется.
    const full = { ...reports, gemini: openaiOk };
    expect(needsStartupSelfHeal(anthropicOk, full, [])).toEqual({
      needed: false,
      missingIpOrProvider: false,
      missingProviders: [],
    });
  });

  it("pickActiveReport и shouldRefreshOnFocus корректно реагируют на пропущенные отчёты", () => {
    const openaiOk = makeReport("openai", "green", "2.2.2.2");
    expect(pickActiveReport({ openai: openaiOk }, ["anthropic"])).toBe(openaiOk);

    expect(shouldRefreshOnFocus(null, 100_000, true)).toBe(false);
    expect(shouldRefreshOnFocus(99_000, 100_000, true)).toBe(true);
    expect(shouldRefreshOnFocus(99_000, 100_000, false)).toBe(false);
    expect(shouldRefreshOnFocus(1_000, 200_000, false)).toBe(true);
  });
});

describe("Баг #4 (UI-шторм): конкурентный runFullAudit и стабильность UI при частичной блокировке", () => {
  it("runConcurrentFullAudit запускает anthropic, openai и gemini конкурентно и сохраняет валидные отчёты при частичном сбое", async () => {
    const started: ProviderId[] = [];
    const deferred: Record<ProviderId, { resolve: (r: RiskReport) => void; reject: (e: Error) => void }> = {} as never;
    const auditFn = vi.fn(
      (provider: ProviderId, _force: boolean, runId?: string) =>
        new Promise<RiskReport>((resolve, reject) => {
          expect(runId).toBeTruthy();
          started.push(provider);
          deferred[provider] = { resolve, reject };
        }),
    );
    let seq = 0;
    const beginRun = vi.fn((provider: ProviderId) => `${provider}-run-${++seq}`);

    const pending = runConcurrentFullAudit(false, auditFn, beginRun, 0);

    // Все три провайдера стартуют немедленно в одной волне без ожидания anthropic.
    expect(started).toEqual(["anthropic", "openai", "gemini"]);
    expect(beginRun).toHaveBeenCalledTimes(3);

    const claudeNew = makeReport("anthropic", "green", "103.139.51.30");
    const gptNew = makeReport("openai", "green", "103.139.51.30");
    deferred.anthropic.resolve(claudeNew);
    deferred.openai.resolve(gptNew);
    deferred.gemini.reject(new Error("transient timeout"));

    const res = await pending;
    expect(res.error).toBeNull();
    expect(res.updates.anthropic).toBe(claudeNew);
    expect(res.updates.openai).toBe(gptNew);
    expect(res.updates.gemini).toBeUndefined();

    const geminiOld = makeReport("gemini", "red", "103.139.51.30");
    const merged = mergeBatchReports(
      {
        anthropic: makeReport("anthropic", "green", "103.139.51.30"),
        openai: makeReport("openai", "green", "103.139.51.30"),
        gemini: geminiOld,
      },
      res.updates,
    );
    expect(merged.anthropic).toBe(claudeNew);
    expect(merged.openai).toBe(gptNew);
    // Упавший при фоновом обновлении gemini сохраняет свой валидный отчёт.
    expect(merged.gemini).toBe(geminiOld);
  });

  it("симуляция цикла runFullAudit при частичной блокировке (gemini blocked, anthropic в trusted_exceptions, openai green): нет прыжка HomeHub/AlertStrip/ServicesPage", async () => {
    const travelCrit: CheckResult = {
      status: "critical",
      code: "IMPOSSIBLE_TRAVEL_CRITICAL",
      message: "Смена страны за 4 часа (103.139.51.4 -> 103.139.51.30)",
    };
    const fullChecks = Array.from({ length: 14 }, () => okCheck);
    const travelChecks = fullChecks.map((c, idx) => (idx === 2 ? travelCrit : c));
    const anthropicReport: RiskReport = {
      ...makeReport("anthropic", "red", "103.139.51.30"),
      telemetry: { ip: "103.139.51.30", country_code: "SE", isp: "TestNet", resolved_at: 1 },
      travel_result: travelCrit,
      checks: travelChecks,
    };
    const openaiReport: RiskReport = {
      ...makeReport("openai", "green", "103.139.51.30"),
      telemetry: { ip: "103.139.51.30", country_code: "SE", isp: "TestNet", resolved_at: 1 },
      checks: fullChecks,
    };
    const geminiReport: RiskReport = {
      ...makeReport("gemini", "red", "103.139.51.30"),
      telemetry: { ip: "103.139.51.30", country_code: "SE", isp: "TestNet", resolved_at: 1 },
      travel_result: travelCrit,
      checks: travelChecks,
    };

    const appState: AppStateData = {
      pinned_ip: null,
      strict_pinning_enabled: true,
      ip_history: {},
      session_allowed_providers: [],
      blocked_providers: ["gemini"],
      trusted_exceptions: { anthropic: ["103.139.51.30"] },
    };

    const renderCycle = (reports: Partial<Record<ProviderId, RiskReport>>, refreshing: boolean) => {
      const activeReport = pickActiveReport(reports, appState.disabled_providers);
      let model!: ReturnType<typeof useOverviewModel>;
      const Probe = () => {
        model = useOverviewModel({
          reports,
          activeReport,
          state: appState,
          currentIp: activeReport?.telemetry.ip || "--",
          sysproxyActive: true,
          killswitchFrozen: false,
          updateInfo: null,
          refreshing,
          startupPending: false,
          guardPauseStatus: {
            paused: false,
            mode: "none",
            gate: "open",
            manual_killswitch: false,
            pending_providers: [],
            blocked_providers: ["gemini"],
          },
        });
        return null;
      };
      renderToStaticMarkup(createElement(Probe));

      const view: OverviewView = {
        loading: !activeReport,
        failed: false,
        progress: progressOf(buildPendingChecks(null, appState)),
        model,
      };

      const overview: OverviewScreenProps = {
        reports,
        activeReport,
        state: appState,
        refreshing,
        auditError: null,
        startupPending: false,
        partial: null,
        currentIp: activeReport?.telemetry.ip || "--",
        trustScore: activeReport?.trust_score ?? 100,
        gatewayStats: null,
        updateInfo: null,
        coverageSnapshot: null,
        routesSnapshot: null,
        hideIpMode: false,
        dataAgeMinutes: null,
        sysproxyActive: true,
        cliProtected: true,
        killswitchFrozen: false,
        onToggleSysproxy: vi.fn(),
        onToggleCli: vi.fn(),
        onToggleKillswitch: vi.fn(),
        onCopyIp: vi.fn(),
        onPinIp: vi.fn(),
        onUnpinIp: vi.fn(),
        onToggleStrict: vi.fn(),
        onAllowProvider: vi.fn(),
        onUnblockProvider: vi.fn(),
        onRetry: vi.fn(),
        onFixService: vi.fn(),
        onOpenChecks: vi.fn(),
        onOpenTimezone: vi.fn(),
        onOpenUpdate: vi.fn(),
        onOpenCrashTest: vi.fn(),
      };

      const coworkGuard = {
        status: null,
        needsRepair: false,
        repairing: false,
        error: null,
        repair: vi.fn(async () => null),
        refresh: vi.fn(async () => null),
      };

      const homeHtml = renderToStaticMarkup(
        createElement(HomeHub, {
          overview,
          view,
          togglingSysproxy: false,
          coworkGuard,
          osTz: {
            osTzStatus: null,
            osTzLoading: false,
            syncOsTimezone: vi.fn(),
            restoreOsTimezone: vi.fn(),
          },
          personaRisk: null,
          gatewayStats: null,
          state: appState,
          routeUnavailableBanner: null,
          onPushRoute: vi.fn(),
          onDismissRouteUnavailable: vi.fn(),
          onRefreshRoutes: vi.fn(async () => {}),
          onRefreshState: vi.fn(async () => {}),
          onAuditRefresh: vi.fn(),
          version: "3.2.1",
        }),
      );

      const servicesHtml = renderToStaticMarkup(
        createElement(ServicesPage, { overview, view }),
      );

      const geminiSvc = model.services.find((s) => s.id === "gemini")!;
      const geminiRowHtml = renderToStaticMarkup(
        createElement(ServiceRow, {
          service: geminiSvc,
          report: reports.gemini,
          state: appState,
          blockedByUser: true,
          defaultOpen: true,
          onFix: vi.fn(),
          onAllow: vi.fn(),
        }),
      );

      return { activeReport, model, view, homeHtml, servicesHtml, geminiRowHtml };
    };

    let reports: Partial<Record<ProviderId, RiskReport>> = {
      anthropic: anthropicReport,
      openai: openaiReport,
      gemini: geminiReport,
    };

    // Запускаем конкурентный аудит (in-flight -> refreshing === true).
    const resolvers: Partial<Record<ProviderId, (r: RiskReport) => void>> = {};
    const auditPromise = runConcurrentFullAudit(
      false,
      (p) => new Promise<RiskReport>((res) => { resolvers[p] = res; }),
      (p) => `run-${p}`,
      0,
    );

    const midFlight = renderCycle(reports, true);
    expect(midFlight.view.loading).toBe(false);
    expect(midFlight.homeHtml).not.toContain("Проверяем сеть и защиту");
    expect(midFlight.homeHtml).toContain("Сторожевой пёс Заставы: обнаружена угроза или перехват");
    expect(midFlight.homeHtml).not.toContain("Сторожевой пёс Заставы: проверка среды");
    expect(
      resolveMascotState({
        refreshing: true,
        sysproxyActive: true,
        killswitchFrozen: false,
        overallStatus: midFlight.model.tone === "danger" ? "red" : midFlight.activeReport?.overall_status,
      }),
    ).toBe("alert");
    // AlertStrip не исчезает во время фонового обновления.
    expect(midFlight.homeHtml).toContain("Запросы к ИИ удерживаются");
    // На ServicesPage ChatGPT не прыгает в «Проверяем…», а Gemini сохраняет причину + кнопку «Что исправить».
    expect(midFlight.servicesHtml).not.toContain("Проверяем…");
    expect(midFlight.servicesHtml).toContain("ChatGPT");
    expect(midFlight.servicesHtml).toContain("Доступен");
    expect(midFlight.model.services.find((s) => s.id === "openai")?.status).toBe("ok");
    expect(midFlight.geminiRowHtml).toContain("Смена страны за 4 часа");
    expect(midFlight.geminiRowHtml).toContain("Что исправить");
    expect(midFlight.geminiRowHtml).not.toContain("Запросы удерживаются шлюзом");

    // Завершаем все 3 провайдера конкурентно.
    resolvers.anthropic!(anthropicReport);
    resolvers.openai!(openaiReport);
    resolvers.gemini!(geminiReport);
    const completed = await auditPromise;
    reports = mergeBatchReports(reports, completed.updates);

    const after = renderCycle(reports, false);
    expect(after.view.loading).toBe(false);
    expect(after.homeHtml).toContain("Запросы к ИИ удерживаются");
    expect(after.homeHtml).toContain("Сторожевой пёс Заставы: обнаружена угроза или перехват");
    expect(after.geminiRowHtml).toContain("Смена страны за 4 часа");
    expect(after.geminiRowHtml).toContain("Что исправить");
  });

  it("runConcurrentFullAudit отменяет retry anthropic без повторного beginRun, если isStale() стал true за время паузы", async () => {
    let stale = false;
    let anthropicCalls = 0;
    const beginRun = vi.fn((p: ProviderId) => `run-${p}`);
    const auditFn = vi.fn(async (p: ProviderId) => {
      if (p === "anthropic") {
        anthropicCalls += 1;
        throw new Error("cold fail");
      }
      return makeReport(p, "green", "1.1.1.1");
    });

    const promise = runConcurrentFullAudit(false, auditFn, beginRun, 25, () => stale);
    await Promise.resolve();
    stale = true;
    const res = await promise;
    expect(anthropicCalls).toBe(1);
    expect(beginRun).toHaveBeenCalledTimes(3);
    expect(res.stale).toBe(true);
    expect(res.updates).toEqual({});
  });

  it("auditEpochRef: медленный runFullAudit #1 (с retry на старую сеть) НЕ перезаписывает отчёты #2, scanLatencyMs и partials нового запуска", async () => {
    const prevWindow = (globalThis as { window?: unknown }).window;
    const prevDocument = (globalThis as { document?: unknown }).document;
    Object.defineProperty(globalThis, "window", { configurable: true, value: { addEventListener: vi.fn(), removeEventListener: vi.fn() } });
    Object.defineProperty(globalThis, "document", { configurable: true, value: { visibilityState: "visible", addEventListener: vi.fn(), removeEventListener: vi.fn() } });

    try {
      let wave = 0;
      const calls: Array<{ wave: number; p: ProviderId; runId?: string }> = [];
      const deferred1: Partial<Record<ProviderId, { resolve: (r: RiskReport) => void; reject: (e: Error) => void }>> = {};
      const deferred2: Partial<Record<ProviderId, (r: RiskReport) => void>> = {};
      const runIdsByWave: Record<number, Partial<Record<ProviderId, string>>> = { 1: {}, 2: {} };

      apiMocks.auditImpl = (p, _force, runId) => {
        const w = wave;
        calls.push({ wave: w, p, runId });
        if (w <= 1) {
          if (w === 1) runIdsByWave[1][p] = runId;
          if (w === 0) return Promise.reject(new Error("boot"));
          return new Promise((resolve, reject) => { deferred1[p] = { resolve, reject }; });
        }
        runIdsByWave[2][p] = runId;
        return new Promise((resolve) => { deferred2[p] = resolve; });
      };

      let gw!: ReturnType<typeof useGatewayState>;
      hookRt.mount(() => {
        hookRt.beginRender();
        gw = useGatewayState({ showToast: vi.fn(), refreshGatewayStats: vi.fn(async () => {}) });
      });

      // Запускаем #1 (старая сеть 1.1.1.1): anthropic падает и ждёт retry, openai/gemini висят.
      wave = 1;
      const audit1 = gw.runFullAudit(true, true);
      deferred1.anthropic!.reject(new Error("old network hiccup"));
      await Promise.resolve();

      // Во время ожидания #1 меняем сеть: invalidateReports() + запускаем #2 (новая сеть 2.2.2.2).
      gw.invalidateReports();
      wave = 2;
      const audit2 = gw.runFullAudit(true, true);
      // Прогресс #2 активен в partials; разрешаем #1 до завершения #2 -> partials #2 не должны затереться!
      apiMocks.onProgress?.({ run_id: runIdsByWave[2].anthropic!, provider: "anthropic", kind: "telemetry", telemetry: { ip: "2.2.2.2", country_code: "NL", resolved_at: 2 } });
      expect(gw.partialAudit?.telemetry?.ip).toBe("2.2.2.2");

      const old1 = (p: ProviderId): RiskReport => ({ ...makeReport(p, "red", "1.1.1.1"), gateway_latency_ms: 999 });
      deferred1.openai!.resolve(old1("openai"));
      deferred1.gemini!.resolve(old1("gemini"));
      await audit1;
      // Retry для wave=1 anthropic не вызывался, partials wave=2 сохранились, старые отчёты не записались.
      expect(calls.filter((c) => c.wave === 1 && c.p === "anthropic")).toHaveLength(1);
      expect(gw.partialAudit?.telemetry?.ip).toBe("2.2.2.2");
      expect(gw.reports.openai).toBeUndefined();

      const fresh2 = (p: ProviderId): RiskReport => ({ ...makeReport(p, "green", "2.2.2.2"), gateway_latency_ms: 24 });
      deferred2.anthropic!(fresh2("anthropic"));
      deferred2.openai!(fresh2("openai"));
      deferred2.gemini!(fresh2("gemini"));
      await audit2;
      expect(gw.reports.anthropic?.telemetry.ip).toBe("2.2.2.2");
      expect(gw.reports.openai?.telemetry.ip).toBe("2.2.2.2");
      expect(gw.reports.gemini?.telemetry.ip).toBe("2.2.2.2");
      expect(gw.scanLatencyMs).toBe(24);
    } finally {
      hookRt.unmount();
      apiMocks.auditImpl = null;
      apiMocks.onProgress = null;
      Object.defineProperty(globalThis, "window", { configurable: true, value: prevWindow });
      Object.defineProperty(globalThis, "document", { configurable: true, value: prevDocument });
    }
  });
});

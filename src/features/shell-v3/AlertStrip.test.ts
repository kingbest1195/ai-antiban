import type { ReactElement } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react")>();
  return {
    ...actual,
    useState: <T,>(initial: T | (() => T)): [T, () => void] => [
      typeof initial === "function" ? (initial as () => T)() : initial,
      vi.fn(),
    ],
    useEffect: vi.fn(),
    useCallback: <T extends (...args: never[]) => unknown>(fn: T): T => fn,
  };
});

const osTzApiMocks = vi.hoisted(() => ({
  getOsTimezoneSyncStatus: vi.fn(async () => ({
    synced: false,
    current_os_tz: "Europe/Moscow",
    original_os_tz: null,
    synced_target_tz: null,
    auto_restore_pending: false,
  })),
  syncOsTimezone: vi.fn(async (targetTz?: string) => ({
    synced: true,
    current_os_tz: targetTz || "Europe/Amsterdam",
    original_os_tz: "Europe/Moscow",
    synced_target_tz: targetTz || "Europe/Amsterdam",
    auto_restore_pending: true,
  })),
  restoreOsTimezone: vi.fn(async () => ({
    synced: false,
    current_os_tz: "Europe/Moscow",
    original_os_tz: null,
    synced_target_tz: null,
    auto_restore_pending: false,
  })),
}));

vi.mock("../../utils/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../utils/api")>();
  return {
    ...actual,
    getOsTimezoneSyncStatus: osTzApiMocks.getOsTimezoneSyncStatus,
    syncOsTimezone: osTzApiMocks.syncOsTimezone,
    restoreOsTimezone: osTzApiMocks.restoreOsTimezone,
  };
});

import { Banner, Button } from "../../ui";
import { ProblemBanner } from "../overview/ProblemBanner";
import { AlertStrip } from "./AlertStrip";
import type { AlertStripProps } from "./types";

function collectButtons(node: unknown, acc: Array<ReactElement<Record<string, unknown>>> = []): Array<ReactElement<Record<string, unknown>>> {
  if (!node || typeof node !== "object") return acc;
  if (Array.isArray(node)) {
    for (const item of node) collectButtons(item, acc);
    return acc;
  }
  const el = node as ReactElement<Record<string, unknown>>;
  if ("type" in el && "props" in el) {
    if (el.type === Button) acc.push(el);
    if (typeof el.type === "function" && el.type !== Button) {
      collectButtons((el.type as (p: Record<string, unknown>) => unknown)(el.props), acc);
      return acc;
    }
    if (el.props?.action) collectButtons(el.props.action, acc);
    if (el.props?.children) collectButtons(el.props.children, acc);
  }
  return acc;
}

function collectProblemBanners(node: unknown, acc: Array<ReactElement<Record<string, unknown>>> = []): Array<ReactElement<Record<string, unknown>>> {
  if (!node || typeof node !== "object") return acc;
  if (Array.isArray(node)) {
    for (const item of node) collectProblemBanners(item, acc);
    return acc;
  }
  const el = node as ReactElement<Record<string, unknown>>;
  if ("type" in el && "props" in el) {
    if (el.type === ProblemBanner) acc.push(el);
    if (el.props?.action) collectProblemBanners(el.props.action, acc);
    if (el.props?.children) collectProblemBanners(el.props.children, acc);
  }
  return acc;
}

function baseOverview(overrides: Partial<AlertStripProps["overview"]> = {}): AlertStripProps["overview"] {
  return {
    reports: {},
    activeReport: null,
    state: null,
    refreshing: false,
    auditError: null,
    startupPending: false,
    partial: null,
    currentIp: "185.212.102.40",
    trustScore: 95,
    gatewayStats: {
      protected_ai_requests: 12,
      intercepted_leaks: 0,
      direct_bypassed_requests: 5,
      active_ai_tunnels: 1,
      uptime_seconds: 120,
      last_protected_host: "api.anthropic.com",
      recent_events: [],
    },
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
    ...overrides,
  };
}

function baseView(banner: AlertStripProps["view"]["model"]["banner"] = null): AlertStripProps["view"] {
  return {
    loading: false,
    failed: false,
    progress: { done: 13, total: 13 },
    model: {
      verdict: "Вы защищены",
      tone: "ok",
      checksPassed: 13,
      checksTotal: 13,
      checksUnknown: 0,
      checksLabel: "13 из 13",
      pinState: "none",
      providerName: "Cloudflare",
      banner,
      services: [
        { id: "anthropic", status: "ok" },
        { id: "openai", status: "ok" },
        { id: "gemini", status: "ok" },
      ],
    },
  };
}

function baseCoworkGuard(overrides: Partial<AlertStripProps["coworkGuard"]> = {}): AlertStripProps["coworkGuard"] {
  return {
    status: null,
    needsRepair: false,
    repairing: false,
    error: null,
    repair: vi.fn(async () => null),
    refresh: vi.fn(async () => null),
    ...overrides,
  };
}

describe("AlertStrip click-to-repair error toast & OS TZ sync", () => {
  beforeEach(() => {
    osTzApiMocks.getOsTimezoneSyncStatus.mockClear();
    osTzApiMocks.syncOsTimezone.mockClear();
    osTzApiMocks.restoreOsTimezone.mockClear();
  });

  it("вызывает overview.onToast с реальной ошибкой бэкенда уже при первом сбое ремонта (когда до клика error === null)", async () => {
    const onToast = vi.fn();
    const repair = vi.fn(async () => ({
      status: null,
      error: "Доступ запрещён",
    }));
    const tree = AlertStrip({
      view: baseView(),
      overview: baseOverview({ onToast }),
      coworkGuard: baseCoworkGuard({
        needsRepair: true,
        error: null,
        repair,
      }),
      ipChangeCooldownUntil: null,
      routeUnavailableBanner: null,
      routesSnapshot: null,
      onPushRoute: vi.fn(),
      onDismissRouteUnavailable: vi.fn(),
      onRefreshRoutes: vi.fn(async () => {}),
      onRefreshState: vi.fn(async () => {}),
      onAuditRefresh: vi.fn(),
    });

    expect(Banner).toBeDefined();
    const buttons = collectButtons(tree).filter((b) => String(b.props.children ?? "").includes("Починить в 1 клик"));
    expect(buttons).toHaveLength(1);

    (buttons[0].props.onClick as () => void)();
    await new Promise((r) => setTimeout(r, 0));
    expect(repair).toHaveBeenCalledTimes(1);
    expect(onToast).toHaveBeenCalledWith("Не удалось защитить фоновую службу Claude", "Доступ запрещён", "error");
  });

  it("использует текст об отмене UAC только когда свежая ошибка бэкенда действительно про отмену или пуста", async () => {
    const onToast = vi.fn();
    const repair = vi.fn(async () => ({
      status: null,
      error: "ELEVATION_CANCELLED",
    }));
    const tree = AlertStrip({
      view: baseView(),
      overview: baseOverview({ onToast }),
      coworkGuard: baseCoworkGuard({
        needsRepair: true,
        error: null,
        repair,
      }),
      ipChangeCooldownUntil: null,
      routeUnavailableBanner: null,
      routesSnapshot: null,
      onPushRoute: vi.fn(),
      onDismissRouteUnavailable: vi.fn(),
      onRefreshRoutes: vi.fn(async () => {}),
      onRefreshState: vi.fn(async () => {}),
      onAuditRefresh: vi.fn(),
    });

    const buttons = collectButtons(tree).filter((b) => String(b.props.children ?? "").includes("Починить в 1 клик"));
    (buttons[0].props.onClick as () => void)();
    await new Promise((r) => setTimeout(r, 0));
    expect(onToast).toHaveBeenCalledWith(
      "Не удалось защитить фоновую службу Claude",
      expect.stringContaining("отменён"),
      "error",
    );
  });

  it("вызывает overview.onToast(..., 'warning') когда repair() возвращает { status: { needs_repair: true, summary }, error }", async () => {
    const onToast = vi.fn();
    const summary = "Планировщик не дал права: служба остаётся в автозапуске.";
    const repair = vi.fn(async () => ({
      status: {
        platform: "windows",
        supported: true,
        service_present: true,
        start_type: 2,
        service_running: true,
        task_installed: false,
        task_healthy: false,
        needs_repair: true,
        summary,
        detected_ai_apps: [],
      },
      error: summary,
    }));
    const tree = AlertStrip({
      view: baseView(),
      overview: baseOverview({ onToast }),
      coworkGuard: baseCoworkGuard({
        needsRepair: true,
        error: null,
        repair,
      }),
      ipChangeCooldownUntil: null,
      routeUnavailableBanner: null,
      routesSnapshot: null,
      onPushRoute: vi.fn(),
      onDismissRouteUnavailable: vi.fn(),
      onRefreshRoutes: vi.fn(async () => {}),
      onRefreshState: vi.fn(async () => {}),
      onAuditRefresh: vi.fn(),
    });

    const buttons = collectButtons(tree).filter((b) => String(b.props.children ?? "").includes("Починить в 1 клик"));
    expect(buttons).toHaveLength(1);

    (buttons[0].props.onClick as () => void)();
    await new Promise((r) => setTimeout(r, 0));
    expect(repair).toHaveBeenCalledTimes(1);
    expect(onToast).toHaveBeenCalledWith(
      "Не удалось завершить защиту фоновой службы Claude",
      summary,
      "warning",
    );
  });

  it("подключает реальный useOsTimezoneSync для TIMEZONE_SYNCED_CLI_ONLY и использует variant secondary/quiet", async () => {
    const overview = baseOverview({
      activeReport: {
        provider: "anthropic",
        overall_status: "yellow",
        trust_score: 90,
        telemetry: { ip: "185.212.102.40", country_code: "NL", timezone: "Europe/Amsterdam", resolved_at: 1 },
        geo_result: { status: "ok", code: "GEO_OK", message: "ok" },
        pinning_result: { status: "ok", code: "PIN_OK", message: "ok" },
        travel_result: { status: "ok", code: "TRAVEL_OK", message: "ok" },
        dnsbl_result: { status: "ok", code: "DNSBL_OK", message: "ok" },
        dnsbl_clean_count: "",
        asn_result: { status: "ok", code: "ASN_OK", message: "ok" },
        ipv6_result: { status: "ok", code: "IPV6_OK", message: "ok" },
        timezone_result: { status: "warning", code: "TIMEZONE_SYNCED_CLI_ONLY", message: "CLI only" },
        checks: [],
      },
    });
    const tree = AlertStrip({
      view: baseView("timezone"),
      overview,
      coworkGuard: baseCoworkGuard(),
      ipChangeCooldownUntil: null,
      routeUnavailableBanner: null,
      routesSnapshot: null,
      onPushRoute: vi.fn(),
      onDismissRouteUnavailable: vi.fn(),
      onRefreshRoutes: vi.fn(async () => {}),
      onRefreshState: vi.fn(async () => {}),
      onAuditRefresh: vi.fn(),
    });

    const problemBanners = collectProblemBanners(tree);
    expect(problemBanners).toHaveLength(1);
    expect(problemBanners[0].props.tzCode).toBe("TIMEZONE_SYNCED_CLI_ONLY");

    const buttons = collectButtons(tree);
    for (const btn of buttons) {
      expect(btn.props.variant).not.toBe("primary");
    }

    const syncBtn = buttons.find((b) => String(b.props.children ?? "").includes("Синхронизировать пояс системы"));
    expect(syncBtn).toBeDefined();
    expect(syncBtn!.props.variant).toBe("secondary");

    (syncBtn!.props.onClick as () => void)();
    await new Promise((r) => setTimeout(r, 0));
    expect(osTzApiMocks.syncOsTimezone).toHaveBeenCalledWith("Europe/Amsterdam");
  });

  it("не показывает TZ ProblemBanner на HomeHub, когда TZ проверка в статусе ok (banner === null)", () => {
    const tree = AlertStrip({
      view: baseView(null),
      overview: baseOverview({
        activeReport: {
          provider: "anthropic",
          overall_status: "green",
          trust_score: 100,
          telemetry: { ip: "185.212.102.40", country_code: "NL", timezone: "Europe/Amsterdam", resolved_at: 1 },
          geo_result: { status: "ok", code: "GEO_OK", message: "ok" },
          pinning_result: { status: "ok", code: "PIN_OK", message: "ok" },
          travel_result: { status: "ok", code: "TRAVEL_OK", message: "ok" },
          dnsbl_result: { status: "ok", code: "DNSBL_OK", message: "ok" },
          dnsbl_clean_count: "",
          asn_result: { status: "ok", code: "ASN_OK", message: "ok" },
          ipv6_result: { status: "ok", code: "IPV6_OK", message: "ok" },
          timezone_result: { status: "ok", code: "TIMEZONE_MATCH", message: "ok" },
          checks: [],
        },
      }),
      coworkGuard: baseCoworkGuard(),
      ipChangeCooldownUntil: null,
      routeUnavailableBanner: null,
      routesSnapshot: null,
      onPushRoute: vi.fn(),
      onDismissRouteUnavailable: vi.fn(),
      onRefreshRoutes: vi.fn(async () => {}),
      onRefreshState: vi.fn(async () => {}),
      onAuditRefresh: vi.fn(),
    });
    expect(tree).toBeNull();
    expect(collectProblemBanners(tree)).toHaveLength(0);
  });

  it("в блоке cooldown оставляет одну компактную кнопку действия без второй карточки-кнопки", () => {
    const tree = AlertStrip({
      view: baseView(null),
      overview: baseOverview(),
      coworkGuard: baseCoworkGuard(),
      ipChangeCooldownUntil: Math.floor(Date.now() / 1000) + 1800,
      routeUnavailableBanner: null,
      routesSnapshot: null,
      onPushRoute: vi.fn(),
      onDismissRouteUnavailable: vi.fn(),
      onRefreshRoutes: vi.fn(async () => {}),
      onRefreshState: vi.fn(async () => {}),
      onAuditRefresh: vi.fn(),
    });
    const buttons = collectButtons(tree);
    expect(buttons).toHaveLength(1);
    expect(String(buttons[0].props.children ?? "")).toContain("Сбросить таймер");
  });
});

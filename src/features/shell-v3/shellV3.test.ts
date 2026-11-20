import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { pushRoute, popRoute, resetRouteStack } from "../../shared/hooks/useNavigation";
import type { Route } from "../../shared/hooks/useNavigation";
import type { AppStateData, PersonaRiskReport } from "../../types";
import type { OverviewScreenProps } from "../overview/OverviewScreen";
import type { OverviewView } from "./types";
import { HeaderBar, menuWithout } from "./HeaderBar";
import { HomeHub, resolveMascotState, resolvePersonaPill } from "./HomeHub";
import { NotificationStack } from "./NotificationStack";
import { PowerPill } from "./PowerPill";
import { SectionList } from "./SectionList";
import { AlertStrip, selectAlertPriorityIds } from "./AlertStrip";
import { shouldShowWhatsNew } from "./WhatsNewSheet";

function makeBaseOverview(overrides: Partial<OverviewScreenProps> = {}): OverviewScreenProps {
  return {
    reports: {},
    activeReport: null,
    state: null,
    refreshing: false,
    auditError: null,
    startupPending: false,
    partial: null,
    currentIp: "1.2.3.4",
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

function makeBaseView(overrides: Partial<OverviewView> = {}): OverviewView {
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
      banner: null,
      services: [
        { id: "anthropic", status: "ok" },
        { id: "openai", status: "ok" },
        { id: "gemini", status: "ok" },
      ],
    },
    ...overrides,
  };
}

describe("Shell v3 navStack", () => {
  it("preserves route params across push and pop (Clean Room Step 4 -> Guide -> Back)", () => {
    let stack: Route[] = [{ page: "home" }];
    stack = pushRoute(stack, { page: "clean-room", cleanRoomTab: "launchpad", cleanRoomStep: 4 });
    stack = pushRoute(stack, { page: "guides", guideRef: "02-safe-payment-cards" });
    expect(stack).toHaveLength(3);

    stack = popRoute(stack);
    expect(stack[stack.length - 1]).toEqual({
      page: "clean-room",
      cleanRoomTab: "launchpad",
      cleanRoomStep: 4,
    });
  });

  it("returns from Clean Room Step 1 back to SOS/Backup with sosBranch preserved", () => {
    let stack: Route[] = [{ page: "home" }];
    stack = pushRoute(stack, { page: "backup", sosBranch: "banned" });
    stack = pushRoute(stack, { page: "clean-room", cleanRoomTab: "launchpad", cleanRoomStep: 1 });
    stack = popRoute(stack);
    expect(stack[stack.length - 1]).toEqual({ page: "backup", sosBranch: "banned" });
  });

  it("preserves checksProvider when returning from Guides", () => {
    let stack: Route[] = [{ page: "home" }];
    stack = pushRoute(stack, { page: "checks", checksProvider: "openai" });
    stack = pushRoute(stack, { page: "guides", guideRef: "01-personal-vpn-15min" });
    stack = popRoute(stack);
    expect(stack[stack.length - 1]).toEqual({ page: "checks", checksProvider: "openai" });
    expect(resetRouteStack()).toEqual([{ page: "home" }]);
  });
});

describe("PowerPill", () => {
  it("disables button during startupPending or togglingSysproxy and uses mascot transition classes", () => {
    const htmlPending = renderToStaticMarkup(
      createElement(PowerPill, { on: false, startupPending: true, toggling: false, onToggle: vi.fn() }),
    );
    expect(htmlPending).toContain("disabled");
    expect(htmlPending).toContain("Запуск защиты");
    expect(htmlPending).toContain("zs-power-transition");

    const htmlToggling = renderToStaticMarkup(
      createElement(PowerPill, { on: false, startupPending: false, toggling: true, onToggle: vi.fn() }),
    );
    expect(htmlToggling).toContain("disabled");
    expect(htmlToggling).toContain("zs-power-transition--waking");
    expect(htmlToggling).toContain("Включаем защиту");
  });
});

describe("AlertStrip", () => {
  it("orders banners by priority: problem > cowork > cooldown > expiring", () => {
    expect(
      selectAlertPriorityIds({
        hasProblem: true,
        coworkNeedsRepair: true,
        hasCooldown: true,
        hasExpiringKey: true,
      }),
    ).toEqual(["problem", "cowork", "cooldown", "expiring"]);
  });

  it("renders top 1 banner and 'ещё N' expand pill when multiple alerts are active", () => {
    const html = renderToStaticMarkup(
      createElement(AlertStrip, {
        view: makeBaseView({ model: { ...makeBaseView().model, banner: "stopped" } }),
        overview: makeBaseOverview(),
        coworkGuard: {
          status: {
            platform: "windows",
            supported: true,
            service_present: true,
            service_running: true,
            start_type: 2,
            task_installed: false,
            task_healthy: false,
            needs_repair: true,
            detected_ai_apps: [],
            summary: "CoworkVMService needs repair",
          },
          needsRepair: true,
          repairing: false,
          error: null,
          repair: vi.fn(async () => null),
          refresh: vi.fn(async () => null),
        },
        ipChangeCooldownUntil: Math.floor(Date.now() / 1000) + 3600,
        routeUnavailableBanner: null,
        onPushRoute: vi.fn(),
        onDismissRouteUnavailable: vi.fn(),
        onRefreshRoutes: vi.fn(async () => {}),
        onRefreshState: vi.fn(async () => {}),
        onAuditRefresh: vi.fn(),
      }),
    );
    expect(html).toContain("ещё 2");
  });
});

describe("WhatsNewSheet visibility", () => {
  it("shows only for v2->v3 migrators with onboarding_v3_done=true and whats_new_v3_seen=false", () => {
    const migrator = { onboarding_v3_done: true, whats_new_v3_seen: false } as AppStateData;
    const seen = { onboarding_v3_done: true, whats_new_v3_seen: true } as AppStateData;
    const freshUser = { onboarding_v3_done: false, whats_new_v3_seen: false } as AppStateData;

    expect(shouldShowWhatsNew(migrator)).toBe(true);
    expect(shouldShowWhatsNew(seen)).toBe(false);
    expect(shouldShowWhatsNew(freshUser)).toBe(false);
    expect(shouldShowWhatsNew(null)).toBe(false);
  });
});

describe("HomeHub & HeaderBar & NotificationStack", () => {
  it("renders 5 sections and Persona pill on HomeHub", () => {
    const personaRisk: PersonaRiskReport = {
      score: 62,
      level: "high",
      factors: [],
      self_check: {
        bought_or_grey_account: false,
        virtual_sms_used: false,
        reseller_payment_used: false,
        multi_account_same_browser: false,
      },
      recommended_actions: ["Check IP"],
      evaluated_at: 1,
    };
    const html = renderToStaticMarkup(
      createElement(HomeHub, {
        overview: makeBaseOverview(),
        view: makeBaseView(),
        togglingSysproxy: false,
        coworkGuard: {
          status: null,
          needsRepair: false,
          repairing: false,
          error: null,
          repair: vi.fn(async () => null),
          refresh: vi.fn(async () => null),
        },
        personaRisk,
        gatewayStats: {
      protected_ai_requests: 12,
      intercepted_leaks: 0,
      direct_bypassed_requests: 5,
      active_ai_tunnels: 1,
      uptime_seconds: 120,
      last_protected_host: "api.anthropic.com",
      recent_events: [],
    },
        state: null,
        routeUnavailableBanner: null,
        onPushRoute: vi.fn(),
        onDismissRouteUnavailable: vi.fn(),
        onRefreshRoutes: vi.fn(async () => {}),
        onRefreshState: vi.fn(async () => {}),
        onAuditRefresh: vi.fn(),
        version: "3.0.0",
      }),
    );

    expect(html).toContain("Нейросети и защита");
    expect(html).toContain("Чистая комната");
    expect(html).toContain("Аккаунты, Бункер и SOS");
    expect(html).toContain("VPN и ключи");
    expect(html).toContain("Проверки и гайды");
    expect(html).toContain("Риск: Высокий");
    expect(html).toContain("Остановить сеть");
  });

  it("maps mascot and persona pill states accurately", () => {
    expect(resolveMascotState({ sysproxyActive: true, killswitchFrozen: false, overallStatus: "green" })).toBe("protected");
    expect(resolveMascotState({ sysproxyActive: false, killswitchFrozen: false })).toBe("sleep");
    expect(resolveMascotState({ sysproxyActive: true, killswitchFrozen: true })).toBe("alert");
    expect(resolvePersonaPill(10)).toEqual({ label: "Риск: Низкий", tone: "ok" });
    expect(resolvePersonaPill(35)).toEqual({ label: "Риск: Средний", tone: "warn" });
    expect(resolvePersonaPill(70)).toEqual({ label: "Риск: Высокий", tone: "danger" });
  });

  it("excludes subscription, rescan, syncTimezone from HeaderBar menu and preserves CopyErrorLogButton", () => {
    const filtered = menuWithout([
      { id: "subscription", label: "Sub", onSelect: vi.fn() },
      { id: "rescan", label: "Rescan", onSelect: vi.fn() },
      { id: "timezone", label: "TZ", onSelect: vi.fn() },
      { id: "settings", label: "Settings", onSelect: vi.fn() },
    ]);
    expect(filtered.map((m) => m.id)).toEqual(["settings"]);

    const headerHtml = renderToStaticMarkup(
      createElement(HeaderBar, {
        pingMs: 42,
        refreshing: false,
        onRescan: vi.fn(),
        hideIpMode: false,
        onToggleHideIp: vi.fn(),
        updateInfo: null,
        onOpenUpdate: vi.fn(),
        menuItems: [],
      }),
    );
    expect(headerHtml).toContain("42 мс");

    const notesHtml = renderToStaticMarkup(
      createElement(NotificationStack, {
        toasts: [{ id: "1", tone: "danger", title: "Ошибка", description: "Детали ошибки" }],
        onDismiss: vi.fn(),
      }),
    );
    expect(notesHtml).toContain("Ошибка");
  });

  it("renders SectionList with 5 rows", () => {
    const html = renderToStaticMarkup(
      createElement(SectionList, {
        overview: makeBaseOverview(),
        view: makeBaseView(),
        state: null,
        personaRisk: null,
        onPushRoute: vi.fn(),
      }),
    );
    expect(html.match(/<li class="zs-row/g)?.length).toBe(5);
  });
});

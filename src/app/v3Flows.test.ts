import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AppStateData, PersonaRiskFixTarget, RiskReport } from "../types";
import {
  coverage as coverageCopy,
  onboarding as onboardingCopy,
  overview as overviewCopy,
  settings as settingsCopy,
  subscription as subscriptionCopy,
  toast as toastCopy,
} from "../shared/copy/ru";
import { bunkerCopy } from "../shared/copy/ru/bunker";
import { handleSysproxyAdminAuthRequired } from "../shared/hooks/useTrayEvents";
import { mockGetPersonaRiskReport } from "../utils/api/mocks/sos";
import { routePersonaFixTarget } from "./AppShell";
import { completeAndRefreshOnboarding } from "./AppShellDialogs";
import { DeepLinkModal } from "./DeepLinkModal";

const openerMock = vi.hoisted(() => ({
  openExternal: vi.fn(async () => {}),
  openTelegramSupport: vi.fn(async () => {}),
  openZastavaBot: vi.fn(async () => {}),
}));

vi.mock("../utils/opener", () => openerMock);

vi.mock("../ui/Modal", () => ({
  Modal: ({ open, title, children, footer }: { open: boolean; title: string; children?: unknown; footer?: unknown }) =>
    open ? createElement("div", { "data-modal": title }, children as never, footer as never) : null,
}));

import { BackupScreen } from "../features/backup/BackupScreen";
import { WebExportHelper } from "../features/bunker/WebExportHelper";
import { ChecksScreen } from "../features/checks/ChecksScreen";
import { CleanRoomScreen } from "../features/clean-room/CleanRoomScreen";
import { ConnectScreen } from "../features/connect/ConnectScreen";
import { SettingsModal } from "../features/settings/SettingsModal";
import { AlertStrip } from "../features/shell-v3/AlertStrip";
import { ServicesPage } from "../features/shell-v3/ServicesPage";
import type { OverviewView } from "../features/shell-v3/types";
import type { OverviewScreenProps } from "../features/overview/OverviewScreen";
import type { ClaudeBackup } from "../shared/hooks";

function makeBaseState(over: Partial<AppStateData> = {}): AppStateData {
  return {
    pinned_ip: null,
    strict_pinning_enabled: true,
    ip_history: {},
    session_allowed_providers: [],
    blocked_providers: [],
    dismissed_hints: [],
    ...over,
  };
}

function makeBaseOverview(over: Partial<OverviewScreenProps> = {}): OverviewScreenProps {
  return {
    reports: {},
    activeReport: null,
    state: makeBaseState(),
    refreshing: false,
    auditError: null,
    startupPending: false,
    partial: null,
    currentIp: "185.212.102.40",
    trustScore: 95,
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
    ...over,
  };
}

function makeBaseView(): OverviewView {
  return {
    loading: false,
    failed: false,
    progress: { done: 14, total: 14 },
    model: {
      verdict: "Вы защищены",
      tone: "ok",
      checksPassed: 14,
      checksTotal: 14,
      checksUnknown: 0,
      checksLabel: "14 из 14",
      pinState: "none",
      providerName: "Datacenter",
      banner: null,
      services: [
        { id: "anthropic", status: "ok" },
        { id: "openai", status: "ok" },
        { id: "gemini", status: "ok" },
      ],
    },
  };
}

function makeMockBackup(claudeSummary: ClaudeBackup["claudeSummary"] = null): ClaudeBackup {
  return {
    claudeSummary,
    loadingClaudeSummary: false,
    claudeExporting: false,
    claudeExportResult: null,
    copiedPrompt: false,
    cleaningClaude: false,
    cleaningGpt: false,
    loadClaudeSummary: vi.fn(),
    handleExportClaude: vi.fn(async () => {}),
    handleCopyRestorePrompt: vi.fn(async () => {}),
    handleCleanSpecificClientCache: vi.fn(async () => {}),
  };
}

const RUST_FIX_TARGETS: PersonaRiskFixTarget[] = [
  "open_clean_room",
  "open_bunker",
  "pin_ip",
  "switch_route",
  "sync_os_tz",
  "clean_cache",
];

describe("v3 Flows: P0/P1/P2 fixes & contract verification", () => {
  beforeEach(() => {
    openerMock.openExternal.mockClear();
  });

  it("P0 #1: routePersonaFixTarget maps all 6 Rust fix_target strings to real actions (zero no-ops)", () => {
    const actions = {
      currentIp: "185.212.102.40",
      openCleanRoom: vi.fn(),
      openConnect: vi.fn(),
      openChecks: vi.fn(),
      pinIp: vi.fn(),
      openTimezone: vi.fn(),
      scrollToElement: vi.fn(),
    };

    for (const target of RUST_FIX_TARGETS) {
      routePersonaFixTarget(target, actions);
      expect(bunkerCopy.personaRisk.fixButtonLabels[target]).toBeTruthy();
    }

    expect(actions.openCleanRoom).toHaveBeenCalledTimes(1);
    expect(actions.openConnect).toHaveBeenCalledTimes(1);
    expect(actions.pinIp).toHaveBeenCalledWith("185.212.102.40");
    expect(actions.openTimezone).toHaveBeenCalledTimes(1);
    expect(actions.scrollToElement).toHaveBeenCalledWith("claude-cache-section", "claude-profiles-section");
    expect(actions.scrollToElement).toHaveBeenCalledWith("bunker-section");

    // Fallback when IP is unknown ("--"): pin_ip opens checks screen
    routePersonaFixTarget("pin_ip", { ...actions, currentIp: "--" });
    expect(actions.openChecks).toHaveBeenCalledTimes(1);

    // Mock sos report only emits targets from the 6-value Rust contract
    const mockReport = mockGetPersonaRiskReport();
    for (const f of mockReport.factors) {
      if (f.fix_target) {
        expect(RUST_FIX_TARGETS).toContain(f.fix_target);
      }
    }
  });

  it("P1 #4: WebExportHelper renders both external export URLs without bare navigation regression", () => {
    const html = renderToStaticMarkup(createElement(WebExportHelper, { onToast: vi.fn() }));
    expect(html).toContain(bunkerCopy.webExport.claudeExportUrl);
    expect(html).toContain(bunkerCopy.webExport.chatgptExportUrl);
    expect(html).toContain(bunkerCopy.webExport.openClaudeExport);
    expect(html).toContain(bunkerCopy.webExport.openChatgptExport);
  });

  it("P1 #6: AlertStrip has no nested interactive div[role=button] around CooldownBanner and keeps clear separate from navigation", () => {
    const onPushRoute = vi.fn();
    const html = renderToStaticMarkup(
      createElement(AlertStrip, {
        view: makeBaseView(),
        overview: makeBaseOverview(),
        coworkGuard: {
          status: null,
          needsRepair: false,
          repairing: false,
          error: null,
          repair: vi.fn(async () => null),
          refresh: vi.fn(async () => null),
        },
        ipChangeCooldownUntil: Math.floor(Date.now() / 1000) + 3600,
        routeUnavailableBanner: null,
        onPushRoute,
        onDismissRouteUnavailable: vi.fn(),
        onRefreshRoutes: vi.fn(async () => {}),
        onRefreshState: vi.fn(async () => {}),
        onAuditRefresh: vi.fn(),
      }),
    );

    expect(html).not.toContain('role="button"');
    expect(html).toContain(overviewCopy.banner.cooldown.title);
    expect(html).toContain(overviewCopy.banner.cooldown.clear);
    expect(html).toContain("Открыть профили и SOS");
  });

  it("P1 #9: completeAndRefreshOnboarding awaits onboarding persistence before calling refreshState", async () => {
    const events: string[] = [];
    let resolvePersist!: () => void;
    const finish = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          events.push("finish:start");
          resolvePersist = () => {
            events.push("finish:done");
            resolve();
          };
        }),
    );
    const refreshState = vi.fn(async () => {
      events.push("refreshState");
    });

    const pending = completeAndRefreshOnboarding(finish, refreshState);
    expect(events).toEqual(["finish:start"]);
    expect(refreshState).not.toHaveBeenCalled();

    resolvePersist();
    await pending;
    expect(events).toEqual(["finish:start", "finish:done", "refreshState"]);
  });

  it("P1 #11: HintCard renders in all 5 Home Hub sections and respects dismissedHints; SettingsModal includes replay button", () => {
    const servicesHtml = renderToStaticMarkup(
      createElement(ServicesPage, { overview: makeBaseOverview(), view: makeBaseView(), onDismissHint: vi.fn() }),
    );
    expect(servicesHtml).toContain('data-hint-id="services_intro"');

    const backupHtml = renderToStaticMarkup(
      createElement(BackupScreen, {
        backup: makeMockBackup(),
        currentIp: "185.212.102.40",
        currentCountry: "NL",
        onProfileSwitched: vi.fn(async () => {}),
        onToast: vi.fn(),
      }),
    );
    expect(backupHtml).toContain('data-hint-id="backup_intro"');
    expect(backupHtml).toContain('id="bunker-section"');
    expect(backupHtml).toContain('id="claude-cache-section"');

    const connectHtml = renderToStaticMarkup(
      createElement(ConnectScreen, {
        state: makeBaseState(),
        currentIp: "185.212.102.40",
        currentCountry: "NL",
        onRefreshState: vi.fn(async () => {}),
        onOpenGuide: vi.fn(),
        onToast: vi.fn(),
      }),
    );
    expect(connectHtml).toContain('data-hint-id="connect_intro"');

    const checksHtml = renderToStaticMarkup(
      createElement(ChecksScreen, {
        report: null as unknown as RiskReport,
        state: makeBaseState(),
        onNavigateToGuide: vi.fn(),
        onSimulate: vi.fn(),
        onPinCurrentIp: vi.fn(),
        onSyncTimezone: vi.fn(),
        onOpenCrashTest: vi.fn(),
      }),
    );
    expect(checksHtml).toContain('data-hint-id="checks_intro"');

    const cleanRoomHtml = renderToStaticMarkup(
      createElement(CleanRoomScreen, { state: makeBaseState() }),
    );
    expect(cleanRoomHtml).toContain('data-hint-id="clean_room_intro"');

    // Dismissed hints suppress HintCard across sections
    const dismissedState = makeBaseState({
      dismissed_hints: ["services_intro", "backup_intro", "connect_intro", "checks_intro", "clean_room_intro"],
    });
    expect(
      renderToStaticMarkup(
        createElement(ServicesPage, {
          overview: makeBaseOverview({ state: dismissedState }),
          view: makeBaseView(),
        }),
      ),
    ).not.toContain('data-hint-id="services_intro"');
    expect(
      renderToStaticMarkup(
        createElement(ConnectScreen, {
          state: dismissedState,
          currentIp: "185.212.102.40",
          currentCountry: "NL",
          onRefreshState: vi.fn(async () => {}),
          onOpenGuide: vi.fn(),
          onToast: vi.fn(),
        }),
      ),
    ).not.toContain('data-hint-id="connect_intro"');

    // SettingsModal renders «Пройти знакомство заново» next to «Показать все подсказки снова»
    const settingsHtml = renderToStaticMarkup(
      createElement(SettingsModal, {
        open: true,
        onClose: vi.fn(),
        autoUpdateEnabled: true,
        onToggleAutoUpdate: vi.fn(async () => {}),
        onReplayOnboarding: vi.fn(),
      }),
    );
    expect(settingsHtml).toContain("Показать все подсказки снова");
    expect(settingsHtml).toContain("Пройти знакомство заново");
  });

  it("P1 #12 & P2 #13: zero stale legacy tab names in toasts, useTrayEvents, onboarding, settings, overview, coverage, subscription", () => {
    const showToast = vi.fn();
    handleSysproxyAdminAuthRequired({ showToast }, "ADMIN_AUTH_REQUIRED:Нужен пароль");
    expect(showToast.mock.calls[0][1]).toContain("Нейросети и защита");
    expect(showToast.mock.calls[0][1]).not.toContain("Обзор");

    const bundles = [
      JSON.stringify(toastCopy),
      JSON.stringify(onboardingCopy),
      JSON.stringify(settingsCopy),
      JSON.stringify(overviewCopy),
      JSON.stringify(coverageCopy),
      JSON.stringify(subscriptionCopy),
    ].join("\n");

    expect(bundles).not.toContain("«Обзор»");
    expect(bundles).not.toContain("вкладке «Обзор»");
    expect(bundles).not.toContain("вкладке «Проверки»");
    expect(bundles).not.toContain("Сеть и проверки");
  });

  it("hideIpMode=true маскирует exit_ip и entrySummary в DeepLinkModal", () => {
    const payload = {
      label: "DE · Key",
      country: "DE",
      exit_ip: "185.212.102.40",
      entry: [{ proto: "https", host: "45.32.11.22", port: 443 }],
    };
    const bytes = new TextEncoder().encode(JSON.stringify(payload));
    const encoded = btoa(String.fromCharCode(...bytes))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const html = renderToStaticMarkup(
      createElement(DeepLinkModal, {
        deepLinkKey: `zastava://${encoded}`,
        hideIpMode: true,
        onClose: vi.fn(),
        onConfirm: vi.fn(),
      }),
    );

    expect(html).not.toContain("185.212.102.40");
    expect(html).not.toContain("45.32.11.22");
    expect(html).toContain("•••.•••.•••.40");
    expect(html).toContain("•••.•••.•••.22");
  });
});

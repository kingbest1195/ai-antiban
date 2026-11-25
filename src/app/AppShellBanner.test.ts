import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { CheckResult, RiskInterceptPayload, RiskReport } from "../types";

const mockIntercept = vi.hoisted(() => ({
  payload: null as RiskInterceptPayload | null,
}));

vi.mock("../utils/api/client", () => ({
  isTauri: () => true,
}));

vi.mock("../shared/hooks", () => ({
  useNavigation: () => ({
    currentRoute: { page: "home" },
    navStack: [{ page: "home" }],
    checksProvider: undefined,
    guideTarget: undefined,
    guideNavKey: 0,
    cleanRoomNavKey: 0,
    sosNavKey: 0,
    push: vi.fn(),
    pop: vi.fn(),
    reset: vi.fn(),
    goHome: vi.fn(),
    goTab: vi.fn(),
    openGuide: vi.fn(),
    openSubscription: vi.fn(),
  }),
  useToasts: () => ({ toasts: [], showToast: vi.fn(), dismissToast: vi.fn() }),
  useGatewayStats: () => ({ gatewayStats: null, refreshGatewayStats: vi.fn() }),
  useGatewayState: () => ({
    reports: {},
    activeReport: null,
    checksReport: null,
    state: null,
    refreshing: false,
    auditError: null,
    startupPending: false,
    partialAudit: null,
    currentIp: "--",
    currentCountry: "--",
    trustScore: 100,
    coverageSnapshot: null,
    routesSnapshot: null,
    dataAgeMinutes: null,
    sysproxyActive: true,
    setSysproxyActive: vi.fn(),
    autoUpdateEnabled: true,
    setAutoUpdateEnabled: vi.fn(),
    scanLatencyMs: null,
    runFullAudit: vi.fn(),
    runProviderAudit: vi.fn(),
    refreshState: vi.fn(async () => {}),
    refreshRoutes: vi.fn(async () => {}),
    guardPauseStatus: null,
    invalidateReports: vi.fn(),
  }),
  useProtectionToggles: () => ({
    cliProtected: true,
    killswitchFrozen: false,
    setKillswitchFrozen: vi.fn(),
    togglingSysproxy: false,
    handleToggleSysproxy: vi.fn(),
    handleToggleCliProtection: vi.fn(),
    handleToggleKillswitch: vi.fn(),
    syncProtectionStatus: vi.fn(),
    protection: undefined,
  }),
  usePinning: () => ({
    handleCopyIp: vi.fn(),
    handlePinIp: vi.fn(),
    handleUnpinIp: vi.fn(),
    handleToggleStrict: vi.fn(),
    handleAllowProvider: vi.fn(),
    handleUnblockProvider: vi.fn(),
    handleVerifyAndUnblockProvider: vi.fn(),
  }),
  useTimezoneSync: () => ({
    handleSyncTz: vi.fn(),
    syncingTz: false,
    tzSyncedNotice: false,
    osTzStatus: null,
    osTzLoading: false,
    osTzError: null,
    syncOsTimezone: vi.fn(),
    restoreOsTimezone: vi.fn(),
    openOsClock: vi.fn(),
  }),
  useUpdater: () => ({
    updateInfo: null,
    checkingUpdate: false,
    showUpdateModal: false,
    setShowUpdateModal: vi.fn(),
    installingUpdate: false,
    updateProgress: null,
    updaterStatus: null,
    rollbackReleases: [],
    rollbackLoading: false,
    rollbackLoaded: false,
    rollbackError: null,
    rollingBackVersion: null,
    handleCheckUpdates: vi.fn(),
    handleInstallUpdate: vi.fn(),
    handleToggleAutoUpdate: vi.fn(),
    handleLoadRollbackVersions: vi.fn(),
    handleInstallRollback: vi.fn(),
    applyUpdateProgress: vi.fn(),
    applyUpdateAvailable: vi.fn(),
    applyUpdateStatus: vi.fn(),
  }),
  useInterception: () => ({
    interceptPayload: mockIntercept.payload,
    setInterceptPayload: vi.fn(),
    allowError: null,
    handleAllowInterception: vi.fn(),
    handlePauseUntilNetworkChange: vi.fn(),
    handleSimulate: vi.fn(),
  }),
  useClaudeBackup: () => ({
    claudeSummary: null,
    loadClaudeSummary: vi.fn(),
    handleExportClaude: vi.fn(),
  }),
  useMockScenario: () => ({ scenario: "clean", handleSwitchScenario: vi.fn() }),
  useTrayEvents: vi.fn(),
}));

vi.mock("../shared/hooks/useCoworkGuardWatcher", () => ({
  useCoworkGuardWatcher: () => ({
    status: null,
    needsRepair: false,
    repairing: false,
    error: null,
    repair: vi.fn(),
    refresh: vi.fn(),
  }),
}));

vi.mock("../features/onboarding", async () => {
  const actual = await vi.importActual<typeof import("../features/onboarding")>("../features/onboarding");
  return {
    ...actual,
    useOnboarding: () => ({
      open: false,
      run: 0,
      initialStep: 0,
      start: vi.fn(),
      finish: vi.fn(),
    }),
  };
});

vi.mock("./AppShellDialogs", () => ({
  AppShellDialogs: () => null,
}));

import { shell as shellCopy } from "../shared/copy/ru";
import { AppShell } from "./AppShell";

const okCheck: CheckResult = { status: "ok", code: "OK", message: "ok" };

function makeReport(ip: string, country_code: string): RiskReport {
  return {
    provider: "anthropic",
    overall_status: "yellow",
    trust_score: 75,
    telemetry: { ip, country_code, resolved_at: 1 },
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

describe("AppShell intercept banner (§2)", () => {
  beforeEach(() => {
    mockIntercept.payload = null;
  });

  it("shows localized detecting status instead of 'Адрес — · —.' during phase=detecting with missing IP", () => {
    mockIntercept.payload = {
      id: "alert-1",
      provider: "anthropic",
      host: "claude.ai",
      report: null,
      ttl_seconds: 90,
      scope: "network",
      detected_at_ms: 1,
      phase: "detecting",
    };

    const html = renderToStaticMarkup(createElement(AppShell));
    expect(html).toContain(shellCopy.intercept.detectingIpText);
    expect(html).not.toContain("Адрес —");
    expect(html).not.toContain("— · —");
  });

  it("shows localized detecting status when report IP is missing or '--' even outside detecting", () => {
    mockIntercept.payload = {
      id: "alert-2",
      provider: "anthropic",
      host: "claude.ai",
      report: makeReport("--", "--"),
      ttl_seconds: 90,
      scope: "network",
      detected_at_ms: 1,
      phase: "ready",
    };

    const html = renderToStaticMarkup(createElement(AppShell));
    expect(html).toContain(shellCopy.intercept.detectingIpText);
    expect(html).not.toContain("Адрес —");
  });

  it("renders resolved IP and country cleanly when phase=ready and telemetry.ip is present", () => {
    mockIntercept.payload = {
      id: "alert-3",
      provider: "anthropic",
      host: "claude.ai",
      report: makeReport("185.212.102.40", "NL"),
      ttl_seconds: 90,
      scope: "network",
      detected_at_ms: 1,
      phase: "ready",
    };

    const html = renderToStaticMarkup(createElement(AppShell));
    expect(html).toContain("Адрес 185.212.102.40 · Нидерланды (NL).");
    expect(html).not.toContain(shellCopy.intercept.detectingIpText);
  });
});

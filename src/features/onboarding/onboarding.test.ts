import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CheckResult, RiskReport } from "../../types";
import { onboarding as copy } from "../../shared/copy/ru";

const tauriMock = vi.hoisted(() => ({
  isTauri: vi.fn(() => false),
  invoke: vi.fn(async () => false as unknown),
}));

vi.mock("@tauri-apps/api/core", () => ({
  isTauri: tauriMock.isTauri,
  invoke: tauriMock.invoke,
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async () => () => {}),
}));

import {
  ONBOARDING_DONE_KEY,
  ONBOARDING_STEPS,
  persistOnboardingDone,
  readDoneFromStorage,
  readOnboardingDone,
  useOnboarding,
  writeDoneToStorage,
} from "./useOnboarding";
import { evaluateNetwork } from "./networkVerdict";
import { OnboardingFlow } from "./OnboardingFlow";
import { StepWelcome } from "./StepWelcome";
import { StepNetwork } from "./StepNetwork";
import { StepProtect } from "./StepProtect";
import { StepAlert } from "./StepAlert";
import { StepDone } from "./StepDone";

function makeMemoryStorage(): Storage {
  const store = new Map<string, string>();
  return {
    get length() {
      return store.size;
    },
    clear: () => store.clear(),
    getItem: (k: string) => (store.has(k) ? store.get(k)! : null),
    key: (i: number) => Array.from(store.keys())[i] ?? null,
    removeItem: (k: string) => {
      store.delete(k);
    },
    setItem: (k: string, v: string) => {
      store.set(k, String(v));
    },
  };
}

function installMockWindow(search = "", hash = "") {
  const localStorage = makeMemoryStorage();
  const mockWin = {
    localStorage,
    location: { search, hash },
    addEventListener: () => {},
    removeEventListener: () => {},
    requestAnimationFrame: () => 0,
    cancelAnimationFrame: () => {},
  };
  Object.defineProperty(globalThis, "window", { value: mockWin, configurable: true, writable: true });
  return { localStorage, mockWin };
}

const ok = (code = "OK"): CheckResult => ({ status: "ok", code, message: "ok" });
const warn = (code: string): CheckResult => ({ status: "warning", code, message: "warn" });
const crit = (code: string): CheckResult => ({ status: "critical", code, message: "crit" });
const unk = (code: string): CheckResult => ({ status: "unknown", code, message: "unknown", reason: "timeout" });

function makeReport(over: Partial<RiskReport> = {}): RiskReport {
  const checks = [
    ok("GEO_OK"),
    ok("PINNED_BY_ZASTAVA_KEY"),
    ok("TRAVEL_OK"),
    ok("DNSBL_CLEAN"),
    ok("ASN_CLEAN"),
    ok("IPV6_KEY_TCP_ISOLATED"),
    ok("DNS_TUN_FAKE_IP_SAFE"),
    ok("TIMEZONE_SYNCED_AI"),
    ok("WIFI_OK"),
    ok("REVERSE_DNS_CLEAN"),
    ok("DNS_COUNTRY_CONSISTENT"),
    ok("LOCALE_OK"),
    ok("UDP_KEY_TCP_PROTECTED"),
    ok("CLAUDE_EXIT_OK"),
  ];
  return {
    provider: "anthropic",
    overall_status: "green",
    trust_score: 96,
    telemetry: {
      ip: "136.244.114.42",
      country_code: "FR",
      resolved_at: Math.floor(Date.now() / 1000),
    },
    geo_result: checks[0],
    pinning_result: checks[1],
    travel_result: checks[2],
    dnsbl_result: checks[3],
    dnsbl_clean_count: "5/5",
    asn_result: checks[4],
    ipv6_result: checks[5],
    timezone_result: checks[7],
    checks,
    unknown_count: 0,
    applicable_count: 14,
    incomplete: false,
    ...over,
  };
}

describe("useOnboarding & Tauri persistence (v2.2)", () => {
  const originalWindow = globalThis.window;

  beforeEach(() => {
    tauriMock.isTauri.mockReset();
    tauriMock.isTauri.mockReturnValue(false);
    tauriMock.invoke.mockReset();
    tauriMock.invoke.mockResolvedValue(false);
    installMockWindow();
  });

  afterEach(() => {
    if (originalWindow === undefined) {
      delete (globalThis as { window?: unknown }).window;
    } else {
      Object.defineProperty(globalThis, "window", { value: originalWindow, configurable: true, writable: true });
    }
  });

  it("uses v2.2 storage key and syncs localStorage in non-Tauri mode", async () => {
    expect(ONBOARDING_DONE_KEY).toBe("zastava_onboarding_v2_2_done");
    expect(readDoneFromStorage()).toBe(false);
    expect(await readOnboardingDone()).toBe(false);

    await persistOnboardingDone(true);
    expect(readDoneFromStorage()).toBe(true);
    expect(window.localStorage.getItem(ONBOARDING_DONE_KEY)).toBe("1");
    expect(tauriMock.invoke).not.toHaveBeenCalled();

    writeDoneToStorage(false);
    expect(readDoneFromStorage()).toBe(false);
  });

  it("reads and persists state via Tauri commands and syncs localStorage cache", async () => {
    tauriMock.isTauri.mockReturnValue(true);
    tauriMock.invoke.mockResolvedValueOnce(true);

    const done = await readOnboardingDone();
    expect(done).toBe(true);
    expect(tauriMock.invoke).toHaveBeenCalledWith("get_onboarding_v2_2_done");
    expect(readDoneFromStorage()).toBe(true);

    tauriMock.invoke.mockResolvedValueOnce(false);
    const notDone = await readOnboardingDone();
    expect(notDone).toBe(false);
    expect(readDoneFromStorage()).toBe(false);

    tauriMock.invoke.mockResolvedValueOnce(undefined);
    await persistOnboardingDone(true);
    expect(tauriMock.invoke).toHaveBeenCalledWith("set_onboarding_v2_2_done", { done: true });
    expect(readDoneFromStorage()).toBe(true);
  });

  it("falls back to localStorage cleanly if Tauri invoke rejects", async () => {
    tauriMock.isTauri.mockReturnValue(true);
    writeDoneToStorage(true);
    tauriMock.invoke.mockRejectedValueOnce(new Error("ipc unavailable"));

    expect(await readOnboardingDone()).toBe(true);

    tauriMock.invoke.mockRejectedValueOnce(new Error("write failed"));
    await expect(persistOnboardingDone(true)).resolves.toBeUndefined();
    expect(readDoneFromStorage()).toBe(true);
  });

  it("useOnboarding honors localStorage, ?onboarding=0/1, and alert-popup window", () => {
    const capture = (search = "") => {
      installMockWindow(search);
      let state!: ReturnType<typeof useOnboarding>;
      const Probe = () => {
        state = useOnboarding();
        return null;
      };
      renderToStaticMarkup(createElement(Probe));
      return state;
    };

    expect(capture().open).toBe(true);

    installMockWindow("");
    writeDoneToStorage(true);
    let doneState!: ReturnType<typeof useOnboarding>;
    renderToStaticMarkup(
      createElement(() => {
        doneState = useOnboarding();
        return null;
      }),
    );
    expect(doneState.open).toBe(false);

    expect(capture("?onboarding=1").open).toBe(true);
    expect(capture("?onboarding=0").open).toBe(false);
    expect(capture("?window=alert-popup").open).toBe(false);
  });
});

describe("networkVerdict (v2.2 checks & country format)", () => {
  it("treats v2.2 key-protected and AI-TZ-synced checks as green with formatted country", () => {
    const report = makeReport();
    const v = evaluateNetwork({ anthropic: report, openai: report, gemini: report }, report);
    expect(v.good).toBe(true);
    expect(v.verdict).toBe("ok");
    expect(v.tone).toBe("ok");
    expect(v.passed).toBe(14);
    expect(v.total).toBe(14);
    expect(v.country).toBe("Франция (FR)");
  });

  it("returns partial when only unknown checks exist and no warnings/criticals", () => {
    const checks = makeReport().checks.slice(0, 13).concat([unk("CLAUDE_EXIT_TIMEOUT")]);
    const report = makeReport({ overall_status: "yellow", checks, unknown_count: 1 });
    const v = evaluateNetwork({ anthropic: report }, report);
    expect(v.good).toBe(true);
    expect(v.verdict).toBe("partial");
    expect(v.tone).toBe("warn");
  });

  it("classifies RU geo, leaks (including UDP_STUN_MISMATCH), and timezone mismatch", () => {
    const ruReport = makeReport({
      overall_status: "red",
      telemetry: { ip: "1.2.3.4", country_code: "RU", resolved_at: 1 },
      geo_result: crit("GEO_HIGH_RISK_RU"),
      checks: [crit("GEO_HIGH_RISK_RU"), ...makeReport().checks.slice(1)],
    });
    expect(evaluateNetwork({ anthropic: ruReport }, ruReport).reason).toBe("noVpn");

    const udpLeak = makeReport({
      overall_status: "yellow",
      checks: [...makeReport().checks.slice(0, 12), warn("UDP_STUN_MISMATCH"), ok("CLAUDE_EXIT_OK")],
    });
    expect(evaluateNetwork({ gemini: udpLeak }, udpLeak).reason).toBe("leak");

    const tzWarn = makeReport({
      overall_status: "yellow",
      timezone_result: warn("TIMEZONE_MISMATCH"),
      checks: [...makeReport().checks.slice(0, 7), warn("TIMEZONE_MISMATCH"), ...makeReport().checks.slice(8)],
    });
    expect(evaluateNetwork({ anthropic: tzWarn }, tzWarn).reason).toBe("timezone");
  });
});

describe("Onboarding v2.2 steps & OnboardingFlow", () => {
  const originalWindow = globalThis.window;

  beforeEach(() => {
    tauriMock.isTauri.mockReturnValue(false);
    installMockWindow();
  });

  afterEach(() => {
    if (originalWindow === undefined) {
      delete (globalThis as { window?: unknown }).window;
    } else {
      Object.defineProperty(globalThis, "window", { value: originalWindow, configurable: true, writable: true });
    }
  });

  const baseFlowProps = {
    reports: { anthropic: makeReport() },
    activeReport: makeReport(),
    refreshing: false,
    auditError: null,
    currentIp: "136.244.114.42",
    trustScore: 96,
    sysproxyActive: true,
    cliProtected: true,
    onToggleSysproxy: () => {},
    onToggleCli: () => {},
    onRecheck: () => {},
    onClose: () => {},
  };

  it("StepWelcome introduces VPN + zastava:// keys and 14 prioritized checks", () => {
    const html = renderToStaticMarkup(createElement(StepWelcome, { onNext: () => {} }));
    expect(html).toContain("zastava://");
    expect(html).toContain("14");
    expect(html).toContain("Claude");
    expect(html).toContain("ChatGPT");
    expect(html).toContain("Gemini");
    expect(html).toContain(copy.welcome.next);
  });

  it("StepNetwork shows live verdict with country code and explains Маршруты по сервисам ИИ", () => {
    const html = renderToStaticMarkup(
      createElement(StepNetwork, {
        reports: { anthropic: makeReport() },
        activeReport: makeReport(),
        refreshing: false,
        auditError: null,
        currentIp: "136.244.114.42",
        trustScore: 96,
        onRecheck: () => {},
        onNext: () => {},
        onBack: () => {},
        onOpenConnect: () => {},
      }),
    );
    expect(html).toContain("136.244.114.42");
    expect(html).toContain("Франция (FR)");
    expect(html).toContain("14 из 14");
    expect(html).toContain("Маршруты по сервисам ИИ");
    expect(html).toContain("zastava://");
    expect(html).toContain("Gemini");
  });

  it("StepProtect explains the 3 v2.2 protection layers and reflects toggle state", () => {
    const htmlBoth = renderToStaticMarkup(
      createElement(StepProtect, {
        sysproxyActive: true,
        cliProtected: true,
        onToggleSysproxy: () => {},
        onToggleCli: () => {},
        onNext: () => {},
        onBack: () => {},
      }),
    );
    expect(htmlBoth).toContain("Браузеры");
    expect(htmlBoth).toContain("PAC");
    expect(htmlBoth).toContain("QUIC/DoH");
    expect(htmlBoth).toContain("V2Box Pro");
    expect(htmlBoth).toContain("Приложения, CLI и IDE");
    expect(htmlBoth).toContain("ai_only");
    expect(htmlBoth).toContain("npm");
    expect(htmlBoth).toContain("Часовой пояс для ИИ");
    expect(htmlBoth).toContain("Синхронизировать для ИИ");
    expect(htmlBoth).toContain(copy.protect.state.both);

    const htmlNone = renderToStaticMarkup(
      createElement(StepProtect, {
        sysproxyActive: false,
        cliProtected: false,
        onToggleSysproxy: () => {},
        onToggleCli: () => {},
        onNext: () => {},
        onBack: () => {},
      }),
    );
    expect(htmlNone).toContain(copy.protect.state.none);
  });

  it("StepAlert explains gate_reason, pause until next network change, and Continue button", () => {
    const html = renderToStaticMarkup(createElement(StepAlert, { onReacted: () => {}, onBack: () => {} }));
    expect(html).toContain("gate_reason");
    expect(html).toContain("Пауза до следующей смены сети");
    expect(html).toContain(copy.alert.show);
    expect(html).toContain(copy.alert.continue);
  });

  it("StepDone mentions clean system restore on shutdown/update", () => {
    const html = renderToStaticMarkup(createElement(StepDone, { onOpenOverview: () => {} }));
    expect(html).toContain(copy.done.shutdown.title);
    expect(html).toContain(copy.done.shutdown.sub);
    expect(html).toContain(copy.done.open);
  });

  it("OnboardingFlow header uses Пропустить on steps 1..3, Продолжить on step 4, and hides it on done", () => {
    const step1 = renderToStaticMarkup(createElement(OnboardingFlow, { ...baseFlowProps, initialStep: 1 }));
    expect(step1).toContain(`Шаг 1 из ${ONBOARDING_STEPS}`);
    expect(step1).toContain(copy.skip);

    const step4 = renderToStaticMarkup(createElement(OnboardingFlow, { ...baseFlowProps, initialStep: 4 }));
    expect(step4).toContain(`Шаг 4 из ${ONBOARDING_STEPS}`);
    expect(step4).not.toContain(`>${copy.skip}<`);
    expect(step4).toContain(`>${copy.continue}<`);

    const stepDone = renderToStaticMarkup(createElement(OnboardingFlow, { ...baseFlowProps, initialStep: 5 }));
    expect(stepDone).toContain(copy.doneProgress);
    expect(stepDone).not.toContain(`>${copy.skip}<`);
    expect(stepDone).not.toContain(`>${copy.continue}<`);
  });
});

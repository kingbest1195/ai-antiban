import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CheckResult, RiskReport } from "../../types";
import { onboarding as copy } from "../../shared/copy/ru";

const tauriMock = vi.hoisted(() => ({
  isTauri: vi.fn(() => false),
  invoke: vi.fn(async () => ({}) as unknown),
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
import type { OnboardingGoal } from "./OnboardingFlow";
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

describe("useOnboarding & Tauri persistence (v3.0)", () => {
  const originalWindow = globalThis.window;

  beforeEach(() => {
    tauriMock.isTauri.mockReset();
    tauriMock.isTauri.mockReturnValue(false);
    tauriMock.invoke.mockReset();
    tauriMock.invoke.mockResolvedValue({ onboarding_v3_done: false });
    installMockWindow();
  });

  afterEach(() => {
    if (originalWindow === undefined) {
      delete (globalThis as { window?: unknown }).window;
    } else {
      Object.defineProperty(globalThis, "window", { value: originalWindow, configurable: true, writable: true });
    }
  });

  it("uses v3.0 storage key, 5 steps, and syncs localStorage in non-Tauri mode", async () => {
    expect(ONBOARDING_DONE_KEY).toBe("zastava_onboarding_v3_done");
    expect(ONBOARDING_STEPS).toBe(5);
    expect(readDoneFromStorage()).toBe(false);
    expect(await readOnboardingDone()).toBe(false);

    await persistOnboardingDone(true);
    expect(readDoneFromStorage()).toBe(true);
    expect(window.localStorage.getItem(ONBOARDING_DONE_KEY)).toBe("1");
    expect(tauriMock.invoke).not.toHaveBeenCalled();

    writeDoneToStorage(false);
    expect(readDoneFromStorage()).toBe(false);
  });

  it("reads onboarding_v3_done and persists via complete_onboarding_v3 in Tauri mode", async () => {
    tauriMock.isTauri.mockReturnValue(true);
    tauriMock.invoke.mockResolvedValueOnce({ onboarding_v3_done: true });

    const done = await readOnboardingDone();
    expect(done).toBe(true);
    expect(tauriMock.invoke).toHaveBeenCalledWith("get_state");
    expect(readDoneFromStorage()).toBe(true);

    tauriMock.invoke.mockResolvedValueOnce({ onboarding_v3_done: false });
    const notDone = await readOnboardingDone();
    expect(notDone).toBe(false);
    expect(readDoneFromStorage()).toBe(false);

    tauriMock.invoke.mockResolvedValueOnce({ onboarding_v3_done: true });
    await persistOnboardingDone(true);
    expect(tauriMock.invoke).toHaveBeenCalledWith("complete_onboarding_v3");
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

describe("networkVerdict (v3.0 checks & country format)", () => {
  it("treats key-protected and AI-TZ-synced checks as green with formatted country", () => {
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

describe("Onboarding v3 steps & OnboardingFlow", () => {
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

  it("StepWelcome renders WatchdogMascot (protected) and 3 Quick-Pick Goal cards", () => {
    const html = renderToStaticMarkup(
      createElement(StepWelcome, { goal: "clean_room", onSelectGoal: () => {}, onNext: () => {} }),
    );
    expect(html).toContain('data-mascot-state="protected"');
    expect(html).toContain("Защитить текущий аккаунт");
    expect(html).toContain("Завести новый чистый аккаунт");
    expect(html).toContain("Уже пришла проверка Persona или бан");
    expect(html).toContain('data-onb-goal="clean_room"');
    expect(html).toContain('aria-checked="true"');
    expect(html).toContain(copy.welcome.next);
  });

  it("StepNetwork embeds SplitRoutingAnim, live network verdict, and SmartScreenGuide", () => {
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
    expect(html).toContain("zs-anim-split");
    expect(html).toContain("136.244.114.42");
    expect(html).toContain("Франция (FR)");
    expect(html).toContain("14 из 14");
    expect(html).toContain("zs-smartguide");
  });

  it("StepProtect embeds CleanRoomRadarAnim, protection layers, and Free Local Bunker", () => {
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
    expect(htmlBoth).toContain("zs-anim-radar");
    expect(htmlBoth).toContain("Браузеры и десктопные приложения");
    expect(htmlBoth).toContain("Редакторы кода и терминал");
    expect(htmlBoth).toContain("Бесплатный локальный Бункер данных");
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

  it("StepAlert embeds KillSwitchAnim (0.04 мс) and human-readable Точная причина остановки", () => {
    const html = renderToStaticMarkup(createElement(StepAlert, { onReacted: () => {}, onBack: () => {} }));
    expect(html).toContain("zs-anim-ks");
    expect(html).toContain("0.04 мс");
    expect(html).toContain("Точная причина остановки");
    expect(html).not.toContain("gate_reason");
    expect(html).toContain(copy.alert.show);
    expect(html).toContain(copy.alert.continue);
  });

  it("StepDone renders all 4 tray indicator colors (including gray) and goal-specific CTA", () => {
    const goals: OnboardingGoal[] = ["protect", "clean_room", "sos"];
    for (const goal of goals) {
      const html = renderToStaticMarkup(createElement(StepDone, { goal, onComplete: () => {} }));
      expect(html).toContain("Зелёный");
      expect(html).toContain("Жёлтый");
      expect(html).toContain("Красный");
      expect(html).toContain("Серый");
      expect(html).toContain("zs-onb__tray-dot--gray");
      expect(html).toContain(copy.done.ctaByGoal[goal]);
    }
  });

  it("OnboardingFlow header uses Пропустить on steps 1..3, Продолжить on step 4, and doneProgress on step 5", () => {
    const step1 = renderToStaticMarkup(createElement(OnboardingFlow, { ...baseFlowProps, initialStep: 1 }));
    expect(step1).toContain("Шаг 1 из 5");
    expect(step1).toContain(copy.skip);

    const step4 = renderToStaticMarkup(createElement(OnboardingFlow, { ...baseFlowProps, initialStep: 4 }));
    expect(step4).toContain("Шаг 4 из 5");
    expect(step4).not.toContain(`>${copy.skip}<`);
    expect(step4).toContain(`>${copy.continue}<`);

    const step5 = renderToStaticMarkup(createElement(OnboardingFlow, { ...baseFlowProps, initialStep: 5 }));
    expect(step5).toContain(copy.doneProgress);
    expect(step5).not.toContain(`>${copy.skip}<`);
    expect(step5).not.toContain(`>${copy.continue}<`);
  });

  it("ru/onboarding copy is free of legacy v2.2 tabs and technical jargon", () => {
    const serialized = JSON.stringify(copy);
    for (const forbidden of [
      "2.2",
      "Обзор",
      "обзоре",
      "вкладке «Проверки»",
      "вкладке «Подключение»",
      "меню «Ещё»",
      "PAC-политик",
      "QUIC/DoH",
      "V2Box",
      "ai_only",
      "gate_reason",
    ]) {
      expect(serialized).not.toContain(forbidden);
    }
  });
});

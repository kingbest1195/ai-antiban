import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type {
  AppStateData,
  CleanRoomAuditReport,
  CleanRoomProfile,
  DetectedBrowser,
} from "../../types";
import { cleanRoom as copy } from "../../shared/copy/ru/cleanRoom";
import { overview as overviewCopy, subscription as subCopy } from "../../shared/copy/ru";
import { warmupProgress } from "../subscription/Warmup";
import {
  CleanRoomScreen,
  isCleanRoomReadyToLaunch,
  providerSignupUrl,
  resolveSandboxBlockReason,
  sortFindingsBySeverity,
} from "./index";

function makeAudit(over: Partial<CleanRoomAuditReport> = {}): CleanRoomAuditReport {
  return {
    checked_at: 1_760_000_000,
    exit_ip: "185.212.102.40",
    exit_country: "DE",
    exit_timezone: "Europe/Berlin",
    ip_is_tainted: false,
    os_tz_matches_exit: true,
    findings: [
      {
        id: "clean_ready",
        category: "browser",
        title: "Следов прошлых банов и утечек не обнаружено",
        detail: "Среда готова.",
        severity: "ok",
        path_hint: null,
        fix_action: null,
      },
    ],
    critical_count: 0,
    warning_count: 0,
    ready_to_launch: true,
    ...over,
  };
}

function makeProfile(over: Partial<CleanRoomProfile> = {}): CleanRoomProfile {
  return {
    id: "cr-1",
    label: "Claude · Новый US",
    provider: "anthropic",
    browser_engine: "chrome",
    bound_route_id: "route-us-1",
    last_exit_ip: "45.80.10.20",
    last_exit_country: "US",
    status: "active",
    created_at: 1_760_000_000,
    last_opened_at: null,
    warmup_started_at: null,
    launchpad_step: 1,
    completed_checklist: [],
    ...over,
  };
}

function makeState(over: Partial<AppStateData> = {}): AppStateData {
  return {
    pinned_ip: "185.212.102.40",
    strict_pinning_enabled: true,
    ip_history: {},
    session_allowed_providers: [],
    blocked_providers: [],
    dismissed_hints: [],
    clean_room: {
      profiles: [makeProfile()],
      active_profile_id: "cr-1",
      tainted_ips: {},
    },
    ...over,
  };
}

const AVAILABLE_BROWSERS: DetectedBrowser[] = [
  {
    engine: "chrome",
    display_name: "Google Chrome",
    executable_path: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    available: true,
  },
];

describe("Clean Room — Hard Readiness Gate", () => {
  it("разрешает запуск только при ready_to_launch && critical_count === 0 && !manualKillswitch", () => {
    expect(isCleanRoomReadyToLaunch(makeAudit(), false)).toBe(true);
    expect(isCleanRoomReadyToLaunch(makeAudit({ critical_count: 1, ready_to_launch: false }), false)).toBe(false);
    expect(isCleanRoomReadyToLaunch(makeAudit({ critical_count: 1, ready_to_launch: true }), false)).toBe(false);
    expect(isCleanRoomReadyToLaunch(makeAudit(), true)).toBe(false);
    expect(isCleanRoomReadyToLaunch(null, false)).toBe(false);
  });

  it("блокирует кнопку «Открыть песочницу» при critical_count > 0 или manualKillswitch", () => {
    const blockedAudit = makeAudit({
      critical_count: 1,
      ready_to_launch: false,
      findings: [
        {
          id: "claude_cookies",
          category: "desktop_traces",
          title: "Найдены cookies старого Claude Desktop",
          detail: "Очистите кэш перед новым аккаунтом.",
          severity: "critical",
          path_hint: "Packages/Claude_test/Cookies",
          fix_action: { kind: "clean_app_cache", provider: "anthropic" },
        },
      ],
    });

    const htmlCritical = renderToStaticMarkup(
      createElement(CleanRoomScreen, {
        state: makeState(),
        initialAudit: blockedAudit,
        initialBrowsers: AVAILABLE_BROWSERS,
      }),
    );
    expect(htmlCritical).toContain(copy.audit.gate.blockedCritical(1));
    expect(htmlCritical).toContain(copy.audit.fix.cleanCache("anthropic"));
    expect(htmlCritical).toContain(copy.sandbox.profileCard.blockedReasonAudit);
    expect(htmlCritical).toContain('aria-disabled="true"');

    const htmlKillswitch = renderToStaticMarkup(
      createElement(CleanRoomScreen, {
        state: makeState(),
        initialAudit: makeAudit(),
        initialBrowsers: AVAILABLE_BROWSERS,
        manualKillswitch: true,
      }),
    );
    expect(htmlKillswitch).toContain(copy.audit.gate.blockedKillswitch);
    expect(htmlKillswitch).toContain(copy.sandbox.profileCard.blockedReasonKillswitch);
    expect(htmlKillswitch).toContain('aria-disabled="true"');
  });

  it("разблокирует запуск при чистом аудите и выключенном Kill-Switch", () => {
    expect(resolveSandboxBlockReason(makeProfile(), true, false)).toBeNull();
    expect(resolveSandboxBlockReason(makeProfile({ status: "tainted" }), true, false)).toBe(
      copy.sandbox.profileCard.blockedReasonTainted,
    );

    const htmlReady = renderToStaticMarkup(
      createElement(CleanRoomScreen, {
        state: makeState(),
        initialAudit: makeAudit(),
        initialBrowsers: AVAILABLE_BROWSERS,
        manualKillswitch: false,
      }),
    );
    expect(htmlReady).toContain(copy.audit.gate.ready);
    expect(htmlReady).toContain(copy.sandbox.profileCard.launchBtn);
    expect(htmlReady).not.toContain(copy.sandbox.profileCard.blockedReasonAudit);
    expect(htmlReady).not.toContain(copy.sandbox.profileCard.blockedReasonKillswitch);
  });

  it("сортирует находки по критичности: critical -> warning -> ok", () => {
    const sorted = sortFindingsBySeverity([
      { id: "ok", category: "browser", title: "ok", detail: "", severity: "ok", path_hint: null, fix_action: null },
      { id: "crit", category: "network_leak", title: "crit", detail: "", severity: "critical", path_hint: null, fix_action: null },
      { id: "warn", category: "os_tz_locale", title: "warn", detail: "", severity: "warning", path_hint: null, fix_action: null },
    ]);
    expect(sorted.map((f) => f.id)).toEqual(["crit", "warn", "ok"]);
  });
});

describe("CleanRoomScreen — вкладки, CooldownBanner и EmptyState", () => {
  it("рендерит подвкладку launchpad с HintCard, радаром и явной меткой «Браузерная песочница (для веба)»", () => {
    const html = renderToStaticMarkup(
      createElement(CleanRoomScreen, {
        state: makeState(),
        initialTab: "launchpad",
        initialAudit: makeAudit(),
        initialBrowsers: AVAILABLE_BROWSERS,
      }),
    );

    expect(html).toContain('data-hint-id="clean_room_intro"');
    expect(html).toContain(copy.tabs.launchpad);
    expect(html).toContain(copy.tabs.payment);
    expect(html).toContain(copy.sandbox.title);
    expect(html).toContain("zs-anim-radar");
    expect(html).toContain(copy.launchpad.title);
  });

  it("рендерит быструю вкладку «Оплата и прогрев» напрямую с CardCheck, AddressCard (DE/OR/NH/MT/AK) и Warmup", () => {
    const startedSec = Math.floor(Date.now() / 1000) - 48 * 3600;
    const state = makeState({
      clean_room: {
        profiles: [makeProfile({ warmup_started_at: startedSec })],
        active_profile_id: "cr-1",
        tainted_ips: {},
      },
    });

    const html = renderToStaticMarkup(
      createElement(CleanRoomScreen, {
        state,
        initialTab: "payment",
        initialAudit: makeAudit({ exit_country: "US" }),
        initialBrowsers: AVAILABLE_BROWSERS,
      }),
    );

    expect(html).toContain(subCopy.card.title);
    expect(html).toContain(subCopy.card.gateway("US"));
    expect(html).toContain(subCopy.address.title);
    for (const code of ["DE", "OR", "NH", "MT", "AK"]) {
      expect(html).toContain(code);
    }
    expect(html).toContain(subCopy.warmup.title);
    expect(html).toContain("48 ч");
    expect(html).toContain(copy.launchpad.step3.disclaimer);
  });

  it("показывает CooldownBanner внутри Чистой комнаты при активном 4-часовом таймере", () => {
    const future = Math.floor(Date.now() / 1000) + 3600;
    const html = renderToStaticMarkup(
      createElement(CleanRoomScreen, {
        state: makeState({ ip_change_cooldown_until: future }),
        initialAudit: makeAudit(),
        initialBrowsers: AVAILABLE_BROWSERS,
      }),
    );

    expect(html).toContain(overviewCopy.banner.cooldown.title);
  });

  it("рендерит EmptyState с маскотом и ссылками Chrome/Edge/Brave при 0 доступных браузеров", () => {
    const html = renderToStaticMarkup(
      createElement(CleanRoomScreen, {
        state: makeState(),
        initialAudit: makeAudit(),
        initialBrowsers: [
          {
            engine: "chrome",
            display_name: "Google Chrome",
            executable_path: "",
            available: false,
          },
        ],
      }),
    );

    expect(html).toContain(copy.sandbox.noBrowsers.title);
    expect(html).toContain('data-mascot-state="sleep"');
    expect(html).toContain("Скачать Chrome");
    expect(html).toContain("Скачать Edge");
    expect(html).toContain("Скачать Brave");
  });

  it("рендерит EmptyState создания профиля, когда браузеры есть, а профилей 0", () => {
    const html = renderToStaticMarkup(
      createElement(CleanRoomScreen, {
        state: makeState({
          clean_room: { profiles: [], active_profile_id: null, tainted_ips: {} },
        }),
        initialAudit: makeAudit(),
        initialBrowsers: AVAILABLE_BROWSERS,
      }),
    );

    expect(html).toContain(copy.sandbox.emptyProfiles.title);
    expect(html).toContain(copy.sandbox.emptyProfiles.cta);
  });
});

describe("LaunchpadSteps — Шаги 2, 3 и 4", () => {
  it("на Шаге 4 показывает красный баннер против перекупщиков и кнопку гайда оплаты", () => {
    const html = renderToStaticMarkup(
      createElement(CleanRoomScreen, {
        state: makeState(),
        initialTab: "launchpad",
        initialStep: 4,
        initialAudit: makeAudit({ exit_country: "NL" }),
        initialBrowsers: AVAILABLE_BROWSERS,
        onNavigateToGuide: () => {},
      }),
    );

    expect(html).toContain("zs-banner--danger");
    expect(html).toContain(copy.launchpad.step4.resellerWarningTitle);
    expect(html).toContain("Playerok");
    expect(html).toContain("FunPay");
    expect(html).toContain("Apple Pay");
    expect(html).toContain(copy.launchpad.step4.openGuideBtn);
  });

  it("на Шаге 2 показывает чеклист почты/SIM и корректные URL провайдеров", () => {
    expect(providerSignupUrl("anthropic")).toBe("https://claude.ai");
    expect(providerSignupUrl("claude")).toBe("https://claude.ai");
    expect(providerSignupUrl("openai")).toBe("https://chatgpt.com");
    expect(providerSignupUrl("chatgpt")).toBe("https://chatgpt.com");
    expect(providerSignupUrl("gemini")).toBe("https://aistudio.google.com");

    const html = renderToStaticMarkup(
      createElement(CleanRoomScreen, {
        state: makeState(),
        initialTab: "launchpad",
        initialStep: 2,
        initialAudit: makeAudit(),
        initialBrowsers: AVAILABLE_BROWSERS,
      }),
    );

    expect(html).toContain(copy.launchpad.step2.launchBtn);
    expect(html).toContain("gmail.com");
    expect(html).toContain("VoIP/SMS-активаторы");
  });

  it("warmupProgress корректно работает и с Unix-секундами, и с миллисекундами", () => {
    const nowMs = 1_760_345_600_000;
    const startedSec = Math.floor(nowMs / 1000) - 96 * 3600;
    const startedMs = nowMs - 48 * 3600 * 1000;

    expect(warmupProgress(startedSec, nowMs)).toMatchObject({
      elapsedHours: 96,
      percent: 100,
      done: true,
    });
    expect(warmupProgress(startedMs, nowMs)).toMatchObject({
      elapsedHours: 48,
      percent: 50,
      done: false,
    });
  });
});

describe("v3.0.1 Clean Room UX: дедупликация tainted-IP, спокойная заметка браузера, hideIpMode и gating шага 1", () => {
  it("дедуплицирует exit_ip_tainted при ip_is_tainted=true, скрывает IP при hideIpMode=true и показывает спокойную справку для личного браузера", () => {
    const audit = makeAudit({
      exit_ip: "45.32.11.22",
      ip_is_tainted: true,
      critical_count: 1,
      ready_to_launch: false,
      findings: [
        {
          id: "exit_ip_tainted",
          category: "ip_collision",
          title: "Выходной IP отмечен как проблемный",
          detail: "Адрес 45.32.11.22 ранее отмечен.",
          severity: "critical",
          path_hint: null,
          fix_action: { kind: "switch_route_or_vpn" },
        },
        {
          id: "personal_browser_profiles",
          category: "browser",
          title: "На компьютере установлен обычный браузер",
          detail: "Обнаружен Chrome.",
          severity: "warning",
          path_hint: null,
          fix_action: { kind: "acknowledge_sandbox_isolation" },
        },
      ],
    });

    const html = renderToStaticMarkup(
      createElement(CleanRoomScreen, {
        state: makeState({
          clean_room: {
            profiles: [makeProfile({ last_exit_ip: "45.80.10.20" })],
            active_profile_id: "cr-1",
            tainted_ips: { "45.32.11.22": 1_760_000_000 },
          },
        }),
        hideIpMode: true,
        initialAudit: audit,
        initialBrowsers: AVAILABLE_BROWSERS,
      }),
    );

    expect(html).toContain(copy.audit.taintedBannerTitle);
    expect(html).toContain(copy.audit.untaintBtn);
    expect(html).not.toContain("cr-finding--critical");
    expect(html).toContain("cr-finding--info");
    expect(html).toContain(copy.audit.personalBrowserNote);
    expect(html).not.toContain("45.32.11.22");
    expect(html).not.toContain("45.80.10.20");
    expect(html).toContain("•••.•••.•••.22");
    expect(html).toContain("•••.•••.•••.20");
    expect(html).toContain(copy.audit.honestyNote);
  });

  it("блокирует «Перейти к шагу 2» без профиля или при провале аудита и убирает дубль «Создать профиль» в шаге 1", () => {
    const html = renderToStaticMarkup(
      createElement(CleanRoomScreen, {
        state: makeState({
          clean_room: { profiles: [], active_profile_id: null, tainted_ips: {} },
        }),
        initialAudit: makeAudit(),
        initialBrowsers: AVAILABLE_BROWSERS,
      }),
    );

    expect(html).toContain(copy.launchpad.step1.gateHint);
    expect(html).toContain(`disabled=""`);
    expect(html).not.toContain("READY · Можно запускать");
    expect(html).not.toContain("Launchpad нового аккаунта");
  });
});

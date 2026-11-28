import type { ReactElement } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type {
  AppStateData,
  CleanRoomAuditReport,
  CleanRoomProfile,
  CleanRoomState,
  DetectedBrowser,
  RouteView,
} from "../../types";
import { cleanRoom as copy } from "../../shared/copy/ru/cleanRoom";

const hookRuntime = vi.hoisted(() => {
  type HookSlot =
    | { kind: "state"; value: unknown }
    | { kind: "ref"; value: { current: unknown } }
    | { kind: "memo"; deps: unknown[] | undefined; value: unknown }
    | { kind: "effect"; deps: unknown[] | undefined; cleanup?: () => void };

  let slots: HookSlot[] = [];
  let cursor = 0;
  let pendingEffects: Array<{ slotIdx: number; fn: () => void | (() => void); deps: unknown[] | undefined }> = [];
  let currentRender: (() => void) | null = null;

  function depsChanged(prev: unknown[] | undefined, next: unknown[] | undefined): boolean {
    if (!prev || !next) return true;
    if (prev.length !== next.length) return true;
    for (let i = 0; i < prev.length; i++) {
      if (!Object.is(prev[i], next[i])) return true;
    }
    return false;
  }

  return {
    reset(renderFn: () => void) {
      for (const s of slots) if (s.kind === "effect") s.cleanup?.();
      slots = [];
      cursor = 0;
      pendingEffects = [];
      currentRender = renderFn;
    },
    beginRender() {
      cursor = 0;
    },
    flushEffects() {
      const queue = pendingEffects;
      pendingEffects = [];
      for (const item of queue) {
        const slot = slots[item.slotIdx] as Extract<HookSlot, { kind: "effect" }>;
        slot.cleanup?.();
        slot.deps = item.deps;
        const cleanup = item.fn();
        slot.cleanup = typeof cleanup === "function" ? cleanup : undefined;
      }
    },
    useState<T>(initial: T | (() => T)): [T, (next: T | ((prev: T) => T)) => void] {
      const idx = cursor++;
      if (idx >= slots.length) {
        const val = typeof initial === "function" ? (initial as () => T)() : initial;
        slots.push({ kind: "state", value: val });
      }
      const slot = slots[idx] as Extract<HookSlot, { kind: "state" }>;
      const setState = (next: T | ((prev: T) => T)) => {
        const resolved = typeof next === "function" ? (next as (prev: T) => T)(slot.value as T) : next;
        if (!Object.is(slot.value, resolved)) {
          slot.value = resolved;
          if (currentRender) {
            currentRender();
            this.flushEffects();
          }
        }
      };
      return [slot.value as T, setState];
    },
    useRef<T>(initial: T): { current: T } {
      const idx = cursor++;
      if (idx >= slots.length) slots.push({ kind: "ref", value: { current: initial } });
      return (slots[idx] as Extract<HookSlot, { kind: "ref" }>).value as { current: T };
    },
    useMemo<T>(factory: () => T, deps: unknown[]): T {
      const idx = cursor++;
      if (idx >= slots.length) {
        const value = factory();
        slots.push({ kind: "memo", deps, value });
        return value;
      }
      const slot = slots[idx] as Extract<HookSlot, { kind: "memo" }>;
      if (depsChanged(slot.deps, deps)) {
        slot.deps = deps;
        slot.value = factory();
      }
      return slot.value as T;
    },
    useCallback<T extends (...args: never[]) => unknown>(fn: T, deps: unknown[]): T {
      return this.useMemo(() => fn, deps);
    },
    useEffect(fn: () => void | (() => void), deps?: unknown[]) {
      const idx = cursor++;
      if (idx >= slots.length) {
        slots.push({ kind: "effect", deps: undefined });
        pendingEffects.push({ slotIdx: idx, fn, deps });
      } else {
        const slot = slots[idx] as Extract<HookSlot, { kind: "effect" }>;
        if (depsChanged(slot.deps, deps)) pendingEffects.push({ slotIdx: idx, fn, deps });
      }
    },
  };
});

vi.mock("react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react")>();
  return {
    ...actual,
    useState: hookRuntime.useState.bind(hookRuntime),
    useRef: hookRuntime.useRef.bind(hookRuntime),
    useMemo: hookRuntime.useMemo.bind(hookRuntime),
    useCallback: hookRuntime.useCallback.bind(hookRuntime),
    useEffect: hookRuntime.useEffect.bind(hookRuntime),
  };
});

const apiMocks = vi.hoisted(() => ({
  runCleanRoomAudit: vi.fn(async (_profileId?: string | null, _routeId?: string | null): Promise<CleanRoomAuditReport> => ({
    checked_at: 1_760_000_000,
    exit_ip: "185.212.102.40",
    exit_country: "DE",
    exit_timezone: "Europe/Berlin",
    ip_is_tainted: false,
    os_tz_matches_exit: true,
    findings: [],
    critical_count: 0,
    warning_count: 0,
    ready_to_launch: true,
  })),
  untaintCleanRoomIp: vi.fn(async (_ip: string): Promise<CleanRoomState> => ({
    profiles: [],
    active_profile_id: null,
    tainted_ips: {},
  })),
  updateCleanProfileRoute: vi.fn(async (profileId: string, routeId: string | null): Promise<CleanRoomProfile> => ({
    id: profileId,
    label: "Claude US",
    provider: "anthropic",
    browser_engine: "chrome",
    bound_route_id: routeId,
    last_exit_ip: "45.80.10.20",
    last_exit_country: "US",
    status: "active",
    created_at: 1,
    last_opened_at: null,
    warmup_started_at: null,
    launchpad_step: 1,
    completed_checklist: [],
  })),
  deleteCleanProfile: vi.fn(async (_profileId: string, _taintExitIp = false): Promise<CleanRoomState> => ({
    profiles: [],
    active_profile_id: null,
    tainted_ips: {},
  })),
  discoverCleanBrowsers: vi.fn(async (): Promise<DetectedBrowser[]> => [
    { engine: "chrome", display_name: "Google Chrome", executable_path: "/usr/bin/chrome", available: true },
  ]),
}));

vi.mock("../../utils/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../utils/api")>();
  return {
    ...actual,
    runCleanRoomAudit: apiMocks.runCleanRoomAudit,
    untaintCleanRoomIp: apiMocks.untaintCleanRoomIp,
    updateCleanProfileRoute: apiMocks.updateCleanProfileRoute,
    deleteCleanProfile: apiMocks.deleteCleanProfile,
    discoverCleanBrowsers: apiMocks.discoverCleanBrowsers,
  };
});

import { Button, ConfirmModal, HintCard, Select } from "../../ui";
import { PreFlightAuditCard, buildRadarLayers } from "./PreFlightAuditCard";
import { SandboxProfilesCard } from "./SandboxProfilesCard";
import { LaunchpadSteps } from "./LaunchpadSteps";
import { CleanRoomScreen } from "./CleanRoomScreen";

function collectElements(
  node: unknown,
  predicate: (el: ReactElement<Record<string, unknown>>) => boolean,
  out: ReactElement<Record<string, unknown>>[] = [],
): ReactElement<Record<string, unknown>>[] {
  if (!node || typeof node !== "object") return out;
  if (Array.isArray(node)) {
    for (const item of node) collectElements(item, predicate, out);
    return out;
  }
  const el = node as ReactElement<Record<string, unknown>>;
  if ("type" in el && "props" in el) {
    if (predicate(el)) out.push(el);
    if (el.props?.children) collectElements(el.props.children, predicate, out);
    if (el.props?.action) collectElements(el.props.action, predicate, out);
    if (el.props?.aside) collectElements(el.props.aside, predicate, out);
  }
  return out;
}

function collectText(node: unknown): string {
  if (node == null || typeof node === "boolean") return "";
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(collectText).join(" ");
  if (typeof node === "object" && "props" in (node as ReactElement)) {
    const props = (node as ReactElement<Record<string, unknown>>).props;
    return [
      props.title,
      props.sub,
      props.label,
      props.value,
      props.text,
      props.children,
      Array.isArray(props.options) ? props.options.map((o: { label?: string }) => o.label ?? "").join(" ") : "",
    ]
      .map(collectText)
      .join(" ");
  }
  return "";
}

function makeRoute(id: string, label: string, exitIp: string): RouteView {
  return {
    id,
    label,
    country: "DE",
    exit_ip: exitIp,
    enabled: true,
    added_at: 1,
    entries: [],
    status: "active",
    is_default: false,
    bound_providers: [],
    is_profile_route: false,
    health: null,
  };
}

function makeProfile(over: Partial<CleanRoomProfile> = {}): CleanRoomProfile {
  return {
    id: "cr-1",
    label: "Claude US",
    provider: "anthropic",
    browser_engine: "chrome",
    bound_route_id: "r-1",
    last_exit_ip: "45.80.10.20",
    last_exit_country: "US",
    status: "active",
    created_at: 1,
    last_opened_at: null,
    warmup_started_at: null,
    launchpad_step: 1,
    completed_checklist: [],
    ...over,
  };
}

function makeAudit(over: Partial<CleanRoomAuditReport> = {}): CleanRoomAuditReport {
  return {
    checked_at: 1_760_000_000,
    exit_ip: "185.212.102.40",
    exit_country: "DE",
    exit_timezone: "Europe/Berlin",
    ip_is_tainted: false,
    os_tz_matches_exit: true,
    findings: [],
    critical_count: 0,
    warning_count: 0,
    ready_to_launch: true,
    ...over,
  };
}

const BROWSERS: DetectedBrowser[] = [
  { engine: "chrome", display_name: "Google Chrome", executable_path: "/usr/bin/chrome", available: true },
];

beforeEach(() => {
  vi.clearAllMocks();
});

describe("Clean Room UX & Privacy v3.0.1 (mounted + element tree)", () => {
  it("PreFlightAuditCard: маскирует IPv4 и IPv6 в exit_ip и в findings[].detail при hideIpMode=true, и дедуплицирует exit_ip_tainted", () => {
    const audit = makeAudit({
      exit_ip: "2001:db8:85a3::7334",
      ip_is_tainted: true,
      critical_count: 1,
      ready_to_launch: false,
      findings: [
        {
          id: "exit_ip_tainted",
          category: "ip_collision",
          title: "Выходной IP отмечен как проблемный",
          detail: "Адрес 2001:db8:85a3::7334 отмечен.",
          severity: "critical",
          path_hint: null,
          fix_action: { kind: "switch_route_or_vpn" },
        },
        {
          id: "ip_history",
          category: "ip_collision",
          title: "IP встречался ранее",
          detail: "IP 185.212.102.40 и 2a01:4f8:c0c::1 были в истории.",
          severity: "warning",
          path_hint: null,
          fix_action: null,
        },
        {
          id: "personal_browsers_present",
          category: "browser",
          title: "На компьютере установлен обычный браузер",
          detail: "Chrome",
          severity: "warning",
          path_hint: null,
          fix_action: null,
        },
      ],
    });

    let tree: ReactElement | null = null;
    const render = () => {
      hookRuntime.beginRender();
      tree = PreFlightAuditCard({
        activeProfileId: "cr-1",
        routes: [makeRoute("r-1", "DE", "185.212.102.40")],
        hideIpMode: true,
        audit,
      }) as ReactElement;
    };
    hookRuntime.reset(render);
    render();

    const text = collectText(tree);
    expect(text).not.toContain("2001:db8:85a3::7334");
    expect(text).not.toContain("185.212.102.40");
    expect(text).not.toContain("2a01:4f8:c0c::1");
    expect(text).toContain("••••:••••:…:7334");
    expect(text).toContain("•••.•••.•••.40");
    expect(text).toContain("••••:••••:…:1");

    // Только один tainted-IP баннер (photo_348) и без карточки exit_ip_tainted
    const dangerBanners = collectElements(
      tree,
      (el) => typeof el.type === "function" && el.type.name === "Banner" && el.props.tone === "danger",
    );
    expect(dangerBanners).toHaveLength(1);
    expect(text).not.toContain("Выходной IP отмечен как проблемный");

    // personal_browser_profiles рендерится спокойно как cr-finding--info
    const personalFinding = collectElements(
      tree,
      (el) => typeof el.props.className === "string" && el.props.className.includes("cr-finding--info"),
    );
    expect(personalFinding).toHaveLength(1);
  });

  it("PreFlightAuditCard: передаёт routeId в runCleanRoomAudit(profileId, routeId) и пересканирует при смене маршрута или routes", async () => {
    let currentRoutes = [makeRoute("r-1", "DE", "185.212.102.40"), makeRoute("r-2", "NL", "95.165.10.22")];
    let currentDefault = "r-1";
    let tree: ReactElement | null = null;

    const render = () => {
      hookRuntime.beginRender();
      tree = PreFlightAuditCard({
        activeProfileId: null,
        routes: currentRoutes,
        defaultRouteId: currentDefault,
      }) as ReactElement;
    };

    hookRuntime.reset(render);
    render();
    hookRuntime.flushEffects();
    await Promise.resolve();

    expect(apiMocks.runCleanRoomAudit).toHaveBeenCalledWith(null, "r-1");

    // Пользователь меняет маршрут в селекторе Pre-Flight
    const routeSelect = collectElements(
      tree,
      (el) => el.props.label === copy.audit.routeField,
    )[0];
    expect(routeSelect).toBeTruthy();
    (routeSelect.props as { onChange: (e: { target: { value: string } }) => void }).onChange({
      target: { value: "r-2" },
    });
    await Promise.resolve();
    expect(apiMocks.runCleanRoomAudit).toHaveBeenLastCalledWith(null, "r-2");

    // Изменение списка routes / defaultRouteId тоже запускает re-scan
    const callsBefore = apiMocks.runCleanRoomAudit.mock.calls.length;
    currentRoutes = [...currentRoutes, makeRoute("r-3", "US", "45.80.10.20")];
    currentDefault = "r-3";
    render();
    hookRuntime.flushEffects();
    await Promise.resolve();
    expect(apiMocks.runCleanRoomAudit.mock.calls.length).toBeGreaterThan(callsBefore);
  });

  it("PreFlightAuditCard: вызывает untaintCleanRoomIp по кнопке на баннере tainted-IP", async () => {
    const onTaintedStateUpdated = vi.fn();
    let tree: ReactElement | null = null;
    const render = () => {
      hookRuntime.beginRender();
      tree = PreFlightAuditCard({
        activeProfileId: "cr-1",
        audit: makeAudit({ exit_ip: "45.32.11.22", ip_is_tainted: true, critical_count: 1, ready_to_launch: false }),
        onTaintedStateUpdated,
      }) as ReactElement;
    };

    hookRuntime.reset(render);
    render();

    const untaintBtn = collectElements(
      tree,
      (el) => typeof el.props.onClick === "function" && collectText(el.props.children).includes(copy.audit.untaintBtn),
    )[0];
    expect(untaintBtn).toBeTruthy();

    (untaintBtn.props as { onClick: () => void }).onClick();
    await Promise.resolve();
    await Promise.resolve();
    expect(apiMocks.untaintCleanRoomIp).toHaveBeenCalledWith("45.32.11.22");
    expect(onTaintedStateUpdated).toHaveBeenCalledTimes(1);
  });

  it("SandboxProfilesCard: маскирует IPv4/IPv6 в last_exit_ip, опциях маршрута и tainted_ips; перепривязывает маршрут, сбрасывает taint и не ставит auto-taint при удалении", async () => {
    const profile = makeProfile({ last_exit_ip: "2001:db8:85a3::7334", bound_route_id: "r-1" });
    const routes = [
      makeRoute("r-1", "DE IPv4", "185.212.102.40"),
      makeRoute("r-2", "NL IPv6", "2a01:4f8:c0c::1"),
    ];
    let tree: ReactElement | null = null;

    const render = () => {
      hookRuntime.beginRender();
      tree = SandboxProfilesCard({
        profiles: [profile],
        activeProfileId: profile.id,
        routes,
        taintedIps: { "45.32.11.22": 1, "2001:db8::99": 2 },
        hideIpMode: true,
        readyToLaunch: true,
        initialBrowsers: BROWSERS,
        onSelectProfile: vi.fn(),
      }) as ReactElement;
    };

    hookRuntime.reset(render);
    render();

    // Раскрываем список отмеченных IP, чтобы проверить маскировку и untaint
    const taintedExpand = collectElements(
      tree,
      (el) => el.props.title === copy.sandbox.profileCard.taintedIpsTitle(2),
    )[0];
    expect(taintedExpand).toBeTruthy();
    (taintedExpand.props as { onToggle: () => void }).onToggle();

    const text = collectText(tree);
    expect(text).not.toContain("2001:db8:85a3::7334");
    expect(text).not.toContain("185.212.102.40");
    expect(text).not.toContain("2a01:4f8:c0c::1");
    expect(text).not.toContain("45.32.11.22");
    expect(text).not.toContain("2001:db8::99");
    expect(text).toContain("••••:••••:…:7334");
    expect(text).toContain("Соединенные Штаты");
    expect(text).not.toContain("(US)");
    expect(text).toContain("•••.•••.•••.40");
    expect(text).toContain("••••:••••:…:1");
    expect(text).toContain("•••.•••.•••.22");
    expect(text).toContain("••••:••••:…:99");

    // Сброс tainted IP из списка профилей
    const tick = () => new Promise((r) => setTimeout(r, 0));
    const untaintBtn = collectElements(
      tree,
      (el) => el.type === Button && collectText(el.props.children).includes(copy.audit.untaintBtn),
    )[0];
    expect(untaintBtn).toBeTruthy();
    (untaintBtn.props as { onClick: () => void }).onClick();
    await tick();
    expect(apiMocks.untaintCleanRoomIp).toHaveBeenCalledWith("45.32.11.22");

    // Перепривязка маршрута существующего профиля
    const routeSelect = collectElements(
      tree,
      (el) => el.type === Select && el.props.label === copy.sandbox.profileCard.routeLabel,
    )[0];
    expect(routeSelect).toBeTruthy();
    (routeSelect.props as { onChange: (e: { target: { value: string } }) => void }).onChange({
      target: { value: "r-2" },
    });
    await tick();
    expect(apiMocks.updateCleanProfileRoute).toHaveBeenCalledWith("cr-1", "r-2");

    // Удаление профиля: по умолчанию taintExitIp = false
    const deleteBtn = collectElements(
      tree,
      (el) => el.type === Button && collectText(el.props.children).includes(copy.sandbox.profileCard.deleteBtn),
    )[0];
    (deleteBtn.props as { onClick: () => void }).onClick();

    let modal = collectElements(tree, (el) => el.type === ConfirmModal && el.props.open === true)[0];
    expect(modal).toBeTruthy();
    const checkbox = collectElements(modal, (el) => el.type === "input" && el.props.type === "checkbox")[0];
    expect(checkbox.props.checked).toBe(false);

    (modal.props as { onConfirm: () => void }).onConfirm();
    await tick();
    expect(apiMocks.deleteCleanProfile).toHaveBeenLastCalledWith("cr-1", false);

    // Повторное удаление с включённым чекбоксом -> taintExitIp = true
    (deleteBtn.props as { onClick: () => void }).onClick();
    modal = collectElements(tree, (el) => el.type === ConfirmModal && el.props.open === true)[0];
    const checkbox2 = collectElements(modal, (el) => el.type === "input" && el.props.type === "checkbox")[0];
    (checkbox2.props as { onChange: (e: { target: { checked: boolean } }) => void }).onChange({
      target: { checked: true },
    });
    modal = collectElements(tree, (el) => el.type === ConfirmModal && el.props.open === true)[0];
    (modal.props as { onConfirm: () => void }).onConfirm();
    await tick();
    expect(apiMocks.deleteCleanProfile).toHaveBeenLastCalledWith("cr-1", true);
  });

  it("LaunchpadSteps: блокирует «Перейти к шагу 2» без профиля или при readyToLaunch=false, разрешает при готовности и не дублирует «Создать профиль»", () => {
    const renderStep1 = (activeProfile: CleanRoomProfile | null, readyToLaunch: boolean) => {
      let tree: ReactElement | null = null;
      const render = () => {
        hookRuntime.beginRender();
        tree = LaunchpadSteps({
          state: null,
          activeProfile,
          exitCountry: "DE",
          readyToLaunch,
          manualKillswitch: false,
          initialStep: 1,
        }) as ReactElement;
      };
      hookRuntime.reset(render);
      render();
      return tree!;
    };

    const noProfileTree = renderStep1(null, true);
    const nextBtnNoProfile = collectElements(
      noProfileTree,
      (el) => el.type === Button && collectText(el.props.children).includes(copy.launchpad.step1.nextBtn),
    )[0];
    expect(nextBtnNoProfile.props.disabled).toBe(true);
    expect(collectText(noProfileTree)).not.toContain(copy.sandbox.createBtn);

    const notReadyTree = renderStep1(makeProfile(), false);
    const nextBtnNotReady = collectElements(
      notReadyTree,
      (el) => el.type === Button && collectText(el.props.children).includes(copy.launchpad.step1.nextBtn),
    )[0];
    expect(nextBtnNotReady.props.disabled).toBe(true);

    const readyTree = renderStep1(makeProfile(), true);
    const nextBtnReady = collectElements(
      readyTree,
      (el) => el.type === Button && collectText(el.props.children).includes(copy.launchpad.step1.nextBtn),
    )[0];
    expect(nextBtnReady.props.disabled).toBe(false);
  });

  it("buildRadarLayers: скрывает MSIX на macOS и показывает «Приложения ИИ»", () => {
    const prevNav = globalThis.navigator;
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { platform: "MacIntel", userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X)" },
    });
    try {
      const layers = buildRadarLayers(makeAudit(), false);
      const labels = layers.map((l) => l.label).join(" ");
      expect(labels).toContain("Приложения ИИ");
      expect(labels).not.toContain("MSIX");
      expect(labels).not.toContain("Store");
    } finally {
      Object.defineProperty(globalThis, "navigator", { configurable: true, value: prevNav });
    }
  });

  it("CleanRoomScreen («Оплата и прогрев»): не рендерит двойные info-баннеры (<= 1 Banner)", () => {
    let tree: ReactElement | null = null;
    const state: AppStateData = {
      pinned_ip: "185.212.102.40",
      strict_pinning_enabled: true,
      ip_history: {},
      session_allowed_providers: [],
      blocked_providers: [],
      dismissed_hints: [],
      clean_room: { profiles: [makeProfile()], active_profile_id: "cr-1", tainted_ips: {} },
    };
    const render = () => {
      hookRuntime.beginRender();
      tree = CleanRoomScreen({
        state,
        initialTab: "payment",
        initialAudit: makeAudit(),
        initialBrowsers: BROWSERS,
      }) as ReactElement;
    };
    hookRuntime.reset(render);
    render();

    const infoBanners = collectElements(
      tree,
      (el) => typeof el.type === "function" && el.type.name === "Banner" && el.props.tone === "info",
    );
    expect(infoBanners.length).toBeLessThanOrEqual(1);
  });

  it("Баг #2: закрытие HintCard sandbox_chrome_flag_note вызывает onDismissHint('sandbox_chrome_flag_note') и скрывает подсказку", async () => {
    const onDismissHint = vi.fn();
    let tree: ReactElement | null = null;
    const state: AppStateData = {
      pinned_ip: "185.212.102.40",
      strict_pinning_enabled: true,
      ip_history: {},
      session_allowed_providers: [],
      blocked_providers: [],
      dismissed_hints: [],
      clean_room: { profiles: [makeProfile()], active_profile_id: "cr-1", tainted_ips: {} },
    };
    const render = () => {
      hookRuntime.beginRender();
      tree = CleanRoomScreen({
        state,
        initialTab: "launchpad",
        initialAudit: makeAudit(),
        initialBrowsers: BROWSERS,
        onDismissHint,
      }) as ReactElement;
    };
    hookRuntime.reset(render);
    render();

    const sandboxEl = collectElements(tree, (el) => el.type === SandboxProfilesCard)[0];
    expect(sandboxEl).toBeTruthy();

    let sandboxTree: ReactElement | null = null;
    const renderSandbox = () => {
      hookRuntime.beginRender();
      sandboxTree = SandboxProfilesCard(
        sandboxEl.props as unknown as Parameters<typeof SandboxProfilesCard>[0],
      ) as ReactElement;
    };
    hookRuntime.reset(renderSandbox);
    renderSandbox();

    const flagHint = collectElements(
      sandboxTree,
      (el) => el.type === HintCard && el.props.hintId === "sandbox_chrome_flag_note",
    )[0];
    expect(flagHint).toBeTruthy();
    expect(flagHint.props.title).toBe(copy.sandbox.chromeFlagHint.title);

    (flagHint.props as { onDismiss: (id: string) => void }).onDismiss("sandbox_chrome_flag_note");
    await Promise.resolve();
    expect(onDismissHint).toHaveBeenCalledWith("sandbox_chrome_flag_note");
  });
});

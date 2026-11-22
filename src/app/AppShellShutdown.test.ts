import type { ReactElement, ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ShutdownProgressPayload } from "../types";

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
  let scheduled = false;

  function depsChanged(prev: unknown[] | undefined, next: unknown[] | undefined): boolean {
    if (!prev || !next) return true;
    if (prev.length !== next.length) return true;
    for (let i = 0; i < prev.length; i++) {
      if (!Object.is(prev[i], next[i])) return true;
    }
    return false;
  }

  function triggerRerender() {
    if (scheduled || !currentRender) return;
    scheduled = true;
    queueMicrotask(() => {
      scheduled = false;
      if (currentRender) {
        currentRender();
        flushEffects();
      }
    });
  }

  function flushEffects() {
    const queue = pendingEffects;
    pendingEffects = [];
    for (const item of queue) {
      const slot = slots[item.slotIdx] as Extract<HookSlot, { kind: "effect" }>;
      slot.cleanup?.();
      slot.deps = item.deps;
      const cleanup = item.fn();
      slot.cleanup = typeof cleanup === "function" ? cleanup : undefined;
    }
  }

  return {
    reset(renderFn: () => void) {
      for (const s of slots) {
        if (s.kind === "effect") s.cleanup?.();
      }
      slots = [];
      cursor = 0;
      pendingEffects = [];
      currentRender = renderFn;
    },
    beginRender() {
      cursor = 0;
    },
    flushEffects,
    unmount() {
      currentRender = null;
      for (const s of slots) {
        if (s.kind === "effect") s.cleanup?.();
      }
      slots = [];
      pendingEffects = [];
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
          triggerRerender();
        }
      };
      return [slot.value as T, setState];
    },
    useRef<T>(initial: T): { current: T } {
      const idx = cursor++;
      if (idx >= slots.length) {
        slots.push({ kind: "ref", value: { current: initial } });
      }
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
    useEffect(fn: () => void | (() => void), deps?: unknown[]) {
      const idx = cursor++;
      if (idx >= slots.length) {
        slots.push({ kind: "effect", deps: undefined });
        pendingEffects.push({ slotIdx: idx, fn, deps });
        return;
      }
      const slot = slots[idx] as Extract<HookSlot, { kind: "effect" }>;
      if (depsChanged(slot.deps, deps)) {
        pendingEffects.push({ slotIdx: idx, fn, deps });
      }
    },
  };
});

const listeners = vi.hoisted(() => ({
  shutdownHandler: null as ((payload: ShutdownProgressPayload) => void) | null,
}));

vi.mock("react", async () => {
  const actual = await vi.importActual<typeof import("react")>("react");
  return {
    ...actual,
    useState: hookRuntime.useState.bind(hookRuntime),
    useRef: hookRuntime.useRef.bind(hookRuntime),
    useMemo: hookRuntime.useMemo.bind(hookRuntime),
    useEffect: hookRuntime.useEffect.bind(hookRuntime),
  };
});

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
    startupPending: true,
    partialAudit: null,
    currentIp: "--",
    currentCountry: "--",
    trustScore: null,
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
    interceptPayload: null,
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

vi.mock("../utils/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../utils/api")>();
  return {
    ...actual,
    bindUpstreamToClaudeProfile: vi.fn(),
    dismissHint: vi.fn(),
    getHideIpMode: vi.fn(async () => false),
    getPersonaRiskReport: vi.fn(),
    markWhatsNewV3Seen: vi.fn(),
    onDeepLink: vi.fn(async () => () => {}),
    onOpenPaymentCheck: vi.fn(async () => () => {}),
    onRouteUnavailable: vi.fn(async () => () => {}),
    onShutdownProgress: vi.fn(async (handler: (payload: ShutdownProgressPayload) => void) => {
      listeners.shutdownHandler = handler;
      return () => {
        listeners.shutdownHandler = null;
      };
    }),
    setHideIpMode: vi.fn(),
    takePendingDeepLink: vi.fn(async () => null),
    upsertRoute: vi.fn(),
  };
});

import { shutdown as copy } from "../shared/copy/ru";
import { AppShell } from "./AppShell";
import { AppShellDialogs } from "./AppShellDialogs";
import { ShutdownOverlay } from "./ShutdownOverlay";

function findInTree(node: ReactNode, predicate: (el: ReactElement) => boolean): ReactElement | null {
  if (!node || typeof node !== "object") return null;
  if (Array.isArray(node)) {
    for (const item of node) {
      const hit = findInTree(item, predicate);
      if (hit) return hit;
    }
    return null;
  }
  const el = node as ReactElement<{ children?: ReactNode }>;
  if (predicate(el)) return el;
  return el.props?.children ? findInTree(el.props.children, predicate) : null;
}

describe("AppShell: обработка app://shutdown-progress с gateway_bound_apps", () => {
  beforeEach(() => {
    listeners.shutdownHandler = null;
  });

  it("передаёт gateway_bound_apps из события в ShutdownOverlay и скрывает подсказку при пустом списке", async () => {
    let tree: ReactNode = null;
    const render = () => {
      hookRuntime.beginRender();
      tree = AppShell();
    };
    hookRuntime.reset(render);
    render();
    hookRuntime.flushEffects();
    await Promise.resolve();

    expect(listeners.shutdownHandler).not.toBeNull();

    listeners.shutdownHandler!({
      mode: "quit",
      step: 4,
      total: 4,
      label: "Готово, закрываем приложение...",
      done: true,
      gateway_bound_apps: [],
    });
    await Promise.resolve();

    const dialogsEmpty = findInTree(tree, (el) => el.type === AppShellDialogs);
    expect(dialogsEmpty).not.toBeNull();
    const ctrlEmpty = (dialogsEmpty!.props as { ctrl: { shutdownProgress: ShutdownProgressPayload | null } }).ctrl;
    const htmlEmpty = renderToStaticMarkup(ShutdownOverlay({ progress: ctrlEmpty.shutdownProgress }));
    expect(htmlEmpty).not.toContain(copy.boundAppsTitle);

    listeners.shutdownHandler!({
      mode: "quit",
      step: 4,
      total: 4,
      label: "Готово, закрываем приложение...",
      done: true,
      gateway_bound_apps: ["Antigravity", "Cursor"],
    });
    await Promise.resolve();

    const dialogsWithApps = findInTree(tree, (el) => el.type === AppShellDialogs);
    const ctrlWithApps = (dialogsWithApps!.props as { ctrl: { shutdownProgress: ShutdownProgressPayload | null } }).ctrl;
    const htmlWithApps = renderToStaticMarkup(ShutdownOverlay({ progress: ctrlWithApps.shutdownProgress }));
    expect(htmlWithApps).toContain(copy.boundAppsTitle);
    expect(htmlWithApps).toContain("Antigravity, Cursor");

    hookRuntime.unmount();
  });
});

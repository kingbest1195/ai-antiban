import type { ReactElement, ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Lightweight mounted React hook & effect harness for Node/Vitest (without jsdom),
 * enabling multi-render lifecycle testing of `useState` / `useEffect` / `useRef`.
 */
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
    useCallback<T extends (...args: never[]) => unknown>(fn: T, deps: unknown[]): T {
      return this.useMemo(() => fn, deps);
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

vi.mock("react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react")>();
  return {
    ...actual,
    useState: hookRuntime.useState.bind(hookRuntime),
    useRef: hookRuntime.useRef.bind(hookRuntime),
    useCallback: hookRuntime.useCallback.bind(hookRuntime),
    useMemo: hookRuntime.useMemo.bind(hookRuntime),
    useEffect: hookRuntime.useEffect.bind(hookRuntime),
  };
});

const apiMocks = vi.hoisted(() => ({
  getPersonaRiskReport: vi.fn(async () => ({
    score: 15,
    level: "low" as const,
    factors: [],
    self_check: {
      bought_or_grey_account: false,
      virtual_sms_used: false,
      reseller_payment_used: false,
      multi_account_same_browser: false,
    },
    recommended_actions: [],
    evaluated_at: 100,
  })),
  updatePersonaSelfCheck: vi.fn(),
  runBunkerBackupNow: vi.fn(),
  getRoutesSnapshot: vi.fn(async () => ({ routes: [], provider_routes: {}, effective: {}, dangling: [] })),
  listCleanProfiles: vi.fn(async () => ({ profiles: [], active_profile_id: null, tainted_ips: {} })),
  updateCleanProfileStep: vi.fn(async () => ({})),
  launchCleanBrowser: vi.fn(),
  startCleanProfileWarmup: vi.fn(),
  dismissHint: vi.fn(async () => {}),
}));

vi.mock("../utils/api/sos", () => ({
  getPersonaRiskReport: apiMocks.getPersonaRiskReport,
  updatePersonaSelfCheck: apiMocks.updatePersonaSelfCheck,
}));

vi.mock("../utils/api/bunker", () => ({
  runBunkerBackupNow: apiMocks.runBunkerBackupNow,
}));

vi.mock("../utils/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../utils/api")>();
  return {
    ...actual,
    getRoutesSnapshot: apiMocks.getRoutesSnapshot,
    listCleanProfiles: apiMocks.listCleanProfiles,
    updateCleanProfileStep: apiMocks.updateCleanProfileStep,
    launchCleanBrowser: apiMocks.launchCleanBrowser,
    startCleanProfileWarmup: apiMocks.startCleanProfileWarmup,
    dismissHint: apiMocks.dismissHint,
  };
});

const openerMock = vi.hoisted(() => ({
  openExternal: vi.fn(async () => {}),
  openTelegramSupport: vi.fn(async () => {}),
  openZastavaBot: vi.fn(async () => {}),
}));

vi.mock("../utils/opener", () => openerMock);

import { bunkerCopy } from "../shared/copy/ru/bunker";
import { useNavigation } from "../shared/hooks/useNavigation";
import { WebExportHelper } from "../features/bunker/WebExportHelper";
import { LaunchpadSteps } from "../features/clean-room/LaunchpadSteps";
import { GuidesScreen } from "../features/guides/GuidesScreen";
import { SosScreen, type SosBranchId } from "../features/sos/SosScreen";
import { PersonaRiskCard } from "../features/bunker/PersonaRiskCard";
import { AlertStrip } from "../features/shell-v3/AlertStrip";
import { CooldownBanner } from "../features/overview/CooldownBanner";
import type { OverviewScreenProps } from "../features/overview/OverviewScreen";
import type { OverviewView } from "../features/shell-v3/types";

function findInTree(node: ReactNode, pred: (el: ReactElement) => boolean): ReactElement | null {
  if (!node || typeof node === "boolean" || typeof node === "string" || typeof node === "number") return null;
  if (Array.isArray(node)) {
    for (const child of node) {
      const hit = findInTree(child, pred);
      if (hit) return hit;
    }
    return null;
  }
  if (typeof node === "object" && "type" in node && "props" in node) {
    const el = node as ReactElement;
    if (pred(el)) return el;
    const props = el.props as { children?: ReactNode; action?: ReactNode };
    return findInTree(props.children, pred) ?? findInTree(props.action, pred);
  }
  return null;
}

function findAllInTree(node: ReactNode, pred: (el: ReactElement) => boolean, out: ReactElement[] = []): ReactElement[] {
  if (!node || typeof node === "boolean" || typeof node === "string" || typeof node === "number") return out;
  if (Array.isArray(node)) {
    for (const child of node) findAllInTree(child, pred, out);
    return out;
  }
  if (typeof node === "object" && "type" in node && "props" in node) {
    const el = node as ReactElement;
    if (pred(el)) out.push(el);
    const props = el.props as { children?: ReactNode; action?: ReactNode };
    if (props.action) findAllInTree(props.action, pred, out);
    if (props.children) findAllInTree(props.children, pred, out);
  }
  return out;
}

async function flushMicrotasks(): Promise<void> {
  await Promise.resolve();
  await new Promise((r) => setTimeout(r, 0));
}

function mountComponent<P, R>(fn: (props: P) => R, initialProps: P) {
  let latestProps = initialProps;
  let latestResult!: R;
  const render = () => {
    hookRuntime.beginRender();
    latestResult = fn(latestProps);
  };
  hookRuntime.reset(render);
  render();
  hookRuntime.flushEffects();
  return {
    get result() {
      return latestResult;
    },
    async rerender(nextProps: P) {
      latestProps = nextProps;
      render();
      hookRuntime.flushEffects();
      await flushMicrotasks();
    },
    async settle() {
      await flushMicrotasks();
    },
    unmount() {
      hookRuntime.unmount();
    },
  };
}

describe("Mounted v3 Navigation & Lifecycle Flows", () => {
  beforeEach(() => {
    apiMocks.getPersonaRiskReport.mockClear();
    openerMock.openExternal.mockClear();
    (globalThis as { window?: unknown }).window = {
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearInterval: globalThis.clearInterval.bind(globalThis),
      setInterval: globalThis.setInterval.bind(globalThis),
      location: { search: "", hash: "" },
    };
  });

  it("useNavigation preserves multi-hop roundtrips and bumps target navKeys only on forward navigation", async () => {
    const m = mountComponent(() => useNavigation(), undefined);

    // 1. Clean Room -> openGuide("payment") -> pop() does NOT bump cleanRoomNavKey
    m.result.push({ page: "clean-room", cleanRoomTab: "launchpad" });
    await m.settle();
    const crKeyBeforeGuide = m.result.cleanRoomNavKey;
    expect(crKeyBeforeGuide).toBe(1);

    m.result.openGuide("payment");
    await m.settle();
    expect(m.result.currentRoute.page).toBe("guides");
    expect(m.result.guideTarget).toBe("payment");
    expect(m.result.guideNavKey).toBe(1);

    m.result.pop();
    await m.settle();
    expect(m.result.currentRoute).toEqual({ page: "clean-room", cleanRoomTab: "launchpad" });
    expect(m.result.cleanRoomNavKey).toBe(crKeyBeforeGuide);

    // 2. Repeated openGuide("payment") bumps guideNavKey even with same guideRef
    m.result.openGuide("payment");
    await m.settle();
    expect(m.result.guideNavKey).toBe(2);

    // 3. SOS Branch 4 -> Clean Room Step 1 -> Back preserves sosBranch
    m.result.push({ page: "backup", sosBranch: "banned" });
    await m.settle();
    expect(m.result.sosNavKey).toBe(1);

    m.result.push({ page: "clean-room", cleanRoomTab: "launchpad", cleanRoomStep: 1 });
    await m.settle();
    expect(m.result.cleanRoomNavKey).toBe(2);
    expect(m.result.currentRoute.cleanRoomStep).toBe(1);

    m.result.pop();
    await m.settle();
    expect(m.result.currentRoute).toEqual({ page: "backup", sosBranch: "banned" });

    m.unmount();
  });

  it("P1 #5: LaunchpadSteps switches to step 1 when initialStep=1 & navKey bump arrive while mounted on step 3", async () => {
    const baseProps = {
      activeProfile: {
        id: "p1",
        label: "Claude",
        provider: "anthropic" as const,
        browser_engine: "chrome" as const,
        status: "ready" as const,
        bound_route_id: "r1",
        launchpad_step: 1,
        completed_checklist: [],
        created_at: 1,
        last_exit_ip: null,
        last_exit_country: null,
        last_opened_at: null,
        warmup_started_at: null,
      },
      exitCountry: "NL",
      readyToLaunch: true,
      manualKillswitch: false,
      initialStep: undefined as number | undefined,
      navKey: 1,
    };
    const m = mountComponent(LaunchpadSteps, baseProps);

    // User clicks Step 3 tab manually
    const stepTabs = findAllInTree(
      m.result,
      (el) => el.type === "button" && (el.props as { role?: string }).role === "tab",
    );
    expect(stepTabs).toHaveLength(4);
    (stepTabs[2].props as { onClick: () => void }).onClick();
    await m.settle();

    const activeAfterClick = findAllInTree(
      m.result,
      (el) => el.type === "button" && (el.props as { role?: string }).role === "tab",
    );
    expect((activeAfterClick[2].props as { "aria-selected": boolean })["aria-selected"]).toBe(true);

    // Now SOS Branch 4 pushes clean-room with initialStep=1 and bumped navKey=2 while mounted
    await m.rerender({ ...baseProps, initialStep: 1, navKey: 2 });

    const tabsAfterJump = findAllInTree(
      m.result,
      (el) => el.type === "button" && (el.props as { role?: string }).role === "tab",
    );
    expect((tabsAfterJump[0].props as { "aria-selected": boolean })["aria-selected"]).toBe(true);
    expect((tabsAfterJump[2].props as { "aria-selected": boolean })["aria-selected"]).toBe(false);

    m.unmount();
  });

  it("P1 #10: GuidesScreen jumps back to payment on repeated initialGuide='payment' when navKey increments", async () => {
    const m = mountComponent(GuidesScreen, { initialGuide: "payment", navKey: 1 });

    // Confirm initially on "payment"
    const segInitial = findInTree(m.result, (el) => (el.props as { value?: string }).value === "payment");
    expect(segInitial).not.toBeNull();

    // User manually switches segmented control to "vps"
    const segControl = findInTree(
      m.result,
      (el) => Array.isArray((el.props as { options?: unknown[] }).options),
    )!;
    (segControl.props as { onChange: (v: "vps" | "payment" | "os") => void }).onChange("vps");
    await m.settle();

    expect((findInTree(m.result, (el) => Array.isArray((el.props as { options?: unknown[] }).options))!.props as { value: string }).value).toBe("vps");

    // Re-navigating to the SAME initialGuide="payment" with bumped navKey=2 jumps back to "payment"
    await m.rerender({ initialGuide: "payment", navKey: 2 });
    expect((findInTree(m.result, (el) => Array.isArray((el.props as { options?: unknown[] }).options))!.props as { value: string }).value).toBe("payment");

    m.unmount();
  });

  it("P2 #15: SosScreen syncs active branch when initialBranch or navKey updates while mounted", async () => {
    const m = mountComponent(SosScreen, { initialBranch: "persona" as SosBranchId, navKey: 1 });

    const tabsInitial = findInTree(m.result, (el) => Array.isArray((el.props as { items?: unknown[] }).items))!;
    expect((tabsInitial.props as { value: string }).value).toBe("persona");

    await m.rerender({ initialBranch: "banned", navKey: 2 });
    const tabsUpdated = findInTree(m.result, (el) => Array.isArray((el.props as { items?: unknown[] }).items))!;
    expect((tabsUpdated.props as { value: string }).value).toBe("banned");

    m.unmount();
  });

  it("P2 #14: PersonaRiskCard skips fetch when visible=false and re-fetches whenever backup becomes visible", async () => {
    const m = mountComponent(PersonaRiskCard, { visible: false, refreshKey: 1 });
    expect(apiMocks.getPersonaRiskReport).toHaveBeenCalledTimes(0);

    await m.rerender({ visible: true, refreshKey: 1 });
    expect(apiMocks.getPersonaRiskReport).toHaveBeenCalledTimes(1);

    await m.rerender({ visible: false, refreshKey: 1 });
    expect(apiMocks.getPersonaRiskReport).toHaveBeenCalledTimes(1);

    await m.rerender({ visible: true, refreshKey: 1 });
    expect(apiMocks.getPersonaRiskReport).toHaveBeenCalledTimes(2);

    m.unmount();
  });

  it("P1 #7: ChecksScreen auto-audit guard runs at most once per visit even if audit fails", async () => {
    const runFullAudit = vi.fn();
    function useChecksAuditGuard(page: string, hasAnthropicReport: boolean, refreshing: boolean, auditError: string | null) {
      const attemptedRef = hookRuntime.useRef(false);
      hookRuntime.useEffect(() => {
        if (page !== "checks") {
          attemptedRef.current = false;
        } else if (!hasAnthropicReport && !refreshing && !auditError && !attemptedRef.current) {
          attemptedRef.current = true;
          runFullAudit(true, true);
        }
      }, [page, hasAnthropicReport, refreshing, auditError]);
    }

    const m = mountComponent(
      (p: { page: string; hasReport: boolean; refreshing: boolean; auditError: string | null }) =>
        useChecksAuditGuard(p.page, p.hasReport, p.refreshing, p.auditError),
      { page: "checks", hasReport: false, refreshing: false, auditError: null as string | null },
    );
    expect(runFullAudit).toHaveBeenCalledTimes(1);

    // Audit starts refreshing, then fails (hasReport stays false, refreshing flips true -> false)
    await m.rerender({ page: "checks", hasReport: false, refreshing: true, auditError: null });
    await m.rerender({ page: "checks", hasReport: false, refreshing: false, auditError: "network error" });
    expect(runFullAudit).toHaveBeenCalledTimes(1);

    // Even if auditError is cleared while staying on checks, no tight retry loop
    await m.rerender({ page: "checks", hasReport: false, refreshing: false, auditError: null });
    expect(runFullAudit).toHaveBeenCalledTimes(1);

    // Leaving checks and returning resets the per-visit guard
    await m.rerender({ page: "home", hasReport: false, refreshing: false, auditError: null });
    await m.rerender({ page: "checks", hasReport: false, refreshing: false, auditError: null });
    expect(runFullAudit).toHaveBeenCalledTimes(2);

    m.unmount();
  });

  it("P1 #4: mounted WebExportHelper intercepts clicks on both external links via openExternal", () => {
    const m = mountComponent(WebExportHelper, { onToast: vi.fn() });
    const links = findAllInTree(
      m.result,
      (el) => typeof el.props === "object" && el.props !== null && "href" in (el.props as Record<string, unknown>),
    );
    expect(links).toHaveLength(2);

    for (const link of links) {
      const props = link.props as { href: string; onClick?: (e: { preventDefault: () => void }) => void };
      const preventDefault = vi.fn();
      props.onClick?.({ preventDefault });
      expect(preventDefault).toHaveBeenCalledTimes(1);
    }
    expect(openerMock.openExternal).toHaveBeenCalledWith(bunkerCopy.webExport.claudeExportUrl);
    expect(openerMock.openExternal).toHaveBeenCalledWith(bunkerCopy.webExport.chatgptExportUrl);

    m.unmount();
  });

  it("P1 #6: mounted AlertStrip keeps CooldownBanner separate from backup navigation button", () => {
    const onPushRoute = vi.fn();
    const overview: OverviewScreenProps = {
      reports: {},
      activeReport: null,
      state: null,
      refreshing: false,
      auditError: null,
      startupPending: false,
      partial: null,
      currentIp: "1.2.3.4",
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
    };
    const view: OverviewView = {
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
        services: [],
      },
    };
    const m = mountComponent(AlertStrip, {
      view,
      overview,
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
    });

    const roleButtons = findAllInTree(
      m.result,
      (el) => el.type === "div" && (el.props as { role?: string }).role === "button",
    );
    expect(roleButtons).toHaveLength(0);

    const cooldownEls = findAllInTree(m.result, (el) => el.type === CooldownBanner);
    expect(cooldownEls).toHaveLength(1);

    const backupBtn = findAllInTree(
      m.result,
      (el) => (el.props as { children?: unknown }).children === "Открыть профили и SOS",
    );
    expect(backupBtn).toHaveLength(0);

    m.unmount();
  });
});

import type { ReactElement, ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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

vi.mock("react", async () => {
  const actual = await vi.importActual<typeof import("react")>("react");
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
  getCoverageSnapshot: vi.fn(async () => ({
    sysproxy_enabled: true,
    cli_protection_enabled: true,
    chained_proxy: null,
    gateway_addr: "127.0.0.1:40111",
    pac_url: "http://127.0.0.1:40111/proxy.pac",
    generated_at_ms: 1,
    cli_mode: "ai_only" as const,
    apps: [
      {
        id: "antigravity",
        name: "Antigravity",
        category: "ide" as const,
        installed: true,
        status: "off" as const,
        detail: "Запустите через Заставу",
        requests_seen: 0,
        ai_requests: 0,
        pac_fetches: 0,
        last_seen_ms: null,
        manual_steps: ["launch_with_env" as const],
        bypass_suspected: false,
      },
    ],
  })),
  recheckCoverage: vi.fn(),
  reapplyBrowserPolicies: vi.fn(),
  relaunchBrowsersWithPac: vi.fn(),
  restartAppWithGateway: vi.fn(async () => "restarted" as const),
  getOsTimezoneStatus: vi.fn(async () => ({
    synced: true,
    current_os_tz: null,
    original_os_tz: null,
    synced_target_tz: null,
    auto_restore_pending: false,
  })),
  syncOsTimezone: vi.fn(),
  restoreOsTimezone: vi.fn(),
}));

vi.mock("../../utils/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../utils/api")>();
  return {
    ...actual,
    ...apiMocks,
  };
});

import { coverage as copy } from "../../shared/copy/ru";
import { ConfirmModal } from "../../ui";
import { CoverageSection } from "./CoverageSection";
import { CoverageVpnBanner } from "./CoverageVpnBanner";

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

describe("CoverageSection: тост при перезапуске IDE через Заставу", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("document", {
      visibilityState: "visible",
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    });
    vi.stubGlobal("window", {
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      setInterval: vi.fn(() => 1),
      clearInterval: vi.fn(),
      setTimeout: vi.fn(() => 1),
      clearTimeout: vi.fn(),
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("restart_app_with_gateway при успехе передаёт в тост пояснение о перезапуске после выхода", async () => {
    const onToast = vi.fn();
    let tree: ReactNode = null;
    const render = () => {
      hookRuntime.beginRender();
      tree = CoverageSection({
        variant: "checks",
        pending: false,
        onToast,
        initialSnapshot: {
          sysproxy_enabled: true,
          cli_protection_enabled: true,
          chained_proxy: null,
          gateway_addr: "127.0.0.1:40111",
          pac_url: "http://127.0.0.1:40111/proxy.pac",
          generated_at_ms: 1,
          cli_mode: "ai_only",
          apps: [
            {
              id: "antigravity",
              name: "Antigravity",
              category: "ide",
              installed: true,
              status: "off",
              detail: "Запустите через Заставу",
              requests_seen: 0,
              ai_requests: 0,
              pac_fetches: 0,
              last_seen_ms: null,
              manual_steps: ["launch_with_env"],
              bypass_suspected: false,
            },
          ],
        },
      });
    };
    hookRuntime.reset(render);
    render();
    hookRuntime.flushEffects();
    await Promise.resolve();

    const modal = findInTree(
      tree,
      (el) => el.type === ConfirmModal && (el.props as { title?: string }).title === copy.restart.confirm.title,
    );
    expect(modal).not.toBeNull();

    (modal!.props as { onConfirm: () => void }).onConfirm();
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();

    expect(apiMocks.restartAppWithGateway).toHaveBeenCalledWith("antigravity");
    expect(onToast).toHaveBeenCalledWith(
      copy.restart.result.restarted.title,
      copy.restart.result.restarted.text,
      "success",
    );
    expect(copy.restart.result.restarted.text).toContain("После выхода из Заставы это приложение понадобится перезапустить.");

    hookRuntime.unmount();
  });

  it("§7.3: CoverageSection прокидывает обновлённый снимок в onSnapshotChange (gw.setCoverageSnapshot) при recheck и relaunch", async () => {
    const onSnapshotChange = vi.fn();
    const updatedSnap = {
      sysproxy_enabled: true,
      cli_protection_enabled: true,
      chained_proxy: null,
      gateway_addr: "127.0.0.1:40111",
      pac_url: "http://127.0.0.1:40111/proxy.pac",
      generated_at_ms: 99,
      cli_mode: "ai_only" as const,
      apps: [],
      system_proxy_effective: false,
      vpn_connected: ["V2BOX Pro"],
      browser_pac_policy_active: true,
      browsers_pac_active: ["Google Chrome"],
      browsers_needing_restart: [],
    };
    apiMocks.recheckCoverage.mockResolvedValueOnce(updatedSnap);
    apiMocks.relaunchBrowsersWithPac.mockResolvedValueOnce({
      restarted: ["Google Chrome"],
      skipped: [],
      failed: [],
      needs_automation_permission: false,
      unsupported: false,
      snapshot: { ...updatedSnap, generated_at_ms: 100 },
    });

    let tree: ReactNode = null;
    const render = () => {
      hookRuntime.beginRender();
      tree = CoverageSection({
        variant: "overview",
        pending: false,
        onSnapshotChange,
        initialSnapshot: {
          ...updatedSnap,
          generated_at_ms: 1,
          browser_pac_policy_active: false,
          browsers_pac_active: [],
          browsers_needing_restart: ["Google Chrome"],
        },
      });
    };
    hookRuntime.reset(render);
    render();
    hookRuntime.flushEffects();
    await Promise.resolve();

    const recheckBtn = findInTree(
      tree,
      (el) => typeof el.props === "object" && el.props !== null && (el.props as { children?: unknown }).children === copy.recheck,
    );
    expect(recheckBtn).not.toBeNull();
    (recheckBtn!.props as { onClick: () => void }).onClick();
    await Promise.resolve();
    await Promise.resolve();
    expect(onSnapshotChange).toHaveBeenCalledWith(expect.objectContaining({ generated_at_ms: 99 }));

    const banner = findInTree(tree, (el) => el.type === CoverageVpnBanner);
    expect(banner).not.toBeNull();
    (banner!.props as { onRelaunchBrowsers: () => void }).onRelaunchBrowsers();
    await Promise.resolve();
    await Promise.resolve();
    expect(onSnapshotChange).toHaveBeenCalledWith(expect.objectContaining({ generated_at_ms: 100 }));

    hookRuntime.unmount();
  });
});

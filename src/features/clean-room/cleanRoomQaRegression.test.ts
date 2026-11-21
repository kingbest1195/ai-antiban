import type { ReactElement, ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

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
      const cleanup = item.fn();
      slot.cleanup = typeof cleanup === "function" ? cleanup : undefined;
      slot.deps = item.deps;
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
      scheduled = false;
    },
    beginRender() {
      cursor = 0;
    },
    flushEffects,
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
    useEffect(fn: () => void | (() => void), deps?: unknown[]) {
      const idx = cursor++;
      if (idx >= slots.length) {
        slots.push({ kind: "effect", deps: undefined });
        pendingEffects.push({ slotIdx: idx, fn, deps });
      } else {
        const slot = slots[idx] as Extract<HookSlot, { kind: "effect" }>;
        if (depsChanged(slot.deps, deps)) {
          pendingEffects.push({ slotIdx: idx, fn, deps });
        }
      }
    },
    useMemo<T>(fn: () => T, deps?: unknown[]): T {
      const idx = cursor++;
      if (idx >= slots.length) {
        const val = fn();
        slots.push({ kind: "memo", deps, value: val });
        return val;
      }
      const slot = slots[idx] as Extract<HookSlot, { kind: "memo" }>;
      if (depsChanged(slot.deps, deps)) {
        slot.value = fn();
        slot.deps = deps;
      }
      return slot.value as T;
    },
    useCallback<T extends (...args: never[]) => unknown>(fn: T, deps?: unknown[]): T {
      return hookRuntime.useMemo(() => fn, deps);
    },
  };
});

vi.mock("react", async () => {
  const actual = await vi.importActual<typeof import("react")>("react");
  return {
    ...actual,
    useState: hookRuntime.useState,
    useRef: hookRuntime.useRef,
    useEffect: hookRuntime.useEffect,
    useMemo: hookRuntime.useMemo,
    useCallback: hookRuntime.useCallback,
  };
});

const apiMocks = vi.hoisted(() => ({
  updateCleanProfileStep: vi.fn(async () => ({})),
  createCleanProfile: vi.fn(async (input: { label: string; provider: string; browser_engine: string; bound_route_id: string | null }) => ({
    id: "created-1",
    label: input.label,
    provider: input.provider,
    browser_engine: input.browser_engine,
    bound_route_id: input.bound_route_id,
    status: "ready",
    launchpad_step: 1,
    completed_checklist: [],
    created_at: 1,
    last_exit_ip: null,
    last_exit_country: null,
    warmup_started_at: null,
  })),
  runCleanRoomAudit: vi.fn(),
  discoverCleanBrowsers: vi.fn(async () => [
    { engine: "chrome", display_name: "Chrome", available: true, executable_path: "/Applications/Chrome.app" },
  ]),
}));

vi.mock("../../utils/api", async () => {
  const actual = await vi.importActual<typeof import("../../utils/api")>("../../utils/api");
  return {
    ...actual,
    updateCleanProfileStep: apiMocks.updateCleanProfileStep,
    createCleanProfile: apiMocks.createCleanProfile,
    runCleanRoomAudit: apiMocks.runCleanRoomAudit,
    discoverCleanBrowsers: apiMocks.discoverCleanBrowsers,
  };
});

import type { CleanRoomAuditReport, CleanRoomProfile, RouteView } from "../../types";
import { cleanRoom as copy } from "../../shared/copy/ru/cleanRoom";
import { Button, Select } from "../../ui";
import { LaunchpadSteps } from "./LaunchpadSteps";
import { SandboxProfilesCard } from "./SandboxProfilesCard";
import { PreFlightAuditCard } from "./PreFlightAuditCard";

function mountComponent<P>(Component: (props: P) => ReactElement | null, initialProps: P) {
  let latestProps = initialProps;
  const box: { result: ReactElement | null } = { result: null };
  const render = () => {
    hookRuntime.beginRender();
    box.result = Component(latestProps);
  };
  hookRuntime.reset(render);
  render();
  hookRuntime.flushEffects();

  return {
    get result() {
      return box.result;
    },
    async rerender(nextProps: P) {
      latestProps = nextProps;
      render();
      hookRuntime.flushEffects();
      await Promise.resolve();
      await Promise.resolve();
    },
    async settle() {
      await Promise.resolve();
      await Promise.resolve();
      await new Promise((r) => setTimeout(r, 0));
      hookRuntime.flushEffects();
    },
    unmount() {
      hookRuntime.reset(() => {});
    },
  };
}

function findAllInTree(node: ReactNode, pred: (el: ReactElement) => boolean): ReactElement[] {
  const found: ReactElement[] = [];
  const walk = (n: unknown) => {
    if (!n || typeof n !== "object") return;
    if (Array.isArray(n)) {
      n.forEach(walk);
      return;
    }
    const el = n as ReactElement<Record<string, unknown>>;
    if (el.type && el.props && typeof el.props === "object") {
      if (pred(el)) found.push(el);
      for (const val of Object.values(el.props)) {
        walk(val);
      }
    }
  };
  walk(node);
  return found;
}

function makeProfile(overrides: Partial<CleanRoomProfile> = {}): CleanRoomProfile {
  return {
    id: "p1",
    label: "Claude Work",
    provider: "anthropic",
    browser_engine: "chrome",
    status: "ready",
    bound_route_id: "r1",
    launchpad_step: 1,
    completed_checklist: [],
    created_at: 1,
    last_exit_ip: null,
    last_exit_country: null,
    last_opened_at: null,
    warmup_started_at: null,
    ...overrides,
  };
}

function makeRoute(id: string, label: string): RouteView {
  return {
    id,
    label,
    country: "NL",
    exit_ip: "185.10.10.1",
    enabled: true,
    expires_at: null,
    is_default: id === "r1",
    added_at: 1,
    entries: [],
    status: "active",
    bound_providers: [],
    is_profile_route: false,
  };
}

function makeAudit(exitIp: string): CleanRoomAuditReport {
  return {
    ready_to_launch: true,
    critical_count: 0,
    warning_count: 0,
    exit_ip: exitIp,
    exit_country: "NL",
    exit_timezone: "Europe/Amsterdam",
    os_tz_matches_exit: true,
    ip_is_tainted: false,
    findings: [],
    checked_at: Date.now(),
  };
}

describe("Clean Room QA Regression (P1 #1, #2, #6 & P2 #1)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("P1 #1: LaunchpadSteps blocks Step 2–4 tab bar and Step 3 advance when Step 1 readiness gate is closed", async () => {
    const m = mountComponent(LaunchpadSteps, {
      activeProfile: makeProfile({ launchpad_step: 1 }),
      exitCountry: "NL",
      readyToLaunch: false,
      manualKillswitch: false,
    });

    const tabs = findAllInTree(
      m.result,
      (el) => el.type === "button" && (el.props as { role?: string }).role === "tab",
    );
    expect(tabs).toHaveLength(4);
    expect((tabs[0].props as { disabled?: boolean }).disabled).toBe(false);
    expect((tabs[1].props as { disabled?: boolean }).disabled).toBe(true);
    expect((tabs[2].props as { disabled?: boolean }).disabled).toBe(true);
    expect((tabs[3].props as { disabled?: boolean }).disabled).toBe(true);

    (tabs[1].props as { onClick: () => void }).onClick();
    await m.settle();

    expect(apiMocks.updateCleanProfileStep).not.toHaveBeenCalled();
    const tabsAfter = findAllInTree(
      m.result,
      (el) => el.type === "button" && (el.props as { role?: string }).role === "tab",
    );
    expect((tabsAfter[0].props as { "aria-selected": boolean })["aria-selected"]).toBe(true);

    await m.rerender({
      activeProfile: makeProfile({ launchpad_step: 2 }),
      exitCountry: "NL",
      readyToLaunch: false,
      manualKillswitch: false,
    });
    const nextStep3Btns = findAllInTree(
      m.result,
      (el) =>
        el.type === Button &&
        String((el.props as { children?: unknown }).children ?? "") === copy.launchpad.step2.nextBtn,
    );
    expect(nextStep3Btns.length).toBe(1);
    expect((nextStep3Btns[0].props as { disabled?: boolean }).disabled).toBe(true);

    m.unmount();
  });

  it("P1 #2 & #6: SandboxProfilesCard keeps DIRECT_VALUE when routes.length > 0 and keeps max 1 primary CTA when create form is open", async () => {
    const routes = [makeRoute("r1", "NL Route")];
    const m = mountComponent(SandboxProfilesCard, {
      profiles: [makeProfile()],
      activeProfileId: "p1",
      routes,
      readyToLaunch: true,
      initialBrowsers: [
        { engine: "chrome", display_name: "Chrome", available: true, executable_path: "/Applications/Chrome.app" },
      ],
      openCreateTrigger: 1,
      onSelectProfile: vi.fn(),
    });

    await m.settle();

    // Only 1 variant="primary" button should exist while showCreate is open
    const primaryBtns = findAllInTree(
      m.result,
      (el) => el.type === Button && (el.props as { variant?: string }).variant === "primary",
    );
    expect(primaryBtns).toHaveLength(1);

    // Find route Select inside the create form and switch to __direct__
    const selects = findAllInTree(
      m.result,
      (el) => el.type === Select && (el.props as { label?: string }).label === copy.sandbox.form.routeField,
    );
    expect(selects.length).toBe(1);
    (selects[0].props as { onChange: (e: { target: { value: string } }) => void }).onChange({
      target: { value: "__direct__" },
    });
    await m.settle();

    // Must NOT snap back to routes[0].id ("r1")
    const selectsAfter = findAllInTree(
      m.result,
      (el) => el.type === Select && (el.props as { label?: string }).label === copy.sandbox.form.routeField,
    );
    expect((selectsAfter[0].props as { value: string }).value).toBe("__direct__");

    // Submit form -> bound_route_id must be null
    const forms = findAllInTree(m.result, (el) => el.type === "form");
    expect(forms).toHaveLength(1);
    (forms[0].props as { onSubmit: (e: { preventDefault: () => void }) => void }).onSubmit({
      preventDefault: () => {},
    });
    await m.settle();

    expect(apiMocks.createCleanProfile).toHaveBeenCalledWith(
      expect.objectContaining({ bound_route_id: null }),
    );

    m.unmount();
  });

  it("P2 #1: PreFlightAuditCard scanSeqRef ignores stale slower audit response after newer route scan", async () => {
    let resolveFirst!: (v: CleanRoomAuditReport) => void;
    let resolveSecond!: (v: CleanRoomAuditReport) => void;
    apiMocks.runCleanRoomAudit
      .mockImplementationOnce(() => new Promise<CleanRoomAuditReport>((r) => { resolveFirst = r; }))
      .mockImplementationOnce(() => new Promise<CleanRoomAuditReport>((r) => { resolveSecond = r; }));

    const onAuditUpdated = vi.fn();
    const m = mountComponent(PreFlightAuditCard, {
      activeProfileId: "p1",
      activeProfileRouteId: "r1",
      routes: [makeRoute("r1", "NL"), makeRoute("r2", "DE")],
      onAuditUpdated,
    });

    await m.settle();
    expect(apiMocks.runCleanRoomAudit).toHaveBeenCalledTimes(1);

    // Switch route -> triggers 2nd scan
    const routeSelects = findAllInTree(
      m.result,
      (el) => el.type === Select && (el.props as { label?: string }).label === copy.audit.routeField,
    );
    expect(routeSelects).toHaveLength(1);
    (routeSelects[0].props as { onChange: (e: { target: { value: string } }) => void }).onChange({
      target: { value: "r2" },
    });
    await m.settle();
    expect(apiMocks.runCleanRoomAudit).toHaveBeenCalledTimes(2);

    // Resolve 2nd (newer) scan first, then 1st (stale) scan
    resolveSecond(makeAudit("2.2.2.2"));
    await m.settle();
    resolveFirst(makeAudit("1.1.1.1"));
    await m.settle();

    expect(onAuditUpdated).toHaveBeenCalledTimes(1);
    expect(onAuditUpdated).toHaveBeenLastCalledWith(expect.objectContaining({ exit_ip: "2.2.2.2" }));

    m.unmount();
  });
});

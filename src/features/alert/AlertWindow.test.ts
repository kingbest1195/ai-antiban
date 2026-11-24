import { beforeEach, describe, expect, it, vi } from "vitest";
import type { EnrichedPayload, GuardPauseStatus, RiskInterceptPayload } from "../../types";

const listeners = vi.hoisted(() => new Map<string, Array<(event: { payload: unknown }) => void>>());

const hookRuntime = vi.hoisted(() => {
  type Slot =
    | { kind: "state"; value: unknown }
    | { kind: "reducer"; value: unknown }
    | { kind: "ref"; value: { current: unknown } }
    | { kind: "memo"; deps: unknown[] | undefined; value: unknown }
    | { kind: "effect"; deps: unknown[] | undefined; cleanup?: () => void };

  let slots: Slot[] = [];
  let cursor = 0;
  let pending: Array<{ idx: number; fn: () => void | (() => void); deps: unknown[] | undefined }> = [];
  let renderFn: (() => void) | null = null;

  function depsChanged(prev: unknown[] | undefined, next: unknown[] | undefined): boolean {
    if (!prev || !next) return true;
    if (prev.length !== next.length) return true;
    for (let i = 0; i < prev.length; i++) {
      if (!Object.is(prev[i], next[i])) return true;
    }
    return false;
  }

  return {
    reset(fn: () => void) {
      for (const s of slots) if (s.kind === "effect") s.cleanup?.();
      slots = [];
      cursor = 0;
      pending = [];
      renderFn = fn;
    },
    beginRender() {
      cursor = 0;
    },
    flush() {
      const q = pending;
      pending = [];
      for (const item of q) {
        const slot = slots[item.idx] as Extract<Slot, { kind: "effect" }>;
        slot.cleanup?.();
        slot.deps = item.deps;
        const c = item.fn();
        slot.cleanup = typeof c === "function" ? c : undefined;
      }
    },
    useState<T>(initial: T | (() => T)): [T, (next: T | ((prev: T) => T)) => void] {
      const idx = cursor++;
      if (idx >= slots.length) {
        const val = typeof initial === "function" ? (initial as () => T)() : initial;
        slots.push({ kind: "state", value: val });
      }
      const slot = slots[idx] as Extract<Slot, { kind: "state" }>;
      const setState = (next: T | ((prev: T) => T)) => {
        const resolved = typeof next === "function" ? (next as (prev: T) => T)(slot.value as T) : next;
        if (!Object.is(slot.value, resolved)) {
          slot.value = resolved;
          if (renderFn) {
            renderFn();
            this.flush();
          }
        }
      };
      return [slot.value as T, setState];
    },
    useReducer<S, A>(reducer: (s: S, a: A) => S, initialArg: unknown, init?: (arg: unknown) => S): [S, (a: A) => void] {
      const idx = cursor++;
      if (idx >= slots.length) {
        const val = init ? init(initialArg) : (initialArg as S);
        slots.push({ kind: "reducer", value: val });
      }
      const slot = slots[idx] as Extract<Slot, { kind: "reducer" }>;
      const dispatch = (action: A) => {
        const next = reducer(slot.value as S, action);
        if (!Object.is(slot.value, next)) {
          slot.value = next;
          if (renderFn) {
            renderFn();
            this.flush();
          }
        }
      };
      return [slot.value as S, dispatch];
    },
    useRef<T>(initial: T): { current: T } {
      const idx = cursor++;
      if (idx >= slots.length) slots.push({ kind: "ref", value: { current: initial } });
      return (slots[idx] as Extract<Slot, { kind: "ref" }>).value as { current: T };
    },
    useEffect(fn: () => void | (() => void), deps?: unknown[]) {
      const idx = cursor++;
      if (idx >= slots.length) {
        slots.push({ kind: "effect", deps: undefined });
        pending.push({ idx, fn, deps });
      } else {
        const slot = slots[idx] as Extract<Slot, { kind: "effect" }>;
        if (depsChanged(slot.deps, deps)) pending.push({ idx, fn, deps });
      }
    },
    useCallback<T extends (...args: never[]) => unknown>(fn: T, deps?: unknown[]): T {
      const idx = cursor++;
      if (idx >= slots.length) {
        slots.push({ kind: "memo", deps, value: fn });
        return fn;
      }
      const slot = slots[idx] as Extract<Slot, { kind: "memo" }>;
      if (depsChanged(slot.deps, deps)) {
        slot.deps = deps;
        slot.value = fn;
      }
      return slot.value as T;
    },
    getReducerState<S>(): S {
      const slot = slots.find((s) => s.kind === "reducer") as Extract<Slot, { kind: "reducer" }>;
      return slot.value as S;
    },
  };
});

const apiMocks = vi.hoisted(() => ({
  getGuardPauseStatus: vi.fn(async (): Promise<GuardPauseStatus> => ({
    paused: true,
    mode: "until_network_change",
    gate: "blocked",
    manual_killswitch: false,
  })),
  getHideIpMode: vi.fn(async () => true),
  resolveInterception: vi.fn(async () => true),
  takePendingAlert: vi.fn(async (): Promise<RiskInterceptPayload | null> => null),
}));

vi.mock("react", () => ({
  useState: hookRuntime.useState.bind(hookRuntime),
  useReducer: hookRuntime.useReducer.bind(hookRuntime),
  useRef: hookRuntime.useRef.bind(hookRuntime),
  useEffect: hookRuntime.useEffect.bind(hookRuntime),
  useCallback: hookRuntime.useCallback.bind(hookRuntime),
}));

vi.mock("react/jsx-runtime", () => ({
  jsx: () => null,
  jsxs: () => null,
  Fragment: "Fragment",
}));

vi.mock("@tauri-apps/api/core", () => ({
  isTauri: () => true,
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async (event: string, cb: (e: { payload: unknown }) => void) => {
    const arr = listeners.get(event) ?? [];
    arr.push(cb);
    listeners.set(event, arr);
    return () => {
      const next = (listeners.get(event) ?? []).filter((f) => f !== cb);
      listeners.set(event, next);
    };
  }),
}));

vi.mock("../../utils/api", () => ({
  MOCK_ALERT_DETECTED_EVENT: "mock-alert-detected",
  MOCK_ALERT_ENRICHED_EVENT: "mock-alert-enriched",
  getGuardPauseStatus: apiMocks.getGuardPauseStatus,
  getHideIpMode: apiMocks.getHideIpMode,
  resolveInterception: apiMocks.resolveInterception,
  takePendingAlert: apiMocks.takePendingAlert,
}));

vi.mock("../../ui", () => ({
  Button: () => null,
  Dialog: () => null,
  Skeleton: () => null,
}));

vi.mock("./CheckoutAlertView", () => ({
  CheckoutAlertView: () => null,
}));

vi.mock("./alert.css", () => ({}));

import { AlertWindow } from "./AlertWindow";
import type { AlertState } from "./alertState";

function emitEvent(name: string, payload: unknown) {
  for (const cb of listeners.get(name) ?? []) {
    cb({ payload });
  }
}

describe("AlertWindow guardPausedRef", () => {
  beforeEach(() => {
    listeners.clear();
    vi.clearAllMocks();
    (globalThis as unknown as { window: Record<string, unknown> }).window = {
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    };
  });

  it("не дропает interceptor://enriched для текущего alert.id при stale guardPausedRef и не дёргает getGuardPauseStatus на каждом событии", async () => {
    const render = () => {
      hookRuntime.beginRender();
      AlertWindow({ hideIpMode: true });
    };
    hookRuntime.reset(render);
    render();
    hookRuntime.flush();

    // Начальный getGuardPauseStatus на монтировании вернул paused: true (stale).
    await Promise.resolve();
    await Promise.resolve();
    expect(apiMocks.getGuardPauseStatus).toHaveBeenCalledTimes(1);

    // Приходит detecting для alert-1 (снимает guardPausedRef), затем пауза могла бы мигнуть,
    // но для текущего alert-1 enriched всё равно должен примениться.
    const detected: RiskInterceptPayload = {
      id: "alert-1",
      provider: "anthropic",
      host: "claude.ai",
      report: null,
      ttl_seconds: 60,
      scope: "network",
      detected_at_ms: 1,
      phase: "detecting",
    };
    emitEvent("interceptor://risk-detected", detected);
    expect(hookRuntime.getReducerState<AlertState>().payload?.id).toBe("alert-1");
    expect(hookRuntime.getReducerState<AlertState>().payload?.phase).toBe("detecting");

    // Даже если pause-status-changed не приходил или ещё не обновился, enriched для alert-1 применяется:
    const enriched: EnrichedPayload = {
      id: "alert-1",
      epoch: 1,
      phase: "ready",
      network_change: { old_ip: "1.1.1.1", new_ip: "5.5.5.5", new_country: "NL" },
    };
    emitEvent("interceptor://enriched", enriched);

    const state = hookRuntime.getReducerState<AlertState>();
    expect(state.payload?.phase).toBe("ready");
    expect(state.payload?.network_change?.new_ip).toBe("5.5.5.5");

    // Повторный risk-detected при paused === true не должен делать лишних IPC getGuardPauseStatus().
    emitEvent("guard://pause-status-changed", {
      paused: true,
      mode: "until_network_change",
      gate: "blocked",
      manual_killswitch: false,
    } satisfies GuardPauseStatus);
    emitEvent("interceptor://risk-detected", { ...detected, id: "alert-2", phase: "ready" });

    expect(apiMocks.getGuardPauseStatus).toHaveBeenCalledTimes(1);
    expect(hookRuntime.getReducerState<AlertState>().payload).toBeNull();
  });
});

import { describe, expect, it, vi } from "vitest";

const hookRuntime = vi.hoisted(() => {
  type Slot =
    | { kind: "state"; value: unknown }
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
    useCallback<T extends (...args: never[]) => unknown>(fn: T): T {
      return fn;
    },
  };
});

const apiMocks = vi.hoisted(() => ({
  resolveInterception: vi.fn(async () => true),
  simulateInterception: vi.fn(async () => {}),
}));

vi.mock("react", () => ({
  useState: hookRuntime.useState.bind(hookRuntime),
  useEffect: hookRuntime.useEffect.bind(hookRuntime),
  useCallback: hookRuntime.useCallback.bind(hookRuntime),
}));

vi.mock("../../utils/api", () => apiMocks);

import { useInterception } from "./useInterception";

describe("useInterception", () => {
  it("handleAllowInterception не дублирует runFullAudit(false) после AllowSession", async () => {
    const runFullAudit = vi.fn(async () => {});
    const showToast = vi.fn();
    let hook: ReturnType<typeof useInterception> | null = null;
    const render = () => {
      hookRuntime.beginRender();
      hook = useInterception({ runFullAudit, showToast });
    };
    hookRuntime.reset(render);
    render();
    hookRuntime.flush();

    hook!.setInterceptPayload({
      id: "alert-1",
      provider: "anthropic",
      host: "claude.ai",
      report: null,
      ttl_seconds: 60,
      scope: "network",
      detected_at_ms: 1,
      phase: "ready",
    });

    await hook!.handleAllowInterception(false);

    expect(apiMocks.resolveInterception).toHaveBeenCalledWith(
      "alert-1",
      "AllowSession",
      "anthropic",
      "network",
      false,
    );
    expect(showToast).toHaveBeenCalledTimes(1);
    expect(hook!.interceptPayload).toBeNull();
    expect(runFullAudit).not.toHaveBeenCalled();
  });
});

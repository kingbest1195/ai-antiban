import { describe, expect, it, vi } from "vitest";
import type { CheckResult, ProviderId, RiskReport } from "../../types";

const hookRuntime = vi.hoisted(() => {
  type Slot =
    | { kind: "state"; value: unknown }
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
    useRef<T>(initial: T): { current: T } {
      const idx = cursor++;
      if (idx >= slots.length) slots.push({ kind: "ref", value: { current: initial } });
      return (slots[idx] as Extract<Slot, { kind: "ref" }>).value as { current: T };
    },
    useMemo<T>(factory: () => T, deps: unknown[]): T {
      const idx = cursor++;
      if (idx >= slots.length) {
        const value = factory();
        slots.push({ kind: "memo", deps, value });
        return value;
      }
      const slot = slots[idx] as Extract<Slot, { kind: "memo" }>;
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
        pending.push({ idx, fn, deps });
      } else {
        const slot = slots[idx] as Extract<Slot, { kind: "effect" }>;
        if (depsChanged(slot.deps, deps)) pending.push({ idx, fn, deps });
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

const okCheck: CheckResult = { status: "ok", code: "OK", message: "ok" };

function makeReport(provider: ProviderId, gatewayLatencyMs?: number | null): RiskReport {
  return {
    provider,
    overall_status: "green",
    trust_score: 100,
    telemetry: { ip: "185.212.102.40", country_code: "NL", resolved_at: 1 },
    geo_result: okCheck,
    pinning_result: okCheck,
    travel_result: okCheck,
    dnsbl_result: okCheck,
    dnsbl_clean_count: "4/4",
    asn_result: okCheck,
    ipv6_result: okCheck,
    timezone_result: okCheck,
    checks: [],
    gateway_latency_ms: gatewayLatencyMs,
  };
}

const latencyHolder = vi.hoisted(() => ({ value: 48 as number | null }));

vi.mock("../../utils/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../utils/api")>();
  return {
    ...actual,
    auditConnection: vi.fn(async (provider: ProviderId) => makeReport(provider, latencyHolder.value)),
    fetchAppState: vi.fn(async () => ({
      pinned_ip: null,
      strict_pinning_enabled: true,
      ip_history: {},
      session_allowed_providers: [],
      blocked_providers: [],
      dismissed_hints: [],
      auto_update_enabled: true,
    })),
    getCoverageSnapshot: vi.fn(async () => ({ items: [] })),
    getRoutesSnapshot: vi.fn(async () => ({ routes: [], provider_routes: {}, effective: {}, dangling: [] })),
    getStartupState: vi.fn(async () => ({ phase: "ready" })),
    getSysproxyStatus: vi.fn(async () => true),
    onAuditProgress: vi.fn(async () => () => {}),
    onAuditRefreshed: vi.fn(async () => () => {}),
    onStartupChanged: vi.fn(async () => () => {}),
  };
});

import { useGatewayState } from "./useGatewayState";

describe("useGatewayState — gateway_latency_ms (4252 мс regression)", () => {
  it("предпочитает RiskReport.gateway_latency_ms вместо wall-clock времени полного аудита", async () => {
    const prevWindow = (globalThis as { window?: unknown }).window;
    const prevDocument = (globalThis as { document?: unknown }).document;
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      value: { addEventListener: vi.fn(), removeEventListener: vi.fn() },
    });
    Object.defineProperty(globalThis, "document", {
      configurable: true,
      value: { visibilityState: "visible", addEventListener: vi.fn(), removeEventListener: vi.fn() },
    });

    try {
      let result: ReturnType<typeof useGatewayState> | null = null;
      const render = () => {
        hookRuntime.beginRender();
        result = useGatewayState({ showToast: vi.fn(), refreshGatewayStats: vi.fn(async () => {}) });
      };

      latencyHolder.value = 64;
      hookRuntime.reset(render);
      render();
      hookRuntime.flush();

      await result!.runFullAudit(true, true);
      expect(result!.scanLatencyMs).toBe(64);

      // При отсутствии gateway_latency_ms возвращается fallback (>= 18 ms)
      latencyHolder.value = null;
      await result!.runFullAudit(true, true);
      expect(typeof result!.scanLatencyMs).toBe("number");
      expect(result!.scanLatencyMs!).toBeGreaterThanOrEqual(18);

      // P1 #5: gateway_latency_ms === 0 не должен падать на fallback (>= 18 ms)
      latencyHolder.value = 0;
      await result!.runFullAudit(true, true);
      expect(result!.scanLatencyMs).toBe(0);

      // P1 #5: runProviderAudit обновляет scanLatencyMs из report.gateway_latency_ms
      latencyHolder.value = 42;
      await result!.runProviderAudit("openai", true);
      expect(result!.scanLatencyMs).toBe(42);

      latencyHolder.value = 0;
      await result!.runProviderAudit("gemini", true);
      expect(result!.scanLatencyMs).toBe(0);
    } finally {
      Object.defineProperty(globalThis, "window", { configurable: true, value: prevWindow });
      Object.defineProperty(globalThis, "document", { configurable: true, value: prevDocument });
    }
  });
});

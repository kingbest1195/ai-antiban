import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const hookRuntime = vi.hoisted(() => {
  type Slot =
    | { kind: "state"; value: unknown }
    | { kind: "ref"; value: { current: unknown } }
    | { kind: "memo"; deps: unknown[] | undefined; value: unknown };

  let slots: Slot[] = [];
  let cursor = 0;

  function depsChanged(prev: unknown[] | undefined, next: unknown[] | undefined): boolean {
    if (!prev || !next) return true;
    if (prev.length !== next.length) return true;
    for (let i = 0; i < prev.length; i++) {
      if (!Object.is(prev[i], next[i])) return true;
    }
    return false;
  }

  return {
    reset() {
      slots = [];
      cursor = 0;
    },
    useState<T>(initial: T | (() => T)): [T, (next: T | ((prev: T) => T)) => void] {
      const idx = cursor++;
      if (idx >= slots.length) {
        const val = typeof initial === "function" ? (initial as () => T)() : initial;
        slots.push({ kind: "state", value: val });
      }
      const slot = slots[idx] as Extract<Slot, { kind: "state" }>;
      const setState = (next: T | ((prev: T) => T)) => {
        slot.value = typeof next === "function" ? (next as (prev: T) => T)(slot.value as T) : next;
      };
      return [slot.value as T, setState];
    },
    useRef<T>(initial: T): { current: T } {
      const idx = cursor++;
      if (idx >= slots.length) slots.push({ kind: "ref", value: { current: initial } });
      return (slots[idx] as Extract<Slot, { kind: "ref" }>).value as { current: T };
    },
    useEffect() {},
    useMemo<T>(fn: () => T, deps?: unknown[]): T {
      const idx = cursor++;
      if (idx >= slots.length) {
        const val = fn();
        slots.push({ kind: "memo", deps, value: val });
        return val;
      }
      const slot = slots[idx] as Extract<Slot, { kind: "memo" }>;
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

const clipboardMock = vi.hoisted(() => ({
  writeClipboard: vi.fn(async () => true),
}));

const apiMocks = vi.hoisted(() => ({
  pinCurrentIp: vi.fn(async () => ({})),
  removeTrustedException: vi.fn(async () => ({ trusted_exceptions: {} })),
}));

vi.mock("../lib/clipboard", () => ({
  writeClipboard: clipboardMock.writeClipboard,
}));

vi.mock("../../utils/api", async () => {
  const actual = await vi.importActual<typeof import("../../utils/api")>("../../utils/api");
  return {
    ...actual,
    pinCurrentIp: apiMocks.pinCurrentIp,
    removeTrustedException: apiMocks.removeTrustedException,
  };
});

import { usePinning } from "./usePinning";
import { useSettingsExceptions } from "../../features/settings/useSettingsExceptions";
import { CheckRow } from "../../features/checks/CheckRow";
import type { PrioritizedCheckItem } from "../../features/checks/checksModel";

describe("hideIpMode leak regression (P1 #3 & P2 #2)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    hookRuntime.reset();
  });

  it("usePinning: handleCopyIp копирует реальный IP, но в тосте показывает замаскированный при hideIpMode=true", async () => {
    const prevWindow = (globalThis as { window?: unknown }).window;
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      value: { setTimeout: vi.fn(() => 1), clearTimeout: vi.fn() },
    });

    try {
      const showToast = vi.fn();
      const hooks = usePinning({
        state: null,
        refreshState: vi.fn(async () => ({}) as never),
        runFullAudit: vi.fn(async () => {}),
        showToast,
        currentIp: "185.220.101.5",
        hideIpMode: true,
      });

      await hooks.handleCopyIp();
      expect(clipboardMock.writeClipboard).toHaveBeenCalledWith("185.220.101.5");
      expect(showToast).toHaveBeenCalledTimes(1);
      expect(String(showToast.mock.calls[0][1])).not.toContain("185.220.101.5");
      expect(String(showToast.mock.calls[0][1])).toContain("•••.•••.•••.5");

      await hooks.handlePinIp("185.220.101.5", "anthropic");
      expect(apiMocks.pinCurrentIp).toHaveBeenCalledWith("185.220.101.5", "anthropic");
      expect(showToast).toHaveBeenCalledTimes(2);
      expect(String(showToast.mock.calls[1][1])).not.toContain("185.220.101.5");
      expect(String(showToast.mock.calls[1][1])).toContain("•••.•••.•••.5");
    } finally {
      Object.defineProperty(globalThis, "window", { configurable: true, value: prevWindow });
    }
  });

  it("useSettingsExceptions: handleRemoveTrustedException маскирует IP в тосте при hideIpMode=true", async () => {
    const onToast = vi.fn();
    const hooks = useSettingsExceptions({
      customDomains: [],
      setCustomDomains: vi.fn(),
      disabledProviders: [],
      setDisabledProviders: vi.fn(),
      trustedExceptions: { anthropic: ["185.220.101.5"] },
      setTrustedExceptions: vi.fn(),
      hideIpMode: true,
      onToast,
    });

    await hooks.handleRemoveTrustedException("anthropic", "185.220.101.5");
    expect(apiMocks.removeTrustedException).toHaveBeenCalledWith("anthropic", "185.220.101.5");
    expect(onToast).toHaveBeenCalledTimes(1);
    expect(String(onToast.mock.calls[0][1])).not.toContain("185.220.101.5");
    expect(String(onToast.mock.calls[0][1])).toContain("•••.•••.•••.5");
  });

  it("CheckRow: маскирует IP в item.result.measured_via при hideIpMode=true", () => {
    const item: PrioritizedCheckItem = {
      id: "claude_exit",
      title: "Выход домена ИИ",
      what: "Проверка выхода",
      cls: "ok",
      pending: false,
      missing: false,
      tier: 2,
      rank: 1,
      advisory: false,
      group: "leaks",
      ok: true,
      data: [],
      action: null,
      advice: null,
      result: {
        status: "ok",
        code: "OK",
        message: "Выход через 185.220.101.5",
        measured_via: "HTTPS proxy 185.220.101.5:8443",
        reason: null,
      },
      help: null,
    };

    const html = renderToStaticMarkup(
      createElement(CheckRow, {
        item,
        providerName: "Claude",
        showPriority: false,
        view: { tone: "ok", icon: "check", word: "ОК", busy: false },
        open: true,
        onToggle: () => {},
        onAction: () => {},
        onGuide: () => {},
        hideIpMode: true,
      }),
    );

    expect(html).not.toContain("185.220.101.5");
    expect(html).toContain("•••.•••.•••.5");
  });
});

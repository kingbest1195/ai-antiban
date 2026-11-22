import type { ReactElement, ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const hookRuntime = vi.hoisted(() => {
  type HookSlot =
    | { kind: "state"; value: unknown }
    | { kind: "effect"; deps: unknown[] | undefined; run: () => void | (() => void) };
  let slots: HookSlot[] = [];
  let cursor = 0;
  let pendingEffects: Array<() => void> = [];
  let currentRender: (() => void) | null = null;

  return {
    reset(renderFn: () => void) {
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
      for (const run of queue) run();
    },
    useState<T>(initial: T | (() => T)): [T, (next: T | ((prev: T) => T)) => void] {
      const idx = cursor++;
      if (idx >= slots.length) {
        const val = typeof initial === "function" ? (initial as () => T)() : initial;
        slots.push({ kind: "state", value: val });
      }
      const slot = slots[idx] as Extract<HookSlot, { kind: "state" }>;
      return [
        slot.value as T,
        (next) => {
          const resolved = typeof next === "function" ? (next as (prev: T) => T)(slot.value as T) : next;
          if (!Object.is(slot.value, resolved)) {
            slot.value = resolved;
            currentRender?.();
          }
        },
      ];
    },
    useEffect(fn: () => void | (() => void), deps?: unknown[]) {
      const idx = cursor++;
      if (idx >= slots.length) {
        slots.push({ kind: "effect", deps, run: fn });
        pendingEffects.push(() => {
          fn();
        });
      }
    },
  };
});

vi.mock("react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react")>();
  return {
    ...actual,
    useState: hookRuntime.useState.bind(hookRuntime),
    useEffect: hookRuntime.useEffect.bind(hookRuntime),
  };
});

const apiMocks = vi.hoisted(() => ({
  getKeepSystemTzOnExit: vi.fn(async () => true),
  setKeepSystemTzOnExit: vi.fn(async (enabled: boolean) => enabled),
}));

vi.mock("../../../utils/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../utils/api")>();
  return {
    ...actual,
    getKeepSystemTzOnExit: apiMocks.getKeepSystemTzOnExit,
    setKeepSystemTzOnExit: apiMocks.setKeepSystemTzOnExit,
  };
});

import { settings as copy } from "../../../shared/copy/ru";
import { Button, Switch } from "../../../ui";
import { TerminalSection } from "./TerminalSection";

function collectAll(
  node: ReactNode,
  pred: (el: ReactElement<Record<string, unknown>>) => boolean,
  out: Array<ReactElement<Record<string, unknown>>> = [],
): Array<ReactElement<Record<string, unknown>>> {
  if (!node || typeof node === "boolean" || typeof node === "string" || typeof node === "number") return out;
  if (Array.isArray(node)) {
    for (const c of node) collectAll(c, pred, out);
    return out;
  }
  if (typeof node === "object" && "type" in node && "props" in node) {
    const el = node as ReactElement<Record<string, unknown>>;
    if (pred(el)) out.push(el);
    if (el.props?.trail) collectAll(el.props.trail as ReactNode, pred, out);
    if (el.props?.children) collectAll(el.props.children as ReactNode, pred, out);
  }
  return out;
}

describe("TerminalSection keep_system_tz_on_exit", () => {
  beforeEach(() => {
    apiMocks.getKeepSystemTzOnExit.mockReset();
    apiMocks.getKeepSystemTzOnExit.mockResolvedValue(true);
    apiMocks.setKeepSystemTzOnExit.mockReset();
    apiMocks.setKeepSystemTzOnExit.mockImplementation(async (enabled: boolean) => enabled);
  });

  it("читает get_keep_system_tz_on_exit и вызывает set_keep_system_tz_on_exit при переключении тумблера", async () => {
    let tree: ReactNode = null;
    const render = () => {
      hookRuntime.beginRender();
      tree = TerminalSection({
        cliMode: "ai_only",
        syncTz: true,
        terminalBusy: false,
        osTzStatus: null,
        osTzLoading: false,
        osTzError: null,
        onCliModeChange: vi.fn(),
        onToggleSyncTz: vi.fn(),
        onSyncOsTimezone: vi.fn(async () => null),
        onRestoreOsTimezone: vi.fn(async () => null),
      });
    };

    hookRuntime.reset(render);
    render();
    hookRuntime.flushEffects();
    await new Promise((r) => setTimeout(r, 0));

    expect(apiMocks.getKeepSystemTzOnExit).toHaveBeenCalledTimes(1);

    const switches = collectAll(tree, (el) => el.type === Switch);
    const keepSwitch = switches.find((s) => s.props["aria-label"] === copy.terminal.keepOsTzOnExit.label);
    expect(keepSwitch).toBeDefined();
    expect(keepSwitch!.props.checked).toBe(true);

    (keepSwitch!.props.onChange as () => void)();
    await new Promise((r) => setTimeout(r, 0));

    expect(apiMocks.setKeepSystemTzOnExit).toHaveBeenCalledWith(false);
    const updatedSwitches = collectAll(tree, (el) => el.type === Switch);
    const updatedKeep = updatedSwitches.find((s) => s.props["aria-label"] === copy.terminal.keepOsTzOnExit.label);
    expect(updatedKeep!.props.checked).toBe(false);
  });

  it("использует человеческие подписи «Часовой пояс системы» и компактную кнопку в trail", () => {
    expect(copy.terminal.osTz.title).toContain("Часовой пояс системы");
    expect(copy.terminal.osTz.title).not.toContain("Системный пояс ОС");
    expect(copy.terminal.osTz.syncAction).toBe("Синхронизировать");
    expect(copy.terminal.osTz.restoreAction).toBe("Вернуть");

    let tree: ReactNode = null;
    const render = () => {
      hookRuntime.beginRender();
      tree = TerminalSection({
        cliMode: "ai_only",
        syncTz: true,
        terminalBusy: false,
        osTzStatus: {
          synced: false,
          current_os_tz: "Europe/Moscow",
          original_os_tz: null,
          synced_target_tz: null,
          auto_restore_pending: false,
        },
        osTzLoading: false,
        osTzError: null,
        onCliModeChange: vi.fn(),
        onToggleSyncTz: vi.fn(),
        onSyncOsTimezone: vi.fn(async () => null),
        onRestoreOsTimezone: vi.fn(async () => null),
      });
    };

    hookRuntime.reset(render);
    render();

    const buttons = collectAll(tree, (el) => el.type === Button);
    const syncBtn = buttons.find((b) => String(b.props.children) === "Синхронизировать");
    expect(syncBtn).toBeDefined();
  });
});

import { createElement } from "react";
import type { ReactElement, ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AppStateData, CheckResult, OsTzSyncStatus, RiskReport } from "../../types";

const hookRuntime = vi.hoisted(() => {
  const slots: Array<{ kind: "state"; value: unknown }> = [];
  let cursor = 0;
  return {
    reset() {
      slots.length = 0;
      cursor = 0;
    },
    beginRender() {
      cursor = 0;
    },
    useState<T>(initial: T | (() => T)): [T, (next: T | ((prev: T) => T)) => void] {
      const idx = cursor++;
      if (idx >= slots.length) {
        const val = typeof initial === "function" ? (initial as () => T)() : initial;
        slots.push({ kind: "state", value: val });
      }
      const slot = slots[idx];
      return [
        slot.value as T,
        (next) => {
          slot.value = typeof next === "function" ? (next as (prev: T) => T)(slot.value as T) : next;
        },
      ];
    },
  };
});

vi.mock("react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react")>();
  return {
    ...actual,
    useState: hookRuntime.useState.bind(hookRuntime),
    useEffect: vi.fn(),
    useCallback: <T extends (...args: never[]) => unknown>(fn: T): T => fn,
  };
});

import { Button, ExpandRow } from "../../ui";
import { CheckRow, statusOf } from "./CheckRow";
import { ChecksScreen } from "./ChecksScreen";
import { buildChecks, partitionChecksForProvider } from "./checksModel";

const ok = (code = "OK"): CheckResult => ({ status: "ok", code, message: "ok" });

function makeReport(tzResult: CheckResult): RiskReport {
  const checks = Array.from({ length: 14 }, (_, i) => (i === 7 ? tzResult : ok(`C${i}`)));
  return {
    provider: "anthropic",
    overall_status: tzResult.status === "ok" ? "green" : "yellow",
    trust_score: 92,
    telemetry: { ip: "185.212.102.40", country_code: "NL", timezone: "Europe/Amsterdam", resolved_at: 1 },
    geo_result: checks[0],
    pinning_result: checks[1],
    travel_result: checks[2],
    dnsbl_result: checks[3],
    dnsbl_clean_count: "",
    asn_result: checks[4],
    ipv6_result: checks[5],
    timezone_result: checks[7],
    checks,
  };
}

function makeState(over: Partial<AppStateData> = {}): AppStateData {
  return {
    pinned_ip: null,
    strict_pinning_enabled: true,
    ip_history: {},
    session_allowed_providers: [],
    blocked_providers: [],
    sync_ai_tz_enabled: true,
    synced_ai_timezone: "Europe/Amsterdam",
    ...over,
  };
}

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
    if (typeof el.type === "function" && el.type !== Button && el.type !== ExpandRow && el.type !== CheckRow) {
      collectAll((el.type as (p: Record<string, unknown>) => ReactNode)(el.props), pred, out);
      return out;
    }
    if (el.props?.trail) collectAll(el.props.trail as ReactNode, pred, out);
    if (el.props?.children) collectAll(el.props.children as ReactNode, pred, out);
  }
  return out;
}

describe("ChecksScreen & CheckRow timezone split + compact trail", () => {
  beforeEach(() => {
    hookRuntime.reset();
  });

  it("в ExpandRow trail строки timezone оставляет только компактный Badge (без широкой кнопки ОС) и держит раздельные строки внутри раскрытия", () => {
    const report = makeReport({
      status: "warning",
      code: "TIMEZONE_SYNCED_CLI_ONLY",
      message: "Редакторы синхронизированы, а пояс системы — нет",
    });
    const state = makeState();
    const { items } = buildChecks(report, state);
    const { actionItems } = partitionChecksForProvider(items, "anthropic");
    const tzItem = actionItems.find((i) => i.id === "timezone")!;
    const onToggle = vi.fn();
    const onAction = vi.fn();
    const onSyncOsTimezone = vi.fn();

    const tree = CheckRow({
      item: tzItem,
      providerName: "Claude",
      showPriority: true,
      hideIpMode: false,
      view: statusOf(tzItem, state, "anthropic"),
      open: true,
      onToggle,
      onAction,
      onGuide: vi.fn(),
      targetTz: "Europe/Amsterdam",
      cliTzSynced: true,
      cliSyncedZone: "Europe/Amsterdam",
      osTzStatus: {
        synced: false,
        current_os_tz: "Europe/Moscow",
        original_os_tz: null,
        synced_target_tz: null,
        auto_restore_pending: false,
      },
      onSyncOsTimezone,
      onRestoreOsTimezone: vi.fn(),
    });

    const expandEl = tree as ReactElement<Record<string, unknown>>;
    expect(expandEl.type).toBe(ExpandRow);
    const trailButtons = collectAll(expandEl.props.trail as ReactNode, (el) => el.type === Button);
    expect(trailButtons).toHaveLength(0);

    // Внутри раскрытия: две раздельные строки деталей — Редакторы и терминал и Часовой пояс системы
    const detailButtons = collectAll(expandEl.props.children as ReactNode, (el) => el.type === Button);
    const cliBtn = detailButtons.find((b) => String(b.props.children).includes("Синхронизировать редакторы"));
    const osBtn = detailButtons.find((b) => String(b.props.children).includes("Синхронизировать пояс"));
    expect(cliBtn).toBeDefined();
    expect(osBtn).toBeDefined();
    (cliBtn!.props.onClick as () => void)();
    expect(onAction).toHaveBeenCalledTimes(1);
    (osBtn!.props.onClick as () => void)();
    expect(onSyncOsTimezone).toHaveBeenCalledTimes(1);
    expect(onToggle).not.toHaveBeenCalled();
  });

  it("показывает «Вернуть пояс» только внутри раскрытых деталей при osTzStatus.synced === true и вызывает onRestoreOsTimezone", () => {
    const report = makeReport(ok("TIMEZONE_OK"));
    const state = makeState();
    const { items } = buildChecks(report, state);
    const { passedItems } = partitionChecksForProvider(items, "anthropic");
    const tzItem = passedItems.find((i) => i.id === "timezone")!;
    const onRestoreOsTimezone = vi.fn();
    const osStatus: OsTzSyncStatus = {
      synced: true,
      current_os_tz: "Europe/Amsterdam",
      original_os_tz: "Europe/Moscow",
      synced_target_tz: "Europe/Amsterdam",
      auto_restore_pending: true,
    };

    const tree = CheckRow({
      item: tzItem,
      providerName: "Claude",
      showPriority: false,
      hideIpMode: false,
      view: statusOf(tzItem, state, "anthropic"),
      open: true,
      onToggle: vi.fn(),
      onAction: vi.fn(),
      onGuide: vi.fn(),
      targetTz: "Europe/Amsterdam",
      cliTzSynced: true,
      cliSyncedZone: "Europe/Amsterdam",
      osTzStatus: osStatus,
      onSyncOsTimezone: vi.fn(),
      onRestoreOsTimezone,
    });

    const expandEl = tree as ReactElement<Record<string, unknown>>;
    const trailButtons = collectAll(expandEl.props.trail as ReactNode, (el) => el.type === Button);
    expect(trailButtons).toHaveLength(0);

    const detailButtons = collectAll(expandEl.props.children as ReactNode, (el) => el.type === Button);
    const restoreBtn = detailButtons.find((b) => String(b.props.children).includes("Вернуть пояс"));
    expect(restoreBtn).toBeDefined();
    (restoreBtn!.props.onClick as () => void)();
    expect(onRestoreOsTimezone).toHaveBeenCalledTimes(1);
  });

  it("ChecksScreen рендерит раздельные блоки «Редакторы и терминал» и «Часовой пояс системы» без вложенных button в button", () => {
    const report = makeReport({
      status: "warning",
      code: "TIMEZONE_SYNCED_CLI_ONLY",
      message: "Редакторы синхронизированы, а пояс системы — нет",
    });
    const html = renderToStaticMarkup(
      createElement(ChecksScreen, {
        report,
        state: makeState(),
        onNavigateToGuide: vi.fn(),
        onSimulate: vi.fn(),
        onPinCurrentIp: vi.fn(),
        onSyncTimezone: vi.fn(),
        onOpenCrashTest: vi.fn(),
        osTzStatus: {
          synced: false,
          current_os_tz: "Europe/Moscow",
          original_os_tz: null,
          synced_target_tz: null,
          auto_restore_pending: false,
        },
        onSyncOsTimezone: vi.fn(),
        onRestoreOsTimezone: vi.fn(),
      }),
    );

    expect(html).toContain("Редакторы и терминал");
    expect(html).toContain("Часовой пояс системы");
    expect(html).toContain("Синхронизировать пояс");
    expect(html).toContain("Синхронизировать редакторы");
    expect(html).not.toContain("CLI / IDE");
    expect(html).not.toContain("Системный TZ ОС");
    expect(html).toContain("Europe/Moscow");
    expect(html).toContain("Europe/Amsterdam");
  });
});

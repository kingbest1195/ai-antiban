import type { ReactElement } from "react";
import { describe, expect, it, vi } from "vitest";

vi.mock("react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react")>();
  return {
    ...actual,
    useState: <T,>(initial: T | (() => T)): [T, () => void] => [
      typeof initial === "function" ? (initial as () => T)() : initial,
      vi.fn(),
    ],
  };
});

import { Banner, Button } from "../../ui";
import { AlertStrip } from "./AlertStrip";
import type { AlertStripProps } from "./types";

function collectButtons(node: unknown, acc: Array<ReactElement<Record<string, unknown>>> = []): Array<ReactElement<Record<string, unknown>>> {
  if (!node || typeof node !== "object") return acc;
  if (Array.isArray(node)) {
    for (const item of node) collectButtons(item, acc);
    return acc;
  }
  const el = node as ReactElement<Record<string, unknown>>;
  if ("type" in el && "props" in el) {
    if (el.type === Button) acc.push(el);
    if (el.props?.action) collectButtons(el.props.action, acc);
    if (el.props?.children) collectButtons(el.props.children, acc);
  }
  return acc;
}

describe("AlertStrip click-to-repair error toast (photo_349)", () => {
  it("вызывает overview.onToast, когда «Починить в 1 клик» завершается неудачей (repair() -> null)", async () => {
    const onToast = vi.fn();
    const repair = vi.fn(async () => null);
    const overview: AlertStripProps["overview"] = {
      reports: {},
      activeReport: null,
      state: null,
      refreshing: false,
      auditError: null,
      startupPending: false,
      partial: null,
      currentIp: "185.212.102.40",
      trustScore: 95,
      gatewayStats: {
        protected_ai_requests: 12,
        intercepted_leaks: 0,
        direct_bypassed_requests: 5,
        active_ai_tunnels: 1,
        uptime_seconds: 120,
        last_protected_host: "api.anthropic.com",
        recent_events: [],
      },
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
      onToast,
    };
    const view: AlertStripProps["view"] = {
      loading: false,
      failed: false,
      progress: { done: 13, total: 13 },
      model: {
        verdict: "Вы защищены",
        tone: "ok",
        checksPassed: 13,
        checksTotal: 13,
        checksUnknown: 0,
        checksLabel: "13 из 13",
        pinState: "none",
        providerName: "Cloudflare",
        banner: null,
        services: [
          { id: "anthropic", status: "ok" },
          { id: "openai", status: "ok" },
          { id: "gemini", status: "ok" },
        ],
      },
    };

    const tree = AlertStrip({
      view,
      overview,
      coworkGuard: {
        status: null,
        needsRepair: true,
        repairing: false,
        error: "Доступ запрещён",
        repair,
        refresh: vi.fn(async () => null),
      },
      ipChangeCooldownUntil: null,
      routeUnavailableBanner: null,
      routesSnapshot: null,
      onPushRoute: vi.fn(),
      onDismissRouteUnavailable: vi.fn(),
      onRefreshRoutes: vi.fn(async () => {}),
      onRefreshState: vi.fn(async () => {}),
      onAuditRefresh: vi.fn(),
    });

    // Внутри tree должен быть Banner с кнопкой «Починить в 1 клик»
    expect(Banner).toBeDefined();
    const buttons = collectButtons(tree).filter((b) => String(b.props.children ?? "").includes("Починить в 1 клик"));
    expect(buttons).toHaveLength(1);

    (buttons[0].props.onClick as () => void)();
    await new Promise((r) => setTimeout(r, 0));
    expect(repair).toHaveBeenCalledTimes(1);
    expect(onToast).toHaveBeenCalledWith("Не удалось защитить фоновую службу Claude", expect.any(String), "error");
  });
});

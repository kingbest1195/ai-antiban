import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { GatewayStatsSnapshot } from "../types";

vi.mock("../ui/Modal", () => ({
  Modal: ({ open, title, children, footer }: { open: boolean; title: string; children?: unknown; footer?: unknown }) =>
    open ? createElement("div", { "data-modal": title }, children as never, footer as never) : null,
}));

import { status as statusCopy } from "../shared/copy/ru";
import { EventsModal } from "./EventsModal";

function makeStats(recent_events: GatewayStatsSnapshot["recent_events"]): GatewayStatsSnapshot {
  return {
    protected_ai_requests: 5,
    intercepted_leaks: 1,
    direct_bypassed_requests: 2,
    active_ai_tunnels: 1,
    uptime_seconds: 120,
    last_protected_host: "claude.ai",
    recent_events,
  };
}

describe("EventsModal (§3 Gateway Event Feed)", () => {
  it("renders MANUAL_ALLOW and legacy blocked-geo PROTECTED (RU/BY) with warning badge, never green Защищено", () => {
    const html = renderToStaticMarkup(
      createElement(EventsModal, {
        open: true,
        onClose: vi.fn(),
        stats: makeStats([
          { timestamp: 1700000001, host: "claude.ai", provider: "anthropic", action: "MANUAL_ALLOW", country: "RU" },
          { timestamp: 1700000002, host: "api.openai.com", provider: "openai", action: "PROTECTED", country: "RU" },
          { timestamp: 1700000003, host: "gemini.google.com", provider: "gemini", action: "PROTECTED", country: "BY" },
        ]),
      }),
    );

    expect(html).toContain(statusCopy.manualAllow);
    expect(html).toContain("Разрешено вручную · Россия (RU)");
    expect(html).toContain("Разрешено вручную · Беларусь (BY)");
    expect(html).toContain("zs-badge--warn");
    expect(html).not.toContain("zs-badge--ok");
    expect(html).not.toContain("Защищено · Россия (RU)");
    expect(html).not.toContain("Защищено · Беларусь (BY)");
  });

  it("filters out legacy pseudo-host 'all' while keeping real AI/direct/blocked events", () => {
    const html = renderToStaticMarkup(
      createElement(EventsModal, {
        open: true,
        onClose: vi.fn(),
        stats: makeStats([
          { timestamp: 1700000001, host: "all", provider: "NetworkGuard", action: "HELD", country: "RU" },
          { timestamp: 1700000002, host: " ALL ", provider: "NetworkGuard", action: "BLOCKED", country: "NL" },
          { timestamp: 1700000003, host: "claude.ai", provider: "anthropic", action: "PROTECTED", country: "NL" },
          { timestamp: 1700000004, host: "discord.com", provider: "non-ai", action: "DIRECT", country: "DIRECT" },
          { timestamp: 1700000005, host: "api.anthropic.com", provider: "anthropic", action: "HELD", country: "RU" },
        ]),
      }),
    );

    expect(html).not.toContain(">all<");
    expect(html).not.toContain("> ALL <");
    expect(html).not.toContain("NetworkGuard");
    expect(html).toContain("claude.ai");
    expect(html).toContain("Защищено · Нидерланды (NL)");
    expect(html).toContain("zs-badge--ok");
    expect(html).toContain("discord.com");
    expect(html).toContain(statusCopy.direct);
    expect(html).toContain("api.anthropic.com");
    expect(html).toContain(statusCopy.blocked);
    expect(html).toContain("zs-badge--danger");
  });
});

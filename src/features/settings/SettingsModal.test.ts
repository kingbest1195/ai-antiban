import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { providers as providerCopy, settings as copy } from "../../shared/copy/ru";

vi.mock("../../ui/Modal", () => ({
  Modal: ({ open, title, children, footer }: { open: boolean; title: string; children?: unknown; footer?: unknown }) =>
    open ? createElement("div", { "data-modal": title }, children as never, footer as never) : null,
}));

import { SettingsModal } from "./SettingsModal";
import { TerminalSection } from "./sections/TerminalSection";

describe("SettingsModal: мониторинг сервисов и сохранённые исключения", () => {
  it("рендерит переключатели мониторинга Claude, ChatGPT, Gemini и пояснение про домены Google", () => {
    const html = renderToStaticMarkup(
      createElement(SettingsModal, {
        open: true,
        onClose: vi.fn(),
        autoUpdateEnabled: true,
        onToggleAutoUpdate: vi.fn(async () => {}),
        disabledProviders: ["gemini"],
        trustedExceptions: {},
      }),
    );

    expect(html).toContain(copy.monitoring.section);
    expect(html).toContain(providerCopy.anthropic.name);
    expect(providerCopy.openai.name).toBe("ChatGPT");
    expect(html).toContain(providerCopy.openai.name);
    expect(html).toContain(providerCopy.gemini.name);
    expect(html).toContain("Google");
    expect(html).toContain(`aria-label="${copy.monitoring.toggleLabel("Claude")}"`);
    expect(html).toContain(`aria-label="${copy.monitoring.toggleLabel("Gemini")}"`);
    expect(html).toContain('aria-checked="false"');
    expect(html).toContain(copy.trustedExceptions.empty);
  });

  it("рендерит сохранённые исключения (Сервис + IP) с кнопками удаления и «Очистить все»", () => {
    const html = renderToStaticMarkup(
      createElement(SettingsModal, {
        open: true,
        onClose: vi.fn(),
        autoUpdateEnabled: true,
        onToggleAutoUpdate: vi.fn(async () => {}),
        disabledProviders: [],
        trustedExceptions: {
          anthropic: ["185.220.101.5"],
          openai: ["95.165.10.22"],
        },
      }),
    );

    expect(html).toContain(copy.trustedExceptions.section);
    expect(html).toContain(copy.trustedExceptions.clearAll);
    expect(html).toContain("185.220.101.5");
    expect(html).toContain("95.165.10.22");
    expect(html).toContain(`aria-label="${copy.trustedExceptions.remove("Claude", "185.220.101.5")}"`);
    expect(html).toContain(`aria-label="${copy.trustedExceptions.remove("ChatGPT", "95.165.10.22")}"`);
  });

  it("маскирует IPv4 и IPv6 в сохранённых исключениях при hideIpMode=true и сворачивает Tier 2 по умолчанию", () => {
    const html = renderToStaticMarkup(
      createElement(SettingsModal, {
        open: true,
        onClose: vi.fn(),
        autoUpdateEnabled: true,
        onToggleAutoUpdate: vi.fn(async () => {}),
        hideIpMode: true,
        disabledProviders: [],
        trustedExceptions: {
          anthropic: ["185.220.101.5"],
          openai: ["2001:db8:85a3::7334"],
        },
      }),
    );

    expect(html).toContain("•••.•••.•••.5");
    expect(html).not.toContain("185.220.101.5");
    expect(html).toContain("••••:••••:…:7334");
    expect(html).not.toContain("2001:db8:85a3::7334");
    expect(html).toContain(copy.advanced.title);
    expect(html).toContain('aria-expanded="false"');
    expect(html).not.toContain('class="zs-xrow__body"');
    expect(html).not.toContain(copy.privacy.networkTitle);
    expect(html).not.toContain("split tunneling");
    expect(html).not.toContain("Start = 2");
    expect(html).not.toContain("--minimized");
  });

  it("§7.1: TerminalSection показывает «Совпадает с IP» и скрывает кнопку синхронизации при already_matches_target=true", () => {
    const htmlMatches = renderToStaticMarkup(
      createElement(TerminalSection, {
        cliMode: "ai_only",
        syncTz: true,
        keepOsTzOnExit: true,
        terminalBusy: false,
        osTzStatus: {
          synced: false,
          already_matches_target: true,
          current_os_tz: "Europe/London",
          original_os_tz: null,
          synced_target_tz: null,
          target_tz: "Europe/London",
          auto_restore_pending: false,
        },
        osTzLoading: false,
        osTzError: null,
        onCliModeChange: vi.fn(),
        onToggleSyncTz: vi.fn(),
        onSyncOsTimezone: vi.fn(async () => {}),
        onRestoreOsTimezone: vi.fn(async () => {}),
      }),
    );
    expect(htmlMatches).toContain(copy.terminal.osTz.alreadyMatches("Europe/London"));
    expect(htmlMatches).not.toContain("Не синхронизирован с IP");
    expect(htmlMatches).not.toContain(`>${copy.terminal.osTz.syncAction}<`);

    const htmlMismatch = renderToStaticMarkup(
      createElement(TerminalSection, {
        cliMode: "ai_only",
        syncTz: true,
        keepOsTzOnExit: true,
        terminalBusy: false,
        osTzStatus: {
          synced: false,
          already_matches_target: false,
          current_os_tz: "Europe/Moscow",
          original_os_tz: null,
          synced_target_tz: null,
          target_tz: "Europe/London",
          auto_restore_pending: false,
        },
        osTzLoading: false,
        osTzError: null,
        onCliModeChange: vi.fn(),
        onToggleSyncTz: vi.fn(),
        onSyncOsTimezone: vi.fn(async () => {}),
        onRestoreOsTimezone: vi.fn(async () => {}),
      }),
    );
    expect(htmlMismatch).toContain("Не синхронизирован с IP");
    expect(htmlMismatch).toContain(copy.terminal.osTz.syncAction);
  });
});

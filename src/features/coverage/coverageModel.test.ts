import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { AppCoverageItem, AppCoverageStatus, CliProtectionReport, RestartOutcome } from "../../types";
import { POLL_FAST_MS, POLL_SLOW_MS, WAIT_TIMEOUT_MS, canRestartAntigravity, coverageNeedsAttention, enableResult, isListed, isProtectionOn, pollInterval, protectedAppNames, protectionControl, resolveWaiting, restartResult, sinceLastSeen, startWaiting, uncoveredAiApps, viewOf, vpnNotice } from "./coverageModel";
import { CoverageSection } from "./CoverageSection";
import { checkCliProtectionStatus, disableCliProtection, enableCliProtection, restartAppWithGateway } from "../../utils/api";
import { coverage as copy } from "../../shared/copy/ru";

const app = (id: string, status: AppCoverageStatus, over: Partial<AppCoverageItem> = {}): AppCoverageItem => ({
  id,
  name: id,
  category: "ide",
  installed: status !== "not_installed",
  status,
  requests_seen: 0,
  ai_requests: 0,
  pac_fetches: 0,
  last_seen_ms: null,
  manual_steps: [],
  detail: "",
  ...over,
});

describe("pollInterval", () => {
  it("при скрытом окне таймер не тикает", () => {
    expect(pollInterval(false, [app("a", "unknown")])).toBe(0);
    expect(pollInterval(false, [])).toBe(0);
  });
  it("5 с пока есть неподтверждённые, 30 с когда все подтверждены или не установлены", () => {
    expect(pollInterval(true, [app("a", "confirmed"), app("b", "configured")])).toBe(POLL_FAST_MS);
    expect(pollInterval(true, [app("a", "off")])).toBe(POLL_FAST_MS);
    expect(pollInterval(true, [app("a", "confirmed"), app("b", "not_installed")])).toBe(POLL_SLOW_MS);
    expect(pollInterval(true, undefined)).toBe(POLL_SLOW_MS);
  });
});

describe("режим «Только ИИ-клиенты и IDE»", () => {
  const node = app("node", "off", { category: "cli" });
  it("обычная терминальная программа идёт напрямую намеренно, а не «не настроено»", () => {
    expect(viewOf(node, {}, 0, "ai_only")).toBe("direct");
    expect(viewOf(node, {}, 0, "global_terminal")).toBe("off");
    expect(viewOf(node, {}, 0, undefined)).toBe("off");
  });
  it("ИИ-клиенты терминала и приложения не из терминала этого статуса не получают", () => {
    expect(viewOf(app("claude-code", "off", { category: "cli" }), {}, 0, "ai_only")).toBe("off");
    expect(viewOf(app("vscode", "off", { category: "ide" }), {}, 0, "ai_only")).toBe("off");
  });
  it("«напрямую» не заставляет опрашивать каждые 5 секунд", () => {
    expect(pollInterval(true, [app("a", "confirmed"), node], "ai_only")).toBe(POLL_SLOW_MS);
    expect(pollInterval(true, [app("a", "confirmed"), node], "global_terminal")).toBe(POLL_FAST_MS);
  });
});

describe("isListed", () => {
  it("«Не установлено» скрыто везде; в «Обзоре» только установленные или с трафиком", () => {
    const missing = app("x", "not_installed");
    expect(isListed(missing, "checks")).toBe(false);
    expect(isListed(missing, "overview")).toBe(false);
    const dynamic = app("d", "confirmed", { installed: false, ai_requests: 3, requests_seen: 3 });
    expect(isListed(dynamic, "overview")).toBe(true);
    expect(isListed(app("i", "off", { installed: false }), "overview")).toBe(false);
    expect(isListed(app("i", "off", { installed: false }), "checks")).toBe(true);
  });
});

describe("waiting", () => {
  const apps = [app("a", "configured"), app("b", "unknown"), app("c", "confirmed"), app("d", "off")];

  it("«Проверить снова» ставит ожидание только приложениям в статусе «Настроено»", () => {
    expect(Object.keys(startWaiting({}, apps, "configured", 1000))).toEqual(["a"]);
  });
  it("«Я настроил» ставит ожидание выбранному, кроме подтверждённых", () => {
    expect(Object.keys(startWaiting({}, apps, ["b", "c"], 1000))).toEqual(["b"]);
  });
  it("до 60 с — «ожидаем», после — «не подтверждено»", () => {
    const w = { a: 1000 };
    expect(viewOf(apps[0], w, 1000 + WAIT_TIMEOUT_MS - 1)).toBe("waiting");
    expect(viewOf(apps[0], w, 1000 + WAIT_TIMEOUT_MS)).toBe("waiting_timeout");
  });
  it("без ожидания виден статус шлюза", () => {
    expect(viewOf(apps[0], {}, 5)).toBe("configured");
    expect(viewOf(apps[2], { c: 1 }, 5)).toBe("confirmed");
  });
  it("подтверждение завершает ожидание: переход configured → waiting → confirmed", () => {
    const w1 = startWaiting({}, apps, "configured", 1000);
    expect(viewOf(apps[0], w1, 2000)).toBe("waiting");
    const next = [app("a", "confirmed", { ai_requests: 1, last_seen_ms: 3000 }), ...apps.slice(1)];
    const w2 = resolveWaiting(w1, next);
    expect(w2).toEqual({});
    expect(viewOf(next[0], w2, 4000)).toBe("confirmed");
  });
  it("статус off или исчезновение приложения тоже снимают ожидание; истёкшее остаётся", () => {
    expect(resolveWaiting({ a: 1 }, [app("a", "off")])).toEqual({});
    expect(resolveWaiting({ a: 1 }, [])).toEqual({});
    expect(resolveWaiting({ a: 1 }, [app("a", "configured")])).toEqual({ a: 1 });
  });
  it("подтверждение откатывается: confirmed → configured без ожидания показывает «Настроено»", () => {
    expect(viewOf(app("a", "configured"), {}, 9)).toBe("configured");
  });
});

describe("sinceLastSeen", () => {
  it("давность в мс или null", () => {
    expect(sinceLastSeen(app("a", "confirmed", { last_seen_ms: 1000 }), 4000)).toBe(3000);
    expect(sinceLastSeen(app("a", "configured"), 4000)).toBeNull();
  });
});

describe("uncoveredAiApps и coverageNeedsAttention: основание жёлтой точки", () => {
  const snap = (apps: AppCoverageItem[], over: Partial<Parameters<typeof coverageNeedsAttention>[0] & object> = {}) => ({
    apps,
    cli_mode: "ai_only" as const,
    sysproxy_enabled: true,
    system_proxy_effective: true as boolean | null,
    ...over,
  });

  it("установленное ИИ-приложение со статусом off не покрыто", () => {
    expect(uncoveredAiApps(snap([app("cursor", "off")])).map((a) => a.id)).toEqual(["cursor"]);
    expect(uncoveredAiApps(snap([app("claude-desktop", "off", { category: "desktop" })])).map((a) => a.id)).toEqual(["claude-desktop"]);
    expect(uncoveredAiApps(snap([app("claude-code", "off", { category: "cli" })])).map((a) => a.id)).toEqual(["claude-code"]);
  });
  it("confirmed и configured покрыты, not_installed не считается", () => {
    expect(coverageNeedsAttention(snap([app("a", "confirmed"), app("b", "configured"), app("c", "not_installed")]))).toBe(false);
  });
  it("unknown (проверить нечем) точку не даёт ни у IDE, ни у ИИ-клиента, ни у CLI", () => {
    expect(coverageNeedsAttention(snap([app("jetbrains", "unknown")]))).toBe(false);
    expect(coverageNeedsAttention(snap([app("claude-desktop", "unknown", { category: "desktop" })]))).toBe(false);
    expect(coverageNeedsAttention(snap([app("claude-code", "unknown", { category: "cli" })]))).toBe(false);
    expect(uncoveredAiApps(snap([app("jetbrains", "unknown")]))).toEqual([]);
  });
  it("«Напрямую — по режиму терминала» не считается, а в глобальном режиме терминал считается только ИИ-клиентский", () => {
    const node = app("node", "off", { category: "cli" });
    expect(coverageNeedsAttention(snap([node]))).toBe(false);
    expect(coverageNeedsAttention(snap([node], { cli_mode: "global_terminal" }))).toBe(false);
    expect(coverageNeedsAttention(snap([app("gemini-cli", "off", { category: "cli" })], { cli_mode: "global_terminal" }))).toBe(true);
  });
  it("браузеры не считаются ИИ-приложениями", () => {
    expect(coverageNeedsAttention(snap([app("browsers", "off", { category: "browser" })]))).toBe(false);
  });
  it("системный прокси не действует поверх VPN — замечание, даже если все приложения в порядке", () => {
    expect(coverageNeedsAttention(snap([app("a", "confirmed")], { system_proxy_effective: false }))).toBe(true);
    expect(coverageNeedsAttention(snap([app("a", "confirmed")], { system_proxy_effective: null }))).toBe(false);
    expect(coverageNeedsAttention(snap([app("a", "confirmed")], { sysproxy_enabled: false, system_proxy_effective: false }))).toBe(false);
  });
  it("снимка нет — замечания нет", () => {
    expect(coverageNeedsAttention(null)).toBe(false);
    expect(uncoveredAiApps(undefined)).toEqual([]);
  });
});

describe("vpnNotice: подключённый VPN и системный прокси", () => {
  const snap = (over: Partial<Parameters<typeof vpnNotice>[0]> = {}) => ({ sysproxy_enabled: true, system_proxy_effective: true as boolean | null, vpn_connected: ["V2 Pro"], ...over });

  it("подключённых VPN нет — сказать нечего", () => {
    expect(vpnNotice(snap({ vpn_connected: [] }))).toBeNull();
    expect(vpnNotice(snap({ vpn_connected: undefined }))).toBeNull();
    expect(vpnNotice(snap({ vpn_connected: ["  "] }))).toBeNull();
  });
  it("VPN есть, PAC действует — только строка «не изменялись»", () => {
    expect(vpnNotice(snap())).toEqual({ names: "V2 Pro", overridden: false });
  });
  it("VPN перебивает PAC — честное предупреждение", () => {
    expect(vpnNotice(snap({ system_proxy_effective: false }))).toEqual({ names: "V2 Pro", overridden: true });
  });
  it("не прочитано (null) и защита выключена — не утверждаем, что прокси не действует", () => {
    expect(vpnNotice(snap({ system_proxy_effective: null }))?.overridden).toBe(false);
    expect(vpnNotice(snap({ sysproxy_enabled: false, system_proxy_effective: false }))?.overridden).toBe(false);
  });
  it("несколько VPN перечисляются через запятую", () => {
    expect(vpnNotice(snap({ vpn_connected: ["Alpha", "Beta Pro"] }))?.names).toBe("Alpha, Beta Pro");
  });
  it("тексты: строка про неизменённые службы и предупреждение с именем и советом", () => {
    expect(copy.vpn.untouched("Alpha, Beta Pro")).toBe("VPN-службы не изменялись: Alpha, Beta Pro");
    expect(copy.vpn.overridden.title("V2 Pro")).toBe("Системный прокси не действует поверх VPN «V2 Pro»: ИИ-трафик может идти мимо Заставы");
    expect(copy.vpn.overridden.text).toContain("системный прокси");
    expect(copy.vpn.overridden.text).toContain("вручную");
  });
});

describe("кнопка защиты: подпись и действие зависят от состояния", () => {
  it("выключено — одна кнопка «Включить», включено — только состояние, кнопки «Включить» нет", () => {
    expect(protectionControl(false, false)).toEqual({ mode: "enable", busy: false });
    expect(protectionControl(true, false)).toEqual({ mode: "on", busy: false });
    expect(protectionControl(false, true).busy).toBe(true);
  });
  it("состояние берётся из снимка шлюза, а не из локального флага", () => {
    const snap = { sysproxy_enabled: true, cli_protection_enabled: false };
    expect(isProtectionOn("sysproxy", snap)).toBe(true);
    expect(isProtectionOn("cli", snap)).toBe(false);
  });
  it("подписи называют действие и объект и различаются по состоянию", () => {
    expect(copy.protection.enable.cli).toBe("Включить защиту IDE и терминала");
    expect(copy.protection.on.cli).toBe("Защита IDE и терминала включена");
    expect(copy.protection.on.cli).not.toBe(copy.protection.enable.cli);
    expect(copy.protection.disable).toBe("Выключить");
  });
  it("повторное «включить» никогда не выключает: явное действие ничего не знает о выключении", async () => {
    await enableCliProtection();
    expect(await checkCliProtectionStatus()).toBe(true);
    await enableCliProtection();
    expect(await checkCliProtectionStatus()).toBe(true);
    await disableCliProtection();
    expect(await checkCliProtectionStatus()).toBe(false);
    await enableCliProtection();
    expect(await checkCliProtectionStatus()).toBe(true);
  });
  it("подтверждение выключения перечисляет то, что останется без защиты", () => {
    const apps = [
      app("vscode", "configured", { name: "VS Code" }),
      app("claude-code", "confirmed", { name: "Claude Code", category: "cli" }),
      app("cursor", "off", { name: "Cursor" }),
      app("browsers", "confirmed", { name: "Браузеры", category: "browser" }),
    ];
    expect(protectedAppNames("cli", apps)).toEqual(["VS Code", "Claude Code"]);
    expect(protectedAppNames("sysproxy", apps)).toEqual(["Браузеры"]);
    const text = copy.protection.confirm.text(["VS Code", "Claude Code"], "cli");
    expect(text).toContain("Останутся без защиты: VS Code, Claude Code");
    expect(copy.protection.confirm.text([], "cli")).toContain("Останутся без защиты:");
  });
});

describe("enableResult: итог берётся из ответа команды", () => {
  const report = (over: Partial<CliProtectionReport> = {}): CliProtectionReport => ({
    enabled: true,
    proxy_url: "http://127.0.0.1:40111",
    configured_targets: ["Cursor", "VS Code", "Claude Code", "Gemini CLI"],
    shell_command: "",
    ...over,
  });
  const antigravity = app("antigravity", "off", { name: "Antigravity", manual_steps: ["enable_system_proxy", "launch_with_env"] });

  it("перечисляет записанное и называет приложения с ручными шагами", () => {
    const r = enableResult("cli", report(), [antigravity]);
    expect(r.title).toBe("Защита IDE и терминала включена");
    expect(r.text).toBe("Записано в: Cursor, VS Code, Claude Code, Gemini CLI. Antigravity: нужны ручные шаги (см. ниже).");
    expect(r.tone).toBe("warn");
  });
  it("без ручных приложений итог зелёный и ничего лишнего не выдумывает", () => {
    const r = enableResult("cli", report({ configured_targets: ["Cursor"] }), []);
    expect(r).toEqual({ tone: "ok", title: "Защита IDE и терминала включена", text: "Записано в: Cursor." });
  });
  it("ничего не записано — так и сказано, тон предупреждения", () => {
    const r = enableResult("cli", report({ configured_targets: [] }), []);
    expect(r.text).toContain("Ничего не записано");
    expect(r.tone).toBe("warn");
  });
  it("заметки и ошибка команды попадают в текст", () => {
    const withNote = enableResult("cli", report({ notes: ["Старый блок в ~/.zshrc не удалён."] }), []);
    expect(withNote.text).toContain("Старый блок в ~/.zshrc не удалён.");
    const failed = enableResult("cli", report({ error: "Журнал недоступен", configured_targets: [] }), []);
    expect(failed.tone).toBe("danger");
    expect(failed.text).toContain("Журнал недоступен");
  });
  it("команда не выполнилась — ошибка", () => {
    expect(enableResult("cli", null, []).tone).toBe("danger");
  });
  it("системный прокси: короткое подтверждение без списка IDE", () => {
    const r = enableResult("sysproxy", null, []);
    expect(r.tone).toBe("ok");
    expect(r.title).toBe("Защита браузеров и приложений включена");
  });
});

describe("кнопка «Перезапустить Antigravity с защитой»", () => {
  const agy = (over: Partial<AppCoverageItem> = {}) => app("antigravity", "off", { manual_steps: ["launch_with_env"], ...over });
  const snap = { gateway_addr: "127.0.0.1:40111" as string | null };

  it("показывается для Antigravity 2.x на macOS, пока трафик не подтверждён", () => {
    expect(canRestartAntigravity(agy(), "off", snap, true)).toBe(true);
    expect(canRestartAntigravity(agy({ status: "configured" }), "configured", snap, true)).toBe(true);
    expect(canRestartAntigravity(agy({ bypass_suspected: true }), "off", snap, true)).toBe(true);
    expect(canRestartAntigravity(agy(), "waiting", snap, true)).toBe(true);
  });
  it("не показывается при «Подтверждено трафиком»", () => {
    expect(canRestartAntigravity(agy({ status: "confirmed" }), "confirmed", snap, true)).toBe(false);
  });
  it("не показывается на Windows и Linux: остаётся ручная команда", () => {
    expect(canRestartAntigravity(agy(), "off", snap, false)).toBe(false);
  });
  it("не показывается, если приложение не установлено, нет шага запуска или адрес шлюза не известен", () => {
    expect(canRestartAntigravity(agy({ installed: false, status: "not_installed" }), "not_installed", snap, true)).toBe(false);
    expect(canRestartAntigravity(agy({ manual_steps: [] }), "off", snap, true)).toBe(false);
    expect(canRestartAntigravity(agy(), "off", { gateway_addr: null }, true)).toBe(false);
  });
  it("не показывается для других приложений", () => {
    expect(canRestartAntigravity(app("cursor", "off", { manual_steps: ["launch_with_env"] }), "off", snap, true)).toBe(false);
  });

  it("каждый исход даёт свой заголовок, тон и понятное «что делать»", () => {
    const outcomes: RestartOutcome[] = ["restarted", "not_closed", "needs_automation_permission", "launch_failed", "not_installed", "unsupported"];
    const views = outcomes.map((o) => restartResult(o));
    expect(new Set(views.map((v) => v.title)).size).toBe(outcomes.length);
    expect(restartResult("restarted")).toMatchObject({ tone: "ok", text: "Сделайте запрос: статус обновится сам." });
    expect(restartResult("not_closed").tone).toBe("warn");
    expect(restartResult("not_closed").text).toContain("закройте его сами");
    expect(restartResult("needs_automation_permission").text).toContain("Системные настройки → Конфиденциальность и безопасность → Автоматизация");
    expect(restartResult("launch_failed").tone).toBe("danger");
    for (const v of views) expect(v.text).not.toBe("");
  });
  it("подтверждение предупреждает про сохранение и лимит в 15 секунд", () => {
    expect(copy.restart.confirm.text).toContain("несохранённые изменения");
    expect(copy.restart.confirm.text).toContain("15 секунд");
    expect(copy.restart.confirm.confirm).toBe("Перезапустить");
  });
});

describe("мок restartAppWithGateway: ?mockRestart", () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });
  const outcomeFor = async (query: string): Promise<RestartOutcome> => {
    vi.useFakeTimers();
    vi.stubGlobal("window", { location: { search: query } });
    const p = restartAppWithGateway("antigravity");
    await vi.runAllTimersAsync();
    return p;
  };
  it("переключает все исходы", async () => {
    expect(await outcomeFor("")).toBe("restarted");
    expect(await outcomeFor("?mockRestart=ok")).toBe("restarted");
    expect(await outcomeFor("?mockRestart=not_closed")).toBe("not_closed");
    expect(await outcomeFor("?mockRestart=permission")).toBe("needs_automation_permission");
    expect(await outcomeFor("?mockRestart=failed")).toBe("launch_failed");
  });
});

describe("CoverageSection: короткие бейджи и zs-cov__row", () => {
  it("бейджи укладываются в 1–2 слова, а строки используют zs-cov__row", () => {
    for (const label of Object.values(copy.status)) {
      expect(label.trim().split(/\s+/).length).toBeLessThanOrEqual(2);
    }
    const html = renderToStaticMarkup(
      createElement(CoverageSection, {
        variant: "overview",
        pending: false,
        initialSnapshot: {
          sysproxy_enabled: true,
          cli_protection_enabled: true,
          chained_proxy: null,
          gateway_addr: "127.0.0.1:40111",
          pac_url: "http://127.0.0.1:40111/proxy.pac",
          generated_at_ms: 1,
          cli_mode: "ai_only",
          apps: [
            app("browsers", "confirmed", { name: "Браузеры", category: "browser", ai_requests: 3, last_seen_ms: 1 }),
            app("chatgpt-desktop", "configured", { name: "ChatGPT Desktop", category: "desktop", detail: "Системный PAC включён" }),
            app("node-cli", "off", { name: "Node.js", category: "cli", detail: "Идёт напрямую" }),
          ],
        },
      }),
    );
    expect(html).toContain("zs-cov__row");
    expect(html).toContain(copy.status.confirmed);
    expect(html).toContain(copy.status.configured);
    expect(html).toContain(copy.status.direct);
  });
});

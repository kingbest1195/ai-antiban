import { describe, expect, it } from "vitest";
import type { AppCoverageItem, AppCoverageStatus, CliProtectionReport } from "../../types";
import { POLL_FAST_MS, POLL_SLOW_MS, WAIT_TIMEOUT_MS, enableResult, isListed, isProtectionOn, pollInterval, protectedAppNames, protectionControl, resolveWaiting, sinceLastSeen, startWaiting, viewOf, vpnNotice } from "./coverageModel";
import { disableCliProtection, enableCliProtection, checkCliProtectionStatus } from "../../utils/api";
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

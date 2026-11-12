import { describe, expect, it } from "vitest";
import type { AppCoverageItem, CliMode, ManualStepKey } from "../../types";
import { MAX_STEPS, buildManualSetup } from "./manualSetup";

const app = (id: string, category: AppCoverageItem["category"], manual_steps: ManualStepKey[], status: AppCoverageItem["status"] = "unknown"): AppCoverageItem => ({
  id,
  name: id,
  category,
  installed: true,
  status,
  requests_seen: 0,
  ai_requests: 0,
  pac_fetches: 0,
  last_seen_ms: null,
  manual_steps,
  detail: "",
});

const snap = (cli_mode: CliMode = "ai_only", gateway_addr: string | null = "127.0.0.1:40111") => ({
  gateway_addr,
  pac_url: gateway_addr ? `http://${gateway_addr}/proxy.pac` : null,
  cli_mode,
});

const jetbrains = app("jetbrains", "ide", ["jetbrains_proxy_settings", "set_pac_url", "set_http_proxy"]);
const allText = (s: ReturnType<typeof buildManualSetup>) => [...s.blocks.flatMap((b) => b.lines), ...s.steps.map((x) => x.text)].join("\n");

describe("buildManualSetup: реальный адрес шлюза", () => {
  it("JetBrains: PAC и адрес берутся из снимка, 8899 нигде не зашит", () => {
    const s = buildManualSetup(jetbrains, snap());
    const lines = s.blocks.flatMap((b) => b.lines);
    expect(lines).toContain("http://127.0.0.1:40111/proxy.pac");
    expect(lines).toContain("127.0.0.1:40111");
    expect(allText(s)).not.toContain("8899");
    expect(s.warning?.text).toContain("Auto-detect");
    expect(s.addressPending).toBe(false);
  });
  it("порт меняется вместе со снимком", () => {
    const lines = buildManualSetup(jetbrains, snap("ai_only", "127.0.0.1:8900")).blocks.flatMap((b) => b.lines);
    expect(lines).toContain("127.0.0.1:8900");
    expect(lines.join("")).not.toContain("40111");
  });
  it("пока gateway_addr = null — адреса нет и показывается «определяется»", () => {
    const s = buildManualSetup(jetbrains, snap("ai_only", null));
    expect(s.blocks).toEqual([]);
    expect(s.addressPending).toBe(true);
  });
  it("VS Code-семейство: http.proxy с адресом шлюза", () => {
    const s = buildManualSetup(app("vscode", "ide", ["enable_protection", "set_http_proxy"], "off"), snap());
    expect(s.blocks.map((b) => b.lines[0])).toContain("http://127.0.0.1:40111");
    expect(s.protection).toBe("cli");
  });
  it("команды терминала с реальным адресом и без setx", () => {
    const s = buildManualSetup(app("claude-code", "cli", ["enable_protection", "set_env_proxy"], "off"), snap("global_terminal"));
    const cmds = s.blocks.filter((b) => b.kind === "command").flatMap((b) => b.lines).join("\n");
    expect(cmds).toContain("HTTPS_PROXY=http://127.0.0.1:40111");
    expect(cmds).toContain('$env:HTTPS_PROXY="http://127.0.0.1:40111"');
    expect(cmds).not.toMatch(/setx/i);
  });
});

describe("buildManualSetup: режим CLI меняет шаги", () => {
  const node = app("node-cli", "cli", ["set_env_proxy"], "off");
  it("ai_only: node/python/curl идут напрямую, шаг про «Глобальный перехват терминала»", () => {
    const s = buildManualSetup(node, snap("ai_only"));
    expect(s.steps.map((x) => x.text).join(" ")).toContain("Глобальный перехват терминала");
  });
  it("global_terminal: для той же программы шагов про прямой режим нет", () => {
    const g = buildManualSetup(app("node-cli", "cli", ["enable_protection", "set_env_proxy"], "off"), snap("global_terminal"));
    expect(g.steps.map((x) => x.text).join(" ")).not.toContain("идут напрямую");
    expect(g.steps.map((x) => x.text).join(" ")).not.toContain("работают напрямую");
    expect(g.steps).not.toEqual(buildManualSetup(node, snap("ai_only")).steps);
  });
  it("Claude/Gemini в ai_only: шаг — включить защиту CLI/IDE; подпись режима в подсказках", () => {
    const s = buildManualSetup(app("claude-code", "cli", ["enable_protection", "set_env_proxy"], "off"), snap("ai_only"));
    expect(s.steps[0].title).toContain("CLI и IDE");
    expect(s.hints.join(" ")).toContain("Только ИИ-клиенты и IDE");
    const g = buildManualSetup(app("claude-code", "cli", ["enable_protection", "set_env_proxy"], "off"), snap("global_terminal"));
    expect(g.hints.join(" ")).toContain("Глобальный перехват терминала");
  });
  it("CLI Configured: только «откройте новый терминал»", () => {
    const s = buildManualSetup(app("gemini-cli", "cli", ["reopen_terminal"], "configured"), snap());
    expect(s.steps).toHaveLength(1);
    expect(s.steps[0].title).toContain("новый терминал");
  });
});

describe("buildManualSetup: общее", () => {
  it("браузеры: включить защиту + PAC + Firefox", () => {
    const s = buildManualSetup(app("browsers", "browser", ["enable_protection", "set_pac_url"]), snap());
    expect(s.protection).toBe("sysproxy");
    expect(s.steps.map((x) => x.title).join(" ")).toContain("Firefox");
  });
  it("подтверждённое/настроенное без шагов — инструкции нет", () => {
    expect(buildManualSetup(app("cursor", "ide", [], "confirmed"), snap()).steps).toEqual([]);
  });
  it("ни при каких ключах шагов больше пяти", () => {
    const all: ManualStepKey[] = ["enable_protection", "set_pac_url", "set_http_proxy", "set_env_proxy", "restart_app", "reopen_terminal", "jetbrains_proxy_settings"];
    for (const id of ["jetbrains", "browsers", "vscode", "claude-code", "node-cli", "claude-desktop"]) {
      for (const category of ["browser", "desktop", "ide", "cli"] as const) {
        for (const mode of ["ai_only", "global_terminal"] as const) {
          expect(buildManualSetup(app(id, category, all), snap(mode)).steps.length).toBeLessThanOrEqual(MAX_STEPS);
        }
      }
    }
  });
  it("неизвестный ключ не даёт пустую инструкцию", () => {
    const s = buildManualSetup(app("x", "ide", ["something_new" as ManualStepKey]), snap());
    expect(s.steps).toHaveLength(1);
  });
});

describe("Antigravity 2.x: ручной запуск с переменными", () => {
  const ag = (steps: ManualStepKey[], over: Partial<AppCoverageItem> = {}) => ({ ...app("antigravity", "ide", steps, "off"), ...over });

  it("нет кнопки «Включить защиту»: защита не выбирается, шаги и значения остаются", () => {
    const s = buildManualSetup(ag(["enable_system_proxy", "launch_with_env"]), snap());
    expect(s.protection).toBeNull();
    expect(s.steps.length).toBeGreaterThan(0);
    expect(s.blocks.length).toBeGreaterThan(0);
  });
  it("адрес и порт берутся из снимка шлюза, 8899 нигде не зашит", () => {
    const s = buildManualSetup(ag(["launch_with_env"]), snap("ai_only", "127.0.0.1:40111"));
    const mac = s.blocks.find((b) => b.id === "launch-mac")!;
    expect(mac.kind).toBe("command");
    expect(mac.lines[0]).toBe("open -a Antigravity --env HTTPS_PROXY=http://127.0.0.1:40111 --env HTTP_PROXY=http://127.0.0.1:40111 --env NO_PROXY=localhost,127.0.0.1,::1");
    expect(s.blocks.find((b) => b.kind === "address")!.lines).toEqual(["http://127.0.0.1:40111"]);
    expect(allText(s)).not.toContain("8899");
    const other = buildManualSetup(ag(["launch_with_env"]), snap("ai_only", "127.0.0.1:50222"));
    expect(other.blocks.flatMap((b) => b.lines).join("\n")).not.toContain("40111");
  });
  it("локальные адреса идут мимо прокси: иначе интерфейс не достучится до локального агента", () => {
    const s = buildManualSetup(ag(["launch_with_env"]), snap());
    expect(s.blocks.filter((b) => b.kind === "command").every((b) => b.lines.join("").includes("NO_PROXY"))).toBe(true);
  });
  it("PowerShell-вариант без setx", () => {
    const ps = buildManualSetup(ag(["launch_with_env"]), snap()).blocks.find((b) => b.id === "launch-ps")!;
    expect(ps.lines[0]).toContain('$env:HTTPS_PROXY="http://127.0.0.1:40111"');
    expect(ps.lines.join("")).not.toMatch(/setx/i);
  });
  it("пока адрес шлюза неизвестен — «определяется», без пустых команд", () => {
    const s = buildManualSetup(ag(["launch_with_env"]), snap("ai_only", null));
    expect(s.blocks).toEqual([]);
    expect(s.addressPending).toBe(true);
  });
  it("«идут мимо Заставы» показывается предупреждением над шагами", () => {
    const s = buildManualSetup(ag(["launch_with_env"], { bypass_suspected: true }), snap());
    expect(s.warning?.title).toBe("Запросы Antigravity, похоже, идут мимо Заставы");
    expect(buildManualSetup(ag(["launch_with_env"]), snap()).warning).toBeNull();
  });
  it("режим ai_only не лишает Antigravity шагов: это ИИ-клиент, а не npm/brew", () => {
    const s = buildManualSetup(ag(["launch_with_env"]), snap("ai_only"));
    expect(s.steps.map((x) => x.title)).toContain("Перезапустите Antigravity с прокси");
    expect(s.steps.map((x) => x.title)).not.toContain("В этом режиме программа идёт напрямую");
  });
  it("старый редактор Antigravity (settings.json) по-прежнему получает кнопку защиты и http.proxy", () => {
    const s = buildManualSetup(ag(["enable_protection", "set_http_proxy"]), snap());
    expect(s.protection).toBe("cli");
    expect(s.blocks.map((b) => b.lines[0])).toContain("http://127.0.0.1:40111");
  });
  it("текст про «В settings.json нет http.proxy» не появляется в шагах 2.x", () => {
    const s = buildManualSetup(ag(["enable_system_proxy", "launch_with_env"]), snap());
    expect([...s.steps.map((x) => x.text), ...s.hints].join(" ")).not.toContain("settings.json");
  });
});

describe("шаг «включите защиту» не показывается, когда защита уже включена", () => {
  const gemini = app("gemini-cli", "cli", ["enable_protection", "set_env_proxy"], "off");
  it("выключена — шаг есть; включена — шага нет, но защита (состояние в карточке) остаётся", () => {
    const off = buildManualSetup(gemini, { ...snap(), cli_protection_enabled: false });
    expect(off.steps.map((s) => s.title)).toContain("Включите защиту CLI и IDE");
    const on = buildManualSetup(gemini, { ...snap(), cli_protection_enabled: true });
    expect(on.steps.map((s) => s.title)).not.toContain("Включите защиту CLI и IDE");
    expect(on.protection).toBe("cli");
    expect(on.steps.length).toBeGreaterThan(0);
  });
});

import type {
  AppCoverageItem,
  CoverageSnapshot,
  ManualStepKey,
  RestartOutcome,
} from "../../../types";
import { mockFlags } from "./state";

/** Сколько раз нажали «Проверить снова»: мок продвигает статусы по шагам. */
export let mockCoverageStage = 0;
export let mockPacPolicyApplied = false;

export function bumpMockCoverageStage(): void {
  mockCoverageStage = Math.min(mockCoverageStage + 1, 2);
}

export function setMockPacPolicyApplied(applied: boolean): void {
  mockPacPolicyApplied = applied;
}

/** Сценарий VPN в моке «Покрытия»: нет VPN, VPN перебивает системный PAC, VPN подключён, но PAC действует. */
export type MockVpnScenario = "none" | "overrides" | "effective";
let mockVpnScenario: MockVpnScenario = "none";

export function setMockVpnScenario(scenario: MockVpnScenario): void {
  mockVpnScenario = scenario;
}

/** Сценарий из мока или из адреса страницы (?mockVpn=overrides|effective) — только в браузере без Tauri. */
export function currentMockVpnScenario(): MockVpnScenario {
  if (mockVpnScenario !== "none" || typeof window === "undefined") return mockVpnScenario;
  const fromUrl = new URLSearchParams(window.location.search).get("mockVpn");
  return fromUrl === "overrides" || fromUrl === "effective" ? fromUrl : "none";
}

/**
 * Сценарий Antigravity 2.x в моке «Покрытия»: нет приложения, не покрыто, запущено без трафика через шлюз
 * («идут мимо»), подтверждено трафиком после запуска с переменными окружения.
 */
export type MockAntigravityScenario = "none" | "uncovered" | "bypass" | "confirmed";
let mockAntigravityScenario: MockAntigravityScenario = "none";

export function setMockAntigravityScenario(scenario: MockAntigravityScenario): void {
  mockAntigravityScenario = scenario;
}

/** Сценарий из мока или из адреса страницы (?mockAntigravity=uncovered|bypass|confirmed) — только в браузере без Tauri. */
export function currentMockAntigravityScenario(): MockAntigravityScenario {
  if (mockAntigravityScenario !== "none" || typeof window === "undefined") return mockAntigravityScenario;
  const fromUrl = new URLSearchParams(window.location.search).get("mockAntigravity");
  return fromUrl === "uncovered" || fromUrl === "bypass" || fromUrl === "confirmed" ? fromUrl : "none";
}

/** Исход «Перезапустить Antigravity с защитой» в моке: ?mockRestart=ok|not_closed|permission|failed (по умолчанию ok). */
export function currentMockRestartOutcome(): RestartOutcome {
  const v = typeof window === "undefined" ? null : new URLSearchParams(window.location.search).get("mockRestart");
  return v === "not_closed" ? "not_closed" : v === "permission" ? "needs_automation_permission" : v === "failed" ? "launch_failed" : "restarted";
}

/** Мок снимка покрытия: порт шлюза не 8899, статусы и шаги по правилам шлюза; «Проверить снова» продвигает их. */
export function mockCoverageSnapshot(): CoverageSnapshot {
  const now = Date.now();
  const stage = mockCoverageStage;
  const sys = mockFlags.sysproxyActive;
  const cli = mockFlags.cliProtection;
  const globalMode = mockFlags.cliMode === "global_terminal";
  type Spec = Pick<AppCoverageItem, "id" | "name" | "category" | "status" | "detail"> & {
    ai?: number;
    ago?: number;
    steps?: ManualStepKey[];
  };
  const app = (s: Spec): AppCoverageItem => ({
    id: s.id,
    name: s.name,
    category: s.category,
    installed: s.status !== "not_installed",
    status: s.status,
    requests_seen: s.ai ?? 0,
    ai_requests: s.ai ?? 0,
    pac_fetches: s.status === "confirmed" || s.status === "configured" ? 3 : 0,
    last_seen_ms: s.ai ? now - (s.ago ?? 120_000) : null,
    manual_steps: s.steps ?? [],
    detail: s.detail,
  });
  const apps: AppCoverageItem[] = [
    sys
      ? app({ id: "browsers", name: "Браузеры", category: "browser", status: "confirmed", ai: 42, ago: 45_000, detail: "Был ИИ-запрос через шлюз" })
      : app({ id: "browsers", name: "Браузеры", category: "browser", status: "off", detail: "Системный PAC выключен", steps: ["enable_protection"] }),
    app({ id: "claude-desktop", name: "Claude Desktop", category: "desktop", status: "confirmed", ai: 18, ago: 240_000, detail: "Был ИИ-запрос через шлюз" }),
    sys
      ? app({ id: "chatgpt-desktop", name: "ChatGPT Desktop", category: "desktop", status: "configured", detail: "Системный PAC включён, ждём первый запрос" })
      : app({ id: "chatgpt-desktop", name: "ChatGPT Desktop", category: "desktop", status: "off", detail: "Системный PAC выключен", steps: ["enable_protection"] }),
    app({ id: "cursor", name: "Cursor", category: "ide", status: "confirmed", ai: 27, ago: 60_000, detail: "Был ИИ-запрос через шлюз" }),
    cli
      ? app({ id: "vscode", name: "VS Code", category: "ide", status: "configured", detail: "http.proxy в settings.json указывает на шлюз" })
      : app({ id: "vscode", name: "VS Code", category: "ide", status: "off", detail: "Защита редакторов выключена", steps: ["enable_protection", "set_http_proxy"] }),
    stage >= 1
      ? app({ id: "jetbrains", name: "JetBrains IDE", category: "ide", status: "configured", detail: "Настройки прокси найдены, ждём первый запрос", steps: [] })
      : app({ id: "jetbrains", name: "JetBrains IDE", category: "ide", status: "unknown", detail: "Не удалось проверить настройки прокси", steps: ["jetbrains_proxy_settings", "set_pac_url", "set_http_proxy"] }),
    cli
      ? app({ id: "claude-code", name: "Claude Code", category: "cli", status: stage >= 2 ? "confirmed" : "configured", ai: stage >= 2 ? 1 : 0, ago: 5_000, detail: "Прокси записан в settings.json", steps: stage >= 2 ? [] : ["reopen_terminal"] })
      : app({ id: "claude-code", name: "Claude Code", category: "cli", status: "off", detail: "Защита CLI выключена", steps: ["enable_protection", "set_env_proxy"] }),
    cli && currentMockAntigravityScenario() !== "none"
      ? app({ id: "gemini-cli", name: "Gemini CLI", category: "cli", status: "off", detail: "В settings.json нет прокси Заставы", steps: ["enable_protection", "set_env_proxy"] })
      : cli
      ? app({ id: "gemini-cli", name: "Gemini CLI", category: "cli", status: "configured", detail: "Прокси записан в настройки", steps: ["reopen_terminal"] })
      : app({ id: "gemini-cli", name: "Gemini CLI", category: "cli", status: "off", detail: "Защита CLI выключена", steps: ["enable_protection", "set_env_proxy"] }),
    cli && globalMode
      ? app({ id: "node-cli", name: "Node.js", category: "cli", status: "configured", detail: "Переменные прокси в профиле терминала", steps: ["reopen_terminal"] })
      : app({
          id: "node-cli",
          name: "Node.js",
          category: "cli",
          status: "off",
          detail: globalMode ? "Защита CLI выключена" : "Не покрывается в режиме «Только ИИ-клиенты и IDE»",
          steps: globalMode ? ["enable_protection", "set_env_proxy"] : ["set_env_proxy"],
        }),
    app({ id: "windsurf", name: "Windsurf", category: "ide", status: "not_installed", detail: "Не установлено" }),
  ];
  const antigravity = currentMockAntigravityScenario();
  if (antigravity !== "none") {
    const base = { id: "antigravity", name: "Antigravity", category: "ide" as const };
    const steps: ManualStepKey[] = sys ? ["launch_with_env"] : ["enable_system_proxy", "launch_with_env"];
    const status = sys ? "configured" : "off";
    const item =
      antigravity === "confirmed"
        ? app({ ...base, status: "confirmed", ai: 9, ago: 20_000, detail: "Подтверждено трафиком (9 запр.)" })
        : antigravity === "bypass"
          ? { ...app({ ...base, status: "off", detail: "Запросы Antigravity, похоже, идут мимо Заставы", steps }), bypass_suspected: true }
          : app({
              ...base,
              status,
              detail: sys
                ? "Интерфейс следует системному PAC, а агент нет: запустите приложение с переменными прокси"
                : "Antigravity не использует прокси Заставы: агент может ходить напрямую",
              steps,
            });
    apps.splice(3, 0, item);
  }
  const vpn = currentMockVpnScenario();
  return {
    sysproxy_enabled: sys,
    cli_protection_enabled: cli,
    chained_proxy: null,
    gateway_addr: "127.0.0.1:40111",
    pac_url: "http://127.0.0.1:40111/proxy.pac",
    generated_at_ms: now,
    cli_mode: mockFlags.cliMode,
    apps,
    system_proxy_effective: sys ? vpn !== "overrides" : null,
    vpn_connected: vpn === "none" ? [] : ["V2BOX Pro"],
    browser_pac_policy_active: sys ? vpn === "effective" || mockPacPolicyApplied : false,
    browsers_pac_active: sys && (vpn === "effective" || mockPacPolicyApplied) ? ["Google Chrome"] : [],
    browsers_needing_restart: sys && vpn === "overrides" && !mockPacPolicyApplied ? ["Google Chrome"] : [],
  };
}

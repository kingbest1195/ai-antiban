export type AppCoverageCategory = "browser" | "desktop" | "ide" | "cli";
/** confirmed — был ИИ-запрос через шлюз; configured — настроено, ждём первый запрос; unknown — проверить нечем; off — не настроено. */
export type AppCoverageStatus = "confirmed" | "configured" | "unknown" | "off" | "not_installed";

/** Режим покрытия CLI: только ИИ-клиенты и IDE (по умолчанию) или глобальный перехват терминала. */
export type CliMode = "ai_only" | "global_terminal";

/** Что осталось сделать вручную; подробности подбирает фронт по приложению и режиму. */
export type ManualStepKey =
  | "enable_protection"
  | "set_pac_url"
  | "set_http_proxy"
  | "set_env_proxy"
  | "restart_app"
  | "reopen_terminal"
  | "jetbrains_proxy_settings"
  | "launch_with_env"
  | "enable_system_proxy";

export interface AppCoverageItem {
  id: string;
  name: string;
  category: AppCoverageCategory;
  installed: boolean;
  status: AppCoverageStatus;
  /** То же, что ai_requests (для старого кода). */
  requests_seen: number;
  ai_requests: number;
  pac_fetches: number;
  /** Unix-время (мс) последнего ИИ-запроса через шлюз. */
  last_seen_ms: number | null;
  manual_steps: ManualStepKey[];
  /** Короткий текст от шлюза по-русски. */
  detail: string;
  /** Приложение запущено, но через шлюз от него ничего нет: запросы, похоже, идут мимо Заставы (Antigravity 2.x). */
  bypass_suspected?: boolean;
}

/** Итог «Перезапустить Antigravity с защитой»: значения совпадают с `RestartOutcome` шлюза (snake_case). */
export type RestartOutcome =
  | "restarted"
  | "not_closed"
  | "needs_automation_permission"
  | "launch_failed"
  | "not_installed"
  | "unsupported";

export interface CliSettings {
  cli_mode: CliMode;
  sync_ai_tz_enabled: boolean;
  cli_protection_enabled: boolean;
  synced_ai_timezone: string | null;
}

export interface CoverageSnapshot {
  sysproxy_enabled: boolean;
  cli_protection_enabled: boolean;
  chained_proxy?: string | null;
  /** "127.0.0.1:<порт>"; null до привязки шлюза. */
  gateway_addr: string | null;
  /** "http://<gateway_addr>/proxy.pac"; null до привязки шлюза. */
  pac_url: string | null;
  generated_at_ms: number;
  cli_mode: CliMode;
  apps: AppCoverageItem[];
  /** Действует ли системный PAC глобально (`scutil --proxy`); null — защита выключена или прочитать не удалось. */
  system_proxy_effective?: boolean | null;
  /** Включённые VPN-службы, подключённые сейчас. Застава в них ничего не пишет. */
  vpn_connected?: string[];
  /** Активна ли управляемая PAC-политика браузеров (в обход TUN/VPN). */
  browser_pac_policy_active?: boolean;
  /** Названия браузеров, в которых PAC-политика реально активна сейчас. */
  browsers_pac_active?: string[];
  /** Названия запущенных браузеров без PAC, которым нужен перезапуск. */
  browsers_needing_restart?: string[];
}

export interface RelaunchBrowsersResult {
  restarted: string[];
  skipped: string[];
  failed: string[];
  needs_automation_permission: boolean;
  unsupported: boolean;
  snapshot: CoverageSnapshot;
}

export interface PolicyApplyReport {
  applied: number;
  unchanged: number;
  skipped: number;
  failed: number;
  pac_policy_active: boolean;
}

export interface CliProtectionReport {
  enabled: boolean;
  proxy_url: string;
  configured_targets: string[];
  shell_command: string;
  notes?: string[];
  error?: string | null;
}

export interface RecentGatewayEvent {
  timestamp: number;
  host: string;
  provider: string;
  action: string; // "PROTECTED" | "MANUAL_ALLOW" | "HELD" | "BLOCKED" | "DIRECT"
  kind?: string;
  country: string;
}

export interface GatewayStatsSnapshot {
  protected_ai_requests: number;
  intercepted_leaks: number;
  direct_bypassed_requests: number;
  active_ai_tunnels: number;
  uptime_seconds: number;
  last_protected_host: string | null;
  recent_events: RecentGatewayEvent[];
}

/** Ответ `run_vpn_crash_test_step` ровно как у Rust (`CrashTestStepResult` в commands/crash_test.rs). */
export interface CrashTestStepResult {
  /** Тестовый запрос прошёл через шлюз штатно. */
  passed_through: boolean;
  /** Шлюз остановил тестовый запрос (отказ, закрытое соединение или нет ответа за 800 мс). */
  intercepted_by_killswitch: boolean;
  latency_ms: number;
  current_ip: string;
  current_country: string;
  /** Короткий итог шага по-русски, от шлюза. */
  status_text: string;
}

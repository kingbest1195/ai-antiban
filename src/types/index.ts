export type ProviderId = "anthropic" | "openai" | "gemini";

export type OverallStatus = "green" | "yellow" | "red";

/** "unknown" — проверку не удалось выполнить: это не «чисто» и не «плохо». Незнакомая строка статуса читается так же. */
export type CheckStatus = "ok" | "warning" | "critical" | "unknown" | "green" | "yellow" | "red";

/** Почему проверка закончилась статусом unknown (snake_case, как в отчёте шлюза). */
export type UnknownReason =
  | "timeout"
  | "network_error"
  | "empty_response"
  | "no_data"
  | "unsupported_os"
  | "internal_error"
  | "not_applicable"
  | "source_refused";

export type InterceptionBehavior = "ask_popup" | "auto_lock_silent" | "auto_allow_trusted";
export type PopupPosition = "top_right" | "top_center";

export interface CheckResult {
  status: CheckStatus;
  code: string;
  message: string;
  guide_ref?: string | null;
  /** Только вместе со статусом unknown. */
  reason?: UnknownReason | null;
  /** Unix-секунды окончания проверки. */
  checked_at?: number | null;
  /** Через какой источник измерено (справочно). */
  measured_via?: string | null;
  /** Что показал каждый независимый источник (пока только у проверок DNS). */
  detail?: CheckDetail | null;
}

/** Как ответил один источник проверки. */
export type SourceState = "answered" | "special" | "empty" | "timeout" | "failed" | "unsupported";

export interface SourceView {
  /** «Akamai», «Google». */
  source: string;
  state: SourceState;
  addr?: string | null;
  /** Публичный DNS-сервис, которому принадлежит адрес («Cloudflare»). */
  operator?: string | null;
  country?: string | null;
}

/** Тип адреса выхода: хостинг, жилой, выход Tor, массовый VPN или не определён. */
export type IpType = "hosting" | "residential" | "tor" | "vpn" | "unknown";

export interface CheckDetail {
  sources: SourceView[];
  /** Тип адреса (заполняет только проверка репутации адреса). */
  ip_type?: IpType | null;
}

/** Этап запуска шлюза в фоне: пока `starting`, состояние защиты ещё не известно. */
export type StartupPhase = "starting" | "ready";

export interface StartupSnapshot {
  phase: StartupPhase;
  /** recovery | protection | guard, пока идёт запуск. */
  step?: string | null;
}

/** Кусок аудита, пришедший до его конца (событие audit://progress). */
export type AuditProgress =
  | { kind: "telemetry"; telemetry: NetworkTelemetry }
  | { kind: "check"; index: number; result: CheckResult };

export type AuditProgressEvent = AuditProgress & { run_id: string; provider: ProviderId };

/** Что уже известно о идущем аудите: адрес выхода и готовые проверки по местам отчёта. */
export interface PartialAudit {
  runId: string;
  provider: ProviderId;
  telemetry: NetworkTelemetry | null;
  /** Место в `RiskReport.checks`; null — результата ещё нет. */
  checks: (CheckResult | null)[];
}

export interface NetworkTelemetry {
  ip: string;
  country_code: string;
  asn?: number;
  org?: string;
  isp?: string;
  timezone?: string;
  resolved_at: number;
}

export interface RiskReport {
  provider: ProviderId;
  overall_status: OverallStatus;
  trust_score: number;
  telemetry: NetworkTelemetry;
  geo_result: CheckResult;
  pinning_result: CheckResult;
  travel_result: CheckResult;
  dnsbl_result: CheckResult;
  dnsbl_clean_count: string;
  asn_result: CheckResult;
  ipv6_result: CheckResult;
  timezone_result: CheckResult;
  /** Выход в сеть идёт по IPv6: спам-базы и список Tor его не проверяют («не применимо»). Старый отчёт поля не содержит. */
  ipv6_exit?: boolean;
  checks: CheckResult[];
  /** Сколько проверок не удалось выполнить (без «не применимо»). Старый отчёт поля не содержит. */
  unknown_count?: number;
  /** Сколько проверок применимо к этой конфигурации (M в «N из M»). */
  applicable_count?: number;
  /** unknown_count > 0: часть защиты не проверена, отчёт не «чистый». */
  incomplete?: boolean;
}

export interface CleanResult {
  provider: ProviderId;
  cleaned_targets: string[];
  files_removed: number;
  bytes_freed: number;
  success: boolean;
  message: string;
}

export interface BinAuditResult {
  bin: string;
  country_code?: string;
  card_type?: string;
  bank_name?: string;
  is_prepaid: boolean;
  status: CheckStatus;
  advisory: string;
  guide_ref?: string;
}

export interface IpHistoryEntry {
  ip: string;
  country_code: string;
  asn?: number;
  timestamp: number;
}

export interface UpstreamProxyConfig {
  enabled: boolean;
  raw_key: string;
  protocol: string;
  host: string;
  port: number;
  username?: string | null;
  password?: string | null;
  label?: string | null;
}

export interface AppStateData {
  pinned_ip: string | null;
  strict_pinning_enabled: boolean;
  ip_history: Record<string, IpHistoryEntry[]>;
  session_allowed_providers: string[];
  blocked_providers: string[];
  upstream_proxy?: UpstreamProxyConfig | null;
  warmup_started_at?: number | null;
  synced_ai_timezone?: string | null;
  auto_update_enabled?: boolean;
  interception_behavior?: InterceptionBehavior;
  popup_position?: PopupPosition;
  custom_ai_domains?: string[];
  /** Независимый тумблер «Подменять часовой пояс и локаль для ИИ в терминале/IDE». */
  sync_ai_tz_enabled?: boolean;
  /** Режим покрытия CLI. */
  cli_mode?: CliMode;
}

export type AppStateSnapshot = AppStateData;

export type InterceptionAction =
  | "AllowSession"
  | "BlockUntilNetworkChange"
  | "OpenGuideAndBlock"
  | "allowSession"
  | "blockUntilNetworkChange"
  | "openGuideAndBlock";

export interface NetworkChange {
  old_ip?: string | null;
  old_country?: string | null;
  /** null, пока новый адрес ещё не определён. */
  new_ip?: string | null;
  /** null, пока страна нового адреса ещё не определена. */
  new_country?: string | null;
}

/** detecting — окно показано до конца проверки; ready — данные полные; failed — проверка не удалась, запросы остановлены. */
export type AlertPhase = "detecting" | "ready" | "failed";

export interface RiskInterceptPayload {
  id: string;
  provider: ProviderId;
  host: string;
  /** null, пока phase === "detecting". */
  report?: RiskReport | null;
  ttl_seconds: number;
  scope?: "provider" | "network" | string;
  network_change?: NetworkChange | null;
  is_simulation?: boolean;
  /** Unix-время (мс), когда изменение сети обнаружено. */
  detected_at_ms: number;
  phase: AlertPhase;
}

/** interceptor://enriched: данные, пришедшие после показа окна. */
export interface EnrichedPayload {
  id: string;
  /** Эпоха шлюза: устаревшие эпохи игнорируются. */
  epoch: number;
  phase: "ready" | "failed";
  report?: RiskReport | null;
  network_change: NetworkChange;
}

export interface UpdateCheckResult {
  current_version: string;
  latest_version: string;
  update_available: boolean;
  release_name: string;
  release_notes: string;
  release_url: string;
  published_at?: string | null;
}

/** Код ошибки проверки/установки обновления; приходит из Rust как { kind, message? }. */
export type UpdateFailureKind = "network" | "signature" | "no-release" | "install" | "install-restored";

export interface UpdateProgressPayload {
  downloaded_bytes: number;
  total_bytes: number;
  percent: number;
  phase: string;
}

export interface UpdateStatusPayload {
  /** downloading | installing | restarting из Rust; "failed" выставляет сам фронт при ошибке установки. */
  stage: string;
  message: string;
  /** Только при stage === "failed". */
  error?: UpdateFailureKind;
}

export interface ClaudeProjectBrief {
  slug: string;
  decoded_path: string;
  sessions_count: number;
  has_memory: boolean;
  total_bytes: number;
  last_modified?: number | null;
}

export interface ClaudeLocalDataSummary {
  exists: boolean;
  claude_dir_path: string;
  projects_count: number;
  sessions_count: number;
  plans_count: number;
  memory_files_count: number;
  total_size_bytes: number;
  projects: ClaudeProjectBrief[];
  has_claude_md: boolean;
  has_history: boolean;
  has_settings: boolean;
  has_desktop_config: boolean;
  has_claude_json: boolean;
}

export interface ClaudeExportResult {
  export_dir_path: string;
  zip_archive_path?: string | null;
  index_summary_path: string;
  restore_prompt_path: string;
  restore_prompt_text: string;
  projects_exported: number;
  sessions_exported: number;
  total_bytes: number;
}

export interface InstallUpdateResult {
  success: boolean;
  message: string;
  will_restart: boolean;
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
  action: string; // "PROTECTED" | "HELD" | "BLOCKED" | "DIRECT"
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

export interface ClaudeProfile {
  id: string;
  name: string;
  bound_ip?: string | null;
  bound_country?: string | null;
  bound_upstream_key?: string | null;
  isolated_device_id: string;
  created_at: number;
  last_used_at: number;
  is_active: boolean;
  has_saved_session: boolean;
}

export interface ClaudeProfileListResponse {
  profiles: ClaudeProfile[];
  active_profile_id: string;
  claude_desktop_installed: boolean;
  storage_dir: string;
}

export interface ProfileSwitchResult {
  previous_profile_id: string;
  active_profile: ClaudeProfile;
  cleaned_cache_items: number;
  restored_files: number;
  pinned_ip_updated?: string | null;
  bound_upstream_key_updated?: string | null;
  message: string;
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

// ---- Подсистема маршрутов (routes) ----

export type EntryProto = "https" | "socks5" | "http";

export interface EntryView {
  proto: EntryProto;
  host: string;
  port: number;
  username?: string | null;
  has_password: boolean;
  sni?: string | null;
}

export type RouteStatus =
  | "active"
  | "disabled"
  | "expired"
  | "unreachable"
  | "exit_ip_mismatch";

export type RouteHealthStatus = RouteStatus;

export interface RouteHealth {
  reachable?: boolean | null;
  last_error?: string | null;
  observed_exit_ip?: string | null;
  observed_country?: string | null;
  exit_ip_matches?: boolean | null;
  latency_ms?: number | null;
  checked_at: number;
}

export interface RouteView {
  id: string;
  label: string;
  country?: string | null;
  exit_ip?: string | null;
  expires_at?: number | null;
  enabled: boolean;
  added_at: number;
  entries: EntryView[];
  status: RouteStatus;
  is_default: boolean;
  bound_providers: string[];
  is_profile_route: boolean;
  health?: RouteHealth | null;
}

export interface DanglingBinding {
  kind: "provider" | "default" | "profile" | string;
  provider?: string | null;
  route_id: string;
}

export interface RoutesSnapshot {
  routes: RouteView[];
  provider_routes: Record<string, string>;
  default_route_id?: string | null;
  profile_route_id?: string | null;
  effective: Record<string, string | null>;
  profile_route_error?: string | null;
  dangling: DanglingBinding[];
}

export interface RouteTestResult {
  ok: boolean;
  exit_ip?: string | null;
  country?: string | null;
  latency_ms?: number | null;
  exit_ip_matches?: boolean | null;
  error?: string | null;
}

// ---- Подсистема покрытия приложений и цепочки PAC ----

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
export type RestartOutcome = "restarted" | "not_closed" | "needs_automation_permission" | "launch_failed" | "not_installed" | "unsupported";

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
}


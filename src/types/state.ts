import type { IpHistoryEntry, ProviderId, RiskReport } from "./audit";
import type { CliMode } from "./coverage";
import type { CheckoutRiskAlert, PostPaymentQuarantine } from "./payment";

export type InterceptionBehavior = "ask_popup" | "auto_lock_silent" | "auto_allow_trusted";
export type PopupPosition = "top_right" | "top_center";

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

export type CleanProfileStatus = "active" | "warming_up" | "ready" | "tainted";

export interface CleanRoomProfile {
  id: string;
  label: string;
  provider: ProviderId | (string & {});
  browser_engine: "chrome" | "edge" | "brave" | (string & {});
  bound_route_id: string | null;
  last_exit_ip: string | null;
  last_exit_country: string | null;
  status: CleanProfileStatus;
  created_at: number;
  last_opened_at: number | null;
  warmup_started_at: number | null;
  launchpad_step: number;
  completed_checklist: string[];
  post_payment_quarantine?: PostPaymentQuarantine | null;
}

export interface CleanRoomState {
  profiles: CleanRoomProfile[];
  active_profile_id: string | null;
  tainted_ips: Record<string, number>;
  global_post_payment_quarantine?: PostPaymentQuarantine | null;
}

export interface BunkerSettings {
  auto_backup_enabled: boolean;
  interval_hours: number;
  retention_count: number;
  max_total_mb?: number;
  last_backup_at: number | null;
  last_backup_size_bytes: number | null;
}

export interface PersonaSelfCheck {
  bought_or_grey_account: boolean;
  virtual_sms_used: boolean;
  reseller_payment_used: boolean;
  multi_account_same_browser: boolean;
}

export interface AppStateData {
  schema_version?: number;
  pinned_ip: string | null;
  strict_pinning_enabled: boolean;
  ip_history: Record<string, IpHistoryEntry[]>;
  session_allowed_providers: string[];
  blocked_providers: string[];
  /** Постоянные исключения вида { provider: [ip, ...] }, сохраняются между перезапусками. */
  trusted_exceptions?: Record<string, string[]>;
  /** Провайдеры с отключённым мониторингом, PAC-перехватом и алертами. */
  disabled_providers?: string[];
  upstream_proxy?: UpstreamProxyConfig | null;
  warmup_started_at?: number | null;
  synced_ai_timezone?: string | null;
  auto_update_enabled?: boolean;
  interception_behavior?: InterceptionBehavior;
  popup_position?: PopupPosition;
  custom_ai_domains?: string[];
  /** Независимый тумблер «Подменять часовой пояс и локаль для ИИ в терминале/IDE». */
  sync_ai_tz_enabled?: boolean;
  /** Сохранять системный часовой пояс ОС при выходе, обновлении и отключении защиты. */
  keep_system_tz_on_exit?: boolean;
  /** Режим покрытия CLI. */
  cli_mode?: CliMode;
  /** Автозапуск Заставы при входе в систему (в трей). */
  autostart_enabled?: boolean;
  /** Защита от фонового автозапуска ИИ-служб (Windows CoworkVMService / macOS). */
  cowork_guard_enabled?: boolean;
  /** Режим выборочной маршрутизации VPN (split tunneling / TUN). */
  split_tunnel_mode?: boolean;
  /** Попровйдерное закрепление IP-адреса (ключ "default" или ProviderId). */
  pinned_ips?: Record<string, string>;
  /** Скрытие реального IP на экране для безопасных скриншотов. */
  hide_ip_mode?: boolean;
  /** Пройден ли мастер настройки v2.2. */
  onboarding_v2_2_done?: boolean;
  /** Маршруты и привязки в state.json. */
  provider_routes?: Record<string, string>;
  default_route_id?: string | null;
  profile_route_id?: string | null;
  legacy_route_id?: string | null;
  profile_route_invalid?: string | null;
  /** Ручной Kill-Switch («СТОП СЕТИ»). */
  manual_killswitch?: boolean;
  /** Unix-время (сек), до которого действует 4-часовой таймер после безопасного выхода из Claude. */
  ip_change_cooldown_until?: number | null;
  /** Unix-время (сек) последнего безопасного выхода из Claude Desktop/CLI. */
  last_safe_logout_at?: number | null;
  /** Состояние «Чистой комнаты» (v3). */
  clean_room?: CleanRoomState;
  /** Настройки локального «Бункера данных» (v3). */
  bunker?: BunkerSettings;
  /** Чек-лист самооценки риска Persona (v3). */
  persona_self_check?: PersonaSelfCheck;
  /** Пройден ли 5-шаговый онбординг v3.0. */
  onboarding_v3_done?: boolean;
  /** Видел ли пользователь экран «Что нового в v3.0». */
  whats_new_v3_seen?: boolean;
  /** Закрытые контекстные подсказки (HintCard). */
  dismissed_hints?: string[];
  /** Добровольное участие в анонимной статистике карт (по умолчанию выключено). */
  bin_radar_opt_in?: boolean;
}

/** Состояние синхронизации системного часового пояса ОС (`os_tz::OsTzSyncStatus`). */
export interface OsTzSyncStatus {
  synced: boolean;
  current_os_tz: string | null;
  original_os_tz: string | null;
  synced_target_tz: string | null;
  auto_restore_pending: boolean;
  already_matches_target?: boolean;
  target_tz?: string | null;
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
  /** Понятная причина срабатывания перехвата из шлюза. */
  gate_reason?: string | null;
  /** Данные PayShield при перехвате чекаута (scope === "checkout"). */
  checkout_risk?: CheckoutRiskAlert | null;
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
  gate_reason?: string | null;
}

/** interceptor://resolved: результат разрешения перехвата. */
export interface InterceptorResolvedPayload {
  id?: string;
  provider?: string;
  decision?: string;
  should_reaudit?: boolean;
}

export type GuardPauseMode = "none" | "until_network_change" | "manual";

export interface GuardPauseStatus {
  paused: boolean;
  mode: GuardPauseMode;
  gate?: string | null;
  gate_reason?: string | null;
  manual_killswitch: boolean;
  pending_providers?: string[];
  blocked_providers?: string[];
}

export interface ProtectionChangePreviewItem {
  category: string;
  target: string;
  action: string;
  description: string;
  reversible: boolean;
}

export interface ShutdownProgressPayload {
  mode: "quit" | "update";
  step: number;
  total: number;
  label: string;
  done: boolean;
  /** Приложения (например, Antigravity или IDE), которые всё ещё держат адрес шлюза в памяти процесса. */
  gateway_bound_apps?: string[];
}

export interface AutostartStatus {
  platform: string;
  supported: boolean;
  enabled: boolean;
  active_in_os: boolean;
  target: string;
}

export interface DetectedAiProcess {
  name: string;
  kind: "process" | "login_item";
  detail: string;
}

export interface CoworkGuardStatus {
  platform: string;
  supported: boolean;
  service_present: boolean;
  start_type: number | null;
  service_running: boolean;
  task_installed: boolean;
  task_healthy: boolean;
  needs_repair: boolean;
  summary: string;
  detected_ai_apps: DetectedAiProcess[];
}

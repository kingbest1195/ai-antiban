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
  /** Задержка шлюза/активного ключа (мс) из лёгкого probe-замера. */
  gateway_latency_ms?: number | null;
}

export interface CleanResult {
  provider: ProviderId;
  cleaned_targets: string[];
  files_removed: number;
  bytes_freed: number;
  success: boolean;
  message: string;
  found_dir?: boolean;
  locked_targets?: string[];
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
  report?: import("./payment").BinReport | null;
}

export interface IpHistoryEntry {
  ip: string;
  country_code: string;
  asn?: number;
  timestamp: number;
}

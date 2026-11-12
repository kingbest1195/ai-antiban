import { invoke, isTauri } from "@tauri-apps/api/core";
import {
  AppStateData,
  BinAuditResult,
  CheckResult,
  CleanResult,
  ClaudeExportResult,
  ClaudeLocalDataSummary,
  ClaudeProfile,
  ClaudeProfileListResponse,
  AppCoverageItem,
  CliMode,
  CliProtectionReport,
  CliSettings,
  CoverageSnapshot,
  ManualStepKey,
  CrashTestStepResult,
  GatewayStatsSnapshot,
  InstallUpdateResult,
  InterceptionAction,
  InterceptionBehavior,
  PopupPosition,
  ProfileSwitchResult,
  ProviderId,
  RiskReport,
  RouteTestResult,
  RouteView,
  RoutesSnapshot,
  UpdateCheckResult,
  UpstreamProxyConfig,
  RiskInterceptPayload,
  EnrichedPayload,
} from "../types";

let mockState: AppStateData = {
  pinned_ip: "185.212.102.40",
  strict_pinning_enabled: true,
  ip_history: {},
  session_allowed_providers: [],
  blocked_providers: [],
  upstream_proxy: null,
  warmup_started_at: null,
  synced_ai_timezone: null,
  auto_update_enabled: true,
  interception_behavior: "ask_popup",
  popup_position: "top_right",
  custom_ai_domains: [],
  // Как в шлюзе: подмена включена по умолчанию, применяется только при известной зоне.
  sync_ai_tz_enabled: true,
  cli_mode: "ai_only",
};

let mockKillswitchStatus = false;
/** Мок настроек CLI и подмены часового пояса: независимые флаги, как у шлюза. */
let mockCliProtection = true;
let mockCliMode: CliMode = "ai_only";
let mockSyncAiTz = true;
/** Сколько раз нажали «Проверить снова»: мок продвигает статусы по шагам. */
let mockCoverageStage = 0;
/** Сценарий VPN в моке «Покрытия»: нет VPN, VPN перебивает системный PAC, VPN подключён, но PAC действует. */
export type MockVpnScenario = "none" | "overrides" | "effective";
let mockVpnScenario: MockVpnScenario = "none";

export function setMockVpnScenario(scenario: MockVpnScenario): void {
  mockVpnScenario = scenario;
}

/** Сценарий из мока или из адреса страницы (?mockVpn=overrides|effective) — только в браузере без Tauri. */
function currentMockVpnScenario(): MockVpnScenario {
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
function currentMockAntigravityScenario(): MockAntigravityScenario {
  if (mockAntigravityScenario !== "none" || typeof window === "undefined") return mockAntigravityScenario;
  const fromUrl = new URLSearchParams(window.location.search).get("mockAntigravity");
  return fromUrl === "uncovered" || fromUrl === "bypass" || fromUrl === "confirmed" ? fromUrl : "none";
}

let mockRoutesSnapshot: RoutesSnapshot = {
  routes: [],
  provider_routes: {},
  default_route_id: null,
  profile_route_id: null,
  effective: {
    anthropic: null,
    openai: null,
    gemini: null,
  },
  profile_route_error: null,
  dangling: [],
};

export type MockScenario = "clean" | "turkey" | "ru";

let mockSysproxyActive = true;
let mockCountryOverride: string | null = null;
let currentMockScenario: MockScenario = "clean";
let mockCrashTestStep = 0;
let mockCrashTestDropped = false;

let mockProfiles: ClaudeProfile[] = [
  {
    id: "default",
    name: "Основной аккаунт (Pro)",
    bound_ip: "185.212.102.40",
    bound_country: "NL",
    isolated_device_id: "7f4c9a81-e32a-4a22-921a-969421fb3101",
    created_at: Math.floor(Date.now() / 1000) - 86400 * 14,
    last_used_at: Math.floor(Date.now() / 1000),
    is_active: true,
    has_saved_session: true,
  },
  {
    id: "backup-dev",
    name: "Рабочий профиль (Dev)",
    bound_ip: "145.241.12.8",
    bound_country: "DE",
    isolated_device_id: "2d1b829c-fa14-4903-883a-4817a0224b55",
    created_at: Math.floor(Date.now() / 1000) - 86400 * 3,
    last_used_at: Math.floor(Date.now() / 1000) - 3600 * 8,
    is_active: false,
    has_saved_session: true,
  },
];

export function setBrowserMockCountry(country: string | null) {
  mockCountryOverride = country;
  if (country === "TR") currentMockScenario = "turkey";
  else if (country === "RU") currentMockScenario = "ru";
  else currentMockScenario = "clean";
}

export function getMockScenario(): MockScenario {
  return currentMockScenario;
}

export function setMockScenario(scenario: MockScenario) {
  currentMockScenario = scenario;
  if (scenario === "turkey") {
    mockCountryOverride = "TR";
  } else if (scenario === "ru") {
    mockCountryOverride = "RU";
  } else {
    mockCountryOverride = "NL";
  }
}

export async function fetchAppState(): Promise<AppStateData> {
  if (isTauri()) {
    return await invoke<AppStateData>("get_state");
  }
  return { ...mockState };
}

export async function toggleAutoUpdate(enabled: boolean): Promise<void> {
  if (isTauri()) {
    return await invoke("toggle_auto_update", { enabled });
  }
  mockState.auto_update_enabled = enabled;
}

export async function auditConnection(
  provider: ProviderId = "anthropic",
  forceRefresh: boolean = false
): Promise<RiskReport> {
  if (isTauri()) {
    return await invoke<RiskReport>("audit_connection", {
      provider,
      forceRefresh,
    });
  }

  const hasUpstream = mockState.upstream_proxy?.enabled;
  const country = hasUpstream ? "NL" : mockCountryOverride || "NL";
  const isTurkey = !hasUpstream && country === "TR";
  const isRu = !hasUpstream && country === "RU";

  let overall: "green" | "yellow" | "red" = "green";
  let score = 98;
  let geoResult = {
    status: "ok" as "ok" | "warning" | "critical",
    code: "GEO_ALLOWED",
    message: `Локация ${country} полностью совместима и безопасна для ${
      provider === "anthropic"
        ? "Claude (Anthropic)"
        : provider === "openai"
        ? "ChatGPT (OpenAI)"
        : "Google Gemini / AI Studio"
    }.`,
  };

  if (isRu) {
    overall = "red";
    score = 15;
    geoResult = {
      status: "critical",
      code: "GLOBAL_SANCTIONED_COUNTRY",
      message:
        "Подключение идет из неподдерживаемого региона. Прямой доступ к сервису ограничен политиками платформы в этой юрисдикции. Переключитесь на доверенный рабочий шлюз (NL, DE, US).",
    };
  } else if (isTurkey) {
    if (provider === "gemini") {
      overall = "red";
      score = 22;
      geoResult = {
        status: "critical",
        code: "GEMINI_GEO_BLOCKED",
        message:
          "Google Gemini и AI Studio не работают или жестко ограничены с турецких IP-адресов (Turkey / TR). Переключитесь на Нидерланды (NL), Германию (DE) или США (US).",
      };
    } else if (provider === "anthropic") {
      overall = "yellow";
      score = 65;
      geoResult = {
        status: "warning",
        code: "ANTHROPIC_GEO_WARNING",
        message:
          "Локация Турция (TR) находится в зоне повышенного риска у Anthropic из-за массового реселлинга и дешевых прокси.",
      };
    }
  }

  const currentIp = isTurkey ? "185.220.101.5" : isRu ? "95.165.10.22" : mockState.pinned_ip || "185.212.102.40";
  const isPinned = mockState.pinned_ip === currentIp;

  const pinningResult = {
    status: isPinned ? ("ok" as const) : mockState.strict_pinning_enabled ? ("critical" as const) : ("warning" as const),
    code: isPinned ? "PINNED_IP_MATCH" : mockState.strict_pinning_enabled ? "PINNED_IP_MISMATCH" : "PINNED_IP_NOT_CONFIGURED",
    message: isPinned
      ? `Трафик идет через ваш закрепленный личный VPS (${currentIp}).`
      : mockState.strict_pinning_enabled
      ? `Нарушение Strict Pinning: текущий IP (${currentIp}) не совпадает с эталонным VPS (${mockState.pinned_ip}).`
      : "Строгая привязка IP отключена. Рекомендуется закрепить личный VPS.",
    guide_ref: "01-personal-vpn-15min",
  };

  const travelResult = {
    status: "ok" as const,
    code: "TRAVEL_NORMAL",
    message: "География сессий стабильна (1 локация за 24ч, аномалий Impossible Travel нет).",
  };

  const dnsblResult = {
    status: isTurkey ? ("warning" as const) : ("ok" as const),
    code: isTurkey ? "DNSBL_LISTED_WARNING" : "DNSBL_CLEAN",
    message: isTurkey
      ? "IP найден в базе абузных прокси DroneBL (пул M247 Europe SRL — 400+ соседей на IP)."
      : "Проверка DNSBL: ответили 4 из 4 спам-баз, совпадений нет.",
  };

  const asnResult = {
    status: isTurkey ? ("warning" as const) : ("ok" as const),
    code: isTurkey ? "HIGH_RISK_MASS_VPN_ASN" : "ASN_VERIFIED_PINNED",
    message: isTurkey
      ? "Подсеть массового VPN «M247 Europe SRL» (AS9009). Сотни пользователей на одном IP."
      : "AS20473 (HostVDS / Choopa LLC) подтвержден как выделенный личный сервер.",
  };

  // В турецком сценарии мок показывает все цвета сразу: ok, warning, critical и «не удалось проверить».
  const ipv6Result: CheckResult = isTurkey
    ? { status: "critical", code: "IPV6_LEAK_DETECTED", message: "Найден глобальный IPv6-адрес: реальный адрес может уйти мимо VPN." }
    : {
        status: "ok",
        code: "IPV6_DISABLED_SAFE",
        message: "Утечек по протоколу IPv6 не обнаружено (трафик идет строго через IPv4-туннель).",
      };

  const dnsResult: CheckResult = isTurkey
    ? {
        status: "unknown",
        code: "DNS_TIMEOUT",
        message: "Проверка DNS-серверов не завершилась.",
        reason: "timeout",
      }
    : {
        status: "ok",
        code: "DNS_CLEAN",
        message: "Утечек через локальные DNS-резолверы РФ не обнаружено (Cloudflare 1.1.1.1).",
        measured_via: "whoami:akamai+google",
      };

  const tzResult = {
    status: isTurkey ? ("warning" as const) : ("ok" as const),
    code: isTurkey ? "TIMEZONE_MISMATCH" : "TIMEZONE_MATCH",
    message: isTurkey
      ? "Часовой пояс ОС (Europe/Moscow) конфликтует с таймзоной IP (Europe/Istanbul)."
      : "Системный часовой пояс совпадает с регионом сервера (Europe/Amsterdam).",
  };

  // Мок показывает «не применимо»: Wi-Fi не используется.
  const locResult: CheckResult = {
    status: "unknown",
    code: "OS_LOCATION_NOT_APPLICABLE",
    message: "Компьютер не подключён к Wi-Fi: проверять геолокацию по роутерам нечего.",
    reason: "not_applicable",
  };

  const report: RiskReport = {
    provider,
    overall_status: overall,
    trust_score: score,
    telemetry: {
      ip: currentIp,
      country_code: country,
      asn: isTurkey ? 9009 : 20473,
      org: isTurkey ? "M247 Europe SRL" : "HostVDS / Choopa LLC",
      isp: isTurkey ? "M247 Europe SRL" : "HostVDS Cloud NL",
      timezone: isTurkey ? "Europe/Istanbul" : "Europe/Amsterdam",
      resolved_at: Math.floor(Date.now() / 1000),
    },
    geo_result: geoResult,
    pinning_result: pinningResult,
    travel_result: travelResult,
    dnsbl_result: dnsblResult,
    dnsbl_clean_count: isTurkey ? "3/4 Внимание" : "4/4 Чисто",
    asn_result: asnResult,
    ipv6_result: ipv6Result,
    timezone_result: tzResult,
    checks: [
      geoResult,
      pinningResult,
      travelResult,
      dnsblResult,
      asnResult,
      ipv6Result,
      dnsResult,
      tzResult,
      locResult,
      {
        status: "ok",
        code: "REVERSE_DNS_CLEAN",
        message: "Reverse DNS: ptr.hostvds.net не содержит стоп-слов коммерческих прокси.",
        guide_ref: null,
      },
      {
        status: "ok",
        code: "DNS_COUNTRY_CONSISTENT",
        message: "DNS-резолверы находятся в той же юрисдикции, что и выходной IP.",
        guide_ref: null,
        measured_via: "whoami:akamai+google",
      },
      {
        status: "ok",
        code: "LOCALE_HYGIENE_CLEAN",
        message: "Локаль среды и системные переменные безопасны.",
        guide_ref: null,
      },
      {
        status: "ok",
        code: "UDP_STUN_MATCH",
        message: "UDP-запросы выходят с тем же адресом, что и обычный трафик: утечки мимо туннеля нет.",
        guide_ref: null,
        measured_via: "stun:cloudflare+google",
      },
    ],
  };
  // Счётчики как у шлюза: «не применимо» не входит ни в unknown_count, ни в applicable_count.
  const notApplicable = report.checks.filter((c) => c.status === "unknown" && c.reason === "not_applicable").length;
  report.unknown_count = report.checks.filter((c) => c.status === "unknown").length - notApplicable;
  report.applicable_count = report.checks.length - notApplicable;
  report.incomplete = report.unknown_count > 0;
  return report;
}

export async function pinCurrentIp(ip: string): Promise<void> {
  if (isTauri()) {
    return await invoke("pin_current_ip", { ip });
  }
  mockState.pinned_ip = ip;
}

export async function unpinIp(): Promise<void> {
  if (isTauri()) {
    return await invoke("unpin_ip");
  }
  mockState.pinned_ip = null;
}

export async function toggleStrictPinning(enabled: boolean): Promise<void> {
  if (isTauri()) {
    return await invoke("toggle_strict_pinning", { enabled });
  }
  mockState.strict_pinning_enabled = enabled;
}

export async function allowProviderSession(provider: ProviderId): Promise<void> {
  if (isTauri()) {
    return await invoke("allow_provider_session", { provider });
  }
  if (!mockState.session_allowed_providers.includes(provider)) {
    mockState.session_allowed_providers.push(provider);
  }
}

export async function unblockProvider(provider: ProviderId): Promise<void> {
  if (isTauri()) {
    return await invoke("unblock_provider_cmd", { provider });
  }
  mockState.blocked_providers = mockState.blocked_providers.filter(
    (p) => p !== provider
  );
}

export async function resolveInterception(
  id: string,
  action: InterceptionAction,
  provider: ProviderId,
  scope?: string
): Promise<void> {
  if (isTauri()) {
    return await invoke("resolve_interception", {
      id,
      action,
      provider,
      scope,
    });
  }
  if (mockPendingAlert?.id === id) mockPendingAlert = null;
}

/** Текущий активный алерт (для окна, открытого после события). В браузере-моке — последний смоделированный. */
export async function takePendingAlert(): Promise<RiskInterceptPayload | null> {
  if (isTauri()) {
    return await invoke<RiskInterceptPayload | null>("take_pending_alert");
  }
  return mockPendingAlert;
}

/** Сценарии мок-эмиттера предупреждения (только в браузере, без Tauri). */
export type MockAlertScenario = "default" | "slow-enrich";

export const MOCK_ALERT_DETECTED_EVENT = "mock-interceptor-risk-detected";
export const MOCK_ALERT_ENRICHED_EVENT = "mock-interceptor-enriched";

let mockPendingAlert: RiskInterceptPayload | null = null;

function mockAlertReport(): RiskReport {
  const now = Math.floor(Date.now() / 1000);
  const ok = (code: string, message: string) => ({ status: "ok" as const, code, message, guide_ref: null });
  return {
    provider: "anthropic",
    overall_status: "red",
    trust_score: 28,
    unknown_count: 1,
    applicable_count: 13,
    incomplete: true,
    telemetry: {
      ip: "185.220.101.5",
      country_code: "RU",
      asn: 9009,
      isp: "M247 Europe SRL",
      org: "M247 Europe SRL",
      timezone: "Europe/Moscow",
      resolved_at: now,
    },
    geo_result: {
      status: "critical",
      code: "GEO_HIGH_RISK_RU",
      message: "Локация RU не поддерживается сервисом ИИ.",
      guide_ref: "01-personal-vpn-15min",
    },
    pinning_result: {
      status: "warning",
      code: "PINNED_IP_NOT_CONFIGURED",
      message: "Трафик идет НЕ через закрепленный VPS.",
      guide_ref: "01-personal-vpn-15min",
    },
    travel_result: ok("TRAVEL_NORMAL", "Конфликтов перемещения за 12ч нет."),
    dnsbl_result: ok("DNSBL_CLEAN", "В спам-базах не числится."),
    dnsbl_clean_count: "4/4 Чисто",
    asn_result: ok("ASN_CLEAN", "Чистая автономная система."),
    ipv6_result: ok("IPV6_SAFE", "Утечек IPv6 нет."),
    timezone_result: ok("TIMEZONE_OK", "Часовой пояс согласован."),
    checks: [],
  };
}

function emitMock(name: string, detail: unknown) {
  window.dispatchEvent(new CustomEvent(name, { detail }));
}

/** Мок-эмиттер: сценарий выбирается аргументом или параметром адреса `?mockAlert=slow-enrich`. */
function runMockAlert(provider: ProviderId, scenario: MockAlertScenario) {
  const id = "sim-" + Date.now();
  const base: RiskInterceptPayload = {
    id,
    provider,
    host: "api.anthropic.com:443",
    ttl_seconds: 60,
    is_simulation: true,
    scope: "provider",
    detected_at_ms: Date.now(),
    phase: "ready",
    network_change: { old_ip: "185.212.102.40", old_country: "NL", new_ip: "185.220.101.5", new_country: "RU" },
    report: mockAlertReport(),
  };
  if (scenario === "slow-enrich") {
    const detecting: RiskInterceptPayload = {
      ...base,
      phase: "detecting",
      report: null,
      network_change: { old_ip: "185.212.102.40", old_country: "NL", new_ip: "185.220.101.5", new_country: null },
    };
    mockPendingAlert = detecting;
    emitMock(MOCK_ALERT_DETECTED_EVENT, detecting);
    window.setTimeout(() => {
      if (mockPendingAlert?.id !== id) return;
      const enriched: EnrichedPayload = {
        id,
        epoch: 1,
        phase: "ready",
        report: base.report,
        network_change: base.network_change!,
      };
      mockPendingAlert = { ...base };
      emitMock(MOCK_ALERT_ENRICHED_EVENT, enriched);
    }, 2000);
    return;
  }
  mockPendingAlert = base;
  emitMock(MOCK_ALERT_DETECTED_EVENT, base);
}

export async function simulateInterception(
  provider: ProviderId = "anthropic",
  scenario?: MockAlertScenario
): Promise<void> {
  if (isTauri()) {
    return await invoke("simulate_interception", { provider });
  }
  const fromUrl = new URLSearchParams(window.location.search).get("mockAlert");
  runMockAlert(provider, scenario ?? (fromUrl === "slow-enrich" ? "slow-enrich" : "default"));
}

export async function toggleSysproxy(enable: boolean): Promise<boolean> {
  if (isTauri()) {
    return await invoke<boolean>("toggle_sysproxy", { enable });
  }
  mockSysproxyActive = enable;
  return mockSysproxyActive;
}

export async function enableCliProtection(): Promise<CliProtectionReport> {
  if (isTauri()) {
    return await invoke<CliProtectionReport>("enable_cli_protection");
  }
  mockCliProtection = true;
  return {
    enabled: true,
    proxy_url: "http://127.0.0.1:40111",
    configured_targets: [
      "~/.zshrc",
      "~/.bashrc",
      "VS Code Settings",
      "Cursor Settings",
    ],
    shell_command:
      'export HTTP_PROXY="http://127.0.0.1:40111" HTTPS_PROXY="http://127.0.0.1:40111" ALL_PROXY="http://127.0.0.1:40111"',
  };
}

export async function disableCliProtection(): Promise<boolean> {
  if (isTauri()) {
    return await invoke<boolean>("disable_cli_protection");
  }
  mockCliProtection = false;
  return false;
}

export async function checkCliProtectionStatus(): Promise<boolean> {
  if (isTauri()) {
    return await invoke<boolean>("check_cli_protection_status");
  }
  return mockCliProtection;
}

export async function syncAiAgentsTimezone(timezone: string): Promise<string> {
  if (isTauri()) {
    return await invoke<string>("sync_ai_agents_timezone", { timezone });
  }
  mockState.synced_ai_timezone = timezone;
  if (!mockSyncAiTz) {
    return `Зона ${timezone} сохранена, но подмена часового пояса и локали выключена.`;
  }
  return `Таймзона ${timezone} и en_US.UTF-8 синхронизированы в браузере и окружении.`;
}

const mockCliSettings = (): CliSettings => ({
  cli_mode: mockCliMode,
  sync_ai_tz_enabled: mockSyncAiTz,
  cli_protection_enabled: mockCliProtection,
  synced_ai_timezone: mockState.synced_ai_timezone ?? null,
});

/** Режим покрытия CLI и тумблер подмены часового пояса/локали (независимые). */
export async function getCliSettings(): Promise<CliSettings> {
  if (isTauri()) {
    return await invoke<CliSettings>("get_cli_settings");
  }
  return mockCliSettings();
}

/** Применяется сразу; при отказе шлюза бросает ошибку с русским текстом, режим не меняется. */
export async function setCliMode(mode: CliMode): Promise<CliSettings> {
  if (isTauri()) {
    return await invoke<CliSettings>("set_cli_mode", { mode });
  }
  mockCliMode = mode;
  mockState.cli_mode = mode;
  return mockCliSettings();
}

/** Включает или откатывает TZ/LANG/LC_TIME сразу; защиту CLI не трогает. */
export async function setSyncAiTzEnabled(enabled: boolean): Promise<CliSettings> {
  if (isTauri()) {
    return await invoke<CliSettings>("set_sync_ai_tz_enabled", { enabled });
  }
  mockSyncAiTz = enabled;
  mockState.sync_ai_tz_enabled = enabled;
  if (enabled && !mockState.synced_ai_timezone) mockState.synced_ai_timezone = "Europe/Amsterdam";
  return mockCliSettings();
}

export async function openOsDatetimeSettings(): Promise<void> {
  if (isTauri()) {
    return await invoke("open_os_datetime_settings_cmd");
  }
}

export async function getSysproxyStatus(): Promise<boolean> {
  if (isTauri()) {
    return await invoke<boolean>("get_sysproxy_status");
  }
  return mockSysproxyActive;
}

export async function checkPaymentBin(
  bin: string,
  vpnCountry?: string
): Promise<BinAuditResult> {
  if (isTauri()) {
    return await invoke<BinAuditResult>("check_payment_bin", {
      bin,
      vpnCountry,
    });
  }

  const cleanBin = bin.replace(/\s+/g, "").slice(0, 6);
  if (cleanBin.startsWith("489504") || cleanBin.startsWith("414720")) {
    return {
      bin: cleanBin,
      country_code: "US",
      card_type: "Debit",
      bank_name: "JPMorgan Chase Bank, N.A.",
      is_prepaid: false,
      status: "ok",
      advisory: "Карта выпущена в США (US), не является предоплаченной (Credit/Debit). Отличная проходимость в Stripe/Anthropic.",
      guide_ref: "02-safe-payment-cards",
    };
  }

  return {
    bin: cleanBin,
    country_code: "GB",
    card_type: "Debit",
    bank_name: "Barclays Bank UK PLC",
    is_prepaid: false,
    status: "ok",
    advisory: "Регион карты совпадает с гео-политиками большинства ИИ-провайдеров.",
    guide_ref: "02-safe-payment-cards",
  };
}

export async function checkForUpdates(): Promise<UpdateCheckResult> {
  if (isTauri()) {
    return await invoke<UpdateCheckResult>("check_for_updates");
  }
  return {
    current_version: "1.2.0",
    latest_version: "1.2.0",
    update_available: false,
    release_name: "Zastava v1.2.0: Multi-Account Isolator & Live VPN Crash-Test",
    release_notes: "Релиз v1.2.0: изоляция мульти-аккаунтов Claude, боевой краш-тест VPN, исправление мигания окон Windows 11.",
    release_url: "https://github.com/kingbest1195/ai-antiban/releases",
  };
}

/** Установка подписанного обновления. Ничего не принимает: адрес и подпись бэкенд берёт из latest.json. */
export async function installUpdate(): Promise<InstallUpdateResult> {
  if (isTauri()) {
    return await invoke<InstallUpdateResult>("install_update");
  }
  return {
    success: true,
    message: "Обновление готово к установке.",
    will_restart: true,
  };
}

export async function setUpstreamProxy(
  key: string
): Promise<UpstreamProxyConfig> {
  if (isTauri()) {
    return await invoke<UpstreamProxyConfig>("set_upstream_proxy", { key });
  }
  const cfg: UpstreamProxyConfig = {
    enabled: true,
    raw_key: key,
    protocol: "http",
    host: "185.212.102.40",
    port: 8899,
    label: "Zastava Upstream Clean NL",
  };
  mockState.upstream_proxy = cfg;
  return cfg;
}

export async function toggleUpstreamProxy(
  enabled: boolean
): Promise<UpstreamProxyConfig | null> {
  if (isTauri()) {
    return await invoke<UpstreamProxyConfig | null>("toggle_upstream_proxy", {
      enabled,
    });
  }
  if (mockState.upstream_proxy) {
    mockState.upstream_proxy.enabled = enabled;
    return { ...mockState.upstream_proxy };
  }
  return null;
}

export async function clearUpstreamProxy(): Promise<boolean> {
  if (isTauri()) {
    return await invoke<boolean>("clear_upstream_proxy");
  }
  mockState.upstream_proxy = null;
  return true;
}

export async function setWarmupTimer(
  timestamp: number | null
): Promise<number | null> {
  if (isTauri()) {
    return await invoke<number | null>("set_warmup_timer", { timestamp });
  }
  mockState.warmup_started_at = timestamp;
  return timestamp;
}

export async function getGatewayStats(): Promise<GatewayStatsSnapshot> {
  if (isTauri()) {
    return await invoke<GatewayStatsSnapshot>("get_gateway_stats");
  }
  return {
    protected_ai_requests: 142,
    intercepted_leaks: 0,
    direct_bypassed_requests: 864,
    active_ai_tunnels: 0,
    uptime_seconds: 1840,
    last_protected_host: "api.anthropic.com",
    recent_events: [
      {
        timestamp: Math.floor(Date.now() / 1000) - 24,
        host: "api.anthropic.com",
        provider: "anthropic",
        action: "PROTECTED",
        country: "NL",
      },
      {
        timestamp: Math.floor(Date.now() / 1000) - 52,
        host: "github.com",
        provider: "non-ai",
        action: "DIRECT",
        country: "DIRECT",
      },
    ],
  };
}

export async function cleanAppCache(provider: ProviderId): Promise<CleanResult> {
  if (isTauri()) {
    return await invoke<CleanResult>("clean_app_cache", { provider });
  }
  return {
    provider,
    cleaned_targets: ["Cookies", "Cache", "ant-device-registry.json"],
    files_removed: 18,
    bytes_freed: 14200000,
    success: true,
    message: "Локальные реестры и кэш успешно сброшены.",
  };
}

export async function scanClaudeLocalData(): Promise<ClaudeLocalDataSummary> {
  if (isTauri()) {
    return await invoke<ClaudeLocalDataSummary>("scan_claude_data_cmd");
  }
  return {
    exists: true,
    claude_dir_path: "~/.claude",
    projects_count: 3,
    sessions_count: 14,
    plans_count: 2,
    memory_files_count: 5,
    total_size_bytes: 4200000,
    projects: [
      {
        slug: "zastava-desktop",
        decoded_path: "~/local-projects/zastava",
        sessions_count: 8,
        has_memory: true,
        total_bytes: 2800000,
      },
      {
        slug: "finance-bot",
        decoded_path: "~/projects/finance-bot",
        sessions_count: 4,
        has_memory: true,
        total_bytes: 1100000,
      },
    ],
    has_claude_md: true,
    has_history: true,
    has_settings: true,
    has_desktop_config: true,
    has_claude_json: true,
  };
}

export async function exportClaudeLocalData(): Promise<ClaudeExportResult> {
  if (isTauri()) {
    return await invoke<ClaudeExportResult>("export_claude_data_cmd");
  }
  return {
    export_dir_path: "~/Desktop/Claude_Export_20261109",
    zip_archive_path: "~/Desktop/Claude_Export_20261109.zip",
    index_summary_path: "~/Desktop/Claude_Export_20261109/INDEX_SUMMARY.md",
    restore_prompt_path: "~/Desktop/Claude_Export_20261109/RESTORE_PROMPT.txt",
    restore_prompt_text: "Вы — AI-ассистент, продолжающий разработку проектов. Вот контекст и история всех сессий...",
    projects_exported: 3,
    sessions_exported: 14,
    total_bytes: 4200000,
  };
}

// -------------------------------------------------------------
// v1.2.0: Multi-Account Claude Profile Switcher API
// -------------------------------------------------------------

export async function listClaudeProfiles(): Promise<ClaudeProfileListResponse> {
  if (isTauri()) {
    return await invoke<ClaudeProfileListResponse>("list_claude_profiles_cmd");
  }
  return {
    profiles: [...mockProfiles],
    active_profile_id: mockProfiles.find((p) => p.is_active)?.id || "default",
    claude_desktop_installed: true,
    storage_dir: "~/.zastava/claude_profiles",
  };
}

export async function createClaudeProfile(
  name: string,
  bindIpOrEmail?: string | null,
  bindCountryOrIp?: string | boolean | null,
  bindUpstreamKeyOrCurrentIp?: string | null,
  bindUpstreamKeyParam?: string | null
): Promise<ClaudeProfileListResponse> {
  let bindIp: string | null = null;
  let bindCountry: string | null = null;
  let upstreamKey: string | null = null;

  if (typeof bindCountryOrIp === "boolean") {
    // Called as: (name, emailOrLabel, bindCurrentIp, currentIp, bindUpstreamKey)
    bindIp = bindCountryOrIp && bindUpstreamKeyOrCurrentIp ? bindUpstreamKeyOrCurrentIp : null;
    bindCountry = null;
    upstreamKey = bindUpstreamKeyParam || null;
  } else {
    // Called as: (name, bindIp, bindCountry, bindUpstreamKey)
    bindIp = bindIpOrEmail || null;
    bindCountry = bindCountryOrIp || null;
    upstreamKey = bindUpstreamKeyOrCurrentIp || bindUpstreamKeyParam || null;
  }

  if (isTauri()) {
    return await invoke<ClaudeProfileListResponse>("create_claude_profile_cmd", {
      name,
      bindIp: bindIp ?? null,
      bindCountry: bindCountry ?? null,
      bindUpstreamKey: upstreamKey ?? null,
    });
  }
  const newProfile: ClaudeProfile = {
    id: "profile-" + Date.now().toString(36),
    name: name.trim(),
    bound_ip: bindIp || null,
    bound_country: bindCountry || null,
    bound_upstream_key: upstreamKey || null,
    isolated_device_id: (typeof crypto !== "undefined" && crypto.randomUUID) ? crypto.randomUUID() : "iso-" + Math.random().toString(36).slice(2),
    created_at: Math.floor(Date.now() / 1000),
    last_used_at: Math.floor(Date.now() / 1000),
    is_active: false,
    has_saved_session: false,
  };
  mockProfiles.push(newProfile);
  return await listClaudeProfiles();
}

export async function switchClaudeProfile(
  targetId: string
): Promise<ProfileSwitchResult> {
  if (isTauri()) {
    return await invoke<ProfileSwitchResult>("switch_claude_profile_cmd", {
      targetId,
    });
  }
  const prevActive = mockProfiles.find((p) => p.is_active)?.id || "default";
  mockProfiles = mockProfiles.map((p) => ({
    ...p,
    is_active: p.id === targetId,
    last_used_at: p.id === targetId ? Math.floor(Date.now() / 1000) : p.last_used_at,
  }));
  const activeProf = mockProfiles.find((p) => p.id === targetId)!;
  if (activeProf.bound_ip) {
    mockState.pinned_ip = activeProf.bound_ip;
  }
  return {
    previous_profile_id: prevActive,
    active_profile: activeProf,
    cleaned_cache_items: 7,
    restored_files: 5,
    pinned_ip_updated: activeProf.bound_ip || null,
    bound_upstream_key_updated: activeProf.bound_upstream_key || null,
    message: `Очищено кэшей: 7, восстановлен изолированный Device ID: #${activeProf.isolated_device_id.slice(0, 8)}`,
  };
}

export async function deleteClaudeProfile(
  profileId: string
): Promise<ClaudeProfileListResponse> {
  if (isTauri()) {
    return await invoke<ClaudeProfileListResponse>("delete_claude_profile_cmd", {
      profileId,
    });
  }
  if (mockProfiles.length > 1) {
    mockProfiles = mockProfiles.filter((p) => p.id !== profileId);
    if (!mockProfiles.some((p) => p.is_active)) {
      mockProfiles[0].is_active = true;
    }
  }
  return await listClaudeProfiles();
}

export async function bindIpToClaudeProfile(
  profileId: string,
  ip: string,
  country?: string | null
): Promise<ClaudeProfileListResponse> {
  if (isTauri()) {
    return await invoke<ClaudeProfileListResponse>("bind_ip_to_claude_profile_cmd", {
      profileId,
      bindIp: ip,
      bindCountry: country ?? null,
    });
  }
  mockProfiles = mockProfiles.map((p) =>
    p.id === profileId ? { ...p, bound_ip: ip, bound_country: country || null } : p
  );
  return await listClaudeProfiles();
}

export async function bindUpstreamToClaudeProfile(
  profileId: string,
  upstreamKey: string | null
): Promise<ClaudeProfileListResponse> {
  if (isTauri()) {
    return await invoke<ClaudeProfileListResponse>(
      "bind_upstream_to_claude_profile_cmd",
      {
        profileId,
        upstreamKey: upstreamKey || null,
      }
    );
  }
  mockProfiles = mockProfiles.map((p) =>
    p.id === profileId ? { ...p, bound_upstream_key: upstreamKey || null } : p
  );
  return await listClaudeProfiles();
}

// -------------------------------------------------------------
// v1.3.0: Interception Behavior, Popup Position & Custom AI Domains
// -------------------------------------------------------------

export async function setInterceptionBehavior(
  behavior: InterceptionBehavior
): Promise<InterceptionBehavior> {
  if (isTauri()) {
    await invoke("set_interception_behavior_cmd", { behavior });
    return behavior;
  }
  mockState.interception_behavior = behavior;
  return behavior;
}

export async function getInterceptionBehavior(): Promise<InterceptionBehavior> {
  if (isTauri()) {
    return await invoke<InterceptionBehavior>("get_interception_behavior_cmd");
  }
  return mockState.interception_behavior || "ask_popup";
}

export async function setPopupPosition(
  position: PopupPosition
): Promise<PopupPosition> {
  if (isTauri()) {
    await invoke("set_popup_position_cmd", { position });
    return position;
  }
  mockState.popup_position = position;
  return position;
}

export async function getPopupPosition(): Promise<PopupPosition> {
  if (isTauri()) {
    return await invoke<PopupPosition>("get_popup_position_cmd");
  }
  return mockState.popup_position || "top_right";
}

export async function getCustomAiDomains(): Promise<string[]> {
  if (isTauri()) {
    return await invoke<string[]>("get_custom_ai_domains_cmd");
  }
  return [...(mockState.custom_ai_domains || [])];
}

export async function addCustomAiDomain(domain: string): Promise<string[]> {
  if (isTauri()) {
    return await invoke<string[]>("add_custom_ai_domain_cmd", { domain });
  }
  const clean = domain.trim().toLowerCase();
  const current = mockState.custom_ai_domains || [];
  if (clean && !current.includes(clean)) {
    mockState.custom_ai_domains = [...current, clean];
  }
  return [...(mockState.custom_ai_domains || [])];
}

export async function removeCustomAiDomain(domain: string): Promise<string[]> {
  if (isTauri()) {
    return await invoke<string[]>("remove_custom_ai_domain_cmd", { domain });
  }
  const clean = domain.trim().toLowerCase();
  mockState.custom_ai_domains = (mockState.custom_ai_domains || []).filter(
    (d) => d.toLowerCase() !== clean
  );
  return [...(mockState.custom_ai_domains || [])];
}

export async function forceCleanOsProxy(): Promise<string[]> {
  if (isTauri()) {
    return await invoke<string[]>("force_clean_os_proxy_cmd");
  }
  return [
    "Системный прокси macOS/Windows очищен",
    "Сетевые переменные окружения HTTP_PROXY/HTTPS_PROXY сброшены",
    "Служебные DNS-записи восстановлены",
  ];
}

export async function toggleNetworkKillswitch(
  freeze?: boolean
): Promise<boolean> {
  if (isTauri()) {
    return await invoke<boolean>("toggle_network_killswitch_cmd", {
      freeze: freeze !== undefined ? freeze : null,
    });
  }
  mockKillswitchStatus = freeze !== undefined ? freeze : !mockKillswitchStatus;
  return mockKillswitchStatus;
}

export async function getNetworkKillswitchStatus(): Promise<boolean> {
  if (isTauri()) {
    return await invoke<boolean>("get_network_killswitch_status_cmd");
  }
  return mockKillswitchStatus;
}

// -------------------------------------------------------------
// v1.2.0: Interactive VPN Crash-Test API
// -------------------------------------------------------------

export async function runVpnCrashTestStep(): Promise<CrashTestStepResult> {
  if (isTauri()) {
    return await invoke<CrashTestStepResult>("run_vpn_crash_test_step");
  }

  mockCrashTestStep++;
  const isDropped = mockCrashTestDropped || mockCrashTestStep >= 12;

  if (isDropped) {
    return {
      timestamp: Math.floor(Date.now() / 1000),
      target_host: "canary-test.anthropic.zastava.local",
      intercepted_by_killswitch: true,
      http_status: 503,
      latency_ms: 0.28,
      status_code: "INTERCEPTED_BY_KILLSWITCH",
      message: "Сбой маршрута мгновенно перехвачен Kill-Switch за 0.3 мс. Ни единого байта не ушло во внешнюю сеть.",
    };
  }

  return {
    timestamp: Math.floor(Date.now() / 1000),
    target_host: "canary-test.anthropic.zastava.local",
    intercepted_by_killswitch: false,
    http_status: 200,
    latency_ms: 0.32 + Math.random() * 0.2,
    status_code: "PROTECTED",
    message: "Пакет проверен ядром за <0.5 мс и подтвержден.",
  };
}

export async function triggerCrashTestDrop(): Promise<void> {
  if (isTauri()) {
    return await invoke("trigger_crash_test_drop");
  }
  mockCrashTestDropped = true;
}

export async function resetCrashTestDrop(): Promise<void> {
  if (isTauri()) {
    return await invoke("reset_crash_test_drop");
  }
  mockCrashTestDropped = false;
  mockCrashTestStep = 0;
}

// ---- Маршруты (routes) ----

export async function getRoutesSnapshot(): Promise<RoutesSnapshot> {
  if (isTauri()) {
    return await invoke<RoutesSnapshot>("list_routes");
  }
  return {
    ...mockRoutesSnapshot,
    routes: [...mockRoutesSnapshot.routes],
    provider_routes: { ...mockRoutesSnapshot.provider_routes },
    effective: { ...mockRoutesSnapshot.effective },
    dangling: [...mockRoutesSnapshot.dangling],
  };
}

export async function upsertRoute(
  rawKey: string,
  label?: string | null,
  setAsDefault?: boolean
): Promise<RouteView> {
  if (isTauri()) {
    const view = await invoke<RouteView>("add_route", { key: rawKey });
    if (setAsDefault) {
      await invoke("set_default_route", { routeId: view.id });
    }
    return view;
  }

  const trimmed = rawKey.trim();
  const id = `r-${Math.random().toString(16).slice(2, 10)}`;
  const displayLabel =
    label && label.trim().length > 0
      ? label.trim()
      : trimmed.startsWith("zastava://")
      ? "Ключ Заставы"
      : trimmed.replace(/^[a-z0-9]+:\/\//i, "").split(/[/@]/)[0] || "Шлюз";

  const newRoute: RouteView = {
    id,
    label: displayLabel,
    country: "NL",
    exit_ip: "185.212.102.40",
    expires_at: null,
    enabled: true,
    added_at: Math.floor(Date.now() / 1000),
    entries: [
      {
        proto: trimmed.startsWith("socks5")
          ? "socks5"
          : trimmed.startsWith("https")
          ? "https"
          : "http",
        host: "185.212.102.40",
        port: 1080,
        username: null,
        has_password: false,
        sni: null,
      },
    ],
    status: "active",
    is_default: Boolean(setAsDefault || mockRoutesSnapshot.routes.length === 0),
    bound_providers: [],
    is_profile_route: false,
    health: {
      reachable: true,
      last_error: null,
      observed_exit_ip: "185.212.102.40",
      observed_country: "NL",
      exit_ip_matches: true,
      latency_ms: 32,
      checked_at: Math.floor(Date.now() / 1000),
    },
  };

  mockRoutesSnapshot.routes.push(newRoute);
  if (newRoute.is_default) {
    mockRoutesSnapshot.default_route_id = newRoute.id;
    for (const r of mockRoutesSnapshot.routes) {
      r.is_default = r.id === newRoute.id;
    }
  }

  return newRoute;
}

export async function removeRoute(routeId: string): Promise<RoutesSnapshot> {
  if (isTauri()) {
    return await invoke<RoutesSnapshot>("remove_route", { id: routeId });
  }

  mockRoutesSnapshot.routes = mockRoutesSnapshot.routes.filter(
    (r) => r.id !== routeId
  );
  if (mockRoutesSnapshot.default_route_id === routeId) {
    mockRoutesSnapshot.default_route_id = null;
  }
  for (const [p, rid] of Object.entries(mockRoutesSnapshot.provider_routes)) {
    if (rid === routeId) {
      delete mockRoutesSnapshot.provider_routes[p];
    }
  }
  return getRoutesSnapshot();
}

export async function setRouteEnabled(
  routeId: string,
  enabled: boolean
): Promise<RoutesSnapshot> {
  if (isTauri()) {
    return await invoke<RoutesSnapshot>("set_route_enabled", {
      id: routeId,
      enabled,
    });
  }

  const r = mockRoutesSnapshot.routes.find((item) => item.id === routeId);
  if (r) {
    r.enabled = enabled;
    r.status = enabled ? "active" : "disabled";
  }
  return getRoutesSnapshot();
}

export async function setDefaultRoute(
  routeId: string | null
): Promise<RoutesSnapshot> {
  if (isTauri()) {
    return await invoke<RoutesSnapshot>("set_default_route", {
      routeId,
    });
  }

  mockRoutesSnapshot.default_route_id = routeId;
  for (const r of mockRoutesSnapshot.routes) {
    r.is_default = r.id === routeId;
  }
  return getRoutesSnapshot();
}

export async function bindProviderRoute(
  provider: ProviderId,
  target: string
): Promise<RoutesSnapshot> {
  const routeId = target === "direct" || target === "default" ? null : target;
  if (isTauri()) {
    return await invoke<RoutesSnapshot>("bind_provider_route", {
      provider,
      routeId,
    });
  }

  if (!routeId) {
    delete mockRoutesSnapshot.provider_routes[provider];
  } else {
    mockRoutesSnapshot.provider_routes[provider] = routeId;
  }

  for (const r of mockRoutesSnapshot.routes) {
    r.bound_providers = Object.entries(mockRoutesSnapshot.provider_routes)
      .filter(([_, rid]) => rid === r.id)
      .map(([p]) => p);
  }

  mockRoutesSnapshot.effective[provider] =
    routeId ?? mockRoutesSnapshot.default_route_id ?? null;

  return getRoutesSnapshot();
}

export async function testRoute(rawOrId: string): Promise<RouteTestResult> {
  if (isTauri()) {
    return await invoke<RouteTestResult>("test_route", { id: rawOrId });
  }

  return {
    ok: true,
    exit_ip: "185.212.102.40",
    country: "NL",
    latency_ms: 38,
    exit_ip_matches: true,
    error: null,
  };
}

// ---- Покрытие приложений и Deep-link ----

let mockPendingDeepLink: string | null = null;

export function setMockPendingDeepLink(link: string | null): void {
  mockPendingDeepLink = link;
}

/** Мок снимка покрытия: порт шлюза не 8899, статусы и шаги по правилам шлюза; «Проверить снова» продвигает их. */
function mockCoverageSnapshot(): CoverageSnapshot {
  const now = Date.now();
  const stage = mockCoverageStage;
  const sys = mockSysproxyActive;
  const cli = mockCliProtection;
  const globalMode = mockCliMode === "global_terminal";
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
    // Сценарий владельца: защита включена, а настройки Gemini CLI Застава не записала (каталога нет).
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
    // Как у шлюза: системный PAC действует — «настроено» без кнопки защиты; иначе «не настроено».
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
    cli_mode: mockCliMode,
    apps,
    system_proxy_effective: sys ? vpn !== "overrides" : null,
    vpn_connected: vpn === "none" ? [] : ["V2BOX Pro"],
  };
}

export async function getCoverageSnapshot(): Promise<CoverageSnapshot> {
  if (isTauri()) {
    return await invoke<CoverageSnapshot>("get_coverage_snapshot");
  }
  return mockCoverageSnapshot();
}

/** Принудительная перепроверка: шлюз заново читает ОС и файлы и отдаёт свежий снимок. */
export async function recheckCoverage(): Promise<CoverageSnapshot> {
  if (isTauri()) {
    return await invoke<CoverageSnapshot>("recheck_coverage");
  }
  mockCoverageStage = Math.min(mockCoverageStage + 1, 2);
  return mockCoverageSnapshot();
}

/** Фокус окна приложения: в Tauri через событие окна, в браузере — без подписки. Возвращает отписку. */
export async function onWindowFocusChanged(handler: (focused: boolean) => void): Promise<() => void> {
  if (!isTauri()) return () => {};
  try {
    const { getCurrentWindow } = await import("@tauri-apps/api/window");
    return await getCurrentWindow().onFocusChanged(({ payload }) => handler(payload));
  } catch {
    return () => {};
  }
}

export async function takePendingDeepLink(): Promise<string | null> {
  if (isTauri()) {
    return await invoke<string | null>("take_pending_deep_link");
  }

  if (typeof window !== "undefined" && window.location.hash.startsWith("#zastava://")) {
    const link = decodeURIComponent(window.location.hash.slice(1));
    try {
      history.replaceState(null, "", window.location.pathname + window.location.search);
    } catch {
      window.location.hash = "";
    }
    return link;
  }

  const pending = mockPendingDeepLink;
  mockPendingDeepLink = null;
  return pending;
}


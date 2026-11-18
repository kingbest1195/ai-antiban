import type {
  AuditProgress,
  CheckResult,
  ProviderId,
  RiskReport,
  StartupSnapshot,
} from "../../../types";
import { emitMock, mockFlags, mockOption, mockState, sleep } from "./state";

export const MOCK_AUDIT_PROGRESS_EVENT = "mock-audit-progress";
export const MOCK_AUDIT_REFRESHED_EVENT = "mock-audit-refreshed";
export const MOCK_STARTUP_EVENT = "mock-startup-phase";

/** Через сколько мс после запуска мок-аудита приходит каждая проверка (место в отчёте → задержка). */
const SLOW_AUDIT_SCHEDULE: Record<number, number> = {
  0: 3000, 1: 3000, 2: 3000, 4: 3200, 9: 3200, 5: 3800, 3: 4600, 7: 5200, 8: 5200, 11: 5600, 10: 6400, 6: 6400, 12: 8000, 13: 8200,
};
const SLOW_AUDIT_TELEMETRY_MS = 3000;
const SLOW_START_MS = 6000;

/** `?slowFactor=5` растягивает моковый запуск в 5 раз: удобно снимать состояния «ожидание» и «готово». */
const slowFactor = () => Math.max(1, Number(mockOption("slowFactor")) || 1);

let mockStartup: StartupSnapshot | null = null;

export function currentMockStartup(): StartupSnapshot {
  if (!mockStartup) {
    const slow = mockOption("startup") === "slow";
    mockStartup = { phase: slow ? "starting" : "ready", step: slow ? "protection" : null };
    if (slow) {
      setTimeout(() => {
        mockStartup = { phase: "ready", step: null };
        emitMock(MOCK_STARTUP_EVENT, mockStartup);
      }, SLOW_START_MS * slowFactor());
    }
  }
  return mockStartup;
}

/** Результаты DNS-проверок мока по сценарию `?dns=`. */
function mockDnsChecks(): { dns: CheckResult; dnsCountry: CheckResult } | null {
  const scenario = mockOption("dns");
  const cloudflareSources = [
    { source: "Akamai", state: "answered" as const, addr: "172.70.161.26", operator: "Cloudflare" },
    { source: "Google", state: "answered" as const, addr: "172.71.240.11", operator: "Cloudflare" },
  ];
  const unknownCountry = (code: string, message: string, reason: CheckResult["reason"], sources: CheckResult["detail"]): CheckResult => ({
    status: "unknown",
    code,
    message,
    reason,
    measured_via: "whoami:akamai+google",
    detail: sources,
  });
  switch (scenario) {
    case "cloudflare":
      return {
        dns: {
          status: "ok",
          code: "DNS_PUBLIC_RESOLVER",
          message:
            "Резолвер: Cloudflare (публичный DNS). Запросы DNS идут на 172.70.161.26; страна резолвера не сравнивается: это anycast-сервис. Источники показали разные адреса (172.70.161.26 и 172.71.240.11), но оба принадлежат Cloudflare: это один и тот же публичный DNS. Настройки DNS ОС (справочно): в списке DNS ОС нет резолверов провайдеров РФ и Яндекс.DNS. ECS и DNS-over-HTTPS в браузере или приложении могут менять картину.",
          measured_via: "whoami:akamai+google",
          detail: { sources: cloudflareSources },
        },
        dnsCountry: {
          status: "unknown",
          code: "DNS_COUNTRY_PUBLIC_RESOLVER",
          message:
            "Запросы DNS идут на публичный резолвер Cloudflare (172.70.161.26); страна резолвера не сравнивается: это anycast-сервис. ECS и DNS-over-HTTPS в браузере или приложении могут менять картину.",
          reason: "not_applicable",
          measured_via: "whoami:akamai+google",
          detail: { sources: cloudflareSources },
        },
      };
    case "disagree": {
      const sources: CheckResult["detail"] = {
        sources: [
          { source: "Akamai", state: "answered", addr: "203.0.113.10" },
          { source: "Google", state: "answered", addr: "198.51.100.7" },
        ],
      };
      const text =
        "два независимых источника показали разные резолверы (Akamai: 203.0.113.10, Google: 198.51.100.7) и общего публичного DNS-сервиса у них нет, надёжно определить его нельзя";
      return {
        dns: unknownCountry("DNS_WHOAMI_DISAGREE", `Проверка DNS-резолвера не выполнена: ${text}. Справочно, настройки ОС: в списке DNS ОС нет резолверов провайдеров РФ и Яндекс.DNS.`, "no_data", sources),
        dnsCountry: unknownCountry("DNS_WHOAMI_DISAGREE", `Согласованность страны DNS и выходного узла не проверена: ${text}.`, "no_data", sources),
      };
    }
    case "fake": {
      const sources: CheckResult["detail"] = {
        sources: [
          { source: "Akamai", state: "special", addr: "198.18.0.7" },
          { source: "Google", state: "answered", addr: "172.71.240.11", operator: "Cloudflare" },
        ],
      };
      const text =
        "DNS ответил служебным адресом 198.18.0.7 (так выглядит fake-IP режим TUN-клиента или локальный DNS-перехватчик), реальный резолвер не виден";
      return {
        dns: unknownCountry("DNS_WHOAMI_FAKE_IP", `Проверка DNS-резолвера не выполнена: ${text}. Справочно, настройки ОС: список DNS ОС прочитать не удалось.`, "source_refused", sources),
        dnsCountry: unknownCountry("DNS_WHOAMI_FAKE_IP", `Согласованность страны DNS и выходного узла не проверена: ${text}.`, "source_refused", sources),
      };
    }
    case "single": {
      const sources: CheckResult["detail"] = {
        sources: [
          { source: "Akamai", state: "answered", addr: "172.70.161.26", operator: "Cloudflare" },
          { source: "Google", state: "timeout" },
        ],
      };
      const text = "ответил только один источник (Akamai), Google не ответил вовремя: подтверждения нет";
      return {
        dns: unknownCountry("DNS_WHOAMI_SINGLE_SOURCE", `Проверка DNS-резолвера не выполнена: ${text}.`, "no_data", sources),
        dnsCountry: unknownCountry("DNS_WHOAMI_SINGLE_SOURCE", `Согласованность страны DNS и выходного узла не проверена: ${text}.`, "no_data", sources),
      };
    }
    default:
      return null;
  }
}

/**
 * Сценарии типа адреса мока (`?iptype=`): hosting, residential, tor, vpn, unknown, unavailable
 * (список Tor не загрузился) и ipv6 (выход по IPv6). Без параметра отчёт прежний.
 */
function mockIpTypeScenario(): {
  asn: CheckResult;
  dnsbl?: CheckResult;
  ip?: string;
  ipv6: boolean;
  net?: { asn: number; name: string };
} | null {
  const scenario = mockOption("iptype");
  const typed = (type: NonNullable<CheckResult["detail"]>["ip_type"], r: Omit<CheckResult, "detail">): CheckResult => ({
    ...r,
    detail: { sources: [], ip_type: type },
  });
  switch (scenario) {
    case "hosting":
      return {
        ipv6: false,
        asn: typed("hosting", {
          status: "ok",
          code: "IP_TYPE_HOSTING",
          message:
            "Хостинг (ожидаемо для личного VPS): AS20473 (HostVDS Cloud NL). Это сервер, на котором работает ваш VPN; в списке выходов Tor и среди известных пулов массовых VPN адреса нет.",
        }),
      };
    case "residential":
      return {
        ipv6: false,
        net: { asn: 64500, name: "Example Broadband Ltd" },
        asn: typed("residential", {
          status: "ok",
          code: "IP_TYPE_RESIDENTIAL",
          message:
            "Жилой или мобильный провайдер: AS64500 (Example Broadband Ltd) (определено по названию, это оценка). В списке выходов Tor и среди известных пулов массовых VPN адреса нет.",
        }),
      };
    case "tor":
      return {
        ipv6: false,
        asn: typed("tor", {
          status: "warning",
          code: "IP_TYPE_TOR",
          message: "Адрес входит в список выходных узлов Tor. ИИ-сервисы часто блокируют такие адреса. Выберите свой сервер или другой VPN-адрес.",
          guide_ref: "01-personal-vpn-15min",
        }),
      };
    case "vpn":
      return {
        ipv6: false,
        net: { asn: 9009, name: "M247 Europe SRL" },
        asn: typed("vpn", {
          status: "warning",
          code: "HIGH_RISK_MASS_VPN_ASN",
          message:
            "Адрес из пула, который часто используют многие люди: «M247 Europe SRL» (AS9009). Сотни пользователей на одном IP. Если это ваш личный сервер, нажмите «Закрепить IP», чтобы убрать предупреждение.",
          guide_ref: "01-personal-vpn-15min",
        }),
      };
    case "unknown":
      return {
        ipv6: false,
        net: { asn: 64500, name: "Example Net" },
        asn: typed("unknown", {
          status: "ok",
          code: "ASN_CLEAN",
          message: "AS64500 (Example Net): тип адреса определить не удалось. В списке выходов Tor и среди известных пулов массовых VPN адреса нет.",
        }),
      };
    case "unavailable":
      return {
        ipv6: false,
        asn: typed("hosting", {
          status: "unknown",
          code: "TOR_LIST_UNAVAILABLE",
          message:
            "Не удалось проверить, не выход ли это сети Tor: список выходных узлов не загрузился. Тип адреса по провайдеру AS20473 (HostVDS Cloud NL): хостинг.",
          reason: "timeout",
        }),
      };
    case "ipv6":
      return {
        ipv6: true,
        ip: "2a01:4f8:c17:1::2",
        dnsbl: {
          status: "unknown",
          code: "DNSBL_IPV6_UNSUPPORTED",
          message: "Не применимо к IPv6: спам-базы DNSBL проверяют только адреса IPv4, а ваш выходной адрес IPv6. Это не значит, что адрес плохой.",
          reason: "not_applicable",
        },
        asn: typed("hosting", {
          status: "unknown",
          code: "IP_TYPE_IPV6_NOT_APPLICABLE",
          message:
            "Не применимо к IPv6: список выходных узлов Tor содержит только адреса IPv4, поэтому про Tor сказать нельзя. Тип адреса по провайдеру AS20473 (HostVDS Cloud NL): хостинг.",
          reason: "not_applicable",
        }),
      };
    default:
      return null;
  }
}

export function buildMockReport(provider: ProviderId): RiskReport {
  const hasUpstream = mockState.upstream_proxy?.enabled;
  const country = hasUpstream ? "NL" : mockFlags.countryOverride || "NL";
  const isTurkey = !hasUpstream && country === "TR";
  const isRu = !hasUpstream && country === "RU";

  let overall: "green" | "yellow" | "red" = "green";
  let score = 98;
  let geoResult = {
    status: "ok" as "ok" | "warning" | "critical",
    code: "GEO_ALLOWED",
    message: `Локация ${country} полностью совместима и безопасна для ${
      provider === "anthropic" ? "Claude (Anthropic)" : provider === "openai" ? "ChatGPT (OpenAI)" : "Google Gemini / AI Studio"
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

  const ipMock = mockIpTypeScenario();
  const currentIp = ipMock?.ip ?? (isTurkey ? "185.220.101.5" : isRu ? "95.165.10.22" : mockState.pinned_ip || "185.212.102.40");
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

  const dnsblResult: CheckResult = ipMock?.dnsbl ?? {
    status: isTurkey ? ("warning" as const) : ("ok" as const),
    code: isTurkey ? "DNSBL_LISTED_WARNING" : "DNSBL_CLEAN",
    message: isTurkey
      ? "IP найден в базе абузных прокси DroneBL (пул M247 Europe SRL — 400+ соседей на IP)."
      : "Проверка DNSBL: ответили 4 из 4 спам-баз, совпадений нет.",
  };

  const asnResult: CheckResult = ipMock?.asn ?? {
    status: isTurkey ? ("warning" as const) : ("ok" as const),
    code: isTurkey ? "HIGH_RISK_MASS_VPN_ASN" : "ASN_VERIFIED_PINNED",
    message: isTurkey
      ? "Подсеть массового VPN «M247 Europe SRL» (AS9009). Сотни пользователей на одном IP."
      : "AS20473 (HostVDS / Choopa LLC) подтвержден как выделенный личный сервер.",
    detail: { sources: [], ip_type: isTurkey ? "vpn" : "hosting" },
  };

  const ipv6Result: CheckResult = isTurkey
    ? { status: "critical", code: "IPV6_LEAK_DETECTED", message: "Найден глобальный IPv6-адрес: реальный адрес может уйти мимо VPN." }
    : {
        status: "ok",
        code: "IPV6_DISABLED_SAFE",
        message: "Утечек по протоколу IPv6 не обнаружено (трафик идет строго через IPv4-туннель).",
      };

  const dnsMock = mockDnsChecks();
  const dnsResult: CheckResult = dnsMock?.dns ?? (isTurkey
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
      });

  const tzResult = {
    status: isTurkey ? ("warning" as const) : ("ok" as const),
    code: isTurkey ? "TIMEZONE_MISMATCH" : "TIMEZONE_MATCH",
    message: isTurkey
      ? "Часовой пояс ОС (Europe/Moscow) конфликтует с таймзоной IP (Europe/Istanbul)."
      : "Системный часовой пояс совпадает с регионом сервера (Europe/Amsterdam).",
  };

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
      asn: ipMock?.net?.asn ?? (isTurkey ? 9009 : 20473),
      org: ipMock?.net?.name ?? (isTurkey ? "M247 Europe SRL" : "HostVDS / Choopa LLC"),
      isp: ipMock?.net?.name ?? (isTurkey ? "M247 Europe SRL" : "HostVDS Cloud NL"),
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
    ipv6_exit: ipMock?.ipv6 ?? false,
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
      dnsMock?.dnsCountry ?? {
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
      provider === "gemini"
        ? {
            status: "unknown",
            code: "PROVIDER_EXIT_NOT_APPLICABLE",
            message: "Выход не проверен напрямую: Google Gemini не отдает /cdn-cgi/trace на прямом маршруте.",
            reason: "not_applicable",
            guide_ref: null,
            measured_via: "gemini (без отдельного маршрута)",
          }
        : isRu
        ? {
            status: "critical",
            code: "PROVIDER_EXIT_BLOCKED_COUNTRY",
            message: `Реальный выход ${provider === "anthropic" ? "Claude (Anthropic)" : "ChatGPT (OpenAI)"} определен как RU (${currentIp}).`,
            guide_ref: "01-personal-vpn-15min",
            measured_via: provider === "anthropic" ? "claude.ai" : "chatgpt.com",
          }
        : {
            status: "ok",
            code: "PROVIDER_EXIT_VERIFIED",
            message: `Реальный выход ${provider === "anthropic" ? "Claude (Anthropic)" : "ChatGPT (OpenAI)"} подтвержден: ${currentIp} (${country}, POP AMS).`,
            guide_ref: null,
            measured_via: provider === "anthropic" ? "claude.ai" : "chatgpt.com",
          },
    ],
  };
  const notApplicable = report.checks.filter((c) => c.status === "unknown" && c.reason === "not_applicable").length;
  report.unknown_count = report.checks.filter((c) => c.status === "unknown").length - notApplicable;
  report.applicable_count = report.checks.length - notApplicable;
  report.incomplete = report.unknown_count > 0;
  return report;
}

export async function runMockAudit(provider: ProviderId, runId?: string): Promise<RiskReport> {
  const report = buildMockReport(provider);
  if (mockOption("startup") === "slow" && provider === "anthropic" && performance.now() < 2000) {
    const send = (progress: AuditProgress) => {
      if (runId) emitMock(MOCK_AUDIT_PROGRESS_EVENT, { ...progress, run_id: runId, provider });
    };
    setTimeout(() => send({ kind: "telemetry", telemetry: report.telemetry }), SLOW_AUDIT_TELEMETRY_MS * slowFactor());
    for (const [index, ms] of Object.entries(SLOW_AUDIT_SCHEDULE)) {
      setTimeout(() => send({ kind: "check", index: Number(index), result: report.checks[Number(index)] }), ms * slowFactor());
    }
    await sleep((Math.max(...Object.values(SLOW_AUDIT_SCHEDULE)) + 200) * slowFactor());
  }
  return report;
}

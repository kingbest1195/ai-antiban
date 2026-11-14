import type { ProviderId } from "../../types";

let names: Intl.DisplayNames | null | undefined;

/** Нормализует нестандартный код («UK» → «GB», верхний регистр). */
export function normalizeCountryCode(code: string | null | undefined): string {
  if (!code) return "";
  const upper = code.trim().toUpperCase();
  if (!upper || upper === "--") return "";
  return upper === "UK" ? "GB" : upper;
}

/** Страна словом по коду ISO: «NL» → «Нидерланды». Без кода или при сбое возвращается исходное значение. */
export function countryName(code: string | null | undefined): string {
  const normalized = normalizeCountryCode(code);
  if (!normalized) return "";
  if (names === undefined) {
    try {
      names = new Intl.DisplayNames(["ru"], { type: "region" });
    } catch {
      names = null;
    }
  }
  try {
    return names?.of(normalized) ?? code ?? "";
  } catch {
    return code ?? "";
  }
}

/** Страна с кодом: «NL» → «Нидерланды (NL)». При отсутствии кода возвращает пустую строку. */
export function formatCountryWithCode(code: string | null | undefined): string {
  const normalized = normalizeCountryCode(code);
  if (!normalized) return "";
  const name = countryName(normalized);
  if (!name || name.toUpperCase() === normalized) return normalized;
  return `${name} (${normalized})`;
}

/** Проверяет, упоминается ли уже в тексте название страны или её ISO-код. */
export function hasCountryMention(text: string | null | undefined, country: string | null | undefined): boolean {
  const haystack = (text ?? "").trim();
  if (!haystack) return false;
  const normalized = normalizeCountryCode(country);
  if (!normalized) {
    const raw = (country ?? "").trim();
    return Boolean(raw) && haystack.toLocaleLowerCase("ru").includes(raw.toLocaleLowerCase("ru"));
  }
  const codePattern = new RegExp(`(^|[^A-Z0-9])${normalized}([^A-Z0-9]|$)`, "i");
  if (codePattern.test(haystack)) return true;
  const name = countryName(normalized);
  if (name && name.toUpperCase() !== normalized) {
    if (haystack.toLocaleLowerCase("ru").includes(name.toLocaleLowerCase("ru"))) return true;
  }
  return false;
}

export interface RouteLabelInput {
  label?: string | null;
  country?: string | null;
  ipOrHost?: string | null;
  fallbackLabel?: string;
}

/**
 * Форматирует подпись маршрута без дублирования страны и вложенных скобок.
 * Пример: label="Zastava · Франция", country="FR", ipOrHost="136.244.114.42" → "Zastava · Франция (FR · 136.244.114.42)".
 */
export function formatRouteOptionLabel({
  label,
  country,
  ipOrHost,
  fallbackLabel = "",
}: RouteLabelInput): string {
  const baseLabel = (label ?? "").trim() || fallbackLabel;
  const cleanIp = (ipOrHost ?? "").trim();
  const normalized = normalizeCountryCode(country);
  const details: string[] = [];

  if (normalized) {
    const name = countryName(normalized);
    const hasName =
      Boolean(name) &&
      name.toUpperCase() !== normalized &&
      baseLabel.toLocaleLowerCase("ru").includes(name.toLocaleLowerCase("ru"));
    const hasCode = new RegExp(`(^|[^A-Z0-9])${normalized}([^A-Z0-9]|$)`, "i").test(baseLabel);

    if (hasName && hasCode) {
      // Страна и код уже есть в названии маршрута.
    } else if (hasName) {
      details.push(normalized);
    } else if (hasCode) {
      if (name && name.toUpperCase() !== normalized) details.push(name);
    } else if (name && name.toUpperCase() !== normalized) {
      details.push(`${name}, ${normalized}`);
    } else {
      details.push(normalized);
    }
  } else {
    const rawCountry = (country ?? "").trim();
    if (rawCountry && !hasCountryMention(baseLabel, rawCountry)) {
      details.push(rawCountry);
    }
  }

  if (cleanIp) details.push(cleanIp);
  if (details.length === 0) return baseLabel;
  return `${baseLabel} (${details.join(" · ")})`;
}

/** Добавляет страну к подписи маршрута через « · », только если она ещё не упомянута в названии. */
export function formatRouteBadgeLabel(label: string | null | undefined, country: string | null | undefined): string {
  const base = (label ?? "").trim();
  const rawCountry = (country ?? "").trim();
  if (!base) return rawCountry;
  if (!rawCountry || hasCountryMention(base, rawCountry)) return base;
  return `${base} · ${rawCountry}`;
}

const GLOBAL_BLOCKED_COUNTRIES = ["RU", "BY", "CN", "HK", "MO", "IR", "KP", "SY", "CU"] as const;

/** Страны, где AI-провайдер блокирует доступ (синхронизировано с rules/provider_matrix.json). */
export const BLOCKED_COUNTRIES_BY_PROVIDER: Record<ProviderId, readonly string[]> = {
  anthropic: [...GLOBAL_BLOCKED_COUNTRIES, "VE", "AF", "MM", "SD", "YE"],
  openai: [...GLOBAL_BLOCKED_COUNTRIES, "VE"],
  gemini: [...GLOBAL_BLOCKED_COUNTRIES],
};

/** Проверяет, блокирует ли выбранный провайдер выходную страну маршрута или VPN. */
export function isCountryBlockedForProvider(provider: ProviderId, country: string | null | undefined): boolean {
  const normalized = normalizeCountryCode(country);
  if (!normalized) return false;
  return BLOCKED_COUNTRIES_BY_PROVIDER[provider].includes(normalized);
}

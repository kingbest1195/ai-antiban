import type { AppStateData, ProviderId } from "../../types";

/** Число с пробелами между разрядами: «5 262». */
export function formatNumber(value: number): string {
  try {
    return value.toLocaleString("ru-RU");
  } catch {
    return String(value);
  }
}

/** «из 13 проверок», «из 1 проверки»: форма слова после «из» (родительный падеж). */
export function checksWord(total: number): string {
  const mod10 = total % 10;
  const mod100 = total % 100;
  if (mod10 === 1 && mod100 !== 11) return "проверки";
  return "проверок";
}

/** Время события шлюза «14:03:27». Метка может быть в секундах или в миллисекундах. */
export function formatClock(timestamp: number): string {
  const ms = timestamp > 1e11 ? timestamp : timestamp * 1000;
  try {
    return new Date(ms).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch {
    return "";
  }
}

/**
 * Маскирует IP-адрес для безопасных скриншотов, когда включён режим «Скрыть IP».
 * Например: «136.244.114.42» → «•••.•••.•••.42».
 */
export function formatIp(ip: string | null | undefined, hideIpMode = false): string {
  if (!ip) return "--";
  const trimmed = ip.trim();
  if (!trimmed || trimmed === "--" || trimmed === "—" || !hideIpMode) return ip;

  // Отделяем возможный порт (например, 185.212.102.40:8080 или [::1]:8080).
  const ipv4PortMatch = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(:\d+)?$/.exec(trimmed);
  if (ipv4PortMatch) {
    return `•••.•••.•••.${ipv4PortMatch[4]}${ipv4PortMatch[5] ?? ""}`;
  }

  // IPv6 (есть двоеточия, не хостнейм с одним портом).
  if (trimmed.includes(":")) {
    const clean = trimmed.replace(/^\[|\](:\d+)?$/g, "");
    const groups = clean.split(":");
    if (groups.length > 2) {
      const last = groups[groups.length - 1] || "••••";
      return `••••:••••:…:${last}`;
    }
  }

  return "•••.•••.•••.•••";
}

/** Маскирует все IPv4-адреса внутри произвольной строки, если включён `hideIpMode`. */
export function maskIpsInText(text: string, hideIpMode = false): string {
  if (!text || !hideIpMode) return text;
  return text.replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.(\d{1,3})\b/g, "•••.•••.•••.$1");
}

/** Возвращает закреплённый IP для конкретного провайдера с откатом к глобальному («default» / `pinned_ip`). */
export function resolvePinnedIp(
  state: Pick<AppStateData, "pinned_ip" | "pinned_ips"> | null | undefined,
  provider?: ProviderId | null,
): string | null {
  if (!state) return null;
  if (provider && state.pinned_ips?.[provider]) {
    return state.pinned_ips[provider];
  }
  return state.pinned_ips?.default ?? state.pinned_ip ?? null;
}

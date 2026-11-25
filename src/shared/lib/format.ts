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

const isValidOctet = (s: string) => /^\d{1,3}$/.test(s) && Number(s) <= 255;

const hasDomainLetterLabel = (token: string) =>
  /\.[a-zA-Z0-9-]*[a-zA-Z][a-zA-Z0-9-]*/.test(token);

function extractTokenAround(text: string, start: number, end: number): string {
  let lo = start;
  while (lo > 0 && !/[\s(),;<>"'«»]/.test(text[lo - 1])) lo -= 1;
  let hi = end;
  while (hi < text.length && !/[\s(),;<>"'«»]/.test(text[hi])) hi += 1;
  return text.slice(lo, hi);
}

function isPrecededByNumericSegment(full: string, offset: number, sep: string): boolean {
  if (offset < 2 || full[offset - 1] !== sep || !/\d/.test(full[offset - 2])) return false;
  let k = offset - 2;
  while (k > 0 && /\d/.test(full[k - 1])) k -= 1;
  return k === 0 || !/[a-zA-Z]/.test(full[k - 1]);
}

/** Маскирует все IPv4- и IPv6-адреса (включая PTR-хосты с точкой/дефисом) внутри произвольной строки, если включён `hideIpMode`. */
export function maskIpsInText(text: string, hideIpMode = false): string {
  if (!text || !hideIpMode) return text;
  const maskedDotV4 = text.replace(
    /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/g,
    (match, o1, o2, o3, o4, offset: number, full: string) => {
      if (![o1, o2, o3, o4].every(isValidOctet)) return match;
      const prev = offset > 0 ? full[offset - 1] : "";
      const prev2 = offset > 1 ? full[offset - 2] : "";
      const after = full.slice(offset + match.length);
      if (/\d/.test(prev) || isPrecededByNumericSegment(full, offset, ".")) return match;
      if (/^\d|^\.\d/.test(after)) return match;
      if ((prev === "v" || prev === "V") && (offset === 1 || !/[a-zA-Z0-9]/.test(prev2))) {
        return match;
      }
      const token = extractTokenAround(full, offset, offset + match.length);
      if (prev === "/" && offset >= 2 && /[a-zA-Z]/.test(prev2) && !hasDomainLetterLabel(token)) {
        return match;
      }
      return `•••.•••.•••.${o4}`;
    },
  );
  const maskedPtrV4 = maskedDotV4.replace(
    /(?<!\d)(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})(?!\d|-\d)/g,
    (match, o1, o2, o3, o4, offset: number, full: string) => {
      if (![o1, o2, o3, o4].every(isValidOctet)) return match;
      const prev = offset > 0 ? full[offset - 1] : "";
      const prev2 = offset > 1 ? full[offset - 2] : "";
      const after = full.slice(offset + match.length);
      if (/\d/.test(prev) || isPrecededByNumericSegment(full, offset, "-")) return match;
      if (/^\d|^-\d/.test(after)) return match;
      if ((prev === "v" || prev === "V") && (offset === 1 || !/[a-zA-Z0-9]/.test(prev2))) {
        return match;
      }
      const token = extractTokenAround(full, offset, offset + match.length);
      if (!hasDomainLetterLabel(token)) return match;
      return `•••-•••-•••-${o4}`;
    },
  );
  // Маскируем IPv6 (с `::` или >= 3 двоеточиями с hex-группами, не затрагивая время вроде 14:03:27).
  return maskedPtrV4.replace(
    /\[?([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{1,4}\]?/g,
    (match) => {
      if (/^\d{1,2}:\d{2}:\d{2}$/.test(match)) return match;
      const clean = match.replace(/^\[|\]$/g, "");
      if (!clean.includes("::") && clean.split(":").length < 4) return match;
      const last = clean.split(":").pop() || "••••";
      return match.startsWith("[") ? `[••••:••••:…:${last}]` : `••••:••••:…:${last}`;
    },
  );
}

/** Возвращает закреплённый IP для конкретного провайдера.
 *  Когда провайдер привязан к своему маршруту (ключа Заставы или профиля Claude),
 *  нельзя подмешивать глобальный `default` / `pinned_ip` локального VPN — иначе UI покажет чужой IP. */
export function resolvePinnedIp(
  state:
    | (Pick<AppStateData, "pinned_ip" | "pinned_ips"> &
        Partial<
          Pick<
            AppStateData,
            "profile_route_id" | "provider_routes" | "default_route_id" | "profile_route_invalid"
          >
        >)
    | null
    | undefined,
  provider?: ProviderId | null,
): string | null {
  if (!state) return null;
  if (provider) {
    const explicit = state.provider_routes?.[provider];
    const isRouted =
      (provider === "anthropic" && Boolean(state.profile_route_id || state.profile_route_invalid)) ||
      (explicit !== undefined ? explicit !== "__direct__" : Boolean(state.default_route_id && state.default_route_id !== "__direct__"));
    if (isRouted) {
      return state.pinned_ips?.[provider] ?? null;
    }
    if (state.pinned_ips?.[provider]) {
      return state.pinned_ips[provider];
    }
  }
  return state.pinned_ips?.default ?? state.pinned_ip ?? null;
}

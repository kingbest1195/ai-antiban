/**
 * Клиентский предпросмотр ключей `zastava://` и прямых URL-прокси без раскрытия паролей,
 * а также расчёт сроков действия ключей и ссылок на продление через @zastava_app_bot.
 */

export const ZASTAVA_BOT_URL = "https://t.me/zastava_app_bot";

export function getBotRenewUrl(routeId?: string | null): string {
  const clean = routeId?.trim();
  if (!clean) return ZASTAVA_BOT_URL;
  return `${ZASTAVA_BOT_URL}?start=renew_${encodeURIComponent(clean)}`;
}

export interface ZastavaKeyPreview {
  kind: "zastava" | "url";
  id?: string;
  label?: string;
  country?: string;
  exit_ip?: string;
  expires_at?: number | null;
  entrySummary?: string;
}

export type ExpiryUrgency = "none" | "soon" | "critical" | "expired";

const DAY_SECONDS = 86_400;
const EXPIRING_SOON_SECONDS = 3 * DAY_SECONDS;

function decodeBase64Flexible(input: string): string | null {
  const clean = input.trim().replace(/^"+|"+$/g, "").replace(/-/g, "+").replace(/_/g, "/");
  if (!clean) return null;
  const rem = clean.length % 4;
  const padded = rem > 0 ? clean + "=".repeat(4 - rem) : clean;
  try {
    const bin = atob(padded);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) {
      bytes[i] = bin.charCodeAt(i);
    }
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  } catch {
    return null;
  }
}

function parseProxyUrlPreview(rawUrl: string, kind: "zastava" | "url"): ZastavaKeyPreview | null {
  try {
    const u = new URL(rawUrl.trim());
    const proto = u.protocol.replace(/:$/, "").toLowerCase();
    if (!["socks5", "socks5h", "http", "https"].includes(proto)) return null;
    const hashLabel = u.hash ? decodeURIComponent(u.hash.slice(1)).trim() : "";
    const portPart = u.port ? `:${u.port}` : "";
    return {
      kind,
      label: hashLabel || undefined,
      entrySummary: u.hostname ? `${proto}://${u.hostname}${portPart}` : undefined,
    };
  } catch {
    return null;
  }
}

/**
 * Разбирает `zastava://` или URL-ключ для отображения пользователю до сохранения.
 * Возвращает `null`, если строка не похожа на поддерживаемый ключ.
 */
export function decodeZastavaKeyPreview(raw: string): ZastavaKeyPreview | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;

  if (/^zastava:\/\//i.test(trimmed)) {
    const payload = trimmed.slice("zastava://".length);
    const decoded = decodeBase64Flexible(payload);
    if (!decoded) return null;
    const text = decoded.trim();
    if (/^(socks5h?|https?):\/\//i.test(text)) {
      return parseProxyUrlPreview(text, "zastava");
    }
    try {
      const obj = JSON.parse(text) as Record<string, unknown>;
      if (!obj || typeof obj !== "object" || Array.isArray(obj)) return null;
      const str = (v: unknown): string | undefined =>
        typeof v === "string" && v.trim() ? v.trim() : undefined;
      const num = (v: unknown): number | undefined =>
        typeof v === "number" && Number.isFinite(v) && v > 0 ? Math.floor(v) : undefined;

      let entrySummary: string | undefined;
      if (Array.isArray(obj.entry) && obj.entry.length > 0) {
        const first = obj.entry[0] as Record<string, unknown> | undefined;
        const proto = str(first?.proto ?? first?.protocol) ?? "https";
        const host = str(first?.host);
        const port = num(first?.port);
        if (host) {
          const base = `${proto}://${host}${port ? `:${port}` : ""}`;
          entrySummary = obj.entry.length > 1 ? `${base} (+${obj.entry.length - 1})` : base;
        }
      } else {
        const proto = str(obj.protocol ?? obj.proto);
        const host = str(obj.host);
        const port = num(obj.port);
        if (proto && host) {
          entrySummary = `${proto}://${host}${port ? `:${port}` : ""}`;
        }
      }

      return {
        kind: "zastava",
        id: str(obj.id),
        label: str(obj.label),
        country: str(obj.country)?.toUpperCase(),
        exit_ip: str(obj.exit_ip),
        expires_at: num(obj.expires_at) ?? null,
        entrySummary,
      };
    } catch {
      return null;
    }
  }

  return parseProxyUrlPreview(trimmed, "url");
}

export function getRouteExpiryUrgency(
  expiresAt?: number | null,
  nowSec = Math.floor(Date.now() / 1000)
): ExpiryUrgency {
  if (!expiresAt || !Number.isFinite(expiresAt)) return "none";
  const left = expiresAt - nowSec;
  if (left <= 0) return "expired";
  if (left < DAY_SECONDS) return "critical";
  if (left < EXPIRING_SOON_SECONDS) return "soon";
  return "none";
}

export function formatRemainingTimeRu(
  expiresAt: number,
  nowSec = Math.floor(Date.now() / 1000)
): string {
  const left = expiresAt - nowSec;
  if (left <= 0) return "истёк";
  if (left < 3600) return "менее часа";
  if (left < DAY_SECONDS) {
    const hours = Math.max(1, Math.floor(left / 3600));
    return `осталось ${hours} ч.`;
  }
  const days = Math.max(1, Math.ceil(left / DAY_SECONDS));
  return `осталось ${days} дн.`;
}

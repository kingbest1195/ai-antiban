import type { AppCoverageItem, AppCoverageStatus, CliMode, CoverageSnapshot } from "../../types";

/** Опрос при наличии неподтверждённых приложений и без них. */
export const POLL_FAST_MS = 5_000;
export const POLL_SLOW_MS = 30_000;
/** Сколько ждём первый запрос после «Я настроил» / «Проверить снова». */
export const WAIT_TIMEOUT_MS = 60_000;

/** Что показываем в бейдже: статус шлюза плюс клиентские waiting/waiting_timeout. */
export type CoverageView = AppCoverageStatus | "waiting" | "waiting_timeout" | "direct";

/** ИИ-клиенты терминала: их режим «Только ИИ-клиенты и IDE» настраивает. */
const AI_CLI_IDS = new Set(["claude-code", "gemini-cli"]);

/** Обычные терминальные программы (node, python, curl…) в режиме «Только ИИ-клиенты и IDE» идут напрямую намеренно: это не «не настроено». */
export function isDirectByMode(app: AppCoverageItem, cliMode: CliMode | undefined): boolean {
  return cliMode === "ai_only" && app.category === "cli" && app.status === "off" && !AI_CLI_IDS.has(app.id);
}

/** Приложение id → момент (мс), когда пользователь начал ждать подтверждения. */
export type WaitingMap = Record<string, number>;

/** Интервал опроса в мс: 0 при скрытом окне, 5 с пока есть неподтверждённые установленные приложения, иначе 30 с. */
export function pollInterval(visible: boolean, apps: AppCoverageItem[] | undefined, cliMode?: CliMode): number {
  if (!visible) return 0;
  const pending = (apps ?? []).some((a) => a.status !== "confirmed" && a.status !== "not_installed" && !isDirectByMode(a, cliMode));
  return pending ? POLL_FAST_MS : POLL_SLOW_MS;
}

/** Показывать ли приложение: «Не установлено» скрыто всегда; в «Обзоре» — только установленные или с трафиком. */
export function isListed(app: AppCoverageItem, variant: "overview" | "checks"): boolean {
  if (app.status === "not_installed") return false;
  if (variant === "checks") return true;
  return app.installed || app.ai_requests > 0 || app.requests_seen > 0;
}

/** Отметить, что пользователь ждёт подтверждения: только для приложений, где оно ещё возможно (не off и не confirmed). */
export function startWaiting(waiting: WaitingMap, apps: AppCoverageItem[], ids: string[] | "configured", now: number): WaitingMap {
  const next = { ...waiting };
  for (const app of apps) {
    const picked = ids === "configured" ? app.status === "configured" : ids.includes(app.id);
    if (picked && app.status !== "confirmed" && app.status !== "not_installed") next[app.id] = now;
  }
  return next;
}

/** Снимок пришёл: ожидание заканчивается, когда приложение подтверждено, выключено или пропало. Истёкшее по времени остаётся, чтобы показать «Не подтверждено». */
export function resolveWaiting(waiting: WaitingMap, apps: AppCoverageItem[]): WaitingMap {
  const next: WaitingMap = {};
  for (const [id, since] of Object.entries(waiting)) {
    const app = apps.find((a) => a.id === id);
    if (!app || app.status === "confirmed" || app.status === "off" || app.status === "not_installed") continue;
    next[id] = since;
  }
  return next;
}

/** Итоговый вид статуса: клиентское ожидание поверх статуса шлюза; через 60 с — «не подтверждено». */
export function viewOf(app: AppCoverageItem, waiting: WaitingMap, now: number, cliMode?: CliMode): CoverageView {
  if (isDirectByMode(app, cliMode)) return "direct";
  const since = waiting[app.id];
  if (since != null && (app.status === "configured" || app.status === "unknown")) {
    return now - since >= WAIT_TIMEOUT_MS ? "waiting_timeout" : "waiting";
  }
  return app.status;
}

/** Давность последнего запроса в мс; null, если запросов не было. */
export function sinceLastSeen(app: AppCoverageItem, now: number): number | null {
  return app.last_seen_ms == null ? null : Math.max(0, now - app.last_seen_ms);
}

/** Что сказать о подключённых VPN-службах: имена и перебивает ли VPN наш системный PAC. null — подключённых нет. */
export interface VpnNotice {
  names: string;
  /** Системный PAC записан на физических службах, но глобально не действует. */
  overridden: boolean;
}

export function vpnNotice(snapshot: Pick<CoverageSnapshot, "sysproxy_enabled" | "system_proxy_effective" | "vpn_connected">): VpnNotice | null {
  const names = (snapshot.vpn_connected ?? []).filter((n) => n.trim() !== "");
  if (names.length === 0) return null;
  return { names: names.join(", "), overridden: snapshot.sysproxy_enabled && snapshot.system_proxy_effective === false };
}

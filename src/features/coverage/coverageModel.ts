import type { AppCoverageItem, AppCoverageStatus, CliMode, CliProtectionReport, CoverageSnapshot, RestartOutcome } from "../../types";
import { coverage as copy } from "../../shared/copy/ru";

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

/**
 * Установленное ИИ-приложение, которое защита не покрывает: статус `off` у ИИ-клиента (десктопные Claude/ChatGPT,
 * Claude Code, Gemini CLI) или IDE. Браузеры, обычные терминальные программы («Напрямую — по режиму терминала»),
 * `not_installed` и `unknown` не считаются: у `unknown` проверить нечем, и пользователю там нечего исправить.
 */
export function uncoveredAiApps(snapshot: Pick<CoverageSnapshot, "apps" | "cli_mode"> | null | undefined): AppCoverageItem[] {
  if (!snapshot) return [];
  return snapshot.apps.filter((app) => {
    if (!app.installed || app.status !== "off") return false;
    if (isDirectByMode(app, snapshot.cli_mode)) return false;
    if (app.category === "desktop" || app.category === "ide") return true;
    return app.category === "cli" && AI_CLI_IDS.has(app.id);
  });
}

/**
 * Замечание для жёлтой точки на «Обзоре»: есть неохваченное ИИ-приложение либо системный PAC не действует из-за VPN
 * (`system_proxy_effective === false`, пока защита включена). Красные состояния учитывает вызывающий: они приоритетнее.
 */
export function coverageNeedsAttention(
  snapshot: Pick<CoverageSnapshot, "apps" | "cli_mode" | "sysproxy_enabled" | "system_proxy_effective"> | null | undefined,
): boolean {
  if (!snapshot) return false;
  if (snapshot.sysproxy_enabled && snapshot.system_proxy_effective === false) return true;
  return uncoveredAiApps(snapshot).length > 0;
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

// ---- Кнопка защиты в карточке приложения ----

export type ProtectionKind = "sysproxy" | "cli";

export const isProtectionOn = (kind: ProtectionKind, snapshot: Pick<CoverageSnapshot, "sysproxy_enabled" | "cli_protection_enabled">): boolean =>
  kind === "sysproxy" ? snapshot.sysproxy_enabled : snapshot.cli_protection_enabled;

/**
 * Вид управления защитой в карточке. Включено — кнопки «Включить» нет совсем (повторный клик не может выключить),
 * остаётся состояние и отдельное тихое «Выключить». Выполняется команда — кнопки заблокированы.
 */
export type ProtectionControl = { mode: "enable"; busy: boolean } | { mode: "on"; busy: boolean };

export function protectionControl(on: boolean, busy: boolean): ProtectionControl {
  return { mode: on ? "on" : "enable", busy };
}

/** Приложения, которые идут через Заставу благодаря этой защите: для текста подтверждения выключения. */
export function protectedAppNames(kind: ProtectionKind, apps: AppCoverageItem[]): string[] {
  const categories: AppCoverageItem["category"][] = kind === "sysproxy" ? ["browser", "desktop"] : ["ide", "cli"];
  return apps
    .filter((a) => a.installed && categories.includes(a.category) && (a.status === "confirmed" || a.status === "configured"))
    .map((a) => a.name);
}

/** Приложения, которым эта кнопка не помогает и нужны ручные шаги (у них свой способ запуска). */
export function manualOnlyNames(apps: AppCoverageItem[]): string[] {
  return apps.filter((a) => a.installed && a.status !== "confirmed" && a.manual_steps.includes("launch_with_env")).map((a) => a.name);
}

export interface ProtectionResult {
  tone: "ok" | "warn" | "danger";
  title: string;
  text: string;
}

/**
 * Итог нажатия «Включить» из ответа команды: список берётся из `configured_targets`, `notes` и `error`, а не придумывается.
 * `report == null` — команда не выполнилась (ошибку уже показал вызывающий).
 */
export function enableResult(kind: ProtectionKind, report: CliProtectionReport | null, apps: AppCoverageItem[]): ProtectionResult {
  const r = copy.protection.result;
  if (kind === "sysproxy") return { tone: "ok", title: r.enabledTitle.sysproxy, text: r.sysproxyText };
  if (!report) return { tone: "danger", title: r.failedTitle, text: "" };
  const parts: string[] = [];
  const targets = report.configured_targets.filter((t) => t.trim() !== "");
  parts.push(targets.length > 0 ? r.written(targets.join(", ")) : r.nothingWritten);
  const manual = manualOnlyNames(apps);
  if (manual.length > 0) parts.push(r.manual(manual.join(", ")));
  for (const n of report.notes ?? []) if (n.trim() !== "") parts.push(n.trim());
  if (report.error) return { tone: "danger", title: r.failedTitle, text: [report.error, ...parts].join(" ") };
  const needsSteps = targets.length === 0 || manual.length > 0;
  return { tone: needsSteps ? "warn" : "ok", title: r.enabledTitle.cli, text: parts.join(" ") };
}

// ---- Кнопка «Перезапустить Antigravity с защитой» ----

/**
 * Показывать ли кнопку перезапуска: только macOS, Antigravity 2.x (шаг «запуск с переменными»), приложение установлено,
 * адрес шлюза известен, а трафик через Заставу ещё не подтверждён (иначе перезапускать незачем).
 */
export function canRestartAntigravity(app: AppCoverageItem, view: CoverageView, snapshot: Pick<CoverageSnapshot, "gateway_addr">, isMac: boolean): boolean {
  return (
    isMac &&
    app.id === "antigravity" &&
    app.installed &&
    app.manual_steps.includes("launch_with_env") &&
    Boolean(snapshot.gateway_addr) &&
    view !== "confirmed"
  );
}

/** Итог перезапуска для строки и тоста: текст и «что делать» из словаря. */
export function restartResult(outcome: RestartOutcome): ProtectionResult {
  const t = copy.restart.result[outcome];
  return { tone: outcome === "restarted" ? "ok" : outcome === "launch_failed" ? "danger" : "warn", title: t.title, text: t.text };
}

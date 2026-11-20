import { Button, Card, EmptyState, InfoTip, Mono, Spinner, cx, toneForScore } from "../../ui";
import { overview as copy, shell as shellCopy } from "../../shared/copy/ru";
import { formatCountryWithCode } from "../../shared/lib/country";
import { formatIp, formatNumber } from "../../shared/lib/format";
import { WatchdogMascot } from "../mascot";
import type { MascotState } from "../mascot";
import { AlertStrip } from "./AlertStrip";
import { PowerPill } from "./PowerPill";
import { SectionList } from "./SectionList";
import { StopNetwork } from "./StopNetwork";
import type { HomeHubProps } from "./types";

/** Вычисляет состояние маскота по текущему состоянию защиты и сети. */
export function resolveMascotState(params: {
  startupPending?: boolean;
  refreshing?: boolean;
  sysproxyActive: boolean;
  killswitchFrozen: boolean;
  overallStatus?: string | null;
}): MascotState {
  if (params.killswitchFrozen || params.overallStatus === "red") return "alert";
  if (params.startupPending || params.refreshing) return "scanning";
  if (!params.sysproxyActive) return "sleep";
  return "protected";
}

/** Классификация риска Persona для компактной пилюли на Home Hub. */
export function resolvePersonaPill(score: number | null | undefined): {
  label: string;
  tone: "ok" | "warn" | "danger";
} {
  if (score == null) return { label: "Риск: —", tone: "ok" };
  if (score >= 55) return { label: "Риск: Высокий", tone: "danger" };
  if (score >= 25) return { label: "Риск: Средний", tone: "warn" };
  return { label: "Риск: Низкий", tone: "ok" };
}

/**
 * Home Hub (460×660 zero-scroll, бюджет ~610–635px):
 * - Компактный горизонтальный Hero: слева WatchdogMascot 64×64, справа Вердикт + IP/страна + Доверие + Persona pill
 * - 1-строчная статистика
 * - PowerPill
 * - Приоритетный AlertStrip
 * - 5 семантических разделов
 * - Нижняя кнопка StopNetwork
 */
export function HomeHub({
  overview,
  view,
  togglingSysproxy,
  coworkGuard,
  personaRisk,
  gatewayStats,
  state,
  routeUnavailableBanner,
  onPushRoute,
  onDismissRouteUnavailable,
  onRefreshRoutes,
  onRefreshState,
  onAuditRefresh,
  version,
}: HomeHubProps) {
  const { loading, failed, model, progress } = view;
  const off = !overview.startupPending && !overview.sysproxyActive && !overview.killswitchFrozen;
  const mascotState = resolveMascotState({
    startupPending: overview.startupPending,
    refreshing: overview.refreshing,
    sysproxyActive: overview.sysproxyActive,
    killswitchFrozen: overview.killswitchFrozen,
    overallStatus: overview.activeReport?.overall_status,
  });

  const ip = overview.currentIp !== "--" ? formatIp(overview.currentIp, overview.hideIpMode) : null;
  const country =
    overview.currentIp !== "--" ? formatCountryWithCode(overview.activeReport?.telemetry.country_code) : null;
  const personaPill = resolvePersonaPill(personaRisk?.score);

  const reqs = gatewayStats ? formatNumber(gatewayStats.protected_ai_requests) : "—";
  const leaks = gatewayStats ? formatNumber(gatewayStats.intercepted_leaks) : "—";
  const direct = gatewayStats ? formatNumber(gatewayStats.direct_bypassed_requests) : "—";

  return (
    <>
      <Card className="zs-v3-hero">
        <div className="zs-v3-hero__top">
          <div className="zs-v3-hero__mascot">
            <WatchdogMascot state={mascotState} size={64} />
          </div>

          <div className="zs-v3-hero__info">
            {loading ? (
              <div role="status" aria-busy="true">
                <p className="zs-v3-verdict">
                  {overview.startupPending ? copy.checking.startingTitle : copy.checking.title}
                </p>
                <div className="zs-v3-meta">
                  <Spinner size={13} />
                  <span>{progress.done > 0 ? copy.checking.progress(progress.done, progress.total) : "Несколько секунд"}</span>
                </div>
              </div>
            ) : failed ? (
              <EmptyState
                icon="alert"
                title={copy.error.title}
                action={
                  <Button size="sm" variant="primary" icon="refresh" onClick={overview.onRetry} disabled={overview.refreshing}>
                    {copy.error.action}
                  </Button>
                }
              >
                {copy.error.text}
              </EmptyState>
            ) : off ? (
              <>
                <p className="zs-v3-verdict zs-v3-verdict--danger">Нейросети без защиты</p>
                <div className="zs-v3-meta">
                  <span>Запросы идут напрямую без проверки</span>
                </div>
              </>
            ) : (
              <>
                <p className={cx("zs-v3-verdict", `zs-v3-verdict--${model.tone}`)}>{model.verdict}</p>
                {(ip || country) && (
                  <div className="zs-v3-meta">
                    {ip && <span className="zs-mono">{ip}</span>}
                    {ip && country && <span aria-hidden="true">·</span>}
                    {country && <span>{country}</span>}
                  </div>
                )}
                <div className="zs-v3-trust-row">
                  <span>Доверие к адресу</span>
                  <b className={`zs-v3-trust__num zs-v3-trust__num--${toneForScore(overview.trustScore)}`}>
                    {Math.round(overview.trustScore)} из 100
                  </b>
                  <InfoTip
                    title="Доверие к адресу"
                    text={`Оценка IP по ${model.checksTotal || 13} проверкам.${model.providerName ? ` Провайдер: ${model.providerName}.` : ""}`}
                  />
                  <button
                    type="button"
                    className={`zs-v3-persona-pill zs-v3-persona-pill--${personaPill.tone}`}
                    onClick={() => onPushRoute({ page: "backup" })}
                    title="Открыть Индекс риска Persona и Бункер"
                  >
                    {personaPill.label}
                  </button>
                </div>
              </>
            )}
          </div>
        </div>

        <button
          type="button"
          className="zs-v3-stats-bar"
          onClick={() => onPushRoute({ page: "stats" })}
          title="Открыть подробную статистику шлюза"
        >
          <span>Защищено: {reqs}</span>
          <span aria-hidden="true">·</span>
          <span>Отражено сбоев: {leaks}</span>
          <span aria-hidden="true">·</span>
          <span>Напрямую: {direct}</span>
        </button>

        <PowerPill
          on={overview.sysproxyActive}
          startupPending={overview.startupPending}
          toggling={togglingSysproxy}
          onToggle={overview.onToggleSysproxy}
        />
      </Card>

      <AlertStrip
        view={view}
        overview={overview}
        coworkGuard={coworkGuard}
        ipChangeCooldownUntil={state?.ip_change_cooldown_until}
        routeUnavailableBanner={routeUnavailableBanner}
        routesSnapshot={overview.routesSnapshot}
        onPushRoute={onPushRoute}
        onDismissRouteUnavailable={onDismissRouteUnavailable}
        onRefreshRoutes={onRefreshRoutes}
        onRefreshState={onRefreshState}
        onAuditRefresh={onAuditRefresh}
      />

      <SectionList
        overview={overview}
        view={view}
        state={state}
        personaRisk={personaRisk}
        onPushRoute={onPushRoute}
      />

      <StopNetwork p={overview} />

      <footer className="zs-app__foot">
        <span>{shellCopy.footer}</span>
        <Mono>v{version}</Mono>
      </footer>
    </>
  );
}

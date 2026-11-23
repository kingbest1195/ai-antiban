import { useState } from "react";
import type { ReactNode } from "react";
import { Banner, Button } from "../../ui";
import { overview as copy } from "../../shared/copy/ru";
import { useOsTimezoneSync } from "../../shared/hooks/useTimezoneSync";
import { getRouteExpiryUrgency } from "../../shared/lib/zastavaKey";
import { openZastavaBot } from "../../utils/opener";
import { RouteUnavailableBanner } from "../connect/RouteUnavailableBanner";
import { CooldownBanner } from "../overview/CooldownBanner";
import { ProblemBanner } from "../overview/ProblemBanner";
import type { AlertStripProps } from "./types";

export interface AlertItem {
  id: "problem" | "cowork" | "cooldown" | "expiring";
  priority: number;
  render: () => ReactNode;
}

/** Pure selector for AlertStrip priority order (tested in shellV3.test.ts). */
export function selectAlertPriorityIds(flags: {
  hasProblem: boolean;
  coworkNeedsRepair: boolean;
  hasCooldown: boolean;
  hasExpiringKey: boolean;
}): Array<AlertItem["id"]> {
  const ids: Array<AlertItem["id"]> = [];
  if (flags.hasProblem) ids.push("problem");
  if (flags.coworkNeedsRepair) ids.push("cowork");
  if (flags.hasCooldown) ids.push("cooldown");
  if (flags.hasExpiringKey) ids.push("expiring");
  return ids;
}

/**
 * Приоритетная полоса баннеров на Home Hub:
 * показывает TOP 1 активный баннер среди ProblemBanner / CoworkGuardBanner / CooldownBanner / ExpiringKeyBanner
 * + пилюлю «ещё N» для раскрытия остальных, плюс RouteUnavailableBanner при обрыве маршрута.
 */
export function AlertStrip({
  view,
  overview,
  coworkGuard,
  osTz: osTzProp,
  ipChangeCooldownUntil,
  routeUnavailableBanner,
  routesSnapshot,
  onPushRoute,
  onDismissRouteUnavailable,
  onRefreshRoutes,
  onRefreshState,
  onAuditRefresh,
}: AlertStripProps) {
  const [expanded, setExpanded] = useState(false);
  const [repairFallbackError, setRepairFallbackError] = useState<string | null>(null);
  const sharedOsTz = useOsTimezoneSync(overview.activeReport?.telemetry?.timezone);
  const osTz = osTzProp ?? sharedOsTz;

  const hasProblem = Boolean(!view.loading && !view.failed && view.model.banner && view.model.banner !== "update");
  const hasCooldown = Boolean(ipChangeCooldownUntil && ipChangeCooldownUntil * 1000 > Date.now());

  const expiringRoute = (routesSnapshot?.routes ?? []).find((r) => {
    if (!r.enabled || !r.expires_at) return false;
    const u = getRouteExpiryUrgency(r.expires_at);
    return u === "expired" || u === "critical" || u === "soon";
  });
  const expiringUrgency = expiringRoute?.expires_at ? getRouteExpiryUrgency(expiringRoute.expires_at) : "none";

  const items: AlertItem[] = [];

  if (hasProblem) {
    items.push({
      id: "problem",
      priority: 1,
      render: () => (
        <ProblemBanner
          kind={view.model.banner}
          targetTz={overview.activeReport?.telemetry?.timezone}
          tzCode={overview.activeReport?.timezone_result?.code}
          osTzStatus={osTz.osTzStatus}
          osTzLoading={osTz.osTzLoading}
          onSyncOsTimezone={() => void osTz.syncOsTimezone(overview.activeReport?.telemetry?.timezone)}
          onRestoreOsTimezone={() => void osTz.restoreOsTimezone()}
          {...overview}
          onOpenChecks={() => onPushRoute({ page: "checks" })}
          onOpenConnect={() => onPushRoute({ page: "connect" })}
        />
      ),
    });
  }

  if (coworkGuard.needsRepair) {
    const displayedCoworkError = coworkGuard.error || repairFallbackError;
    items.push({
      id: "cowork",
      priority: 2,
      render: () => (
        <Banner
          tone="warn"
          title="Фоновая служба Claude не защищена"
          action={
            <Button
              size="sm"
              variant="secondary"
              disabled={coworkGuard.repairing}
              onClick={() => {
                setRepairFallbackError(null);
                void coworkGuard.repair().then((res) => {
                  const isOutcomeObj =
                    res !== null &&
                    typeof res === "object" &&
                    ("status" in res || "error" in res);
                  const updated = isOutcomeObj
                    ? (res as { status: typeof coworkGuard.status; error: string | null }).status
                    : (res as typeof coworkGuard.status);
                  const freshError = isOutcomeObj
                    ? (res as { status: typeof coworkGuard.status; error: string | null }).error
                    : coworkGuard.error;
                  if (!updated) {
                    const backendErr = (freshError ?? coworkGuard.error)?.trim();
                    if (backendErr) {
                      setRepairFallbackError(backendErr);
                    }
                    const isUacCancel =
                      !backendErr ||
                      backendErr.includes("ELEVATION_CANCELLED") ||
                      /отмен[её]н|cancel/iu.test(backendErr);
                    overview.onToast?.(
                      "Не удалось защитить фоновую службу Claude",
                      isUacCancel
                        ? "Запрос прав администратора отменён или планировщик вернул ошибку. Попробуйте снова или проверьте настройки."
                        : backendErr,
                      "error",
                    );
                  } else if (updated.needs_repair) {
                    const summary =
                      updated.summary ||
                      freshError ||
                      "Защита фоновой службы Claude настроена не полностью. Откройте настройки или проверьте права администратора.";
                    setRepairFallbackError(summary);
                    overview.onToast?.(
                      "Не удалось завершить защиту фоновой службы Claude",
                      summary,
                      "warning",
                    );
                  } else {
                    setRepairFallbackError(null);
                  }
                });
              }}
            >
              {coworkGuard.repairing ? "Чиним…" : "Починить в 1 клик"}
            </Button>
          }
        >
          <>
            <span>Может запускаться в обход прокси до старта Заставы.</span>
            {displayedCoworkError && (
              <p className="zs-v3-alert-error" role="alert">
                {displayedCoworkError}
              </p>
            )}
          </>
        </Banner>
      ),
    });
  }

  if (hasCooldown) {
    items.push({
      id: "cooldown",
      priority: 3,
      render: () => (
        <CooldownBanner
          cooldownUntil={ipChangeCooldownUntil}
          onCleared={overview.onRetry}
          onToast={overview.onToast}
        />
      ),
    });
  }

  if (expiringRoute && expiringRoute.expires_at) {
    items.push({
      id: "expiring",
      priority: 4,
      render: () => (
        <Banner
          tone={expiringUrgency === "critical" || expiringUrgency === "expired" ? "danger" : "warn"}
          title={
            expiringUrgency === "expired"
              ? copy.banner.expiringKey.titleExpired
              : copy.banner.expiringKey.titleSoon
          }
          action={
            <div className="zs-banner__actions">
              <Button size="sm" variant="secondary" onClick={() => openZastavaBot(expiringRoute.id)}>
                {copy.banner.expiringKey.renew}
              </Button>
              <Button size="sm" variant="quiet" onClick={() => onPushRoute({ page: "connect" })}>
                {copy.banner.expiringKey.openConnect}
              </Button>
            </div>
          }
        >
          {copy.banner.expiringKey.text(
            expiringRoute.label || copy.facts.key,
            new Date(expiringRoute.expires_at! * 1000).toLocaleDateString("ru-RU"),
          )}
        </Banner>
      ),
    });
  }

  if (items.length === 0 && !routeUnavailableBanner) return null;

  const visible = expanded ? items : items.slice(0, 1);
  const moreCount = items.length - 1;

  return (
    <div className="zs-v3-alerts">
      {routeUnavailableBanner && (
        <RouteUnavailableBanner
          banner={routeUnavailableBanner}
          routesSnapshot={routesSnapshot}
          dismissLabel="Скрыть"
          onOpenConnect={() => {
            onPushRoute({ page: "connect" });
            onDismissRouteUnavailable();
          }}
          onDismiss={onDismissRouteUnavailable}
          onRefreshRoutes={onRefreshRoutes}
          onRefreshState={onRefreshState}
          onAuditRefresh={onAuditRefresh}
          onToast={overview.onToast}
        />
      )}
      {visible.map((item) => (
        <div key={item.id}>{item.render()}</div>
      ))}
      {moreCount > 0 && (
        <button
          type="button"
          className="zs-v3-alerts__more"
          onClick={() => setExpanded((v) => !v)}
          aria-expanded={expanded}
        >
          {expanded ? "Свернуть" : `ещё ${moreCount}`}
        </button>
      )}
    </div>
  );
}

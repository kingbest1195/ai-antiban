import { useState } from "react";
import type { ProviderId, RouteUnavailablePayload, RoutesSnapshot } from "../../types";
import { Banner, Button, ConfirmModal } from "../../ui";
import { CopyErrorLogButton } from "../../shared/components/CopyErrorLogButton";
import { connect as copy } from "../../shared/copy/ru";
import type { ShowToast } from "../../shared/hooks";
import {
  ALL_PROVIDERS,
  isRouteDisabledReason,
  switchUnavailableBannerToDirect,
} from "./routeDisableModel";

export interface RouteUnavailableBannerProps {
  banner: RouteUnavailablePayload;
  routesSnapshot?: RoutesSnapshot | null;
  dismissLabel: string;
  onOpenConnect: () => void;
  onDismiss: () => void;
  onRefreshRoutes?: () => Promise<unknown>;
  onRefreshState?: () => Promise<unknown>;
  onAuditRefresh?: (providerId?: ProviderId) => Promise<unknown> | void;
  onToast?: ShowToast;
}

/**
 * Баннер недоступности маршрута (`route://unavailable`):
 * сохраняет `CopyErrorLogButton` и добавляет 1-click перевод на свой VPN (Direct) при `reason === "disabled"`,
 * требуя отдельного подтверждения, если задействован `profile_route_id`.
 */
export function RouteUnavailableBanner({
  banner,
  routesSnapshot,
  dismissLabel,
  onOpenConnect,
  onDismiss,
  onRefreshRoutes,
  onRefreshState,
  onAuditRefresh,
  onToast,
}: RouteUnavailableBannerProps) {
  const [switching, setSwitching] = useState(false);
  const [confirmProfileReset, setConfirmProfileReset] = useState(false);

  const title = copy.routes.bannerTitle(banner.provider);
  const showDirectSwitch = isRouteDisabledReason(banner.reason);

  const finalizeRefresh = async () => {
    await onRefreshRoutes?.();
    await onRefreshState?.();
    const provider = banner.provider.toLowerCase() as ProviderId;
    if (ALL_PROVIDERS.includes(provider)) {
      await onAuditRefresh?.(provider);
    }
    onToast?.(
      copy.routes.disableModal.toastDirectTitle,
      copy.routes.disableModal.toastDirectText,
      "info",
    );
    onDismiss();
  };

  const handleQuickSwitchDirect = async (allowProfileReset = false) => {
    setSwitching(true);
    try {
      const outcome = await switchUnavailableBannerToDirect(banner, routesSnapshot, {
        allowProfileReset,
      });
      if (outcome === "needs_profile_confirmation") {
        setConfirmProfileReset(true);
        return;
      }
      setConfirmProfileReset(false);
      await finalizeRefresh();
    } catch (err: unknown) {
      onToast?.(copy.routes.toast.boundError, err instanceof Error ? err.message : String(err), "error");
    } finally {
      setSwitching(false);
    }
  };

  const pCopy = copy.routes.profileResetModal;

  return (
    <>
      <Banner
        tone="danger"
        role="alert"
        title={title}
        action={
          <div className="zs-banner__actions">
            {showDirectSwitch && (
              <Button
                size="sm"
                variant="primary"
                disabled={switching}
                onClick={() => void handleQuickSwitchDirect(false)}
              >
                {switching ? copy.routes.disableModal.busy : copy.routes.switchToDirect}
              </Button>
            )}
            <Button size="sm" variant={showDirectSwitch ? "secondary" : "primary"} onClick={onOpenConnect}>
              {copy.routes.openConnect}
            </Button>
            <CopyErrorLogButton title={title} message={banner.message} variant="secondary" />
            <Button size="sm" variant="quiet" onClick={onDismiss}>
              {dismissLabel}
            </Button>
          </div>
        }
      >
        {banner.message}
      </Banner>

      <ConfirmModal
        open={confirmProfileReset}
        title={pCopy.title}
        confirmLabel={pCopy.confirm}
        cancelLabel={pCopy.cancel}
        busy={switching}
        busyLabel={pCopy.busy}
        onConfirm={() => void handleQuickSwitchDirect(true)}
        onCancel={() => setConfirmProfileReset(false)}
      >
        {pCopy.text}
      </ConfirmModal>
    </>
  );
}

import { Banner, Button, ConfirmModal, Modal } from "../../ui";
import { connect as copy } from "../../shared/copy/ru";
import { formatRouteUsageSummary, type PendingDisableRoute } from "./routeDisableModel";

export interface RouteDisableModalsProps {
  pendingDisable: PendingDisableRoute | null;
  confirmProfileReset: PendingDisableRoute | null;
  busy: boolean;
  onCancelDisable: () => void;
  onChooseDirect: () => void;
  onChooseStopAndBlock: () => void;
  onCancelProfileReset: () => void;
  onConfirmProfileReset: () => void;
}

/**
 * Диалоги выключения активного маршрута (Bug #6):
 * 1) выбор между переходом на свой VPN (Direct) и строгой остановкой (fail-closed),
 * 2) отдельное подтверждение сброса `profile_route_id` с предупреждением о мультиаккаунт-изоляции.
 */
export function RouteDisableModals({
  pendingDisable,
  confirmProfileReset,
  busy,
  onCancelDisable,
  onChooseDirect,
  onChooseStopAndBlock,
  onCancelProfileReset,
  onConfirmProfileReset,
}: RouteDisableModalsProps) {
  const dCopy = copy.routes.disableModal;
  const pCopy = copy.routes.profileResetModal;

  return (
    <>
      <Modal
        open={pendingDisable !== null}
        onClose={busy ? () => {} : onCancelDisable}
        title={dCopy.title(pendingDisable?.routeLabel || copy.key.defaultLabel)}
        footer={
          <Button variant="quiet" onClick={onCancelDisable} disabled={busy}>
            {dCopy.cancel}
          </Button>
        }
      >
        {pendingDisable && (
          <div className="zs-stack gap-3">
            <p className="zs-modal-text">{dCopy.text(formatRouteUsageSummary(pendingDisable.usage))}</p>
            {pendingDisable.usage.isProfileRoute && (
              <Banner tone="warn" title={copy.key.profileBadge}>
                {dCopy.profileNote}
              </Banner>
            )}
            <div className="zs-stack gap-2">
              <Button variant="primary" block disabled={busy} onClick={onChooseDirect}>
                {busy ? dCopy.busy : dCopy.switchToDirect}
              </Button>
              <Button variant="danger" block disabled={busy} onClick={onChooseStopAndBlock}>
                {busy ? dCopy.busy : dCopy.stopAndBlock}
              </Button>
            </div>
          </div>
        )}
      </Modal>

      <ConfirmModal
        open={confirmProfileReset !== null}
        title={pCopy.title}
        confirmLabel={pCopy.confirm}
        cancelLabel={pCopy.cancel}
        busy={busy}
        busyLabel={pCopy.busy}
        onConfirm={onConfirmProfileReset}
        onCancel={onCancelProfileReset}
      >
        {pCopy.text}
      </ConfirmModal>
    </>
  );
}

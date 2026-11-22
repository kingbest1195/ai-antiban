import type { PostPaymentQuarantineStatus } from "../../types";
import { Banner, ConfirmModal } from "../../ui";
import { countryName } from "../../shared/lib/country";
import { subscription } from "../../shared/copy/ru";

const copy = subscription.quarantine;

export interface QuarantineBannerProps {
  status: PostPaymentQuarantineStatus | null | undefined;
}

/** Спокойный статус-баннер активной 72-часовой защиты маршрута после оплаты. */
export function QuarantineBanner({ status }: QuarantineBannerProps) {
  if (!status?.active) return null;
  const pinnedCountry = status.quarantine?.pinnedCountry
    ? countryName(status.quarantine.pinnedCountry) || status.quarantine.pinnedCountry
    : null;
  return (
    <Banner
      tone="info"
      icon="lock"
      title={
        <span className="subs-quarantine-countdown">
          {copy.activeBannerTitle(status.remainingHours)}
        </span>
      }
    >
      {copy.activeBannerText(pinnedCountry)}
    </Banner>
  );
}

export interface QuarantineOverrideModalProps {
  open: boolean;
  remainingHours: number;
  busy?: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}

/** Модальное окно перехвата смены маршрута/сервера при активном 72-часовом карантине. */
export function QuarantineOverrideModal({
  open,
  remainingHours,
  busy = false,
  onCancel,
  onConfirm,
}: QuarantineOverrideModalProps) {
  return (
    <ConfirmModal
      open={open}
      title={copy.modalTitle}
      confirmLabel={copy.modalConfirm}
      cancelLabel={copy.modalCancel}
      busy={busy}
      onCancel={onCancel}
      onConfirm={onConfirm}
    >
      {copy.modalText(remainingHours)}
    </ConfirmModal>
  );
}

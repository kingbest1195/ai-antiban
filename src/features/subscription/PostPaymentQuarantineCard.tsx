import { useEffect, useState } from "react";
import type {
  PassportChannel,
  PaymentChannel,
  PaymentPassport,
  PostPaymentQuarantineStatus,
} from "../../types";
import {
  activatePostPaymentQuarantine,
  getPostPaymentQuarantineStatus,
  savePaymentPassport,
} from "../../utils/api";
import { Badge, Banner, Button, Card, Mono } from "../../ui";
import type { ShowToast } from "../../shared/hooks";
import { countryName } from "../../shared/lib/country";
import { formatIp } from "../../shared/lib/format";
import { subscription } from "../../shared/copy/ru";
import { notifyQuarantineUpdated, subscribeQuarantineUpdated } from "./useQuarantineGuard";

const copy = subscription.quarantine;

export interface PostPaymentQuarantineCardProps {
  profileId?: string | null;
  routeId?: string | null;
  exitIp?: string | null;
  exitAsn?: number | null;
  exitCountry?: string | null;
  binPrefix?: string | null;
  cardCountry?: string | null;
  billingCountry?: string | null;
  channel?: PaymentChannel;
  hideIpMode?: boolean;
  ctaVariant?: "primary" | "secondary";
  /** Предзагруженный статус защиты (для SSR/тестов). */
  initialStatus?: PostPaymentQuarantineStatus | null;
  onStatusChange?: (status: PostPaymentQuarantineStatus) => void;
  onPassportSaved?: (passport: PaymentPassport) => void;
  onToast?: ShowToast;
}

function toPassportChannel(channel: PaymentChannel): PassportChannel {
  if (channel === "appleIAP") return "appleIAP";
  if (channel === "api") return "api";
  return "directCard";
}

/** 72-часовая защита маршрута после оплаты: кнопка фиксации и спокойный отсчёт. */
export function PostPaymentQuarantineCard({
  profileId,
  routeId,
  exitIp,
  exitAsn,
  exitCountry,
  binPrefix,
  cardCountry,
  billingCountry,
  channel = "appleIAP",
  hideIpMode = false,
  ctaVariant = "secondary",
  initialStatus,
  onStatusChange,
  onPassportSaved,
  onToast,
}: PostPaymentQuarantineCardProps) {
  const [status, setStatus] = useState<PostPaymentQuarantineStatus | null>(initialStatus ?? null);
  const [busy, setBusy] = useState<boolean>(false);

  useEffect(() => {
    if (initialStatus !== undefined) {
      setStatus(initialStatus);
      return;
    }
    let cancelled = false;
    const load = () => {
      getPostPaymentQuarantineStatus(profileId ?? null)
        .then((res) => {
          if (!cancelled) setStatus(res);
        })
        .catch(() => {});
    };
    load();
    const unsubscribe = subscribeQuarantineUpdated(load);
    return () => {
      cancelled = true;
      unsubscribe();
    };
  }, [profileId, initialStatus]);

  const handleMarkPaid = async () => {
    if (busy) return;
    setBusy(true);
    try {
      const nextStatus = await activatePostPaymentQuarantine({
        profileId: profileId ?? null,
        routeId: routeId ?? null,
        exitIp: exitIp ?? null,
        exitAsn: exitAsn ?? null,
        exitCountry: exitCountry ?? null,
      });
      setStatus(nextStatus);
      notifyQuarantineUpdated();
      onStatusChange?.(nextStatus);

      const resolvedIp = nextStatus.quarantine?.pinnedExitIp || exitIp || "";
      const passportChannel = toPassportChannel(channel);
      const validBin = binPrefix && /^\d{6,8}$/.test(binPrefix.trim()) ? binPrefix.trim() : "";
      const canSavePassport =
        Boolean(resolvedIp) &&
        (passportChannel === "appleIAP" || passportChannel === "api" || validBin.length >= 6);

      if (canSavePassport) {
        const resolvedCardCc =
          cardCountry?.trim().toUpperCase() ||
          (passportChannel === "appleIAP" ? "US" : exitCountry?.trim().toUpperCase() || "US");
        const resolvedBillCc =
          billingCountry?.trim().toUpperCase() || resolvedCardCc;
        const saved = await savePaymentPassport({
          profileId: profileId?.trim() || "default",
          binPrefix: validBin,
          cardCountry: resolvedCardCc,
          channel: passportChannel,
          billingCountry: resolvedBillCc,
          exitIp: resolvedIp,
          exitAsn: exitAsn ?? nextStatus.quarantine?.pinnedAsn ?? null,
          paidAt: Math.floor(Date.now() / 1000),
        });
        onPassportSaved?.(saved);
      }

      onToast?.(copy.toastActivated, copy.toastActivatedText, "success");
    } catch (err: unknown) {
      onToast?.(
        subscription.card.errors.generic,
        err instanceof Error ? err.message : String(err),
        "error",
      );
    } finally {
      setBusy(false);
    }
  };

  const active = Boolean(status?.active);
  const pinnedIp = status?.quarantine?.pinnedExitIp
    ? formatIp(status.quarantine.pinnedExitIp, hideIpMode)
    : null;
  const pinnedCountryName = status?.quarantine?.pinnedCountry
    ? countryName(status.quarantine.pinnedCountry) || status.quarantine.pinnedCountry
    : null;

  return (
    <Card
      title={copy.title}
      aside={
        active && status ? (
          <Badge tone="info" icon="lock">
            <span className="subs-quarantine-countdown">{status.remainingHours} ч</span>
          </Badge>
        ) : undefined
      }
    >
      {active && status ? (
        <Banner
          tone="info"
          icon="lock"
          title={
            <span className="subs-quarantine-countdown">
              {copy.activeBannerTitle(status.remainingHours)}
            </span>
          }
        >
          {copy.activeBannerText(pinnedCountryName)}
          {pinnedIp && (
            <>
              {" "}
              <Mono>{pinnedIp}</Mono>
            </>
          )}
        </Banner>
      ) : (
        <p className="zs-t-body subs-lead">{copy.idleText}</p>
      )}

      <div className="subs-block-gap">
        <Button
          variant={ctaVariant}
          icon="check"
          disabled={busy}
          onClick={() => void handleMarkPaid()}
        >
          {copy.paidButton}
        </Button>
      </div>
    </Card>
  );
}

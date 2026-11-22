import { useEffect, useState } from "react";
import type {
  PassportChannel,
  PassportVerificationResult,
  PaymentPassport,
} from "../../types";
import { getPaymentPassport, verifyPaymentPassport } from "../../utils/api";
import { Badge, Banner, Button, Card, Mono, Row, Rows } from "../../ui";
import type { ShowToast } from "../../shared/hooks";
import { countryName } from "../../shared/lib/country";
import { formatIp } from "../../shared/lib/format";
import { subscription } from "../../shared/copy/ru";

const copy = subscription.passport;

export interface PaymentPassportCardProps {
  profileId?: string | null;
  currentBin?: string | null;
  currentCardCountry?: string | null;
  currentBillingCountry?: string | null;
  currentChannel?: PassportChannel | null;
  currentExitIp?: string | null;
  currentExitAsn?: number | null;
  hideIpMode?: boolean;
  refreshTrigger?: number;
  initialPassport?: PaymentPassport | null;
  onToast?: ShowToast;
}

/** Памятка прошлой оплаты: скрыта до первой отметки, хранит привязку без номера карты. */
export function PaymentPassportCard({
  profileId,
  currentBin,
  currentCardCountry,
  currentBillingCountry,
  currentChannel,
  currentExitIp,
  currentExitAsn,
  hideIpMode = false,
  refreshTrigger = 0,
  initialPassport,
  onToast,
}: PaymentPassportCardProps) {
  const effectiveProfileId = profileId?.trim() || "default";
  const [passport, setPassport] = useState<PaymentPassport | null>(initialPassport ?? null);
  const [verification, setVerification] = useState<PassportVerificationResult | null>(null);
  const [verifying, setVerifying] = useState<boolean>(false);

  useEffect(() => {
    if (initialPassport !== undefined) {
      setPassport(initialPassport);
      return;
    }
    let cancelled = false;
    getPaymentPassport(effectiveProfileId)
      .then((res) => {
        if (!cancelled) setPassport(res);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [effectiveProfileId, refreshTrigger, initialPassport]);

  if (!passport) {
    return null;
  }

  const handleVerify = async () => {
    if (verifying) return;
    setVerifying(true);
    try {
      const res = await verifyPaymentPassport(effectiveProfileId, {
        binPrefix: currentBin ?? null,
        cardCountry: currentCardCountry ?? null,
        billingCountry: currentBillingCountry ?? null,
        channel: currentChannel ?? null,
        exitIp: currentExitIp ?? null,
        exitAsn: currentExitAsn ?? null,
      });
      setVerification(res);
    } catch (err: unknown) {
      onToast?.(
        copy.title,
        err instanceof Error ? err.message : String(err),
        "error",
      );
    } finally {
      setVerifying(false);
    }
  };

  const cardCountryRu = countryName(passport.cardCountry) || passport.cardCountry;
  const billingCountryRu = countryName(passport.billingCountry) || passport.billingCountry;

  return (
    <Card
      title={copy.title}
      aside={
        <Badge tone="info" icon="shield">
          {subscription.readiness.channels[passport.channel] ?? passport.channel}
        </Badge>
      }
    >
      <Rows>
        {passport.binPrefix && (
          <Row icon="key" title={<Mono>{passport.binPrefix}</Mono>} sub={copy.fields.bin} />
        )}
        <Row icon="globe" title={cardCountryRu} sub={copy.fields.cardCountry} />
        <Row icon="folder" title={billingCountryRu} sub={copy.fields.billingCountry} />
        <Row
          icon="shield"
          title={<Mono>{formatIp(passport.exitIp, hideIpMode)}</Mono>}
          sub={copy.fields.exitIp}
        />
        {passport.exitAsn && (
          <Row
            icon="info"
            title={<Mono>AS{passport.exitAsn}</Mono>}
            sub={copy.fields.exitAsn}
          />
        )}
      </Rows>

      <div className="subs-block-gap">
        <Button
          size="sm"
          variant="secondary"
          disabled={verifying}
          onClick={() => void handleVerify()}
        >
          {copy.verifyBtn}
        </Button>
      </div>

      {verification && (
        <div className="subs-block-gap">
          <Banner
            tone={verification.matched ? "ok" : "danger"}
            icon={verification.matched ? "check" : "alert"}
            role={verification.matched ? "status" : "alert"}
            title={verification.matched ? copy.matchedTitle : copy.mismatchTitle}
          >
            {verification.mismatches[0] ?? verification.warnings[0]}
          </Banner>
        </div>
      )}
    </Card>
  );
}

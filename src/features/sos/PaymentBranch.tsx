import { useState } from "react";
import type { BinReport } from "../../types";
import { Card } from "../../ui";
import { sosCopy as copy } from "../../shared/copy/ru/sos";
import type { ShowToast } from "../../shared/hooks";
import { AddressCard } from "../subscription/AddressCard";
import { CardCheck } from "../subscription/CardCheck";
import "./sos.css";

export interface PaymentBranchProps {
  currentCountry?: string;
  ctaVariant?: "primary" | "secondary";
  onToast?: ShowToast;
  onNavigateToPaymentGuide?: () => void;
}

/** Ветка 3 SOS: ошибка оплаты / 3DS — диагностика двойного VPN + встроенные CardCheck и AddressCard. */
export function PaymentBranch({
  currentCountry,
  ctaVariant = "primary",
  onToast,
  onNavigateToPaymentGuide,
}: PaymentBranchProps) {
  const t = copy.payment;
  const [binReport, setBinReport] = useState<BinReport | null>(null);
  const trimmedCountry = currentCountry?.trim();
  const resolvedCountry = trimmedCountry && trimmedCountry !== "--" ? trimmedCountry : undefined;

  return (
    <div className="zs-stack">
      <Card title={t.title}>
        <div className="zs-sos__step">
          <p className="zs-t-body zs-sos__step-title">
            <strong>{t.pitfallsTitle}</strong>
          </p>
          <ul className="zs-t-caption zs-sos__list">
            {t.pitfalls.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      </Card>
      <CardCheck
        exitCountry={resolvedCountry}
        ctaVariant={ctaVariant}
        onToast={onToast}
        onNavigateToPaymentGuide={onNavigateToPaymentGuide}
        onBinChecked={setBinReport}
      />
      <AddressCard cardCountry={binReport?.countryCode ?? null} scenario="card" onToast={onToast} />
    </div>
  );
}

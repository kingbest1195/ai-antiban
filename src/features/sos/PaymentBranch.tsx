import { Banner, Card } from "../../ui";
import { sosCopy as copy } from "../../shared/copy/ru/sos";
import type { ShowToast } from "../../shared/hooks";
import { AddressCard } from "../subscription/AddressCard";
import { CardCheck } from "../subscription/CardCheck";
import "./sos.css";

export interface PaymentBranchProps {
  currentCountry?: string;
  onToast?: ShowToast;
  onNavigateToPaymentGuide?: () => void;
}

/** Ветка 3 SOS: ошибка оплаты / 3DS — диагностика двойного VPN + встроенные CardCheck и AddressCard. */
export function PaymentBranch({ currentCountry, onToast, onNavigateToPaymentGuide }: PaymentBranchProps) {
  const t = copy.payment;
  return (
    <div className="zs-stack">
      <Card title={t.title}>
        <Banner tone="warn" icon="alert" title={t.pitfallsTitle}>
          <ul className="zs-t-caption zs-sos__list">
            {t.pitfalls.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </Banner>
      </Card>
      <CardCheck
        country={currentCountry}
        onToast={onToast}
        onNavigateToPaymentGuide={onNavigateToPaymentGuide}
      />
      <AddressCard onToast={onToast} />
    </div>
  );
}

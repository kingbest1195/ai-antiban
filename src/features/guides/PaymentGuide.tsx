import { useRef } from "react";
import { Badge, Banner, Button, Card, Row, Steps } from "../../ui";
import type { StepItem } from "../../ui";
import { common, guides as copy } from "../../shared/copy/ru";
import { openExternal } from "../../utils/opener";
import { AddressCard } from "../subscription/AddressCard";
import { CardCheck } from "../subscription/CardCheck";
import "../subscription/subscription.css";
import { useGuide } from "./context";
import { Rich } from "./Rich";
import { VIRTUAL_CARD_PROVIDERS } from "./providers";
import type { VirtualCardProvider } from "./providers";

export interface PaymentGuideProps {
  onOpenPaymentTools?: () => void;
}

/** Раздел «Оплата»: BIN-чекер, безналоговый адрес США, сервисы виртуальных карт и правила платежной гигиены. */
export function PaymentGuide({ onOpenPaymentTools }: PaymentGuideProps) {
  const { currentCountry, onToast } = useGuide();
  const paymentToolsRef = useRef<HTMLDivElement>(null);
  const t = copy.payment;

  const handleOpenPaymentTools = () => {
    if (onOpenPaymentTools) {
      onOpenPaymentTools();
      return;
    }
    paymentToolsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const open = (card: VirtualCardProvider) => {
    openExternal(card.url);
    onToast?.(copy.toast.openCard, copy.toast.openCardText(card.name), "info");
  };

  const rules: StepItem[] = t.rules.map((rule) => ({
    status: "todo",
    title: rule.title,
    text: <Rich text={rule.text} />,
  }));

  return (
    <>
      <Banner
        tone="warn"
        icon="lock"
        title={t.pitchTitle}
        action={
          <Button size="sm" variant="secondary" onClick={handleOpenPaymentTools}>
            {t.openPaymentTools}
          </Button>
        }
      >
        {t.pitchText}
      </Banner>

      <div ref={paymentToolsRef} className="zs-stack">
        <CardCheck country={currentCountry} onToast={onToast} />

        <AddressCard onToast={onToast} />
      </div>

      <Card title={t.servicesTitle}>
        <p className="guides-note guides-note--tight">{t.servicesAside}</p>
        <ul className="guides-offers">
          {VIRTUAL_CARD_PROVIDERS.map((card) => (
            <li key={card.id} className="guides-offer">
              <Row
                as="div"
                icon="lock"
                title={
                  <>
                    {card.name}
                    <span className="zs-sr">{common.openSite}</span>
                  </>
                }
                sub={card.tier}
                onClick={() => open(card)}
              />
              <p className="guides-offer__text">{card.description}</p>
              <div className="guides-offer__meta">
                <Badge tone="info">{card.badge}</Badge>
              </div>
            </li>
          ))}
        </ul>
      </Card>

      <Card title={t.rulesLabel}>
        <Steps items={rules} />
      </Card>
    </>
  );
}

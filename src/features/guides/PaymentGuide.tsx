import { Badge, Banner, Card, Row, Steps } from "../../ui";
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

/** Раздел «Оплата»: BIN-чекер, безналоговый адрес США, сервисы виртуальных карт и правила платежной гигиены. */
export function PaymentGuide() {
  const { currentCountry, onToast } = useGuide();
  const t = copy.payment;

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
      <Banner tone="warn" icon="lock" title={t.pitchTitle}>
        {t.pitchText}
      </Banner>

      <CardCheck country={currentCountry} onToast={onToast} />

      <AddressCard onToast={onToast} />

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

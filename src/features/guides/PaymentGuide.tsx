import { useRef, useState } from "react";
import type { BinReport } from "../../types";
import { Badge, Banner, Button, Card, Icon, Row, Rows, Steps } from "../../ui";
import type { StepItem } from "../../ui";
import { common, guides as copy } from "../../shared/copy/ru";
import { openExternal } from "../../utils/opener";
import { AddressCard } from "../subscription/AddressCard";
import { CardCheck } from "../subscription/CardCheck";
import "../subscription/subscription.css";
import { useGuide } from "./context";
import { Rich } from "./Rich";
import { BLACKLISTED_PROVIDERS, VIRTUAL_CARD_PROVIDERS } from "./providers";
import type { VirtualCardProvider } from "./providers";

export interface PaymentGuideProps {
  onOpenPaymentTools?: () => void;
}

function ProviderOfferList({
  providers,
  importantPointsLabel,
  nuancesToggle,
  onOpen,
}: {
  providers: VirtualCardProvider[];
  importantPointsLabel: string;
  nuancesToggle: string;
  onOpen: (card: VirtualCardProvider) => void;
}) {
  return (
    <ul className="guides-offers">
      {providers.map((card) => {
        const isAppStore = card.tier === "tier1_iap";

        return (
          <li key={card.id} className="guides-offer">
            <Row
              as="div"
              icon={isAppStore ? "shield" : "lock"}
              tone={isAppStore ? "ok" : "warn"}
              title={card.name}
              sub={card.subtitle}
              trail={
                card.url ? (
                  <Button size="sm" variant="secondary" icon="arrow" onClick={() => onOpen(card)}>
                    {common.goTo}
                  </Button>
                ) : undefined
              }
            />
            <p className="guides-offer__text">
              <Rich text={card.description} />
            </p>
            {card.steps && card.steps.length > 0 && (
              <ol className="guides-steps">
                {card.steps.map((step, index) => (
                  <li key={step} className="guides-steps__item">
                    <span className="guides-steps__num" aria-hidden="true">
                      {index + 1}
                    </span>
                    <span className="guides-steps__text">
                      <Rich text={step} />
                    </span>
                  </li>
                ))}
              </ol>
            )}
            {card.alternative && (
              <div className="guides-alt">
                <p className="guides-alt__title">{card.alternative.title}</p>
                <p className="guides-alt__text">
                  <Rich text={card.alternative.text} />
                </p>
              </div>
            )}
            {card.warnings.length > 0 && (
              <div className="guides-points" aria-label={importantPointsLabel}>
                <p className="guides-points__title">{importantPointsLabel}</p>
                <ul className="guides-points__list">
                  {card.warnings.map((warning) => (
                    <li key={warning}>
                      <Rich text={warning} />
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {card.nuances && card.nuances.length > 0 && (
              <details className="guides-nuances">
                <summary className="guides-nuances__summary">
                  <Icon name="chev" className="guides-nuances__chev" />
                  <span>{nuancesToggle}</span>
                </summary>
                <ul className="guides-nuances__list">
                  {card.nuances.map((nuance) => (
                    <li key={nuance}>
                      <Rich text={nuance} />
                    </li>
                  ))}
                </ul>
              </details>
            )}
            <div className="guides-offer__meta">
              <Badge tone={isAppStore ? "ok" : "warn"} icon={isAppStore ? "shield" : "alert"}>
                {card.badge}
              </Badge>
            </div>
          </li>
        );
      })}
    </ul>
  );
}

/** Раздел «Оплата»: проверка карты, адрес США, способы оплаты, ненадёжные сервисы и защита маршрута. */
export function PaymentGuide({ onOpenPaymentTools }: PaymentGuideProps) {
  const { currentCountry, onToast } = useGuide();
  const [binReport, setBinReport] = useState<BinReport | null>(null);
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
    if (!card.url) return;
    openExternal(card.url);
    onToast?.(copy.toast.openCard, copy.toast.openCardText(card.name), "info");
  };

  const appStoreProviders = VIRTUAL_CARD_PROVIDERS.filter((p) => p.tier === "tier1_iap");
  const webCardProviders = VIRTUAL_CARD_PROVIDERS.filter((p) => p.tier === "tier2_conditional");

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
        <CardCheck exitCountry={currentCountry} onToast={onToast} onBinChecked={setBinReport} />

        <AddressCard cardCountry={binReport?.countryCode ?? null} scenario="card" onToast={onToast} />
      </div>

      <Card className="guides-card" title={t.appStoreTitle} aside={<Badge tone="ok" icon="shield">{t.appStoreBadge}</Badge>}>
        <p className="guides-note guides-note--tight">
          <Rich text={t.appStoreAside} />
        </p>
        <ProviderOfferList
          providers={appStoreProviders}
          importantPointsLabel={t.importantPointsLabel}
          nuancesToggle={t.nuancesToggle}
          onOpen={open}
        />
      </Card>

      <Card className="guides-card" title={t.webCardTitle} aside={<Badge tone="warn" icon="alert">{t.webCardBadge}</Badge>}>
        <p className="guides-note guides-note--tight">
          <Rich text={t.webCardAside} />
        </p>
        <ProviderOfferList
          providers={webCardProviders}
          importantPointsLabel={t.importantPointsLabel}
          nuancesToggle={t.nuancesToggle}
          onOpen={open}
        />
      </Card>

      <Card className="guides-card" title={t.blacklistTitle} aside={<Badge tone="danger" icon="alert">{t.blacklistBadge}</Badge>}>
        <Banner tone="danger" role="alert" icon="alert" title={t.blacklistBannerTitle}>
          {t.blacklistBannerText}
        </Banner>
        <Rows>
          {BLACKLISTED_PROVIDERS.map((item) => (
            <Row key={item.id} icon="x" tone="danger" title={item.name} sub={<Rich text={item.reason} />} />
          ))}
        </Rows>
      </Card>

      <Card className="guides-card" title={t.rulesLabel}>
        <Steps items={rules} />
      </Card>
    </>
  );
}

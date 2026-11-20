import type { RouteView } from "../../types";
import { Badge, Button, Card, Field, Row, Rows } from "../../ui";
import { common, connect as copy, PROMO_COPY } from "../../shared/copy/ru";
import { openExternal, openZastavaBot } from "../../utils/opener";
import { HOSTINGS } from "./hostings";
import type { AddKeyScope } from "./RouteListSection";

export interface ConnectSalesCardsProps {
  routes: RouteView[];
  hasRoutes: boolean;
  isLegacyConfigured: boolean;
  inputKey: string;
  addScope: AddKeyScope;
  error: string | null;
  connecting: boolean;
  onInputKeyChange: (val: string) => void;
  onAddScopeChange: (scope: AddKeyScope) => void;
  onAddKey: () => void;
  onOpenGuide: (guideId: string) => void;
}

/** Продающая раскладка (layout="sales"): 1-я карточка — ВПН Заставы с вводом ключа, 2-я — Свой сервер (без бейджа «Бесплатно»). */
export function ConnectSalesCards({
  inputKey,
  error,
  connecting,
  onInputKeyChange,
  onAddKey,
  onOpenGuide,
}: ConnectSalesCardsProps) {
  return (
    <>
      <Card
        className="zs-sale zs-sale--key"
        title={copy.key.title}
        aside={<Badge tone="ok">{PROMO_COPY.keyPriceLabel}</Badge>}
      >
        <p className="zs-t-body mb-2 text-ink-2">{copy.key.text}</p>
        <ul className="zs-sale__list">
          {PROMO_COPY.keyBenefits.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
        <p className="zs-t-caption mb-3 text-ink-3">{PROMO_COPY.keyIssuanceTime}</p>
        <Button variant="primary" block onClick={() => openZastavaBot()}>
          {copy.key.get}
        </Button>

        <div className="mt-3 zs-stack">
          <Field
            label={copy.key.fieldLabel}
            placeholder={copy.key.placeholder}
            value={inputKey}
            onChange={(e) => onInputKeyChange(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") onAddKey();
            }}
            autoComplete="off"
            spellCheck={false}
            help={copy.key.caption}
            error={error ?? undefined}
            action={
              <Button variant="secondary" onClick={onAddKey} disabled={connecting}>
                {connecting ? copy.key.connecting : copy.key.connect}
              </Button>
            }
          />
        </div>
      </Card>

      <Card className="zs-sale" title={copy.vpn.title}>
        <p className="zs-t-body mb-2 text-ink-2">{copy.vpn.text}</p>
        <ul className="zs-sale__list">
          {PROMO_COPY.salesServerBenefits.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
        <Rows>
          {HOSTINGS.map((h) => (
            <Row
              key={h.id}
              icon="globe"
              title={h.name}
              sub={h.sub}
              trail={
                <Button size="sm" variant="secondary" onClick={() => openExternal(h.url)}>
                  {common.goTo}
                </Button>
              }
            />
          ))}
        </Rows>
        <Button
          variant="secondary"
          block
          className="mt-3"
          onClick={() => onOpenGuide("01-personal-vpn-15min")}
        >
          {copy.vpn.open}
        </Button>
      </Card>
    </>
  );
}

/** Классическая карточка «Свой сервер» для layout="default". */
export function ConnectDefaultVpnCard({
  hasRoutes,
  isLegacyConfigured,
  onOpenGuide,
}: {
  hasRoutes: boolean;
  isLegacyConfigured: boolean;
  onOpenGuide: (guideId: string) => void;
}) {
  return (
    <Card title={copy.vpn.title}>
      <p className="zs-t-body mb-3 text-ink-2">{copy.vpn.text}</p>
      <Rows>
        {HOSTINGS.map((h) => (
          <Row
            key={h.id}
            icon="globe"
            title={h.name}
            sub={h.sub}
            trail={
              <Button size="sm" variant="secondary" onClick={() => openExternal(h.url)}>
                {common.goTo}
              </Button>
            }
          />
        ))}
      </Rows>
      <Button
        variant={hasRoutes || isLegacyConfigured ? "secondary" : "primary"}
        block
        className="mt-3"
        onClick={() => onOpenGuide("01-personal-vpn-15min")}
      >
        {copy.vpn.open}
      </Button>
    </Card>
  );
}

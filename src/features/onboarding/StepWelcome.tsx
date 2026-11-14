import { Card, Row, Rows } from "../../ui";
import { onboarding as copy } from "../../shared/copy/ru";
import { StepFooter, StepFrame } from "./parts";

/** Шаг 1: возможности Заставы v2.2 — VPN или ключи zastava://, 14 проверок, защита при обрыве, локальная работа. */
export function StepWelcome({ onNext }: { onNext: () => void }) {
  const rows = copy.welcome.rows;
  return (
    <StepFrame
      title={copy.welcome.title}
      lead={copy.welcome.lead}
      footer={<StepFooter primary={{ onClick: onNext, children: copy.welcome.next }} />}
    >
      <Card>
        <Rows>
          <Row icon="key" title={rows.vpnOrKey.title} sub={rows.vpnOrKey.sub} />
          <Row icon="pulse" title={rows.watch.title} sub={rows.watch.sub} />
          <Row icon="alert" title={rows.pause.title} sub={rows.pause.sub} />
          <Row icon="lock" title={rows.local.title} sub={rows.local.sub} />
        </Rows>
      </Card>
    </StepFrame>
  );
}

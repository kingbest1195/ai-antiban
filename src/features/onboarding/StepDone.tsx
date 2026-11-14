import { Card, Row, Rows } from "../../ui";
import { onboarding as copy } from "../../shared/copy/ru";
import { StepFooter, StepFrame } from "./parts";

const IS_MAC = typeof navigator !== "undefined" && /Mac|iPhone|iPad/i.test(navigator.platform || navigator.userAgent);

/** Финал: Застава работает в фоне, где её значок, что делать при остановке запроса и чистое восстановление при выходе. */
export function StepDone({ onOpenOverview }: { onOpenOverview: () => void }) {
  const d = copy.done;
  return (
    <StepFrame
      title={d.title}
      lead={d.lead}
      footer={<StepFooter primary={{ icon: "arrow", onClick: onOpenOverview, children: d.open }} />}
    >
      <Card>
        <Rows>
          <Row icon="shield" title={d.tray.title(IS_MAC)} sub={d.tray.sub} />
          <Row icon="alert" title={d.alert.title} sub={d.alert.sub} />
          <Row icon="power" title={d.shutdown.title} sub={d.shutdown.sub} />
          <Row icon="refresh" title={d.replay.title} sub={d.replay.sub} />
        </Rows>
      </Card>
    </StepFrame>
  );
}

import { Card, Row, Rows, Section } from "../../ui";
import { onboarding as copy } from "../../shared/copy/ru";
import type { OnboardingGoal } from "./types";
import { StepFooter, StepFrame } from "./parts";

const IS_MAC = typeof navigator !== "undefined" && /Mac|iPhone|iPad/i.test(navigator.platform || navigator.userAgent);

export interface StepDoneProps {
  goal?: OnboardingGoal;
  onComplete?: (goal: OnboardingGoal) => void;
  /** @deprecated Используйте onComplete. */
  onOpenOverview?: () => void;
  onBack?: () => void;
}

/** Шаг 5 (финал): 4 цвета индикатора в трее и автоматический переход к выбранной цели. */
export function StepDone({ goal = "protect", onComplete, onOpenOverview, onBack }: StepDoneProps) {
  const d = copy.done;
  const finish = () => {
    if (onComplete) onComplete(goal);
    else onOpenOverview?.();
  };

  return (
    <StepFrame
      title={d.title}
      lead={d.lead}
      footer={<StepFooter back={onBack} primary={{ icon: "arrow", onClick: finish, children: d.ctaByGoal[goal] }} />}
    >
      <Section title={d.trayTitle(IS_MAC)}>
        <Card>
          <Rows>
            <Row
              icon="check"
              title={d.trayColors.green.title}
              sub={d.trayColors.green.sub}
              trail={<span className="zs-onb__tray-dot zs-onb__tray-dot--green" aria-hidden="true" />}
            />
            <Row
              icon="alert"
              title={d.trayColors.yellow.title}
              sub={d.trayColors.yellow.sub}
              trail={<span className="zs-onb__tray-dot zs-onb__tray-dot--yellow" aria-hidden="true" />}
            />
            <Row
              icon="shield"
              title={d.trayColors.red.title}
              sub={d.trayColors.red.sub}
              trail={<span className="zs-onb__tray-dot zs-onb__tray-dot--red" aria-hidden="true" />}
            />
            <Row
              icon="power"
              title={d.trayColors.gray.title}
              sub={d.trayColors.gray.sub}
              trail={<span className="zs-onb__tray-dot zs-onb__tray-dot--gray" aria-hidden="true" />}
            />
          </Rows>
        </Card>
      </Section>
      <Card>
        <Rows>
          <Row icon="power" title={d.shutdown.title} sub={d.shutdown.sub} />
          <Row icon="refresh" title={d.replay.title} sub={d.replay.sub} />
        </Rows>
      </Card>
    </StepFrame>
  );
}

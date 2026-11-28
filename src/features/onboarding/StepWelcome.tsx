import { useState } from "react";
import { Section } from "../../ui";
import { onboarding as copy } from "../../shared/copy/ru";
import { WatchdogMascot } from "../mascot";
import type { OnboardingGoal } from "./types";
import { StepFooter, StepFrame } from "./parts";

export interface StepWelcomeProps {
  goal?: OnboardingGoal;
  onSelectGoal?: (goal: OnboardingGoal) => void;
  onNext: () => void;
}

const GOAL_IDS: OnboardingGoal[] = ["protect", "clean_room", "sos"];

/** Шаг 1: приветствие маскота Заставы и быстрый выбор цели (Quick-Pick Goal). */
export function StepWelcome({ goal, onSelectGoal, onNext }: StepWelcomeProps) {
  const [localGoal, setLocalGoal] = useState<OnboardingGoal>(goal ?? "protect");
  const selected = goal ?? localGoal;

  const choose = (nextGoal: OnboardingGoal) => {
    setLocalGoal(nextGoal);
    onSelectGoal?.(nextGoal);
  };

  return (
    <StepFrame
      title={copy.welcome.title}
      lead={copy.welcome.lead}
      footer={<StepFooter primary={{ onClick: onNext, children: copy.welcome.next }} />}
    >
      <div className="zs-onb__hero">
        <WatchdogMascot state="protected" size={64} decorative />
        <p className="zs-onb__note">{copy.welcome.goalsTitle}</p>
      </div>
      <Section title={copy.welcome.goalsTitle}>
        <div className="zs-onb__goals" role="radiogroup" aria-label={copy.welcome.goalsTitle}>
          {GOAL_IDS.map((id) => {
            const item = copy.welcome.goals[id];
            const active = selected === id;
            return (
              <button
                key={id}
                type="button"
                role="radio"
                aria-checked={active}
                data-onb-goal={id}
                className={active ? "zs-onb__goal zs-onb__goal--active" : "zs-onb__goal"}
                onClick={() => choose(id)}
              >
                <span className="zs-onb__goal-title">{item.title}</span>
                <span className="zs-onb__goal-sub">{item.sub}</span>
              </button>
            );
          })}
        </div>
        {selected === "protect" && <p className="zs-onb__note">{copy.welcome.goals.protect.note}</p>}
      </Section>
    </StepFrame>
  );
}

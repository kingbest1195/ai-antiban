import { useCallback, useEffect, useRef, useState } from "react";
import type { ProviderId, RiskReport } from "../../types";
import { Button, Progress } from "../../ui";
import { getFocusable, trapTab } from "../../ui/dom";
import { onboarding as copy } from "../../shared/copy/ru";
import { ONBOARDING_STEPS } from "./useOnboarding";
import { StepWelcome } from "./StepWelcome";
import { StepNetwork } from "./StepNetwork";
import { StepProtect } from "./StepProtect";
import { StepAlert } from "./StepAlert";
import { StepDone } from "./StepDone";
import "./onboarding.css";

/** Куда перейти после закрытия знакомства. Без значения — остаться где были. */
export type OnboardingExit = "overview" | "connect" | undefined;

export interface OnboardingFlowProps {
  /** С какого шага начать (1…5; 5 — финал). Нужен для проверки в dev. */
  initialStep?: number;
  reports: Partial<Record<ProviderId, RiskReport>>;
  activeReport: RiskReport | null;
  refreshing: boolean;
  auditError: string | null;
  currentIp: string;
  trustScore: number;
  sysproxyActive: boolean;
  cliProtected: boolean;
  onToggleSysproxy: () => void;
  onToggleCli: () => void;
  /** Тот же аудит, что и на «Обзоре» (runFullAudit(true)). */
  onRecheck: () => void;
  /** Закрытие: «Пропустить», Esc или завершение. Флаг «пройдено» ставит вызывающий. */
  onClose: (to?: OnboardingExit) => void;
}

const DONE_STEP = ONBOARDING_STEPS + 1;

/** Полноэкранный сценарий первого запуска поверх оболочки: четыре шага и финал. */
export function OnboardingFlow({ initialStep = 1, onClose, ...data }: OnboardingFlowProps) {
  const [step, setStep] = useState(initialStep);
  const layerRef = useRef<HTMLDivElement>(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;

  const next = useCallback(() => setStep((s) => Math.min(DONE_STEP, s + 1)), []);
  const back = useCallback(() => setStep((s) => Math.max(1, s - 1)), []);

  // Окно диалога: фокус внутрь при открытии и возврат при закрытии.
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    return () => previous?.focus?.();
  }, []);

  // Клавиатура: Enter — главное действие, Esc — закрыть, Tab не выходит из окна.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented || e.ctrlKey || e.metaKey || e.altKey) return;
      // Поверх знакомства открыт демо-диалог: он сам ловит свои клавиши.
      if (document.querySelector(".zs-alert-overlay")) return;
      const layer = layerRef.current;
      if (!layer) return;

      if (e.key === "Escape") {
        e.preventDefault();
        closeRef.current();
      } else if (e.key === "Enter" && !e.repeat) {
        const t = e.target as HTMLElement | null;
        // На кнопках, ссылках и тумблерах Enter и так нажимает их сам.
        if (t && t.closest("button, a[href], input, textarea, select, summary, [role='switch']")) return;
        const primary = layer.querySelector<HTMLButtonElement>("[data-onb-primary]:not(:disabled)");
        if (primary) {
          e.preventDefault();
          primary.click();
        }
      } else if (e.key === "Tab") {
        if (!layer.contains(document.activeElement) || document.activeElement === layer) {
          const items = getFocusable(layer);
          const target = e.shiftKey ? items[items.length - 1] : items[0];
          if (target) {
            e.preventDefault();
            target.focus();
          }
        } else {
          trapTab(e, layer);
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const finished = step === DONE_STEP;
  const isAlertStep = step === ONBOARDING_STEPS;
  // На шаге с пробной тревогой кнопка в шапке ведёт к финалу («Продолжить»), на остальных закрывает знакомство.
  const headerAction = () => (isAlertStep ? next() : onClose());

  let body;
  switch (step) {
    case 1:
      body = <StepWelcome onNext={next} />;
      break;
    case 2:
      body = (
        <StepNetwork
          reports={data.reports}
          activeReport={data.activeReport}
          refreshing={data.refreshing}
          auditError={data.auditError}
          currentIp={data.currentIp}
          trustScore={data.trustScore}
          onRecheck={data.onRecheck}
          onNext={next}
          onBack={back}
          onOpenConnect={() => onClose("connect")}
        />
      );
      break;
    case 3:
      body = (
        <StepProtect
          sysproxyActive={data.sysproxyActive}
          cliProtected={data.cliProtected}
          onToggleSysproxy={data.onToggleSysproxy}
          onToggleCli={data.onToggleCli}
          onNext={next}
          onBack={back}
        />
      );
      break;
    case 4:
      body = <StepAlert onReacted={next} onBack={back} />;
      break;
    default:
      body = <StepDone onOpenOverview={() => onClose("overview")} />;
  }

  return (
    <div ref={layerRef} className="zs-onb" role="dialog" aria-modal="true" aria-label={copy.label} tabIndex={-1}>
      <div className="zs-onb__panel">
        <header className="zs-onb__head">
          <Progress
            label={finished ? copy.doneProgress : copy.step(step, ONBOARDING_STEPS)}
            value={finished ? 100 : (step / ONBOARDING_STEPS) * 100}
            showValue={false}
          />
          {!finished && (
            <Button size="sm" onClick={headerAction}>
              {isAlertStep ? copy.continue : copy.skip}
            </Button>
          )}
        </header>
        {/* key: шаг монтируется заново, фокус снова уходит на его заголовок */}
        <div key={step} className="zs-onb__step">
          {body}
        </div>
      </div>
    </div>
  );
}

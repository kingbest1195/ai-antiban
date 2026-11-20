import { useCallback, useEffect, useRef, useState } from "react";
import { Banner, Card, Row, Rows, Section } from "../../ui";
import { onInterceptorResolved, simulateInterception } from "../../utils/api";
import { isTauri } from "../../utils/api/client";
import { onboarding as copy } from "../../shared/copy/ru";
import { AlertOverlay } from "../alert";
import { KillSwitchAnim } from "../mascot";
import { StepFooter, StepFrame } from "./parts";

type Phase = "idle" | "waiting" | "error";

/**
 * Шаг 4: демо-перехват. В Tauri simulate_interception открывает отдельное окно alert-popup, а о реакции
 * сообщает событие interceptor://resolved. В браузере (моки) окно рисует тот же AlertOverlay с Dialog в демо-режиме.
 */
export function StepAlert({ onReacted, onBack }: { onReacted: () => void; onBack: () => void }) {
  const [phase, setPhase] = useState<Phase>("idle");
  const [overlay, setOverlay] = useState(false);
  const reacted = useRef(false);

  const react = useCallback(() => {
    if (reacted.current) return;
    reacted.current = true;
    setOverlay(false);
    onReacted();
  }, [onReacted]);

  const show = async () => {
    try {
      await simulateInterception("anthropic");
      if (isTauri()) setPhase("waiting");
      else setOverlay(true);
    } catch (err) {
      console.error("Onboarding: simulate failed", err);
      setPhase("error");
    }
  };

  // Tauri: ждём решения пользователя в окне-диалоге.
  useEffect(() => {
    if (phase !== "waiting" || !isTauri()) return;
    let cancelled = false;
    let unlisten: (() => void) | undefined;
    onInterceptorResolved(() => react()).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [phase, react]);

  // Браузер: фокус сразу в диалог, иначе Tab уходил бы под него.
  useEffect(() => {
    if (!overlay) return;
    const id = window.requestAnimationFrame(() => {
      document.querySelector<HTMLElement>(".zs-alert-overlay .zs-dialog .zs-btn--primary")?.focus();
    });
    return () => window.cancelAnimationFrame(id);
  }, [overlay]);

  const c = copy.alert.choices;
  return (
    <>
      <StepFrame
        title={copy.alert.title}
        lead={copy.alert.lead}
        footer={
          <StepFooter
            back={onBack}
            primary={{ icon: "zap", onClick: show, children: phase === "waiting" ? copy.alert.showAgain : copy.alert.show }}
            secondary={{ onClick: onReacted, children: copy.alert.continue }}
          />
        }
      >
        <KillSwitchAnim triggered latencyLabel="0.04 мс" compact />
        <div aria-live="polite" aria-atomic="true">
          {phase === "waiting" && (
            <Banner tone="info" title={copy.alert.waiting.title}>
              {copy.alert.waiting.text}
            </Banner>
          )}
          {phase === "error" && (
            <Banner tone="warn" title={copy.alert.error.title}>
              {copy.alert.error.text}
            </Banner>
          )}
        </div>
        <Section title={copy.alert.sectionChoices}>
          <Card>
            <Rows>
              <Row icon="alert" title={c.reason.title} sub={c.reason.sub} />
              <Row icon="shield" title={c.block.title} sub={c.block.sub} />
              <Row icon="zap" title={c.allow.title} sub={c.allow.sub} />
            </Rows>
          </Card>
        </Section>
      </StepFrame>
      {overlay && <AlertOverlay onResolved={react} />}
    </>
  );
}

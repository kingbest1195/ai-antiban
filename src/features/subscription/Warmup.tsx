import type { StepItem } from "../../ui";
import type { AppStateData } from "../../types";
import { setWarmupTimer } from "../../utils/api";
import { Badge, Button, Card, Progress, Row, Rows, Section, Stat, Stats, Steps } from "../../ui";
import { subscription } from "../../shared/copy/ru";
import type { ShowToast } from "../../shared/hooks";

const copy = subscription.warmup;
const list = subscription.checklist;

/** Рекомендуемый срок прогрева, часы (4 дня): совет, а не гарантия; источника статистики нет. */
export const WARMUP_TARGET_HOURS = 96;

/** Состояние прогрева по времени старта. Формулы те же, что были в BinCheckerTab. */
export function warmupProgress(startedAt: number | null | undefined, now: number = Date.now()) {
  const started = startedAt || null;
  const elapsedMs = started ? Math.max(0, now - started) : 0;
  const elapsedHours = Math.floor(elapsedMs / (1000 * 60 * 60));
  const percent = started ? Math.min(100, Math.round((elapsedHours / WARMUP_TARGET_HOURS) * 100)) : 0;
  return { started, elapsedHours, percent, done: elapsedHours >= WARMUP_TARGET_HOURS };
}

interface WarmupProps {
  state?: AppStateData | null;
  onStateChange?: () => void;
  onNavigateToPaymentGuide?: () => void;
  onToast?: ShowToast;
}

/** Таймер прогрева аккаунта (Stat и Progress), чеклист перед оплатой (Steps) и переход к руководству. */
export function Warmup({ state, onStateChange, onNavigateToPaymentGuide, onToast }: WarmupProps) {
  const { started, elapsedHours, percent, done } = warmupProgress(state?.warmup_started_at);

  const start = async () => {
    try {
      await setWarmupTimer(Date.now());
      onToast?.(copy.toast.started, copy.toast.startedText, "success");
      onStateChange?.();
    } catch (err: unknown) {
      onToast?.(copy.toast.errorTitle, err instanceof Error && err.message ? err.message : copy.toast.startError, "error");
    }
  };

  const reset = async () => {
    try {
      await setWarmupTimer(null);
      onToast?.(copy.toast.reset, copy.toast.resetText, "info");
      onStateChange?.();
    } catch (err: unknown) {
      onToast?.(copy.toast.errorTitle, err instanceof Error && err.message ? err.message : copy.toast.resetError, "error");
    }
  };

  const items: StepItem[] = list.items.map((item, i) => ({
    // Второй пункт — про прогрев: следит за таймером. Остальные — памятка без состояния.
    status: i === 1 ? (done ? "done" : started ? "current" : "todo") : "todo",
    title: item.title,
    text: item.text,
  }));

  return (
    <>
      <Card title={copy.title} aside={<Badge tone="warn" icon="alert">{copy.aside}</Badge>}>
        <p className="zs-t-body subs-lead">{copy.text}</p>

        {started ? (
          <div className="subs-timer">
            <Stats>
              <Stat value={copy.stats.hours(elapsedHours)} label={copy.stats.elapsed} />
              <Stat
                value={copy.stats.hours(Math.max(0, WARMUP_TARGET_HOURS - elapsedHours))}
                label={copy.stats.left}
                tone={done ? "ok" : "neutral"}
              />
              <Stat value={copy.stats.hours(WARMUP_TARGET_HOURS)} label={copy.stats.target} />
            </Stats>
            <Progress label={copy.progressLabel} value={percent} />
            {done ? (
              <p className="subs-ready">
                <Badge tone="ok" icon="check">
                  {copy.ready}
                </Badge>
                <span className="zs-t-body">{copy.readyText}</span>
              </p>
            ) : (
              <Badge tone="info">{copy.running}</Badge>
            )}
            <div>
              <Button variant="quiet" size="sm" icon="refresh" onClick={reset}>
                {copy.reset}
              </Button>
            </div>
          </div>
        ) : (
          <div className="subs-timer">
            <p className="zs-t-heading">{copy.idleTitle}</p>
            <p className="zs-t-body subs-lead">{copy.idleText}</p>
            <Button variant="primary" icon="pulse" onClick={start}>
              {copy.start}
            </Button>
          </div>
        )}
      </Card>

      <Section title={list.label}>
        <Card>
          <Steps items={items} />
        </Card>
      </Section>

      {onNavigateToPaymentGuide && (
        <Card>
          <Rows>
            <Row icon="shield" title={list.guideLink} onClick={onNavigateToPaymentGuide} />
          </Rows>
        </Card>
      )}
    </>
  );
}

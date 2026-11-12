import { useEffect, useRef, useState } from "react";
import type { CrashTestStepResult } from "../../types";
import { resetCrashTestDrop, runVpnCrashTestStep, triggerCrashTestDrop } from "../../utils/api";
import { Badge, Banner, Button, Modal, Mono, Row, Rows, Section, Stat, Stats, Steps } from "../../ui";
import type { StepItem } from "../../ui";
import type { ShowToast } from "../../shared/hooks";
import { crashTest as copy } from "../../shared/copy/ru";
import "./crash-test.css";

export interface CrashTestModalProps {
  open: boolean;
  onClose: () => void;
  onToast: ShowToast;
}

const STEP_MS = 350;
const STREAM_LIMIT = 5;

const errText = (err: unknown) => (err instanceof Error ? err.message : String(err));

/** Тест обрыва VPN: живой поток тестовых запросов, обрыв туннеля и реакция шлюза по шагам. */
export function CrashTestModal({ open, onClose, onToast }: CrashTestModalProps) {
  const [packets, setPackets] = useState<CrashTestStepResult[]>([]);
  const [sentCount, setSentCount] = useState(0);
  const [lastLatency, setLastLatency] = useState(0.28);
  const [isDropped, setIsDropped] = useState(false);
  const [intercepted, setIntercepted] = useState(false);
  const [dropping, setDropping] = useState(false);
  const [restoring, setRestoring] = useState(false);
  const timerRef = useRef<number | undefined>(undefined);

  // Живой поток: шаг каждые 350 мс, пока окно открыто.
  useEffect(() => {
    if (!open) {
      setPackets([]);
      setSentCount(0);
      setIsDropped(false);
      setIntercepted(false);
      return;
    }
    let active = true;

    const executeStep = async () => {
      try {
        const step = await runVpnCrashTestStep();
        if (!active) return;
        setSentCount((prev) => prev + 1);
        setLastLatency(step.latency_ms);
        setPackets((prev) => [step, ...prev.slice(0, 8)]);
        if (step.intercepted_by_killswitch) {
          setIsDropped(true);
          setIntercepted(true);
        }
      } catch (err) {
        console.warn("Crash test step error:", err);
      }
    };

    executeStep();
    timerRef.current = window.setInterval(executeStep, STEP_MS);
    return () => {
      active = false;
      window.clearInterval(timerRef.current);
    };
  }, [open]);

  const handleSimulateDrop = async () => {
    if (dropping || isDropped) return;
    setDropping(true);
    try {
      await triggerCrashTestDrop();
      setIsDropped(true);
      onToast(copy.toast.dropTitle, copy.toast.dropText, "warning");
    } catch (err) {
      onToast(copy.toast.dropError, errText(err), "error");
    } finally {
      setDropping(false);
    }
  };

  const handleRestoreAndClose = async () => {
    setRestoring(true);
    try {
      await resetCrashTestDrop();
      setIsDropped(false);
      setIntercepted(false);
      onToast(copy.toast.restoreTitle, copy.toast.restoreText, "success");
      onClose();
    } catch (err) {
      onToast(copy.toast.restoreError, errText(err), "error");
    } finally {
      setRestoring(false);
    }
  };

  const handleManualClose = async () => {
    if (isDropped) {
      try {
        await resetCrashTestDrop();
      } catch {
        // Закрытие важнее: сбой сброса не должен держать окно.
      }
    }
    onClose();
  };

  const s = copy.steps;
  const flowing = sentCount > 0;
  const items: StepItem[] = [
    {
      title: s.watch.title,
      status: flowing ? "done" : "current",
      text: flowing ? s.watch.textDone : s.watch.textRunning,
    },
    {
      title: s.drop.title,
      status: isDropped ? "done" : flowing ? "current" : "todo",
      text: isDropped ? copy.toast.dropText : flowing ? s.drop.text : undefined,
      action:
        flowing && !isDropped ? (
          <Button variant="danger" icon="alert" disabled={dropping} onClick={handleSimulateDrop}>
            {dropping ? s.drop.acting : s.drop.action}
          </Button>
        ) : undefined,
    },
    {
      title: s.verdict.title,
      status: intercepted ? "done" : isDropped ? "current" : "todo",
      text: intercepted ? s.verdict.done : isDropped ? s.verdict.wait : undefined,
    },
    {
      title: s.restore.title,
      status: intercepted ? "current" : "todo",
      text: intercepted ? s.restore.text : undefined,
      action: intercepted ? (
        <Button variant="primary" icon="refresh" disabled={restoring} onClick={handleRestoreAndClose}>
          {restoring ? s.restore.acting : s.restore.action}
        </Button>
      ) : undefined,
    },
  ];

  return (
    <Modal open={open} onClose={handleManualClose} title={copy.title} footer={<Button onClick={handleManualClose}>{copy.close}</Button>}>
      <div className="zs-crash">
        <p className="zs-t-body zs-crash__lead">{copy.text}</p>

        <Stats>
          <Stat value={copy.metrics.sentValue(sentCount)} label={copy.metrics.sent} />
          <Stat value={copy.metrics.latencyValue(lastLatency)} label={copy.metrics.latency} />
          <Stat value={copy.metrics.stoppedValue(intercepted)} label={copy.metrics.stopped} />
        </Stats>

        {intercepted && (
          <Banner tone="ok" icon="shield" title={copy.result.title}>
            {copy.result.text}
          </Banner>
        )}

        <Steps items={items} />

        {!intercepted && (
          <Section title={copy.stream.title}>
            {packets.length === 0 ? (
              <p className="zs-crash__note">{copy.stream.empty}</p>
            ) : (
              <Rows className="zs-crash__stream">
                {packets.slice(0, STREAM_LIMIT).map((pkt, i) => (
                  <Row
                    key={`${pkt.timestamp}-${i}`}
                    title={<Mono className="zs-crash__host">{pkt.target_host}</Mono>}
                    sub={copy.stream.latency(pkt.latency_ms)}
                    trail={
                      pkt.intercepted_by_killswitch ? (
                        <Badge tone="danger" icon="alert">
                          {copy.stream.blocked}
                        </Badge>
                      ) : (
                        <Badge tone="ok" icon="check">
                          {copy.stream.allowed}
                        </Badge>
                      )
                    }
                  />
                ))}
              </Rows>
            )}
          </Section>
        )}

        <p className="zs-crash__note">{copy.footer}</p>
      </div>
    </Modal>
  );
}

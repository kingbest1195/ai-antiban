import { useEffect, useState } from "react";
import type { MouseEvent } from "react";
import { Toast, cx } from "../../ui";
import { CopyErrorLogButton } from "../../shared/components/CopyErrorLogButton";
import type { ToastItem } from "../../shared/hooks";

/**
 * Стопка уведомлений внизу экрана со счётчиком «ещё N».
 * Использует лёгкое затемнение color-mix вместо тяжёлого backdrop-filter: blur(6px)
 * и сохраняет CopyErrorLogButton на danger-тостах (Zero-Regression).
 */
export function NotificationStack({
  toasts,
  onDismiss,
}: {
  toasts: ToastItem[];
  onDismiss: (id: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    if (toasts.length <= 1) setExpanded(false);
  }, [toasts.length]);

  if (toasts.length === 0) return null;

  const newestFirst = [...toasts].reverse();
  const action = (t: ToastItem) =>
    t.tone === "danger" ? <CopyErrorLogButton title={t.title} message={t.description} /> : undefined;

  if (expanded) {
    return (
      <>
        <div className="zs-v3-notes-backdrop" onClick={() => setExpanded(false)} aria-hidden="true" />
        <div className="zs-v3-notes is-open" role="dialog" aria-label="Уведомления">
          <div className="zs-v3-notes__head">
            <span className="zs-v3-notes__title">Уведомления · {toasts.length}</span>
            <button type="button" className="zs-v3-notes__chip" onClick={() => setExpanded(false)}>
              Свернуть
            </button>
            <button type="button" className="zs-v3-notes__chip" onClick={() => toasts.forEach((t) => onDismiss(t.id))}>
              Очистить все
            </button>
          </div>
          <div className="zs-v3-notes__list">
            {newestFirst.map((t) => (
              <Toast key={t.id} tone={t.tone} title={t.title} action={action(t)} onClose={() => onDismiss(t.id)}>
                {t.description}
              </Toast>
            ))}
          </div>
        </div>
      </>
    );
  }

  const front = newestFirst[0];
  const more = toasts.length - 1;
  const onStackClick = (e: MouseEvent<HTMLDivElement>) => {
    if ((e.target as HTMLElement).closest("button")) return;
    if (more > 0) setExpanded(true);
  };

  return (
    <div className="zs-v3-notes" aria-live="polite" aria-label="Уведомления">
      <div
        className={cx("zs-v3-notes__stack", more > 0 && "has-more")}
        onClick={onStackClick}
        title={more > 0 ? "Показать все уведомления" : undefined}
      >
        {newestFirst.slice(1, 3).map((t, i) => (
          <div key={t.id} className="zs-v3-notes__ghost" style={{ ["--i" as string]: i + 1 }} aria-hidden="true" />
        ))}
        <Toast
          key={front.id}
          tone={front.tone}
          title={front.title}
          duration={front.tone === "danger" ? undefined : 4500}
          action={action(front)}
          onClose={() => onDismiss(front.id)}
        >
          {front.description}
        </Toast>
        {more > 0 && (
          <button type="button" className="zs-v3-notes__more" onClick={() => setExpanded(true)}>
            ещё {more}
          </button>
        )}
      </div>
    </div>
  );
}

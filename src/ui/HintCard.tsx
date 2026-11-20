import type { ReactNode } from "react";
import { Button } from "./Button";
import { Icon } from "./Icon";
import type { IconName } from "./Icon";
import { cx } from "./cx";

export interface HintCardAction {
  label: string;
  onClick: () => void;
}

export interface HintCardProps {
  hintId: string;
  title?: string;
  body: ReactNode;
  dismissedHints?: readonly string[];
  onDismiss: (hintId: string) => void;
  /** Опциональная кнопка-действие (объект { label, onClick } или готовый ReactNode). */
  action?: HintCardAction | ReactNode;
  icon?: IconName;
  tone?: "info" | "neutral";
  dismissLabel?: string;
  className?: string;
}

function isActionSpec(action: HintCardProps["action"]): action is HintCardAction {
  return (
    typeof action === "object" &&
    action !== null &&
    "label" in action &&
    "onClick" in action &&
    typeof (action as HintCardAction).label === "string" &&
    typeof (action as HintCardAction).onClick === "function"
  );
}

/** Проверяет, скрыта ли подсказка пользователем. */
export function isHintDismissed(hintId: string, dismissedHints?: readonly string[]): boolean {
  return Boolean(dismissedHints?.includes(hintId));
}

/**
 * Контекстная закрываемая подсказка при первом входе в раздел.
 * Возвращает null, если hintId присутствует в dismissedHints.
 */
export function HintCard({
  hintId,
  title,
  body,
  dismissedHints,
  onDismiss,
  action,
  icon = "info",
  tone = "info",
  dismissLabel = "Скрыть подсказку",
  className,
}: HintCardProps) {
  if (isHintDismissed(hintId, dismissedHints)) {
    return null;
  }

  return (
    <aside
      className={cx("zs-hint", tone === "neutral" && "zs-hint--neutral", className)}
      aria-label={title ?? "Подсказка"}
      data-hint-id={hintId}
    >
      <span className="zs-hint__icon" aria-hidden="true">
        <Icon name={icon} size={15} />
      </span>

      <div className="zs-hint__body">
        {title && <p className="zs-hint__title">{title}</p>}
        <p className="zs-hint__text">{body}</p>
        {action && (
          <div className="zs-hint__action">
            {isActionSpec(action) ? (
              <Button size="sm" variant="quiet" onClick={action.onClick}>
                {action.label}
              </Button>
            ) : (
              action
            )}
          </div>
        )}
      </div>

      <button
        type="button"
        className="zs-hint__close"
        aria-label={dismissLabel}
        onClick={() => onDismiss(hintId)}
      >
        <Icon name="x" size={14} />
      </button>
    </aside>
  );
}

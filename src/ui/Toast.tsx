import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Button } from "./Button";
import { Icon } from "./Icon";
import type { IconName } from "./Icon";
import { cx } from "./cx";
import type { Tone } from "./Badge";

export type ToastTone = Tone | "neutral";

const ICON: Record<ToastTone, IconName> = {
  neutral: "info",
  ok: "check",
  warn: "alert",
  danger: "alert",
  info: "info",
};

/** Слово для скринридера: статус не передаётся одним цветом. */
const WORD: Record<ToastTone, string> = {
  neutral: "Сообщение",
  ok: "Готово",
  warn: "Внимание",
  danger: "Ошибка",
  info: "Справка",
};

export interface ToastProps {
  tone?: ToastTone;
  title: ReactNode;
  children?: ReactNode;
  /** Одно действие справа, например кнопка sm. */
  action?: ReactNode;
  /** Показывает кнопку закрытия. */
  onClose?: () => void;
  /** Автозакрытие через N мс (нужен onClose). Пауза при наведении и фокусе. */
  duration?: number;
  className?: string;
}

/** Короткое уведомление. Тон = иконка + слово для скринридера; shadow-pop — всплывающий слой. */
export function Toast({ tone = "neutral", title, children, action, onClose, duration, className }: ToastProps) {
  const [paused, setPaused] = useState(false);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;

  useEffect(() => {
    if (!duration || paused) return;
    const id = window.setTimeout(() => closeRef.current?.(), duration);
    return () => window.clearTimeout(id);
  }, [duration, paused]);

  return (
    <div
      role={tone === "danger" ? "alert" : "status"}
      className={cx("zs-toast", tone !== "neutral" && `zs-toast--${tone}`, className)}
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
      onFocus={() => setPaused(true)}
      onBlur={() => setPaused(false)}
    >
      <span className={cx("zs-toast__icon", tone !== "neutral" && `zs-toast__icon--${tone}`)}>
        <Icon name={ICON[tone]} />
      </span>
      <div className="zs-toast__body">
        <p className="zs-toast__title">
          <span className="zs-sr">{WORD[tone]}: </span>
          {title}
        </p>
        {children && <p className="zs-toast__text">{children}</p>}
        {action && <div className="zs-toast__action">{action}</div>}
      </div>
      {onClose && <Button variant="quiet" size="sm" iconOnly icon="x" aria-label="Закрыть уведомление" onClick={onClose} />}
    </div>
  );
}

/** Контейнер стопки уведомлений у нижнего края окна. */
export function ToastViewport({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={cx("zs-toasts", className)} aria-live="polite" aria-label="Уведомления">
      {children}
    </div>
  );
}

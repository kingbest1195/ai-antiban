import { useEffect, useId, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Badge } from "./Badge";
import type { BadgeTone } from "./Badge";
import { Button } from "./Button";
import { Icon } from "./Icon";
import type { IconName } from "./Icon";
import { cx } from "./cx";

export interface DialogAction {
  label: string;
  /** Иконка слева (обычно только у главного действия). */
  icon?: IconName;
  onSelect: () => void;
  /** Отключает кнопку и горячую клавишу (например, пока решение отправляется). */
  disabled?: boolean;
}

export interface DialogProps {
  /** Заголовок-факт: «Запрос к ИИ приостановлен». */
  title: string;
  /** Одно предложение причины. */
  text: ReactNode;
  /** Маршрут: сервис → IP → страна. */
  service: string;
  ip: string;
  /** Строка или заглушка (Skeleton), пока страна определяется. */
  country: ReactNode;
  /** Тон бейджа страны; по умолчанию danger (небезопасный адрес). */
  countryTone?: BadgeTone;
  /** Бейдж «Демо» в маршруте. */
  demo?: boolean;
  /** Секунды до автодействия. Без значения таймера нет. */
  seconds?: number;
  /** Вызывается один раз, когда таймер дошёл до нуля. */
  onTimeout?: () => void;
  /** Три действия в порядке клавиш 1 → 2 → 3: главное, второе, третье. */
  actions: [DialogAction, DialogAction, DialogAction];
  /** Горячие клавиши 1, 2, 3 (на уровне окна). По умолчанию включены. */
  hotkeys?: boolean;
  /** Сразу сфокусировать главное действие. */
  autoFocus?: boolean;
  /** Кнопка закрытия ✕ в шапке. Без обработчика кнопки нет. */
  onClose?: () => void;
  /** aria-label кнопки закрытия. */
  closeLabel?: string;
  className?: string;
}

/** Окно-прерывание: Застава остановила запрос и ждёт решения. Единственное место с shadow-pop по ДС. */
export function Dialog({
  title,
  text,
  service,
  ip,
  country,
  countryTone = "danger",
  demo,
  seconds,
  onTimeout,
  actions,
  hotkeys = true,
  autoFocus,
  onClose,
  closeLabel = "Закрыть",
  className,
}: DialogProps) {
  const uid = useId();
  const titleId = `${uid}-title`;
  const textId = `${uid}-text`;
  const [left, setLeft] = useState(seconds);

  // Таймер: тикает раз в секунду, на нуле один раз зовёт onTimeout.
  useEffect(() => {
    setLeft(seconds);
    if (seconds === undefined || seconds <= 0) return;
    const id = window.setInterval(() => {
      setLeft((v) => (v === undefined || v <= 0 ? v : v - 1));
    }, 1000);
    return () => window.clearInterval(id);
  }, [seconds]);

  const timeoutRef = useRef(onTimeout);
  timeoutRef.current = onTimeout;
  const firedRef = useRef(false);
  useEffect(() => {
    firedRef.current = false;
  }, [seconds]);
  useEffect(() => {
    if (left === 0 && seconds !== undefined && !firedRef.current) {
      firedRef.current = true;
      timeoutRef.current?.();
    }
  }, [left, seconds]);

  // Клавиши 1 → 2 → 3 совпадают с порядком кнопок на экране.
  const actionsRef = useRef(actions);
  actionsRef.current = actions;
  useEffect(() => {
    if (!hotkeys) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented || e.ctrlKey || e.metaKey || e.altKey || e.repeat) return;
      const t = e.target as HTMLElement | null;
      if (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) return;
      const index = ["1", "2", "3"].indexOf(e.key);
      if (index < 0) return;
      e.preventDefault();
      if (actionsRef.current[index].disabled) return;
      actionsRef.current[index].onSelect();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [hotkeys]);

  const [first, second, third] = actions;
  return (
    <div
      role="alertdialog"
      aria-modal="true"
      aria-labelledby={titleId}
      aria-describedby={textId}
      className={cx("zs-dialog", className)}
    >
      <div className="zs-dialog__head">
        <h2 className="zs-dialog__title" id={titleId}>
          {title}
        </h2>
        {left !== undefined && (
          <Badge tone="warn" role="timer" aria-label={`Осталось ${left} с`}>
            {left} с
          </Badge>
        )}
        {onClose && <Button variant="quiet" size="sm" iconOnly icon="x" aria-label={closeLabel} onClick={onClose} />}
      </div>
      <p className="zs-dialog__text" id={textId}>
        {text}
      </p>
      <div className="zs-route">
        <b>{service}</b>
        <Icon name="arrow" />
        <span className="zs-mono">{ip}</span>
        {demo && <Badge tone="info">Демо</Badge>}
        <Badge tone={countryTone} icon={countryTone === "danger" || countryTone === "warn" ? "alert" : undefined}>
          {country}
        </Badge>
      </div>
      <div className="zs-dialog__actions">
        <Button
          variant="primary"
          size="lg"
          icon={first.icon}
          kbd="1"
          autoFocus={autoFocus}
          disabled={first.disabled}
          onClick={first.onSelect}
        >
          {first.label}
        </Button>
        <Button icon={second.icon} kbd="2" disabled={second.disabled} onClick={second.onSelect}>
          {second.label}
        </Button>
        <Button variant="quiet" icon={third.icon} kbd="3" disabled={third.disabled} onClick={third.onSelect}>
          {third.label}
        </Button>
      </div>
    </div>
  );
}

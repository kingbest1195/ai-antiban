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
  /** Вариант вторичной кнопки (например, danger для рискованного разрешения). */
  variant?: "secondary" | "danger";
  onSelect: () => void;
  /** Отключает кнопку и горячую клавишу (например, пока решение отправляется). */
  disabled?: boolean;
}

export interface DialogPreviousRoute {
  ip: string;
  country?: ReactNode;
  label?: string;
}

export interface DialogProps {
  /** Заголовок-факт: «Запрос к ИИ приостановлен». */
  title: string;
  /** Одно предложение причины. */
  text: ReactNode;
  /** Маршрут: сервис → IP → страна (или заголовок карточки «Было → Стало»). */
  service: string;
  ip: string;
  /** Строка или заглушка (Skeleton), пока страна определяется. */
  country: ReactNode;
  /** Тон бейджа страны; по умолчанию danger (небезопасный адрес). */
  countryTone?: BadgeTone;
  /** Предыдущий адрес и страна для блока «Было → Стало». Без него рисуется одиночный маршрут. */
  previous?: DialogPreviousRoute | null;
  /** Подпись правой колонки «Было → Стало» (по умолчанию «Стало»). */
  currentLabel?: string;
  /** Подпись, если предыдущая страна не определена. */
  unknownCountryLabel?: string;
  /** Бейдж «Демо» в маршруте. */
  demo?: boolean;
  /** Секунды до автодействия. Без значения таймера нет. */
  seconds?: number;
  /** Вызывается один раз, когда таймер дошёл до нуля. */
  onTimeout?: () => void;
  /** Два действия в порядке клавиш 1 → 2: главное и второе. */
  actions: [DialogAction, DialogAction];
  /** Встроенное подтверждение вместо кнопок действий (например, при риске RU/BY/red). */
  inlineConfirm?: ReactNode;
  /** Горячие клавиши 1, 2 (на уровне окна). По умолчанию включены. */
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
  previous,
  currentLabel = "Стало",
  unknownCountryLabel = "Не определена",
  demo,
  seconds,
  onTimeout,
  actions,
  inlineConfirm,
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

  // Клавиши 1 → 2 совпадают с порядком кнопок на экране.
  const actionsRef = useRef(actions);
  actionsRef.current = actions;
  useEffect(() => {
    if (!hotkeys) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented || e.ctrlKey || e.metaKey || e.altKey || e.repeat) return;
      const t = e.target as HTMLElement | null;
      if (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) return;
      const index = ["1", "2"].indexOf(e.key);
      if (index < 0) return;
      e.preventDefault();
      if (actionsRef.current[index].disabled) return;
      actionsRef.current[index].onSelect();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [hotkeys]);

  const [first, second] = actions;
  const badgeIcon = countryTone === "danger" || countryTone === "warn" ? "alert" : undefined;
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
      {previous?.ip ? (
        <div className="zs-route-diff">
          <div className="zs-route-diff__head">
            <b>{service}</b>
            {demo && <Badge tone="info">Демо</Badge>}
          </div>
          <div className="zs-route-diff__cols">
            <div className="zs-route-diff__col">
              <span className="zs-route-diff__label">{previous.label ?? "Было"}</span>
              <span className="zs-route-diff__country">{previous.country || unknownCountryLabel}</span>
              <span className="zs-mono">{previous.ip}</span>
            </div>
            <Icon name="arrow" className="zs-route-diff__arrow" />
            <div className="zs-route-diff__col">
              <span className="zs-route-diff__label">{currentLabel}</span>
              <Badge tone={countryTone} icon={badgeIcon}>
                {country}
              </Badge>
              <span className="zs-mono">{ip}</span>
            </div>
          </div>
        </div>
      ) : (
        <div className="zs-route">
          <b>{service}</b>
          <Icon name="arrow" />
          <span className="zs-mono">{ip}</span>
          {demo && <Badge tone="info">Демо</Badge>}
          <Badge tone={countryTone} icon={badgeIcon}>
            {country}
          </Badge>
        </div>
      )}
      {inlineConfirm ? (
        <div className="zs-dialog__confirm" role="group" aria-label="Подтверждение">
          {inlineConfirm}
        </div>
      ) : (
        <div className="zs-dialog__actions">
          <Button
            variant="primary"
            size="lg"
            block
            icon={first.icon}
            kbd="1"
            autoFocus={autoFocus}
            disabled={first.disabled}
            onClick={first.onSelect}
          >
            {first.label}
          </Button>
          <Button
            variant={second.variant ?? "secondary"}
            block
            icon={second.icon}
            kbd="2"
            disabled={second.disabled}
            onClick={second.onSelect}
          >
            {second.label}
          </Button>
        </div>
      )}
    </div>
  );
}

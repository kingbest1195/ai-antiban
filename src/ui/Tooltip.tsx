import { useId, useLayoutEffect, useRef, useState } from "react";
import type { KeyboardEvent, ReactNode } from "react";
import { createPortal } from "react-dom";
import { cx } from "./cx";

export interface TooltipBounds {
  anchorLeft: number;
  anchorTop: number;
  anchorWidth: number;
  anchorBottom: number;
  popWidth: number;
  popHeight: number;
  viewportWidth: number;
  viewportHeight: number;
  margin?: number;
  gap?: number;
}

/**
 * Вычисляет координаты всплывающей подсказки так, чтобы она не выходила за границы окна
 * по горизонтали и вертикали (viewport clamping).
 */
export function clampTooltipPosition({
  anchorLeft,
  anchorTop,
  anchorWidth,
  anchorBottom,
  popWidth,
  popHeight,
  viewportWidth,
  viewportHeight,
  margin = 8,
  gap = 8,
}: TooltipBounds): { left: number; top: number } {
  const maxLeft = Math.max(margin, viewportWidth - popWidth - margin);
  const left = Math.max(margin, Math.min(anchorLeft + anchorWidth / 2 - popWidth / 2, maxLeft));

  let top = anchorBottom + gap;
  if (top + popHeight > viewportHeight - margin) {
    const above = anchorTop - gap - popHeight;
    top = above >= margin ? above : Math.max(margin, viewportHeight - margin - popHeight);
  }
  return { left, top };
}

export interface TipProps {
  children: ReactNode;
  title?: string;
  text: ReactNode;
  className?: string;
}

/** Всплывающее пояснение при наведении, фокусе или нажатии; всегда остаётся в границах окна. */
export function Tip({ children, title, text, className }: TipProps) {
  const id = useId();
  const anchorRef = useRef<HTMLSpanElement>(null);
  const popRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ left: number; top: number } | null>(null);

  useLayoutEffect(() => {
    if (!open || !anchorRef.current || !popRef.current) return;
    const a = anchorRef.current.getBoundingClientRect();
    const vw = document.documentElement.clientWidth;
    const vh = window.innerHeight;
    const pw = popRef.current.offsetWidth;
    const ph = popRef.current.offsetHeight;
    setPos(
      clampTooltipPosition({
        anchorLeft: a.left,
        anchorTop: a.top,
        anchorWidth: a.width,
        anchorBottom: a.bottom,
        popWidth: pw,
        popHeight: ph,
        viewportWidth: vw,
        viewportHeight: vh,
      }),
    );
  }, [open, title, text]);

  const show = () => setOpen(true);
  const hide = () => {
    setOpen(false);
    setPos(null);
  };
  const onKeyDown = (e: KeyboardEvent<HTMLSpanElement>) => {
    if (e.key === "Escape" && open) {
      e.stopPropagation();
      hide();
    }
  };

  const maxWidth =
    typeof document !== "undefined" ? Math.min(260, Math.max(160, document.documentElement.clientWidth - 16)) : 260;

  return (
    <span
      ref={anchorRef}
      className={cx("zs-tip", className)}
      aria-describedby={open ? id : undefined}
      onMouseEnter={show}
      onMouseLeave={hide}
      onFocus={show}
      onBlur={hide}
      onKeyDown={onKeyDown}
    >
      {children}
      {open &&
        typeof document !== "undefined" &&
        createPortal(
          <div
            ref={popRef}
            role="tooltip"
            id={id}
            className="zs-tip__pop"
            style={{
              left: pos?.left ?? -9999,
              top: pos?.top ?? -9999,
              width: maxWidth,
            }}
          >
            {title && <span className="zs-tip__title">{title}</span>}
            <span className="zs-tip__text">{text}</span>
          </div>,
          document.body,
        )}
    </span>
  );
}

export interface InfoTipProps {
  title?: string;
  text: ReactNode;
  label?: string;
  className?: string;
}

/** Значок «!» с пояснением при наведении/фокусе и прижатием к границам окна. */
export function InfoTip({ title, text, label = "Пояснение", className }: InfoTipProps) {
  return (
    <Tip title={title} text={text} className={className}>
      <span className="zs-info-i" tabIndex={0} role="button" aria-label={label}>
        !
      </span>
    </Tip>
  );
}

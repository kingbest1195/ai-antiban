import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import type { KeyboardEvent, MouseEvent, ReactNode } from "react";
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

export interface TooltipInteractionState {
  hovered: boolean;
  focused: boolean;
  pinned: boolean;
  suppressed: boolean;
}

export type TooltipAction =
  | "hoverStart"
  | "hoverEnd"
  | "focus"
  | "blur"
  | "clickToggle"
  | "escape"
  | "outsideClick";

export const INITIAL_TOOLTIP_STATE: TooltipInteractionState = {
  hovered: false,
  focused: false,
  pinned: false,
  suppressed: false,
};

/** Чистый конечный автомат состояния подсказки (hover + focus + click toggle + Escape + outside click). */
export function reduceTooltipState(
  state: TooltipInteractionState,
  action: TooltipAction,
): TooltipInteractionState {
  switch (action) {
    case "hoverStart":
      return { ...state, hovered: true, suppressed: false };
    case "hoverEnd":
      return { ...state, hovered: false, suppressed: false };
    case "focus":
      return { ...state, focused: true, suppressed: false };
    case "blur":
      return { ...state, focused: false, suppressed: false };
    case "clickToggle":
      return state.pinned
        ? { ...state, pinned: false, suppressed: true }
        : { ...state, pinned: true, suppressed: false };
    case "escape":
      return { ...state, pinned: false, suppressed: true };
    case "outsideClick":
      return INITIAL_TOOLTIP_STATE;
  }
}

export function isTooltipVisible(state: TooltipInteractionState): boolean {
  return state.pinned || (!state.suppressed && (state.hovered || state.focused));
}

export interface TipProps {
  children: ReactNode;
  title?: string;
  text: ReactNode;
  id?: string;
  role?: "tooltip" | "dialog";
  /** Включает фиксацию/переключение подсказки по клику/тапу (для InfoTip включено по умолчанию). */
  toggleOnClick?: boolean;
  onOpenChange?: (open: boolean) => void;
  className?: string;
}

/** Всплывающее пояснение при наведении, фокусе или клике; всегда остаётся в границах окна. */
export function Tip({
  children,
  title,
  text,
  id: providedId,
  role = "tooltip",
  toggleOnClick = false,
  onOpenChange,
  className,
}: TipProps) {
  const generatedId = useId();
  const resolvedId = providedId ?? generatedId;
  const anchorRef = useRef<HTMLSpanElement>(null);
  const popRef = useRef<HTMLDivElement>(null);
  const [state, setState] = useState<TooltipInteractionState>(INITIAL_TOOLTIP_STATE);
  const [pos, setPos] = useState<{ left: number; top: number } | null>(null);

  const open = isTooltipVisible(state);

  useEffect(() => {
    onOpenChange?.(open);
  }, [open, onOpenChange]);

  useLayoutEffect(() => {
    if (!open) {
      setPos(null);
      return;
    }
    if (!anchorRef.current || !popRef.current) return;
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

  useEffect(() => {
    if (!open || typeof document === "undefined") return;

    const onDocPointerDown = (e: PointerEvent) => {
      const target = e.target as Node | null;
      if (!target) return;
      if (anchorRef.current?.contains(target) || popRef.current?.contains(target)) return;
      setState((prev) => reduceTooltipState(prev, "outsideClick"));
    };

    const onDocKeyDown = (e: globalThis.KeyboardEvent) => {
      if (e.key === "Escape") {
        setState((prev) => reduceTooltipState(prev, "escape"));
      }
    };

    document.addEventListener("pointerdown", onDocPointerDown);
    document.addEventListener("keydown", onDocKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onDocPointerDown);
      document.removeEventListener("keydown", onDocKeyDown);
    };
  }, [open]);

  const onKeyDown = (e: KeyboardEvent<HTMLSpanElement>) => {
    if (e.key === "Escape" && open) {
      e.stopPropagation();
      setState((prev) => reduceTooltipState(prev, "escape"));
    }
  };

  const onClick = (e: MouseEvent<HTMLSpanElement>) => {
    if (!toggleOnClick) return;
    e.stopPropagation();
    setState((prev) => reduceTooltipState(prev, "clickToggle"));
  };

  const maxWidth =
    typeof document !== "undefined" ? Math.min(260, Math.max(160, document.documentElement.clientWidth - 16)) : 260;

  return (
    <span
      ref={anchorRef}
      className={cx("zs-tip", className)}
      aria-describedby={open && role === "tooltip" ? resolvedId : undefined}
      onMouseEnter={() => setState((prev) => reduceTooltipState(prev, "hoverStart"))}
      onMouseLeave={() => setState((prev) => reduceTooltipState(prev, "hoverEnd"))}
      onFocus={() => setState((prev) => reduceTooltipState(prev, "focus"))}
      onBlur={() => setState((prev) => reduceTooltipState(prev, "blur"))}
      onClick={onClick}
      onKeyDown={onKeyDown}
    >
      {children}
      {open &&
        typeof document !== "undefined" &&
        createPortal(
          <div
            ref={popRef}
            role={role}
            aria-label={role === "dialog" ? title ?? "Пояснение" : undefined}
            id={resolvedId}
            className={cx("zs-tip__pop", state.pinned && "zs-tip__pop--pinned")}
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
  role?: "tooltip" | "dialog";
  toggleOnClick?: boolean;
  className?: string;
}

/** Значок «i» с пояснением при наведении, фокусе и клике/тапе; прижимается к границам окна. */
export function InfoTip({
  title,
  text,
  label = "Пояснение",
  role = "tooltip",
  toggleOnClick = true,
  className,
}: InfoTipProps) {
  const tipId = useId();
  const [expanded, setExpanded] = useState(false);

  return (
    <Tip
      id={tipId}
      title={title}
      text={text}
      role={role}
      toggleOnClick={toggleOnClick}
      onOpenChange={setExpanded}
      className={className}
    >
      <button
        type="button"
        className="zs-info-i"
        aria-label={label}
        aria-expanded={expanded}
        aria-controls={expanded ? tipId : undefined}
      >
        i
      </button>
    </Tip>
  );
}

import { useId, useLayoutEffect, useRef, useState } from "react";
import type { KeyboardEvent } from "react";
import { Button } from "./Button";
import { Icon } from "./Icon";
import type { IconName } from "./Icon";
import { cx } from "./cx";
import { useClickOutside } from "./dom";

export interface MenuItem {
  type?: "item";
  id: string;
  label: string;
  icon?: IconName;
  /** danger — для опасного пункта (текст и иконка danger-text). */
  tone?: "danger";
  disabled?: boolean;
  onSelect: () => void;
}

export interface MenuSeparator {
  type: "separator";
  id: string;
}

export type MenuEntry = MenuItem | MenuSeparator;

export interface MenuProps {
  items: MenuEntry[];
  /** aria-label кнопки-триггера. */
  label?: string;
  /** С какого края выравнивать список. */
  align?: "end" | "start";
  className?: string;
}

/** Отступ списка от края окна, px. */
const EDGE = 16;

/** Выпадающее меню «Ещё»: Esc и клик вне закрывают, стрелки двигают по пунктам. */
export function Menu({ items, label = "Ещё", align = "end", className }: MenuProps) {
  const [open, setOpen] = useState(false);
  /** Список перевёрнут относительно align: не помещался у своего края окна. */
  const [flip, setFlip] = useState(false);
  /** Сдвиг списка по горизонтали, px: прижимает к полю окна, если не помещается ни с одной стороны. */
  const [shift, setShift] = useState(0);
  const rootRef = useRef<HTMLDivElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const listId = useId();

  useClickOutside(rootRef, open, () => setOpen(false));

  // До отрисовки кадра: если список у стороны align выходит за край окна, берём противоположную сторону;
  // если не помещается ни с одной, прижимаем к полю окна.
  useLayoutEffect(() => {
    if (!open) {
      setFlip(false);
      setShift(0);
      return;
    }
    const list = listRef.current;
    const trigger = triggerRef.current;
    if (!list || !trigger) return;
    const t = trigger.getBoundingClientRect();
    const width = list.getBoundingClientRect().width;
    const viewport = document.documentElement.clientWidth;
    const fits = (left: number) => left >= EDGE && left + width <= viewport - EDGE;
    const startLeft = t.left;
    const endLeft = t.right - width;
    const [preferred, other] = align === "start" ? [startLeft, endLeft] : [endLeft, startLeft];
    const useFlip = !fits(preferred) && fits(other);
    const left = useFlip ? other : preferred;
    const clamped = Math.min(Math.max(left, EDGE), Math.max(EDGE, viewport - EDGE - width));
    setFlip(useFlip);
    setShift(clamped - left);
  }, [open, align]);

  const enabledItems = () =>
    Array.from(listRef.current?.querySelectorAll<HTMLButtonElement>('[role="menuitem"]:not(:disabled)') ?? []);

  const openMenu = (focus: "first" | "last") => {
    setOpen(true);
    // Список появляется в следующем кадре — фокус ставим после отрисовки.
    requestAnimationFrame(() => {
      const list = enabledItems();
      (focus === "first" ? list[0] : list[list.length - 1])?.focus();
    });
  };

  const close = (returnFocus: boolean) => {
    setOpen(false);
    if (returnFocus) triggerRef.current?.focus();
  };

  const onTriggerKey = (e: KeyboardEvent<HTMLButtonElement>) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      openMenu("first");
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      openMenu("last");
    }
  };

  const onListKey = (e: KeyboardEvent<HTMLUListElement>) => {
    const list = enabledItems();
    const index = list.indexOf(document.activeElement as HTMLButtonElement);
    if (e.key === "ArrowDown") {
      e.preventDefault();
      list[(index + 1) % list.length]?.focus();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      list[(index - 1 + list.length) % list.length]?.focus();
    } else if (e.key === "Home") {
      e.preventDefault();
      list[0]?.focus();
    } else if (e.key === "End") {
      e.preventDefault();
      list[list.length - 1]?.focus();
    } else if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      close(true);
    } else if (e.key === "Tab") {
      e.preventDefault();
      close(true);
    }
  };

  return (
    <div ref={rootRef} className={cx("zs-menu", align === "start" && "zs-menu--start", flip && "zs-menu--flip", className)}>
      <Button
        ref={triggerRef}
        variant="quiet"
        iconOnly
        icon="more"
        aria-label={label}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? listId : undefined}
        onClick={() => (open ? close(false) : openMenu("first"))}
        onKeyDown={onTriggerKey}
      />
      {open && (
        <ul
          ref={listRef}
          id={listId}
          role="menu"
          aria-label={label}
          className="zs-menu__list"
          style={shift ? { transform: `translateX(${shift}px)` } : undefined}
          onKeyDown={onListKey}
        >
          {items.map((entry) =>
            entry.type === "separator" ? (
              <li key={entry.id} role="separator" className="zs-menu__sep" />
            ) : (
              <li key={entry.id} role="none">
                <button
                  type="button"
                  role="menuitem"
                  tabIndex={-1}
                  disabled={entry.disabled}
                  className={cx("zs-menu__item", entry.tone === "danger" && "zs-menu__item--danger")}
                  onClick={() => {
                    close(true);
                    entry.onSelect();
                  }}
                >
                  {entry.icon && <Icon name={entry.icon} />}
                  {entry.label}
                </button>
              </li>
            ),
          )}
        </ul>
      )}
    </div>
  );
}

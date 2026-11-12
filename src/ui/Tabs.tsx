import { useRef } from "react";
import type { KeyboardEvent, ReactNode } from "react";
import { cx } from "./cx";

export interface TabItem<T extends string = string> {
  id: T;
  label: string;
  disabled?: boolean;
  /** Статус без захода во вкладку: точка (danger, warn) или число проблем. */
  badge?: "danger" | "warn" | number;
}

export interface TabsProps<T extends string = string> {
  items: TabItem<T>[];
  value: T;
  onChange: (id: T) => void;
  /** Префикс id для связи вкладок с панелями (aria-controls). */
  idPrefix?: string;
  "aria-label"?: string;
  /** Дополнение к подписи вкладки с бейджем для скринридера, например «, есть проблема». */
  badgeLabel?: string;
  className?: string;
}

const tabId = (prefix: string, id: string) => `${prefix}-tab-${id}`;
const panelId = (prefix: string, id: string) => `${prefix}-panel-${id}`;

/** Переключатель разделов. Стрелки, Home и End переключают вкладку; Tab уходит из списка. */
export function Tabs<T extends string = string>({
  items,
  value,
  onChange,
  idPrefix = "zs",
  className,
  badgeLabel,
  ...rest
}: TabsProps<T>) {
  const listRef = useRef<HTMLDivElement>(null);

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const enabled = items.filter((i) => !i.disabled);
    const index = enabled.findIndex((i) => i.id === value);
    let next = -1;
    if (e.key === "ArrowRight") next = (index + 1) % enabled.length;
    else if (e.key === "ArrowLeft") next = (index - 1 + enabled.length) % enabled.length;
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = enabled.length - 1;
    if (next < 0) return;
    e.preventDefault();
    const target = enabled[next];
    onChange(target.id);
    listRef.current?.querySelector<HTMLElement>(`[id="${tabId(idPrefix, target.id)}"]`)?.focus();
  };

  return (
    <div
      ref={listRef}
      role="tablist"
      aria-label={rest["aria-label"]}
      className={cx("zs-tabs", className)}
      onKeyDown={onKeyDown}
    >
      {items.map((item) => {
        const selected = item.id === value;
        return (
          <button
            key={item.id}
            type="button"
            role="tab"
            id={tabId(idPrefix, item.id)}
            aria-selected={selected}
            aria-controls={panelId(idPrefix, item.id)}
            tabIndex={selected ? 0 : -1}
            disabled={item.disabled}
            className="zs-tab"
            aria-label={item.badge !== undefined && badgeLabel ? `${item.label}${badgeLabel}` : undefined}
            onClick={() => onChange(item.id)}
          >
            {item.label}
            {item.badge !== undefined && (
              <span
                aria-hidden="true"
                className={cx(
                  "zs-tab__badge",
                  typeof item.badge === "number" ? "zs-tab__badge--count" : `zs-tab__badge--${item.badge}`,
                )}
              >
                {typeof item.badge === "number" ? item.badge : null}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}

export interface TabPanelProps {
  /** Тот же idPrefix, что у Tabs. */
  idPrefix?: string;
  id: string;
  /** Показывается только для выбранной вкладки. */
  selected: boolean;
  children: ReactNode;
  className?: string;
}

/** Панель содержимого вкладки: связана с кнопкой через aria-labelledby. */
export function TabPanel({ idPrefix = "zs", id, selected, children, className }: TabPanelProps) {
  if (!selected) return null;
  return (
    <div role="tabpanel" id={panelId(idPrefix, id)} aria-labelledby={tabId(idPrefix, id)} className={className}>
      {children}
    </div>
  );
}

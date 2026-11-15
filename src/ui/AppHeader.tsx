import type { ReactNode } from "react";
import { Badge } from "./Badge";
import { Icon } from "./Icon";
import { Menu } from "./Menu";
import type { MenuEntry } from "./Menu";
import { cx } from "./cx";

export interface AppHeaderProps {
  /** Название в шапке. */
  name?: string;
  /** Пинг, например «41 мс». Показывается нейтральным бейджем. */
  ping?: string;
  /** Пункты меню «Ещё». Без них кнопка не выводится. */
  menuItems?: MenuEntry[];
  menuLabel?: string;
  /** Индикатор на кнопке меню (например, доступно обновление). */
  menuDot?: boolean;
  /** Дополнительные элементы справа перед пингом. */
  children?: ReactNode;
  className?: string;
}

/** Шапка окна в одну строку: щит на brand-soft, название, пинг, меню «Ещё». */
export function AppHeader({ name = "Застава", ping, menuItems, menuLabel = "Ещё", menuDot = false, children, className }: AppHeaderProps) {
  return (
    <header className={cx("zs-app__bar", className)}>
      <span className="zs-app__logo">
        <Icon name="shield" />
      </span>
      <span className="zs-app__name">{name}</span>
      <span className="zs-app__spacer" />
      {children}
      {ping && <Badge aria-label={`Пинг ${ping}`}>{ping}</Badge>}
      {menuItems && <Menu items={menuItems} label={menuLabel} triggerDot={menuDot} />}
    </header>
  );
}

import type { ReactNode } from "react";
import { WatchdogMascot } from "../features/mascot/WatchdogMascot";
import type { MascotSize, MascotState } from "../features/mascot/WatchdogMascot";
import { Icon } from "./Icon";
import type { IconName } from "./Icon";
import { cx } from "./cx";

export interface EmptyStateProps {
  /** Иконка ДС (опциональна при использовании mascotState или illustration). */
  icon?: IconName;
  /** Состояние маскота Заставы вместо иконки. */
  mascotState?: MascotState;
  /** Размер маскота в px (по умолчанию 64). */
  mascotSize?: MascotSize;
  /** Пользовательская иллюстрация вместо иконки/маскота. */
  illustration?: ReactNode;
  title: string;
  /** Пояснение: почему пусто и что делать. */
  description?: ReactNode;
  /** Пояснение или дополнительное содержимое (сохранено для обратной совместимости). */
  children?: ReactNode;
  /** Основное действие (предпочтительно перед action). */
  primaryAction?: ReactNode;
  /** Вторичное действие рядом с основным. */
  secondaryAction?: ReactNode;
  /** Устаревший алиас одного действия — обычно Button. */
  action?: ReactNode;
  className?: string;
}

/** Пустое состояние: маскот или иконка, заголовок, пояснение и 1–2 понятных действия. */
export function EmptyState({
  icon,
  mascotState,
  mascotSize = 64,
  illustration,
  title,
  description,
  children,
  primaryAction,
  secondaryAction,
  action,
  className,
}: EmptyStateProps) {
  const mainAction = primaryAction ?? action;
  const hasActions = Boolean(mainAction || secondaryAction);

  return (
    <div className={cx("zs-empty", className)}>
      {mascotState ? (
        <div className="zs-empty__mascot">
          <WatchdogMascot state={mascotState} size={mascotSize} decorative />
        </div>
      ) : illustration ? (
        <div className="zs-empty__mascot">{illustration}</div>
      ) : icon ? (
        <span className="zs-empty__icon">
          <Icon name={icon} size={20} />
        </span>
      ) : null}

      <h3 className="zs-empty__title">{title}</h3>
      {description && <p className="zs-empty__text">{description}</p>}
      {children &&
        (description ? (
          <div className="zs-empty__extra">{children}</div>
        ) : (
          <p className="zs-empty__text">{children}</p>
        ))}
      {hasActions && (
        <div className="zs-empty__action">
          {mainAction}
          {secondaryAction}
        </div>
      )}
    </div>
  );
}

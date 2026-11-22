import { useId } from "react";
import type { ReactNode } from "react";
import { Icon } from "./Icon";
import type { IconName } from "./Icon";
import { cx } from "./cx";
import type { RowTone } from "./Row";

export interface ExpandRowProps {
  icon?: IconName;
  tone?: RowTone;
  title: ReactNode;
  sub?: ReactNode;
  /** Бейдж или значение справа; шеврон раскрытия добавляется сам. */
  trail?: ReactNode;
  open: boolean;
  onToggle: () => void;
  /** Подпись области с подробностями для скринридера. */
  detailLabel?: string;
  /** Подробности: показываются только у раскрытой строки. */
  children?: ReactNode;
  className?: string;
}

/** Раскрывающаяся строка списка (вариант Row): заголовок — кнопка с aria-expanded, подробности под ним. Кладите внутрь Rows. */
export function ExpandRow({ icon, tone = "neutral", title, sub, trail, open, onToggle, detailLabel, children, className }: ExpandRowProps) {
  const detailId = useId();
  return (
    <li className={cx("zs-xrow", className)}>
      <div className="zs-xrow__head zs-row--action" data-open={open || undefined}>
        {icon && (
          <span className={cx("zs-row__icon", tone !== "neutral" && `zs-row__icon--${tone}`)}>
            <Icon name={icon} />
          </span>
        )}
        <span className="zs-row__body">
          <button
            type="button"
            className="zs-row__hit zs-xrow__hit"
            aria-expanded={open}
            aria-controls={detailId}
            onClick={onToggle}
          >
            <span className="zs-row__title">{title}</span>
            {sub && <span className="zs-row__sub">{sub}</span>}
          </button>
        </span>
        <span className="zs-row__trail">
          {trail}
          <Icon name="chev" className="zs-xrow__chev" />
        </span>
      </div>
      {open && (
        <div id={detailId} className="zs-xrow__detail" role="region" aria-label={detailLabel}>
          {children}
        </div>
      )}
    </li>
  );
}

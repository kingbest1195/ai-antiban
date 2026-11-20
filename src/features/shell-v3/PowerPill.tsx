import { Icon, Spinner, cx } from "../../ui";
import "../mascot/mascot.css";

export interface PowerPillProps {
  on: boolean;
  startupPending?: boolean;
  toggling?: boolean;
  onToggle: () => void;
}

/**
 * Главный выключатель защиты: заблокирован во время startupPending || togglingSysproxy,
 * никогда не показывает оптимистичное неподтверждённое состояние и использует transition-классы из mascot.css.
 */
export function PowerPill({ on, startupPending = false, toggling = false, onToggle }: PowerPillProps) {
  const locked = Boolean(startupPending || toggling);
  const title = startupPending
    ? "Запуск защиты…"
    : toggling
      ? on
        ? "Выключаем защиту…"
        : "Включаем защиту…"
      : on
        ? "Защита включена"
        : "Защита выключена";
  const sub = locked
    ? "Подождите несколько секунд"
    : on
      ? "Нажмите, чтобы выключить"
      : "Нажмите, чтобы включить";

  return (
    <button
      type="button"
      className={cx(
        "zs-v3-pill",
        "zs-power-transition",
        on && "is-on",
        toggling && (on ? "zs-power-transition--sleeping" : "zs-power-transition--waking"),
      )}
      aria-pressed={on}
      aria-busy={locked || undefined}
      disabled={locked}
      onClick={onToggle}
    >
      <span className="zs-v3-pill__icon">{locked ? <Spinner size={18} /> : <Icon name="power" size={18} />}</span>
      <span className="zs-v3-pill__text">
        <span className="zs-v3-pill__title">{title}</span>
        <span className="zs-v3-pill__sub">{sub}</span>
      </span>
      <span className="zs-v3-pill__knob" aria-hidden="true" />
    </button>
  );
}

import { useMascotPause } from "./useMascotPause";
import "./mascot.css";

export interface KillSwitchAnimProps {
  /** Зафиксирован обрыв/утечка: щит мгновенно захлопывается. */
  triggered?: boolean;
  /** Компактный режим для AlertWindow и CrashTestModal. */
  compact?: boolean;
  /** Метка времени реакции Kill-Switch. */
  latencyLabel?: string;
  paused?: boolean;
  className?: string;
}

/**
 * Анимация 2: мгновенный перехват «0.04 мс» — fail-closed захлопывание щита,
 * блокирующее утечку AI-трафика при смене сети или обрыве VPN.
 */
export function KillSwitchAnim({
  triggered = true,
  compact = false,
  latencyLabel = "0.04 мс",
  paused = false,
  className,
}: KillSwitchAnimProps) {
  const { paused: autoPaused } = useMascotPause(paused);
  const rootClass = [
    "zs-anim-ks",
    triggered ? "zs-anim-ks--triggered" : "",
    compact ? "zs-anim-ks--compact" : "",
    autoPaused ? "zs-mascot--paused" : "",
    className ?? "",
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <div
      className={rootClass}
      role="img"
      aria-label={`Мгновенная блокировка утечки трафика: заслон срабатывает за ${latencyLabel}`}
      data-ks-triggered={triggered ? "true" : "false"}
    >
      <div className="zs-anim-ks__stage" aria-hidden="true">
        <span className="zs-anim-ks__packet" />
        <span className="zs-anim-ks__gate">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
            <path
              d="M12 2.5L20 5.5V12C20 16.8 16.5 20.5 12 22C7.5 20.5 4 16.8 4 12V5.5L12 2.5Z"
              fill="currentColor"
              fillOpacity="0.18"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinejoin="round"
            />
            {triggered ? (
              <path d="M9.5 9.5L14.5 14.5M14.5 9.5L9.5 14.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
            ) : (
              <path d="M8.5 12.2L11 14.7L15.8 9.8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            )}
          </svg>
        </span>
      </div>

      <div className="zs-anim-ks__body">
        <div className="zs-anim-ks__head">
          <span className="zs-anim-ks__title">
            {triggered ? "Заслон перекрыл утечку" : "Заслон на дежурстве"}
          </span>
          <span className="zs-anim-ks__ms">{latencyLabel}</span>
        </div>
        <p className="zs-anim-ks__sub">
          {triggered
            ? "Ни один запрос к AI не уйдёт в обход, пока вы не примете решение."
            : "При обрыве VPN щит захлопнется до отправки первого пакета."}
        </p>
      </div>
    </div>
  );
}

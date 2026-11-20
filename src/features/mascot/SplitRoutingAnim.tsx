import { useMascotPause } from "./useMascotPause";
import "./mascot.css";

export interface SplitRoutingAnimProps {
  /** Защита активна: показывает живой поток через щит. */
  active?: boolean;
  /** Компактный режим для встроенных карточек. */
  compact?: boolean;
  paused?: boolean;
  className?: string;
}

/**
 * Анимация 1: наглядная схема разделения трафика (Split-Routing).
 * Обычные российские сервисы идут напрямую, а AI-трафик проходит через щит Заставы.
 */
export function SplitRoutingAnim({
  active = true,
  compact = false,
  paused = false,
  className,
}: SplitRoutingAnimProps) {
  const { paused: autoPaused } = useMascotPause(paused);
  const rootClass = [
    "zs-anim-split",
    active ? "zs-anim-split--active" : "",
    compact ? "zs-anim-split--compact" : "",
    autoPaused ? "zs-mascot--paused" : "",
    className ?? "",
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <div
      className={rootClass}
      role="img"
      aria-label="Схема раздельного трафика: нейросети идут через щит Заставы, обычные сайты — напрямую"
      data-anim-active={active ? "true" : "false"}
    >
      <div className="zs-anim-split__lane zs-anim-split__lane--ai">
        <div className="zs-anim-split__label">
          <span className="zs-anim-split__title">Claude · ChatGPT · Gemini</span>
          <span className="zs-anim-split__sub">AI и редакторы кода</span>
        </div>
        <div className="zs-anim-split__track" aria-hidden="true">
          <span className="zs-anim-split__line" />
          <span className="zs-anim-split__dot" />
          <span className="zs-anim-split__dot zs-anim-split__dot--delay" />
        </div>
        <div className="zs-anim-split__node">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path
              d="M12 3L20 6V12C20 16.5 16.5 20.2 12 21.5C7.5 20.2 4 16.5 4 12V6L12 3Z"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinejoin="round"
            />
          </svg>
          <span>Щит Заставы</span>
        </div>
      </div>

      <div className="zs-anim-split__lane">
        <div className="zs-anim-split__label">
          <span className="zs-anim-split__title">Сбербанк · Ozon · Почта</span>
          <span className="zs-anim-split__sub">Обычные сайты</span>
        </div>
        <div className="zs-anim-split__track" aria-hidden="true">
          <span className="zs-anim-split__line" />
          <span className="zs-anim-split__dot" />
        </div>
        <div className="zs-anim-split__node">
          <span>Напрямую</span>
        </div>
      </div>
    </div>
  );
}

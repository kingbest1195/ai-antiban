import { useMascotPause } from "./useMascotPause";
import "./mascot.css";

export type MascotState = "protected" | "scanning" | "alert" | "sleep" | "warmup";
export type MascotSize = 48 | 64 | 96 | number;

export interface WatchdogMascotProps {
  state: MascotState;
  size?: MascotSize;
  /** Принудительная пауза анимаций (дополняет авто-паузу в фоне). */
  paused?: boolean;
  /** true, если рядом уже есть текстовый статус и маскот носит декоративный характер. */
  decorative?: boolean;
  label?: string;
  className?: string;
}

const DEFAULT_LABELS: Record<MascotState, string> = {
  protected: "Сторожевой пёс Заставы: защита включена",
  scanning: "Сторожевой пёс Заставы: проверка среды",
  alert: "Сторожевой пёс Заставы: обнаружена угроза или перехват",
  sleep: "Сторожевой пёс Заставы: защита выключена",
  warmup: "Сторожевой пёс Заставы: прогрев и сохранение данных",
};

interface Palette {
  shieldFill: string;
  shieldStroke: string;
  cloak: string;
  cloakShade: string;
  fur: string;
  furShade: string;
  muzzle: string;
  badge: string;
}

function paletteFor(state: MascotState): Palette {
  if (state === "alert") {
    return {
      shieldFill: "var(--danger-soft)",
      shieldStroke: "var(--danger)",
      cloak: "var(--danger)",
      cloakShade: "var(--danger-soft)",
      fur: "var(--mascot-fur)",
      furShade: "var(--mascot-fur-shade)",
      muzzle: "var(--mascot-muzzle)",
      badge: "var(--danger-text)",
    };
  }
  if (state === "sleep") {
    return {
      shieldFill: "var(--bg-2)",
      shieldStroke: "var(--line-strong)",
      cloak: "var(--mascot-sleep-cloak)",
      cloakShade: "var(--bg-2)",
      fur: "var(--mascot-sleep-fur)",
      furShade: "var(--bg-3)",
      muzzle: "var(--mascot-sleep-muzzle)",
      badge: "var(--ink-3)",
    };
  }
  return {
    shieldFill: "var(--mascot-shield-bg)",
    shieldStroke: "var(--mascot-shield-stroke)",
    cloak: "var(--mascot-cloak)",
    cloakShade: "var(--mascot-cloak-shade)",
    fur: "var(--mascot-fur)",
    furShade: "var(--mascot-fur-shade)",
    muzzle: "var(--mascot-muzzle)",
    badge: state === "warmup" ? "var(--brand-text)" : "var(--brand)",
  };
}

/**
 * Плоский геометрический векторный маскот Заставы (сторожевой корги/лайка в плаще-щите).
 * Цвета задаются исключительно через CSS-переменные токенов; анимации работают только на transform/opacity.
 */
export function WatchdogMascot({
  state,
  size = 64,
  paused = false,
  decorative = false,
  label,
  className,
}: WatchdogMascotProps) {
  const { paused: autoPaused } = useMascotPause(paused);
  const p = paletteFor(state);
  const rootClass = [
    "zs-mascot",
    `zs-mascot--${state}`,
    autoPaused ? "zs-mascot--paused" : "",
    className ?? "",
  ]
    .filter(Boolean)
    .join(" ");

  const ariaLabel = decorative ? undefined : (label ?? DEFAULT_LABELS[state]);
  const earsUp = state === "alert" ? -3 : 0;

  return (
    <span
      className={rootClass}
      style={{ width: size, height: size }}
      data-mascot-state={state}
      data-mascot-paused={autoPaused ? "true" : "false"}
      role={decorative ? undefined : "img"}
      aria-label={ariaLabel}
      aria-hidden={decorative ? true : undefined}
    >
      <svg className="zs-mascot__svg" viewBox="0 0 96 96" fill="none" xmlns="http://www.w3.org/2000/svg">
        {/* Щит-ореол позади силуэта */}
        <path
          className="zs-mascot__halo"
          d="M48 8L82 20V47C82 67.5 67.5 82.8 48 88C28.5 82.8 14 67.5 14 47V20L48 8Z"
          fill={p.shieldFill}
          stroke={p.shieldStroke}
          strokeWidth="2.5"
          strokeLinejoin="round"
        />

        {state === "sleep" ? (
          /* Свернувшаяся поза покоя */
          <g className="zs-mascot__sleep-pose">
            <path d="M26 62C26 50 36 44 49 44C63 44 72 52 72 64C72 72 62 76 48 76C34 76 26 71 26 62Z" fill={p.cloak} />
            <ellipse cx="48" cy="60" rx="18" ry="12" fill={p.fur} />
            <path d="M33 56L29 48L39 52Z" fill={p.furShade} />
            <path d="M60 56L65 49L55 52Z" fill={p.furShade} />
            <ellipse cx="47" cy="63" rx="10" ry="7" fill={p.muzzle} />
            <path d="M39 58Q42 60 45 58" stroke="var(--mascot-eye)" strokeWidth="2" strokeLinecap="round" />
            <path d="M50 58Q53 60 56 58" stroke="var(--mascot-eye)" strokeWidth="2" strokeLinecap="round" />
            <circle cx="47.5" cy="63" r="2.3" fill="var(--mascot-eye)" />
          </g>
        ) : (
          /* Бодрая сторожевая поза (protected / scanning / alert / warmup) */
          <>
            {/* Плащ-накидка Заставы */}
            <g className="zs-mascot__chest">
              <path d="M27 76L34 52H62L69 76C63 80 55.5 82.5 48 83.5C40.5 82.5 33 80 27 76Z" fill={p.cloak} />
              <path d="M48 52H62L69 76C63 80 55.5 82.5 48 83.5V52Z" fill={p.cloakShade} opacity="0.45" />
              {/* Белая грудка */}
              <path d="M40 55L48 74L56 55H40Z" fill={p.muzzle} />
              {/* Застёжка-щиток на плаще */}
              <path d="M48 56L53 58.5V62.5C53 65.5 50.8 67.6 48 68.5C45.2 67.6 43 65.5 43 62.5V58.5L48 56Z" fill={p.badge} />
            </g>

            {/* Голова и уши корги/лайки */}
            <g className="zs-mascot__head" transform={`translate(0 ${earsUp})`}>
              {/* Левое и правое заострённые уши */}
              <path d="M32 36L28 19L41 28Z" fill={p.furShade} />
              <path d="M33 34L30.5 23L39 29Z" fill={p.muzzle} opacity="0.7" />
              <path d="M64 36L68 19L55 28Z" fill={p.furShade} />
              <path d="M63 34L65.5 23L57 29Z" fill={p.muzzle} opacity="0.7" />

              {/* Геометричный контур головы */}
              <path
                d="M30 40C30 30 38 25 48 25C58 25 66 30 66 40C66 50 58 56 48 56C38 56 30 50 30 40Z"
                fill={p.fur}
              />
              {/* Светлая мордочка */}
              <path
                d="M36 44C36 39.5 41 37 48 37C55 37 60 39.5 60 44C60 51 55 55.5 48 55.5C41 55.5 36 51 36 44Z"
                fill={p.muzzle}
              />
              {/* Переносица */}
              <path d="M46 27H50L49 41H47L46 27Z" fill={p.muzzle} />

              {/* Глаза */}
              <g className="zs-mascot__eyes">
                <circle cx="41" cy="39.5" r="2.5" fill="var(--mascot-eye)" />
                <circle cx="55" cy="39.5" r="2.5" fill="var(--mascot-eye)" />
                <circle cx="41.7" cy="38.8" r="0.8" fill="var(--ink)" />
                <circle cx="55.7" cy="38.8" r="0.8" fill="var(--ink)" />
              </g>

              {/* Нос и уверенная линия морды */}
              <path d="M45.5 44.5H50.5L48 48Z" fill="var(--mascot-eye)" />
              {state === "alert" ? (
                <path d="M44 51.5L48 49.5L52 51.5" stroke="var(--mascot-eye)" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
              ) : (
                <path d="M45 50.5Q48 52.5 51 50.5" stroke="var(--mascot-eye)" strokeWidth="1.6" strokeLinecap="round" />
              )}
            </g>

            {/* Сканер-луч в состоянии scanning */}
            {state === "scanning" && (
              <rect
                className="zs-mascot__scan-beam"
                x="46"
                y="18"
                width="3"
                height="62"
                rx="1.5"
                fill="var(--brand-text)"
              />
            )}

            {/* Мини-индикатор прогрева/бэкапа в состоянии warmup */}
            {state === "warmup" && (
              <g className="zs-mascot__warmup-ring">
                <circle cx="76" cy="72" r="9" fill="var(--bg-1)" stroke="var(--brand)" strokeWidth="2" />
                <path d="M76 67V72L79.5 74" stroke="var(--brand-text)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
              </g>
            )}
          </>
        )}
      </svg>
    </span>
  );
}

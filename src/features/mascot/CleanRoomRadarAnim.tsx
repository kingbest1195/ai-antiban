import { InfoTip } from "../../ui";
import { useMascotPause } from "./useMascotPause";
import "./mascot.css";

export type RadarLayerStatus = "pending" | "scanning" | "ok" | "warn" | "critical";

export interface RadarLayerItem {
  id: string;
  label: string;
  status: RadarLayerStatus;
  tip?: string;
}

export interface CleanRoomRadarAnimProps {
  /** Идёт ли сканирование в данный момент. */
  scanning?: boolean;
  /** Индекс активного слоя (0..3) при пошаговом сканировании. */
  activeLayerIndex?: number;
  /** 4 слоя аудита (по умолчанию Браузеры, Приложения ИИ, IP и DNS, Время и язык). */
  layers?: RadarLayerItem[];
  paused?: boolean;
  className?: string;
}

export function isMacPlatform(): boolean {
  if (typeof navigator === "undefined") return false;
  const plat = `${navigator.platform ?? ""} ${navigator.userAgent ?? ""}`.toLowerCase();
  return plat.includes("mac");
}

function buildDefaultLayers(): RadarLayerItem[] {
  return [
    { id: "browsers", label: "Браузеры", status: "pending" },
    { id: "desktop", label: isMacPlatform() ? "Приложения ИИ" : "Приложения ИИ и Store", status: "pending" },
    { id: "network", label: "IP и DNS", status: "pending" },
    { id: "os_tz", label: "Время и язык", status: "pending" },
  ];
}

/**
 * Анимация 3: пошаговый 4-слойный радар «Чистой комнаты».
 * Последовательно подсвечивает слои проверки среды без чтения секретов и куки-строк.
 */
export function CleanRoomRadarAnim({
  scanning = false,
  activeLayerIndex,
  layers,
  paused = false,
  className,
}: CleanRoomRadarAnimProps) {
  const resolvedLayers = layers ?? buildDefaultLayers();
  const { paused: autoPaused } = useMascotPause(paused);
  const rootClass = [
    "zs-anim-radar",
    scanning ? "zs-anim-radar--scanning" : "",
    autoPaused ? "zs-mascot--paused" : "",
    className ?? "",
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <div
      className={rootClass}
      role="status"
      aria-label={scanning ? "Идёт 4-слойная проверка Чистой комнаты" : "4 слоя проверки Чистой комнаты"}
      data-radar-scanning={scanning ? "true" : "false"}
    >
      <svg className="zs-anim-radar__dial" viewBox="0 0 56 56" fill="none" aria-hidden="true">
        <circle cx="28" cy="28" r="24" stroke="var(--line-strong)" strokeWidth="1.5" />
        <circle cx="28" cy="28" r="15" stroke="var(--line)" strokeWidth="1.5" />
        <circle cx="28" cy="28" r="5" fill="var(--brand-soft)" stroke="var(--brand)" strokeWidth="1.5" />
        <g className="zs-anim-radar__sweep">
          <path d="M28 28L28 4" stroke="var(--brand-text)" strokeWidth="2" strokeLinecap="round" />
          <path d="M28 28L44 12" stroke="var(--brand)" strokeWidth="1.5" strokeOpacity="0.4" strokeLinecap="round" />
        </g>
      </svg>

      <div className="zs-anim-radar__layers">
        {resolvedLayers.slice(0, 4).map((layer, idx) => {
          const isActive = activeLayerIndex === idx || (scanning && layer.status === "scanning");
          const statusClass =
            layer.status === "ok"
              ? "zs-anim-radar__layer--ok"
              : layer.status === "warn"
                ? "zs-anim-radar__layer--warn"
                : layer.status === "critical"
                  ? "zs-anim-radar__layer--critical"
                  : isActive
                    ? "zs-anim-radar__layer--active"
                    : "";
          return (
            <div
              key={layer.id}
              className={`zs-anim-radar__layer zs-anim-radar__layer--${idx + 1} ${statusClass}`.trim()}
              title={layer.tip}
            >
              <span className="zs-anim-radar__dot" aria-hidden="true" />
              <span>{layer.label}</span>
              {layer.tip && <InfoTip title={layer.label} text={layer.tip} />}
            </div>
          );
        })}
      </div>
    </div>
  );
}

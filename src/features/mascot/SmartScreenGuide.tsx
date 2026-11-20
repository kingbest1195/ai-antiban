import { useState } from "react";
import { useMascotPause } from "./useMascotPause";
import "./mascot.css";

export type GuidePlatform = "windows" | "macos" | "auto";

export interface SmartScreenGuideProps {
  platform?: GuidePlatform;
  /** Разрешить переключение вкладок Windows / macOS. */
  allowPlatformSwitch?: boolean;
  /** Сворачиваемый режим для Шага 2 онбординга. */
  collapsible?: boolean;
  defaultExpanded?: boolean;
  paused?: boolean;
  className?: string;
}

function detectPlatform(pref: GuidePlatform): "windows" | "macos" {
  if (pref === "windows" || pref === "macos") return pref;
  if (typeof navigator !== "undefined") {
    const raw = `${navigator.platform ?? ""} ${navigator.userAgent ?? ""}`.toLowerCase();
    if (raw.includes("mac")) return "macos";
  }
  return "windows";
}

/**
 * Анимация 4: 2-кадровый визуальный гайд первого запуска
 * (Windows SmartScreen «Подробнее → Выполнить в любом случае» / macOS Gatekeeper «Открыть»).
 */
export function SmartScreenGuide({
  platform = "auto",
  allowPlatformSwitch = true,
  collapsible = false,
  defaultExpanded = !collapsible,
  paused = false,
  className,
}: SmartScreenGuideProps) {
  const { paused: autoPaused } = useMascotPause(paused);
  const [expanded, setExpanded] = useState(defaultExpanded);
  const [activeTab, setActiveTab] = useState<"windows" | "macos">(() => detectPlatform(platform));
  const [userSelected, setUserSelected] = useState(false);

  const current = platform !== "auto" && !userSelected ? platform : activeTab;
  const rootClass = [
    "zs-smartguide",
    autoPaused ? "zs-mascot--paused" : "",
    className ?? "",
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <div className={rootClass} data-guide-platform={current}>
      {collapsible && (
        <button
          type="button"
          className="zs-smartguide__toggle"
          aria-expanded={expanded}
          onClick={() => setExpanded((v) => !v)}
        >
          <span>Если Windows или macOS предупредит при первом запуске</span>
          <span>{expanded ? "Скрыть" : "Показать 2 шага"}</span>
        </button>
      )}

      {expanded && (
        <>
          {allowPlatformSwitch && (
            <div className="zs-smartguide__tabs" role="tablist" aria-label="Платформа">
              <button
                type="button"
                role="tab"
                className="zs-smartguide__tab"
                aria-selected={current === "windows"}
                onClick={() => {
                  setUserSelected(true);
                  setActiveTab("windows");
                }}
              >
                Windows SmartScreen
              </button>
              <button
                type="button"
                role="tab"
                className="zs-smartguide__tab"
                aria-selected={current === "macos"}
                onClick={() => {
                  setUserSelected(true);
                  setActiveTab("macos");
                }}
              >
                macOS Gatekeeper
              </button>
            </div>
          )}

          {current === "windows" ? (
            <div className="zs-smartguide__frames">
              <div className="zs-smartguide__frame zs-smartguide__frame--1">
                <span className="zs-smartguide__step">Кадр 1 · Окно защиты</span>
                <div className="zs-smartguide__mock" aria-hidden="true">
                  <span className="zs-smartguide__mock-bar" />
                  <span className="zs-smartguide__cta">Подробнее</span>
                </div>
                <p className="zs-smartguide__caption">Нажмите ссылку «Подробнее» под текстом окна.</p>
              </div>

              <div className="zs-smartguide__frame zs-smartguide__frame--2">
                <span className="zs-smartguide__step">Кадр 2 · Разрешение</span>
                <div className="zs-smartguide__mock" aria-hidden="true">
                  <span className="zs-smartguide__mock-bar" />
                  <span className="zs-smartguide__cta">Выполнить в любом случае</span>
                </div>
                <p className="zs-smartguide__caption">Появится кнопка «Выполнить в любом случае».</p>
              </div>
            </div>
          ) : (
            <div className="zs-smartguide__frames">
              <div className="zs-smartguide__frame zs-smartguide__frame--1">
                <span className="zs-smartguide__step">Кадр 1 · Настройки</span>
                <div className="zs-smartguide__mock" aria-hidden="true">
                  <span className="zs-smartguide__mock-bar" />
                  <span className="zs-smartguide__cta">Всё равно открыть</span>
                </div>
                <p className="zs-smartguide__caption">Конфиденциальность и безопасность → «Всё равно открыть».</p>
              </div>

              <div className="zs-smartguide__frame zs-smartguide__frame--2">
                <span className="zs-smartguide__step">Кадр 2 · Подтверждение</span>
                <div className="zs-smartguide__mock" aria-hidden="true">
                  <span className="zs-smartguide__mock-bar" />
                  <span className="zs-smartguide__cta">Открыть</span>
                </div>
                <p className="zs-smartguide__caption">В диалоге нажмите «Открыть» один раз.</p>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

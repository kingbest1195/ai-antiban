import type { ShutdownProgressPayload } from "../types";
import { Banner, Icon, Progress, Spinner } from "../ui";
import { shutdown as copy } from "../shared/copy/ru";

export interface ShutdownOverlayProps {
  progress: ShutdownProgressPayload | null;
}

/**
 * Незакрываемый прелоадер штатного завершения работы или подготовки к обновлению.
 * Показывается поверх всего окна, пока Rust возвращает прокси, политики и окружение терминала в исходное состояние.
 */
export function ShutdownOverlay({ progress }: ShutdownOverlayProps) {
  if (!progress) return null;

  const isUpdate = progress.mode === "update";
  const heading = isUpdate ? copy.titleUpdate : copy.titleQuit;
  const total = Math.max(1, progress.total || copy.stages.length);
  const clampedStep = Math.max(0, Math.min(total, progress.step));
  const percent = progress.done ? 100 : Math.round((clampedStep / total) * 100);
  const liveLabel = progress.label || (isUpdate ? copy.titleUpdate : copy.titleQuit);
  const boundApps = Array.from(
    new Set((progress.gateway_bound_apps ?? []).map((app) => app.trim()).filter(Boolean)),
  );

  return (
    <div
      className="zs-shutdown"
      role="alertdialog"
      aria-modal="true"
      aria-busy="true"
      aria-labelledby="zs-shutdown-title"
      aria-describedby="zs-shutdown-desc"
    >
      <div className="zs-shutdown__card">
        <div className="zs-shutdown__head">
          <span className="zs-shutdown__badge" aria-hidden="true">
            <Spinner size={18} />
          </span>
          <div>
            <h2 id="zs-shutdown-title" className="zs-t-title zs-shutdown__title">
              {heading}
            </h2>
          </div>
        </div>

        <p id="zs-shutdown-desc" className="zs-t-body zs-shutdown__desc">
          {copy.description}
        </p>

        <Progress value={percent} label={liveLabel} />

        <ol className="zs-shutdown__steps">
          {copy.stages.map((stageLabel, idx) => {
            const stepNum = idx + 1;
            const completed = progress.done || progress.step > stepNum;
            const active = !progress.done && progress.step === stepNum;
            const stateClass = completed
              ? "zs-shutdown__step--done"
              : active
                ? "zs-shutdown__step--active"
                : "zs-shutdown__step--pending";

            return (
              <li
                key={stageLabel}
                className={`zs-shutdown__step ${stateClass}`}
                aria-current={active ? "step" : undefined}
              >
                <span className="zs-shutdown__step-icon" aria-hidden="true">
                  {completed ? (
                    <Icon name="check" size={14} />
                  ) : active ? (
                    <Spinner size={14} />
                  ) : (
                    <span className="zs-shutdown__dot" />
                  )}
                </span>
                <span className="zs-t-body">{stageLabel}</span>
              </li>
            );
          })}
        </ol>

        {boundApps.length > 0 && (
          <Banner tone="info" title={copy.boundAppsTitle}>
            {copy.boundAppsHint(boundApps)}
          </Banner>
        )}
      </div>
    </div>
  );
}

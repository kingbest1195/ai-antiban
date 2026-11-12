import { useState } from "react";
import type { UpdateCheckResult, UpdateProgressPayload, UpdateStatusPayload } from "../types";
import { Badge, Banner, Button, Modal, Progress } from "../ui";
import { updates as copy } from "../shared/copy/ru";
import { parseReleaseNotes } from "../shared/lib/releaseNotes";
import { openExternal } from "../utils/opener";

interface UpdateModalProps {
  open: boolean;
  onClose: () => void;
  info: UpdateCheckResult | null;
  installing: boolean;
  progress: UpdateProgressPayload | null;
  status: UpdateStatusPayload | null;
  onInstall: () => void;
}

/** Обновление: версии, список изменений (краткий и полный текст), установка с прогрессом. */
export function UpdateModal({ open, onClose, info, installing, progress, status, onInstall }: UpdateModalProps) {
  const [fullText, setFullText] = useState<boolean>(false);
  if (!info) return null;

  const notes = info.release_notes || info.release_name || "";
  const phaseLabel = status?.message || progress?.phase || copy.installing;
  // Ошибка установки приходит как status { stage: "failed", error }.
  const failure = status?.stage === "failed" && status.error ? status.error : null;

  return (
    <Modal
      open={open}
      // Пока идёт установка, окно не закрывается ни крестиком, ни Esc, ни кликом по фону.
      onClose={() => {
        if (!installing) onClose();
      }}
      closeOnBackdrop={!installing}
      title={info.update_available ? copy.available(info.latest_version) : copy.upToDate}
      footer={
        <>
          <Button variant="quiet" onClick={() => openExternal(info.release_url)}>
            {copy.openRelease}
          </Button>
          {info.update_available ? (
            <Button variant="primary" disabled={installing} onClick={onInstall}>
              {installing ? copy.installing : failure ? copy.retry : copy.install}
            </Button>
          ) : (
            <Button onClick={onClose}>{copy.ok}</Button>
          )}
        </>
      }
    >
      <p className="zs-modal-text">
        <Badge>{copy.versions(info.current_version, info.latest_version)}</Badge>
      </p>

      {failure && (
        <Banner tone="danger" role="alert" title={copy.errorTitle[failure]}>
          {copy.errors[failure]}
        </Banner>
      )}

      {installing && (
        <Progress
          label={phaseLabel}
          value={progress && progress.total_bytes > 0 ? progress.percent : undefined}
        />
      )}

      {info.update_available && (
        <>
          <div className="zs-shell__subhead">
            <h3 className="zs-t-heading">{copy.whatsNew}</h3>
            <span className="zs-app__spacer" />
            <Button variant="quiet" size="sm" onClick={() => setFullText((v) => !v)}>
              {fullText ? copy.shortList : copy.fullText}
            </Button>
          </div>
          {fullText ? (
            <p className="zs-changelog__raw">{info.release_notes || info.release_name || copy.noNotes}</p>
          ) : (
            parseReleaseNotes(notes).map((section, sIdx) => (
              <div key={sIdx}>
                {section.title && <p className="zs-changelog__title">{section.title}</p>}
                <ul className="zs-changelog">
                  {section.items.map((item, iIdx) => (
                    <li key={iIdx}>
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ))
          )}
        </>
      )}
    </Modal>
  );
}

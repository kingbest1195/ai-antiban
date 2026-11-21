import { useState } from "react";
import { Banner, Button, Card, Segmented } from "../../ui";
import { bunkerCopy } from "../../shared/copy/ru/bunker";
import { sosCopy as copy } from "../../shared/copy/ru/sos";
import type { ShowToast } from "../../shared/hooks";
import { writeClipboard } from "../../shared/lib/clipboard";
import { generateBunkerRestorePrompt, runBunkerBackupNow } from "../../utils/api/bunker";
import "./sos.css";

export type PersonaDocChoice = "ru_only" | "foreign_legal";

export interface PersonaBranchProps {
  initialChoice?: PersonaDocChoice;
  ctaVariant?: "primary" | "secondary";
  onToast?: ShowToast;
  onBackupCreated?: () => void;
}

/**
 * Ветка 1 SOS: Persona (паспорт + селфи).
 * 1A (RU-only): строгий красный STOP + 3-шаговый Протокол выживания (Бункер + отмена списаний + BYOK/OpenRouter).
 * 1B (ВНЖ / иностранный паспорт): 4-пунктовый Pre-Flight чек-лист согласования реальных данных.
 */
export function PersonaBranch({
  initialChoice = "ru_only",
  ctaVariant = "primary",
  onToast,
  onBackupCreated,
}: PersonaBranchProps) {
  const t = copy.persona;
  const [choice, setChoice] = useState<PersonaDocChoice>(initialChoice);
  const [backingUp, setBackingUp] = useState(false);
  const [backupFilesCount, setBackupFilesCount] = useState<number | null>(null);
  const [copiedPrompt, setCopiedPrompt] = useState(false);
  const [checkedIds, setCheckedIds] = useState<Record<string, boolean>>({});

  const handleEmergencyBackup = async () => {
    if (backingUp) return;
    setBackingUp(true);
    try {
      const res = await runBunkerBackupNow();
      setBackupFilesCount(res.snapshot.files_count);
      onToast?.(
        bunkerCopy.toasts.backupOkTitle,
        bunkerCopy.toasts.backupOkText(res.snapshot.files_count),
        "success",
      );
      onBackupCreated?.();
    } catch (err) {
      onToast?.(bunkerCopy.toasts.backupErrTitle, err instanceof Error ? err.message : String(err), "error");
    } finally {
      setBackingUp(false);
    }
  };

  const handleCopyRestore = async () => {
    try {
      const prompt = await generateBunkerRestorePrompt();
      const ok = await writeClipboard(prompt);
      if (ok) {
        setCopiedPrompt(true);
        onToast?.(bunkerCopy.toasts.promptCopiedTitle, bunkerCopy.toasts.promptCopiedText, "success");
      }
    } catch (err) {
      onToast?.(bunkerCopy.toasts.promptErrTitle, err instanceof Error ? err.message : String(err), "error");
    }
  };

  const toggleCheck = (id: string) => {
    setCheckedIds((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  return (
    <Card title={t.question}>
      <Segmented<PersonaDocChoice>
        aria-label={t.question}
        value={choice}
        onChange={setChoice}
        options={[
          { value: "ru_only", label: t.choiceRuOnly },
          { value: "foreign_legal", label: t.choiceForeign },
        ]}
      />

      {choice === "ru_only" ? (
        <>
          <Banner tone="danger" icon="alert" role="alert" title={t.ruStopTitle} className="zs-sos__block">
            {t.ruStopBody}
          </Banner>

          <div className="zs-sos__block">
            <p className="zs-t-heading">{t.protocolTitle}</p>

            <div className="zs-sos__step">
              <p className="zs-t-body zs-sos__step-title">
                <strong>{t.step1Title}</strong>
              </p>
              <p className="zs-t-caption zs-sos__step-desc">{t.step1Desc}</p>
              <Button
                variant={ctaVariant}
                block
                icon="shield"
                disabled={backingUp}
                onClick={() => void handleEmergencyBackup()}
              >
                {backingUp ? t.step1Busy : t.step1Btn}
              </Button>
              {backupFilesCount !== null && (
                <Banner tone="ok" icon="check" title={t.step1Done(backupFilesCount)} className="zs-sos__block" />
              )}
            </div>

            <div className="zs-sos__step">
              <p className="zs-t-body zs-sos__step-title">
                <strong>{t.step2Title}</strong>
              </p>
              <ul className="zs-t-caption zs-sos__list">
                {t.step2Items.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>

            <div className="zs-sos__step">
              <p className="zs-t-body zs-sos__step-title">
                <strong>{t.step3Title}</strong>
              </p>
              <p className="zs-t-caption zs-sos__step-desc">{t.step3Desc}</p>
              <Button
                block
                icon={copiedPrompt ? "check" : "copy"}
                onClick={() => void handleCopyRestore()}
              >
                {copiedPrompt ? t.copiedRestoreBtn : t.copyRestoreBtn}
              </Button>
            </div>
          </div>
        </>
      ) : (
        <div className="zs-sos__block">
          <Banner tone="info" icon="shield" title={t.foreignTitle}>
            {t.foreignDesc}
          </Banner>
          <div className="zs-sos__checklist">
            {t.foreignChecklist.map((item) => {
              const checked = Boolean(checkedIds[item.id]);
              return (
                <label key={item.id} className="zs-sos__check-row">
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={() => toggleCheck(item.id)}
                  />
                  <div>
                    <div className="zs-t-body">{item.title}</div>
                    <div className="zs-t-caption">{item.detail}</div>
                  </div>
                </label>
              );
            })}
          </div>
        </div>
      )}
    </Card>
  );
}

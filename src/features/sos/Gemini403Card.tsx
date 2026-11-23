import { useState } from "react";
import { Banner, Button, Card } from "../../ui";
import { sosCopy as copy } from "../../shared/copy/ru/sos";
import type { ShowToast } from "../../shared/hooks";
import { cleanAntigravityAuthCache } from "../../utils/api/sos";
import "./sos.css";

export interface Gemini403CardProps {
  onToast?: ShowToast;
}

/** Блок 1-клик сброса кеша входа при 403 ToS для Antigravity и Gemini. */
export function Gemini403Card({ onToast }: Gemini403CardProps) {
  const t = copy.gemini403;
  const [cleaning, setCleaning] = useState(false);
  const [resultMsg, setResultMsg] = useState<string | null>(null);

  const handleClean = async () => {
    if (cleaning) return;
    setCleaning(true);
    try {
      const res = await cleanAntigravityAuthCache();
      setResultMsg(res.message);
      onToast?.(t.toastOkTitle, res.message, res.success ? "success" : "warning");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      onToast?.(t.toastErrTitle, msg, "error");
    } finally {
      setCleaning(false);
    }
  };

  return (
    <Card title={t.title}>
      <Banner tone="warn" icon="alert" title={t.warningTitle}>
        {t.warningBody}
      </Banner>

      <div className="zs-sos__step">
        <p className="zs-t-body zs-sos__step-desc">{t.cleanNote}</p>
        <Button
          variant="secondary"
          size="sm"
          icon="shield"
          disabled={cleaning}
          onClick={() => void handleClean()}
        >
          {cleaning ? t.cleaningBtn : t.cleanBtn}
        </Button>
        {resultMsg && (
          <p className="zs-t-caption zs-sos__block">{resultMsg}</p>
        )}
      </div>

      <p className="zs-t-heading zs-sos__block">{t.checklistTitle}</p>
      <ol className="zs-t-body zs-sos__list">
        {t.checklist.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ol>
    </Card>
  );
}

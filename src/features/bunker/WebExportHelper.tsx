import { useState } from "react";
import type { FormEvent } from "react";
import { Banner, Button, EmptyState, Field, Link, Mono } from "../../ui";
import { bunkerCopy as copy } from "../../shared/copy/ru/bunker";
import type { ShowToast } from "../../shared/hooks";
import { writeClipboard } from "../../shared/lib/clipboard";
import { convertWebExport } from "../../utils/api/bunker";
import { openExternal } from "../../utils/opener";
import type { WebExportConvertResult } from "../../types";
import "./bunker.css";

export interface WebExportHelperProps {
  /** Заголовок для EmptyState (можно переопределить при встраивании). */
  title?: string;
  /** Вариант основной кнопки (внутри BunkerCard — `secondary`, чтобы на экране оставался 1 `primary`). */
  ctaVariant?: "primary" | "secondary";
  onConverted?: (result: WebExportConvertResult) => void;
  onToast?: ShowToast;
}

/**
 * Помощник экспорта для пользователей веб-версий Claude.ai / ChatGPT:
 * заменяет мёртвую заглушку «Claude не найден» и локально конвертирует export.zip / conversations.json.
 */
export function WebExportHelper({
  title,
  ctaVariant = "primary",
  onConverted,
  onToast,
}: WebExportHelperProps) {
  const t = copy.webExport;
  const [sourcePath, setSourcePath] = useState("");
  const [converting, setConverting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<WebExportConvertResult | null>(null);
  const [copied, setCopied] = useState(false);

  const handleConvert = async (e: FormEvent) => {
    e.preventDefault();
    const trimmed = sourcePath.trim();
    if (!trimmed) {
      setError(t.pathRequired);
      return;
    }
    setError(null);
    setConverting(true);
    try {
      const converted = await convertWebExport(trimmed);
      setResult(converted);
      setCopied(false);
      onConverted?.(converted);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg || t.convertError);
      onToast?.(t.convertError, msg, "error");
    } finally {
      setConverting(false);
    }
  };

  const handleCopyPrompt = async () => {
    if (!result?.restore_prompt_preview) return;
    const ok = await writeClipboard(result.restore_prompt_preview);
    if (ok) {
      setCopied(true);
      onToast?.(copy.toasts.promptCopiedTitle, copy.toasts.promptCopiedText, "success");
    }
  };

  return (
    <EmptyState
      mascotState="warmup"
      mascotSize={48}
      title={title ?? t.title}
      description={t.description}
    >
      <div className="zs-bunker__form">
        <p className="zs-t-caption zs-bunker__section-label">{t.stepsTitle}</p>
        <ol className="zs-t-caption zs-bunker__steps">
          {t.steps.map((step) => (
            <li key={step}>{step}</li>
          ))}
        </ol>

        <div className="zs-bunker__links">
          <Link
            href={t.claudeExportUrl}
            onClick={(e) => {
              e.preventDefault();
              void openExternal(t.claudeExportUrl);
            }}
          >
            {t.openClaudeExport}
          </Link>
          <Link
            href={t.chatgptExportUrl}
            onClick={(e) => {
              e.preventDefault();
              void openExternal(t.chatgptExportUrl);
            }}
          >
            {t.openChatgptExport}
          </Link>
        </div>

        <form onSubmit={handleConvert} className="zs-bunker__form">
          <Field
            label={t.pathLabel}
            placeholder={t.pathPlaceholder}
            value={sourcePath}
            error={error ?? undefined}
            onChange={(e) => {
              setSourcePath(e.target.value);
              setError(null);
            }}
          />
          <Button type="submit" variant={ctaVariant} block disabled={converting} icon="download">
            {converting ? t.convertingBtn : t.convertBtn}
          </Button>
        </form>

        {result && (
          <Banner tone="ok" icon="check" title={t.resultTitle} className="zs-bunker__block">
            <p className="zs-t-caption">
              {t.resultSummary(result.detected_provider, result.conversations_count, result.markdown_files.length)}
            </p>
            <Mono className="zs-path">{result.output_dir}</Mono>
            {result.restore_prompt_preview && (
              <pre className="zs-bunker__preview">{result.restore_prompt_preview}</pre>
            )}
            <div className="zs-bunker__actions">
              <Button
                size="sm"
                icon={copied ? "check" : "copy"}
                onClick={handleCopyPrompt}
              >
                {copied ? t.copiedPreview : t.copyPreview}
              </Button>
            </div>
          </Banner>
        )}
      </div>
    </EmptyState>
  );
}

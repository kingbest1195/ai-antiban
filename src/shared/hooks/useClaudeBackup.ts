import { useCallback, useEffect, useRef, useState } from "react";
import type { ClaudeExportResult, ClaudeLocalDataSummary, ProviderId } from "../../types";
import { cleanAppCache, exportClaudeLocalData, scanClaudeLocalData } from "../../utils/api";
import { writeClipboard } from "../lib/clipboard";
import { common, toast as t } from "../copy/ru";
import type { ShowToast } from "./useToasts";

/** Бэкап и очистка данных Claude для вкладки «Бэкап». Выгрузка запускается и из трея, поэтому хук живёт в оболочке. */
export function useClaudeBackup(showToast: ShowToast) {
  const [claudeSummary, setClaudeSummary] = useState<ClaudeLocalDataSummary | null>(null);
  const [loadingClaudeSummary, setLoadingClaudeSummary] = useState<boolean>(false);
  const [claudeExporting, setClaudeExporting] = useState<boolean>(false);
  const [claudeExportResult, setClaudeExportResult] = useState<ClaudeExportResult | null>(null);
  const [copiedPrompt, setCopiedPrompt] = useState<boolean>(false);
  const [cleaningClaude, setCleaningClaude] = useState<boolean>(false);
  const [cleaningGpt, setCleaningGpt] = useState<boolean>(false);
  const copiedTimer = useRef<number | undefined>(undefined);

  useEffect(() => () => window.clearTimeout(copiedTimer.current), []);

  const loadClaudeSummary = useCallback(async () => {
    setLoadingClaudeSummary(true);
    try {
      const summary = await scanClaudeLocalData();
      setClaudeSummary(summary);
    } catch (err: any) {
      console.error("Failed to scan Claude data:", err);
    } finally {
      setLoadingClaudeSummary(false);
    }
  }, []);

  const handleExportClaude = useCallback(async () => {
    setClaudeExporting(true);
    try {
      const res = await exportClaudeLocalData();
      setClaudeExportResult(res);
      showToast(t.backup.exported, t.backup.exportedText(res.zip_archive_path || res.export_dir_path), "success");
    } catch (err: any) {
      showToast(t.backup.exportError, err?.message || String(err), "error");
    } finally {
      setClaudeExporting(false);
    }
  }, [showToast]);

  const handleCopyRestorePrompt = useCallback(async () => {
    try {
      let promptText = claudeExportResult?.restore_prompt_text;
      if (!promptText) {
        setClaudeExporting(true);
        const res = await exportClaudeLocalData();
        setClaudeExportResult(res);
        promptText = res.restore_prompt_text;
        setClaudeExporting(false);
      }
      if (promptText) {
        const ok = await writeClipboard(promptText);
        if (!ok) {
          showToast(t.backup.promptError, common.copyFailText, "error");
          return;
        }
        setCopiedPrompt(true);
        showToast(t.backup.promptCopied, t.backup.promptCopiedText, "success");
        window.clearTimeout(copiedTimer.current);
        copiedTimer.current = window.setTimeout(() => setCopiedPrompt(false), 2000);
      }
    } catch (err: any) {
      setClaudeExporting(false);
      showToast(t.backup.promptError, err?.message || String(err), "error");
    }
  }, [claudeExportResult, showToast]);

  const handleCleanSpecificClientCache = useCallback(
    async (provider: ProviderId) => {
      const isClaude = provider === "anthropic";
      if (isClaude) setCleaningClaude(true);
      else setCleaningGpt(true);

      try {
        const res = await cleanAppCache(provider);
        const totalFiles = res.files_removed || 0;
        const mbFreed = ((res.bytes_freed || 0) / (1024 * 1024)).toFixed(1);
        const clientName = isClaude ? "Claude Desktop" : "ChatGPT Desktop";
        showToast(t.backup.cacheCleaned(clientName), t.backup.cacheCleanedText(totalFiles, mbFreed), "success");
      } catch (err: any) {
        showToast(t.backup.cacheError, err?.message || String(err), "error");
      } finally {
        if (isClaude) setCleaningClaude(false);
        else setCleaningGpt(false);
      }
    },
    [showToast],
  );

  return {
    claudeSummary,
    loadingClaudeSummary,
    claudeExporting,
    claudeExportResult,
    copiedPrompt,
    cleaningClaude,
    cleaningGpt,
    loadClaudeSummary,
    handleExportClaude,
    handleCopyRestorePrompt,
    handleCleanSpecificClientCache,
  };
}

export type ClaudeBackup = ReturnType<typeof useClaudeBackup>;

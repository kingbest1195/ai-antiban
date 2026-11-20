import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanAppCache, exportClaudeLocalData } from "../../utils/api";
import { backup as backupCopy, common, toast as t } from "../copy/ru";
import { writeClipboard } from "../lib/clipboard";
import { useClaudeBackup } from "./useClaudeBackup";
import type { ClaudeBackup } from "./useClaudeBackup";
import type { ShowToast } from "./useToasts";

vi.mock("../../utils/api", () => ({
  cleanAppCache: vi.fn(),
  exportClaudeLocalData: vi.fn(),
  scanClaudeLocalData: vi.fn(),
}));

vi.mock("../lib/clipboard", () => ({
  writeClipboard: vi.fn(),
}));

const mockedClean = vi.mocked(cleanAppCache);
const mockedExport = vi.mocked(exportClaudeLocalData);
const mockedWriteClipboard = vi.mocked(writeClipboard);

function mountHook(showToast: ShowToast): ClaudeBackup {
  let out: ClaudeBackup | null = null;
  const Probe = () => {
    out = useClaudeBackup(showToast);
    return null;
  };
  renderToStaticMarkup(createElement(Probe));
  if (!out) throw new Error("useClaudeBackup probe failed");
  return out;
}

describe("useClaudeBackup.handleCopyRestorePrompt", () => {
  beforeEach(() => {
    mockedExport.mockReset();
    mockedWriteClipboard.mockReset();
    vi.stubGlobal("window", {
      clearTimeout: vi.fn(),
      setTimeout: vi.fn(() => 1),
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("показывает toast успеха при успешном writeClipboard", async () => {
    mockedExport.mockResolvedValue({
      export_dir_path: "/tmp/export",
      zip_archive_path: "/tmp/export.zip",
      index_summary_path: "/tmp/export/index.md",
      restore_prompt_path: "/tmp/export/prompt.txt",
      restore_prompt_text: "RESTORE PROMPT",
      projects_exported: 1,
      sessions_exported: 2,
      total_bytes: 100,
    });
    mockedWriteClipboard.mockResolvedValue(true);

    const showToast = vi.fn();
    const hook = mountHook(showToast);
    await hook.handleCopyRestorePrompt();

    expect(mockedWriteClipboard).toHaveBeenCalledWith("RESTORE PROMPT");
    expect(showToast).toHaveBeenCalledWith(t.backup.promptCopied, t.backup.promptCopiedText, "success");
  });

  it("показывает toast.backup.promptError и не показывает успех, если writeClipboard вернул false", async () => {
    mockedExport.mockResolvedValue({
      export_dir_path: "/tmp/export",
      zip_archive_path: "/tmp/export.zip",
      index_summary_path: "/tmp/export/index.md",
      restore_prompt_path: "/tmp/export/prompt.txt",
      restore_prompt_text: "RESTORE PROMPT",
      projects_exported: 1,
      sessions_exported: 2,
      total_bytes: 100,
    });
    mockedWriteClipboard.mockResolvedValue(false);

    const showToast = vi.fn();
    const hook = mountHook(showToast);
    await hook.handleCopyRestorePrompt();

    expect(mockedWriteClipboard).toHaveBeenCalledWith("RESTORE PROMPT");
    expect(showToast).toHaveBeenCalledTimes(1);
    expect(showToast).toHaveBeenCalledWith(t.backup.promptError, common.copyFailText, "error");
  });
});

describe("useClaudeBackup.handleCleanSpecificClientCache", () => {
  beforeEach(() => {
    mockedClean.mockReset();
    vi.stubGlobal("window", {
      clearTimeout: vi.fn(),
      setTimeout: vi.fn(() => 1),
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("показывает info-тост, если каталог приложения не найден (found_dir: false)", async () => {
    mockedClean.mockResolvedValue({
      provider: "anthropic",
      cleaned_targets: [],
      files_removed: 0,
      bytes_freed: 0,
      success: true,
      message: "not found",
      found_dir: false,
      locked_targets: [],
    });

    const showToast = vi.fn();
    const hook = mountHook(showToast);
    await hook.handleCleanSpecificClientCache("anthropic");

    expect(showToast).toHaveBeenCalledTimes(1);
    expect(showToast).toHaveBeenCalledWith(
      backupCopy.cache.notFoundTitle("Claude Desktop"),
      backupCopy.cache.notFoundText("Claude Desktop"),
      "info",
    );
  });

  it("показывает info-тост при files_removed === 0 и пустом locked_targets (уже чисто)", async () => {
    mockedClean.mockResolvedValue({
      provider: "openai",
      cleaned_targets: [],
      files_removed: 0,
      bytes_freed: 0,
      success: true,
      message: "already clean",
      found_dir: true,
      locked_targets: [],
    });

    const showToast = vi.fn();
    const hook = mountHook(showToast);
    await hook.handleCleanSpecificClientCache("openai");

    expect(showToast).toHaveBeenCalledTimes(1);
    expect(showToast).toHaveBeenCalledWith(
      backupCopy.cache.alreadyCleanTitle("ChatGPT Desktop"),
      backupCopy.cache.alreadyCleanText("ChatGPT Desktop"),
      "info",
    );
  });

  it("показывает warning-тост с перечислением заблокированных файлов при непустом locked_targets", async () => {
    mockedClean.mockResolvedValue({
      provider: "anthropic",
      cleaned_targets: ["Cache"],
      files_removed: 3,
      bytes_freed: 1024,
      success: false,
      message: "locked",
      found_dir: true,
      locked_targets: ["Cookies", "Local Storage"],
    });

    const showToast = vi.fn();
    const hook = mountHook(showToast);
    await hook.handleCleanSpecificClientCache("anthropic");

    expect(showToast).toHaveBeenCalledTimes(1);
    const [title, desc, kind] = showToast.mock.calls[0];
    expect(title).toBe(backupCopy.cache.lockedTitle("Claude Desktop"));
    expect(desc).toContain("Cookies");
    expect(desc).toContain("Local Storage");
    expect(desc).toContain("Claude Desktop");
    expect(kind).toBe("warning");
  });

  it("показывает success-тост при нормальной очистке файлов без блокировок", async () => {
    mockedClean.mockResolvedValue({
      provider: "anthropic",
      cleaned_targets: ["Cookies", "ant-device-registry.json"],
      files_removed: 18,
      bytes_freed: 14200000,
      success: true,
      message: "cleaned",
      found_dir: true,
      locked_targets: [],
    });

    const showToast = vi.fn();
    const hook = mountHook(showToast);
    await hook.handleCleanSpecificClientCache("anthropic");

    expect(showToast).toHaveBeenCalledTimes(1);
    expect(showToast).toHaveBeenCalledWith(
      t.backup.cacheCleaned("Claude Desktop"),
      t.backup.cacheCleanedText(18, "13.5"),
      "success",
    );
  });
});

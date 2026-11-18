import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { exportClaudeLocalData } from "../../utils/api";
import { common, toast as t } from "../copy/ru";
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

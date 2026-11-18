import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { copyTextToClipboard } from "../../utils/api";
import { writeClipboard } from "./clipboard";

vi.mock("../../utils/api", () => ({
  copyTextToClipboard: vi.fn(),
}));

const mockedNativeCopy = vi.mocked(copyTextToClipboard);

describe("writeClipboard", () => {
  beforeEach(() => {
    mockedNativeCopy.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("использует нативную команду Tauri в первую очередь и не обращается к navigator.clipboard", async () => {
    mockedNativeCopy.mockResolvedValue(true);
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });

    await expect(writeClipboard("hello-tauri")).resolves.toBe(true);
    expect(mockedNativeCopy).toHaveBeenCalledWith("hello-tauri");
    expect(writeText).not.toHaveBeenCalled();
  });

  it("переходит к navigator.clipboard.writeText, когда нативная команда возвращает false", async () => {
    mockedNativeCopy.mockResolvedValue(false);
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });

    await expect(writeClipboard("browser-fallback")).resolves.toBe(true);
    expect(mockedNativeCopy).toHaveBeenCalledWith("browser-fallback");
    expect(writeText).toHaveBeenCalledWith("browser-fallback");
  });

  it("переходит к document.execCommand('copy') при ошибке обоих основных путей и удаляет textarea", async () => {
    mockedNativeCopy.mockRejectedValue(new Error("tauri unavailable"));
    const writeText = vi.fn().mockRejectedValue(new Error("user activation expired"));
    vi.stubGlobal("navigator", { clipboard: { writeText } });

    const appended: unknown[] = [];
    const removed: unknown[] = [];
    const textarea = {
      value: "",
      style: {} as Record<string, string>,
      setAttribute: vi.fn(),
      select: vi.fn(),
    };
    const execCommand = vi.fn().mockReturnValue(true);

    vi.stubGlobal("document", {
      createElement: vi.fn().mockReturnValue(textarea),
      execCommand,
      body: {
        appendChild: (node: unknown) => appended.push(node),
        removeChild: (node: unknown) => removed.push(node),
      },
    });

    await expect(writeClipboard("exec-fallback")).resolves.toBe(true);
    expect(textarea.value).toBe("exec-fallback");
    expect(textarea.select).toHaveBeenCalledTimes(1);
    expect(execCommand).toHaveBeenCalledWith("copy");
    expect(appended).toEqual([textarea]);
    expect(removed).toEqual([textarea]);
  });

  it("возвращает false при отказе всех способов и не оставляет textarea в DOM", async () => {
    mockedNativeCopy.mockResolvedValue(false);
    vi.stubGlobal("navigator", {
      clipboard: {
        writeText: vi.fn().mockRejectedValue(new Error("denied")),
      },
    });

    const removed: unknown[] = [];
    const textarea = {
      value: "",
      style: {} as Record<string, string>,
      setAttribute: vi.fn(),
      select: vi.fn(() => {
        throw new Error("select failed");
      }),
    };

    vi.stubGlobal("document", {
      createElement: vi.fn().mockReturnValue(textarea),
      execCommand: vi.fn().mockReturnValue(false),
      body: {
        appendChild: vi.fn(),
        removeChild: (node: unknown) => removed.push(node),
      },
    });

    await expect(writeClipboard("all-fail")).resolves.toBe(false);
    expect(removed).toEqual([textarea]);
  });

  it("возвращает false в среде без document, когда нативный и navigator.clipboard недоступны", async () => {
    mockedNativeCopy.mockResolvedValue(false);
    vi.stubGlobal("navigator", {});
    vi.stubGlobal("document", undefined);

    await expect(writeClipboard("headless")).resolves.toBe(false);
  });
});

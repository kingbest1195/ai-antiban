import { copyTextToClipboard } from "../../utils/api";

/**
 * Надёжная запись текста в системный буфер обмена (macOS WKWebView / Windows / браузер).
 * Порядок: нативная команда Tauri (`pbcopy` / Win32), затем `navigator.clipboard.writeText`,
 * затем резервный путь через скрытый `<textarea>` и `document.execCommand("copy")`.
 */
export async function writeClipboard(text: string): Promise<boolean> {
  try {
    if (await copyTextToClipboard(text)) {
      return true;
    }
  } catch {
    // fallback below
  }

  if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // fallback below
    }
  }

  if (typeof document === "undefined" || !document.body) {
    return false;
  }

  const el = document.createElement("textarea");
  el.value = text;
  el.setAttribute("readonly", "");
  el.style.position = "fixed";
  el.style.opacity = "0";
  document.body.appendChild(el);
  try {
    el.select();
    return document.execCommand("copy");
  } catch {
    return false;
  } finally {
    document.body.removeChild(el);
  }
}

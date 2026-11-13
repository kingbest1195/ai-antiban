import { useState } from "react";
import { Button } from "../../ui";
import type { ButtonSize, ButtonVariant } from "../../ui";
import { getErrorDiagnostics } from "../../utils/api";

interface CopyErrorLogButtonProps {
  title?: string;
  message?: string;
  size?: ButtonSize;
  variant?: ButtonVariant;
}

function fallbackFormat(title?: string, message?: string): string {
  return [
    `Time: ${new Date().toISOString()}`,
    title ? `Error title: ${title}` : null,
    message ? `Error text: ${message}` : null,
    typeof navigator !== "undefined" ? `UA: ${navigator.userAgent}` : null,
  ]
    .filter(Boolean)
    .join("\n");
}

async function writeClipboard(text: string): Promise<boolean> {
  if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // fallback below
    }
  }
  if (typeof document === "undefined") return false;
  try {
    const el = document.createElement("textarea");
    el.value = text;
    el.setAttribute("readonly", "");
    el.style.position = "fixed";
    el.style.opacity = "0";
    document.body.appendChild(el);
    el.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(el);
    return ok;
  } catch {
    return false;
  }
}

/** Кнопка копирования диагностического лога для быстрого разбора ошибок с macOS/Windows. */
export function CopyErrorLogButton({
  title,
  message,
  size = "sm",
  variant = "quiet",
}: CopyErrorLogButtonProps) {
  const [status, setStatus] = useState<"idle" | "busy" | "copied" | "failed">("idle");

  const handleCopy = async () => {
    if (status === "busy") return;
    setStatus("busy");
    let text = "";
    try {
      text = await getErrorDiagnostics(title, message);
    } catch {
      text = fallbackFormat(title, message);
    }
    if (!text.trim()) text = fallbackFormat(title, message);
    const ok = await writeClipboard(text);
    setStatus(ok ? "copied" : "failed");
    window.setTimeout(() => setStatus("idle"), 2500);
  };

  const label =
    status === "busy"
      ? "Собираем лог…"
      : status === "copied"
        ? "Лог скопирован"
        : status === "failed"
          ? "Не удалось скопировать"
          : "Скопировать лог";

  return (
    <Button
      size={size}
      variant={variant}
      icon={status === "copied" ? "check" : "copy"}
      disabled={status === "busy"}
      onClick={() => void handleCopy()}
    >
      {label}
    </Button>
  );
}

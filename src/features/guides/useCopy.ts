import { useCallback, useEffect, useRef, useState } from "react";
import type { ShowToast } from "../../shared/hooks";
import { writeClipboard } from "../../shared/lib/clipboard";
import { common } from "../../shared/copy/ru";

interface CopyNotice {
  title: string;
  text?: string;
}

/** Копирование в буфер: запоминает, что именно скопировано (2,5 с), и показывает уведомление. */
export function useCopy(onToast?: ShowToast, resetMs = 2500) {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const timer = useRef<number | undefined>(undefined);

  useEffect(() => () => window.clearTimeout(timer.current), []);

  const copy = useCallback(
    async (id: string, value: string, notice?: CopyNotice) => {
      const ok = await writeClipboard(value);
      if (ok) {
        setCopiedId(id);
        window.clearTimeout(timer.current);
        timer.current = window.setTimeout(() => setCopiedId(null), resetMs);
        if (notice) onToast?.(notice.title, notice.text, "success");
      } else {
        onToast?.(common.copyFailTitle, common.copyFailText, "error");
      }
    },
    [onToast, resetMs],
  );

  return { copiedId, copy };
}

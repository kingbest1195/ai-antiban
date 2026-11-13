import { createContext, useContext } from "react";
import type { ShowToast } from "../../shared/hooks";

export interface GuideContextValue {
  currentIp: string;
  currentCountry: string;
  currentTimezone?: string;
  onPinIp?: (ip: string) => void;
  onToast?: ShowToast;
  /** Какой блок только что скопирован (для подписи «Скопировано»). */
  copiedId: string | null;
  copy: (id: string, value: string, notice?: { title: string; text?: string }) => Promise<void>;
}

export const GuideContext = createContext<GuideContextValue | null>(null);

export function useGuide(): GuideContextValue {
  const ctx = useContext(GuideContext);
  if (!ctx) throw new Error("useGuide: нет GuideContext");
  return ctx;
}

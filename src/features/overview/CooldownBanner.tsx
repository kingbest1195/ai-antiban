import { useEffect, useState } from "react";
import { Banner, Button } from "../../ui";
import { overview as copy } from "../../shared/copy/ru";
import type { ShowToast } from "../../shared/hooks";
import { clearIpChangeCooldown } from "../../utils/api";
import { formatCooldownHms } from "../backup/profileModel";

export interface CooldownBannerProps {
  cooldownUntil?: number | null;
  onCleared?: () => Promise<unknown> | void;
  onToast?: ShowToast;
}

/** Возвращает оставшееся время паузы в секундах (0, если пауза неактивна или истекла). */
export function remainingCooldownSeconds(
  cooldownUntil: number | null | undefined,
  nowSec: number = Math.floor(Date.now() / 1000),
): number {
  if (typeof cooldownUntil !== "number" || !Number.isFinite(cooldownUntil)) return 0;
  return Math.max(0, Math.floor(cooldownUntil - nowSec));
}

/** Живой баннер 4-часового таймера после безопасного выхода из Claude с кнопкой сброса. */
export function CooldownBanner({ cooldownUntil, onCleared, onToast }: CooldownBannerProps) {
  const [nowSec, setNowSec] = useState<number>(() => Math.floor(Date.now() / 1000));
  const [clearing, setClearing] = useState(false);
  const [clearedFor, setClearedFor] = useState<number | null>(null);

  const isSuppressed = clearedFor !== null && clearedFor === cooldownUntil;
  const remaining = isSuppressed ? 0 : remainingCooldownSeconds(cooldownUntil, nowSec);

  useEffect(() => {
    setNowSec(Math.floor(Date.now() / 1000));
    if (typeof cooldownUntil !== "number" || cooldownUntil <= Math.floor(Date.now() / 1000)) {
      return;
    }
    const id = window.setInterval(() => {
      setNowSec(Math.floor(Date.now() / 1000));
    }, 1000);
    return () => window.clearInterval(id);
  }, [cooldownUntil]);

  if (remaining <= 0) return null;

  const handleClear = async () => {
    if (clearing) return;
    setClearing(true);
    try {
      await clearIpChangeCooldown();
      setClearedFor(cooldownUntil ?? null);
      onToast?.(copy.banner.cooldown.clearedTitle, copy.banner.cooldown.clearedText, "info");
      await onCleared?.();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      onToast?.(copy.banner.cooldown.clearError, msg, "error");
    } finally {
      setClearing(false);
    }
  };

  return (
    <Banner
      tone="warn"
      title={copy.banner.cooldown.title}
      action={
        <Button size="sm" variant="secondary" disabled={clearing} onClick={handleClear}>
          {clearing ? copy.banner.cooldown.clearing : copy.banner.cooldown.clear}
        </Button>
      }
    >
      {copy.banner.cooldown.text(formatCooldownHms(remaining))}
    </Banner>
  );
}

import { openUrl } from "@tauri-apps/plugin-opener";
import { getBotRenewUrl } from "../shared/lib/zastavaKey";

export const TELEGRAM_SUPPORT_URL = "https://t.me/nomadnocode";
export const TELEGRAM_FALLBACK_URL = "https://telegram.me/nomadnocode";

export async function openExternal(url: string): Promise<void> {
  try {
    await openUrl(url);
  } catch (err) {
    console.warn("Failed to open URL via plugin-opener, falling back to window.open", err);
    try {
      window.open(url, "_blank", "noopener,noreferrer");
    } catch {
      // Ignored
    }
  }
}

/**
 * Opens Telegram support contact: tries https://t.me/nomadnocode,
 * and falls back to https://telegram.me/nomadnocode if needed.
 */
export async function openTelegramSupport(): Promise<void> {
  try {
    await openExternal(TELEGRAM_SUPPORT_URL);
  } catch {
    await openExternal(TELEGRAM_FALLBACK_URL);
  }
}

export async function openZastavaBot(routeId?: string | null): Promise<void> {
  await openExternal(getBotRenewUrl(routeId));
}

import type { AppStateData } from "../../types";
import { isTauri, tauriInvoke } from "./client";
import { mockState, snapshotMockState } from "./mocks/state";

// Примечание: прогрев профиля Чистой комнаты (`startCleanProfileWarmup`) находится в `./cleanRoom.ts`.

/** Завершить 5-шаговый онбординг v3.0 (устанавливает onboarding_v3_done и whats_new_v3_seen в true). */
export async function completeOnboardingV3(): Promise<AppStateData> {
  if (isTauri()) {
    return await tauriInvoke<AppStateData>("complete_onboarding_v3");
  }
  mockState.onboarding_v3_done = true;
  mockState.onboarding_v2_2_done = true;
  mockState.whats_new_v3_seen = true;
  return snapshotMockState();
}

/** Отметить экран «Что нового в v3.0» как просмотренный. */
export async function markWhatsNewV3Seen(): Promise<AppStateData> {
  if (isTauri()) {
    return await tauriInvoke<AppStateData>("mark_whats_new_v3_seen");
  }
  mockState.whats_new_v3_seen = true;
  return snapshotMockState();
}

/** Скрыть контекстную подсказку HintCard и сохранить её id в dismissed_hints. */
export async function dismissHint(hintId: string): Promise<AppStateData> {
  if (isTauri()) {
    return await tauriInvoke<AppStateData>("dismiss_hint", { hintId });
  }
  const cleanId = hintId.trim();
  if (cleanId) {
    const existing = mockState.dismissed_hints ?? [];
    if (!existing.includes(cleanId)) {
      mockState.dismissed_hints = [...existing, cleanId];
    }
  }
  return snapshotMockState();
}

/** Сбросить все скрытые подсказки HintCard (`dismissed_hints = []`). */
export async function resetDismissedHints(): Promise<AppStateData> {
  if (isTauri()) {
    return await tauriInvoke<AppStateData>("reset_dismissed_hints");
  }
  mockState.dismissed_hints = [];
  return snapshotMockState();
}

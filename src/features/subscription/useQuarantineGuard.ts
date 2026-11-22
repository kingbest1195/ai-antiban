import { useEffect, useState } from "react";
import type { PostPaymentQuarantineStatus } from "../../types";
import {
  getPostPaymentQuarantineStatus,
  overridePostPaymentQuarantine,
} from "../../utils/api";

const quarantineListeners = new Set<() => void>();

/** Уведомляет все смонтированные useQuarantineGuard / PostPaymentQuarantineCard об изменении статуса карантина. */
export function notifyQuarantineUpdated(): void {
  for (const listener of Array.from(quarantineListeners)) {
    listener();
  }
}

export function subscribeQuarantineUpdated(listener: () => void): () => void {
  quarantineListeners.add(listener);
  return () => {
    quarantineListeners.delete(listener);
  };
}

export interface UseQuarantineGuardOptions {
  profileId?: string | null;
  initialStatus?: PostPaymentQuarantineStatus | null;
  refreshKey?: number;
}

/**
 * Перехватывает смену страны/сервера ключа или маршрута профиля при активном 72ч карантине,
 * открывая подтверждающее модальное окно с явным override («Сменить всё равно»).
 */
export function useQuarantineGuard({
  profileId,
  initialStatus,
  refreshKey = 0,
}: UseQuarantineGuardOptions = {}) {
  const [quarantineStatus, setQuarantineStatus] = useState<PostPaymentQuarantineStatus | null>(
    initialStatus ?? null,
  );
  const [pendingAction, setPendingAction] = useState<(() => Promise<void> | void) | null>(null);
  const [overriding, setOverriding] = useState<boolean>(false);

  const refreshQuarantine = async () => {
    try {
      const next = await getPostPaymentQuarantineStatus(profileId ?? null);
      setQuarantineStatus(next);
      return next;
    } catch {
      return null;
    }
  };

  useEffect(() => {
    if (initialStatus !== undefined) {
      setQuarantineStatus(initialStatus);
      return;
    }
    let cancelled = false;
    getPostPaymentQuarantineStatus(profileId ?? null)
      .then((next) => {
        if (!cancelled) setQuarantineStatus(next);
      })
      .catch(() => {});
    const unsubscribe = subscribeQuarantineUpdated(() => {
      getPostPaymentQuarantineStatus(profileId ?? null)
        .then((next) => {
          if (!cancelled) setQuarantineStatus(next);
        })
        .catch(() => {});
    });
    return () => {
      cancelled = true;
      unsubscribe();
    };
  }, [initialStatus, profileId, refreshKey]);

  const guardRouteSwitch = (action: () => Promise<void> | void) => {
    if (quarantineStatus?.active) {
      setPendingAction(() => action);
      return true;
    }
    void action();
    return false;
  };

  const confirmOverrideAndRun = async () => {
    if (!pendingAction || overriding) return;
    const action = pendingAction;
    setOverriding(true);
    try {
      const updated = await overridePostPaymentQuarantine(
        profileId ?? null,
        "explicit_route_switch",
      );
      setQuarantineStatus(updated);
      notifyQuarantineUpdated();
      setPendingAction(null);
      await action();
    } finally {
      setOverriding(false);
    }
  };

  const cancelOverride = () => {
    if (!overriding) setPendingAction(null);
  };

  return {
    quarantineStatus,
    refreshQuarantine,
    overrideModalOpen: pendingAction !== null,
    overriding,
    guardRouteSwitch,
    confirmOverrideAndRun,
    cancelOverride,
  };
}

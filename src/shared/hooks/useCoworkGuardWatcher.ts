import { useCallback, useEffect, useRef, useState } from "react";
import type { CoworkGuardStatus } from "../../types";
import { onCoworkGuardStatus } from "../../utils/api/events";
import { getCoworkGuardStatus, installOrRepairCoworkGuard } from "../../utils/api/sysproxy";

export interface CoworkGuardRepairResult {
  status: CoworkGuardStatus | null;
  error: string | null;
}

export interface CoworkGuardWatcherState {
  status: CoworkGuardStatus | null;
  needsRepair: boolean;
  repairing: boolean;
  error: string | null;
  repair: () => Promise<CoworkGuardRepairResult | CoworkGuardStatus | null>;
  refresh: () => Promise<CoworkGuardStatus | null>;
}

export function isCoworkGuardNeedsRepair(status: CoworkGuardStatus | null): boolean {
  return Boolean(status?.supported && status?.needs_repair);
}

export interface CoworkWatcherDeps {
  getStatus: () => Promise<CoworkGuardStatus>;
  subscribe: (handler: (status: CoworkGuardStatus) => void) => Promise<() => void>;
  onStatus: (status: CoworkGuardStatus) => void;
  onError?: (err: unknown) => void;
}

/**
 * Запускает немедленную проверку статуса на mount (без 5с ожидания первого emit)
 * и подписывается на живые события `cowork-guard://status`.
 */
export function startCoworkGuardWatcher({
  getStatus,
  subscribe,
  onStatus,
  onError,
}: CoworkWatcherDeps): () => void {
  let active = true;
  let unlisten: (() => void) | undefined;

  // Немедленный fetch при монтировании — не ждём 5-секундного тика фонового воркера.
  getStatus()
    .then((initial) => {
      if (active) onStatus(initial);
    })
    .catch((err) => {
      if (active) onError?.(err);
    });

  subscribe((live) => {
    if (active) onStatus(live);
  })
    .then((fn) => {
      if (active) unlisten = fn;
      else fn();
    })
    .catch((err) => {
      if (active) onError?.(err);
    });

  return () => {
    active = false;
    unlisten?.();
  };
}

export interface CoworkRepairDeps {
  installOrRepair: () => Promise<CoworkGuardStatus>;
  onStatus: (status: CoworkGuardStatus) => void;
  onRepairingChange: (repairing: boolean) => void;
  onError: (message: string | null) => void;
}

export async function runCoworkGuardRepair({
  installOrRepair,
  onStatus,
  onRepairingChange,
  onError,
}: CoworkRepairDeps): Promise<CoworkGuardStatus | null> {
  onRepairingChange(true);
  onError(null);
  try {
    const updated = await installOrRepair();
    onStatus(updated);
    if (updated.needs_repair) {
      onError(
        updated.summary ||
          "Не удалось завершить защиту фоновой службы Claude. Проверьте права администратора или откройте настройки.",
      );
    }
    return updated;
  } catch (err: unknown) {
    onError(err instanceof Error ? err.message : String(err));
    return null;
  } finally {
    onRepairingChange(false);
  }
}

/**
 * Глобальный watcher статуса Windows CoworkVMService для оболочки приложения:
 * показывает спокойный warn-баннер даже при закрытых Настройках и снимает его после починки.
 */
export function useCoworkGuardWatcher(): CoworkGuardWatcherState {
  const [status, setStatus] = useState<CoworkGuardStatus | null>(null);
  const [repairing, setRepairing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    const stop = startCoworkGuardWatcher({
      getStatus: getCoworkGuardStatus,
      subscribe: onCoworkGuardStatus,
      onStatus: (next) => {
        if (mountedRef.current) {
          setStatus(next);
          if (!next.needs_repair) {
            setError(null);
          }
        }
      },
    });
    return () => {
      mountedRef.current = false;
      stop();
    };
  }, []);

  const refresh = useCallback(async () => {
    try {
      const next = await getCoworkGuardStatus();
      if (mountedRef.current) {
        setStatus(next);
        if (!next.needs_repair) {
          setError(null);
        }
      }
      return next;
    } catch (err: unknown) {
      if (mountedRef.current) {
        setError(err instanceof Error ? err.message : String(err));
      }
      return null;
    }
  }, []);

  const repair = useCallback(async (): Promise<CoworkGuardRepairResult> => {
    let latestError: string | null = null;
    const nextStatus = await runCoworkGuardRepair({
      installOrRepair: installOrRepairCoworkGuard,
      onStatus: (updated) => {
        if (mountedRef.current) setStatus(updated);
      },
      onRepairingChange: (next) => {
        if (mountedRef.current) setRepairing(next);
      },
      onError: (msg) => {
        latestError = msg;
        if (mountedRef.current) setError(msg);
      },
    });
    return { status: nextStatus, error: latestError };
  }, []);

  return {
    status,
    needsRepair: isCoworkGuardNeedsRepair(status),
    repairing,
    error,
    repair,
    refresh,
  };
}

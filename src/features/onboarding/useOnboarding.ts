import { useCallback, useEffect, useRef, useState } from "react";
import { completeOnboardingV3, fetchAppState } from "../../utils/api";
import { isTauri } from "../../utils/api/client";

/** Флаг «знакомство пройдено или пропущено» для версии 3.0 (хранится в state.json и кэшируется в localStorage). */
export const ONBOARDING_DONE_KEY = "zastava_onboarding_v3_done";

export const ONBOARDING_STEPS = 5;

export function readDoneFromStorage(): boolean {
  try {
    if (typeof window === "undefined" || !window.localStorage) return false;
    return window.localStorage.getItem(ONBOARDING_DONE_KEY) === "1";
  } catch {
    return false;
  }
}

export function writeDoneToStorage(done = true): void {
  try {
    if (typeof window === "undefined" || !window.localStorage) return;
    if (done) window.localStorage.setItem(ONBOARDING_DONE_KEY, "1");
    else window.localStorage.removeItem(ONBOARDING_DONE_KEY);
  } catch {
    // Хранилище недоступно (приватное окно, запрет): знакомство просто покажется снова.
  }
}

export async function readOnboardingDone(): Promise<boolean> {
  if (isTauri()) {
    try {
      const state = await fetchAppState();
      const done = Boolean(state.onboarding_v3_done);
      writeDoneToStorage(done);
      return done;
    } catch {
      return readDoneFromStorage();
    }
  }
  return readDoneFromStorage();
}

export async function persistOnboardingDone(done = true): Promise<void> {
  writeDoneToStorage(done);
  if (!done) return;
  try {
    await completeOnboardingV3();
  } catch {
    // Ошибка записи в state.json не должна блокировать закрытие онбординга; localStorage уже обновлён.
  }
}

interface Initial {
  open: boolean;
  /** 1…5; 5 — финальный экран. Параметр ?step= работает только в dev. */
  step: number;
  forced: boolean;
  isAlertWindow: boolean;
}

/** ?onboarding=1 открывает всегда, ?onboarding=0 подавляет; окно alert-popup — никогда. */
function readInitial(): Initial {
  if (typeof window === "undefined") {
    return { open: !readDoneFromStorage(), step: 1, forced: false, isAlertWindow: false };
  }
  const params = new URLSearchParams(window.location.search);
  const isAlertWindow =
    params.get("window") === "alert-popup" ||
    params.get("window") === "alert" ||
    window.location.hash === "#alert-popup" ||
    window.location.hash === "#alert";
  const forcedParam = params.get("onboarding");
  const forced = forcedParam === "1" || forcedParam === "0";

  let open = !readDoneFromStorage();
  if (forcedParam === "1") open = true;
  if (forcedParam === "0") open = false;
  if (isAlertWindow) open = false;

  let step = 1;
  if (import.meta.env.DEV) {
    const n = Number(params.get("step"));
    if (Number.isInteger(n) && n >= 1 && n <= ONBOARDING_STEPS) step = n;
  }
  return { open, step, forced, isAlertWindow };
}

/** Показ онбординга v3.0: первый запуск, повторный запуск из Настроек, запись `onboarding_v3_done`. */
export function useOnboarding() {
  const [initial] = useState(readInitial);
  const [open, setOpen] = useState(initial.open);
  /** Меняется при каждом запуске: сценарий монтируется заново и начинается с первого шага. */
  const [run, setRun] = useState(0);
  const userInteractedRef = useRef(false);

  // В Tauri гидратируем состояние из state.json и держим localStorage-кэш в синхронизации.
  useEffect(() => {
    if (initial.forced || initial.isAlertWindow || !isTauri()) return;
    let cancelled = false;
    readOnboardingDone().then((done) => {
      if (cancelled || userInteractedRef.current) return;
      setOpen(!done);
    });
    return () => {
      cancelled = true;
    };
  }, [initial.forced, initial.isAlertWindow]);

  const start = useCallback(() => {
    userInteractedRef.current = true;
    setRun((n) => n + 1);
    setOpen(true);
  }, []);

  /** Закрыть и запомнить: и «Пропустить», и обычное завершение. */
  const finish = useCallback(async () => {
    userInteractedRef.current = true;
    writeDoneToStorage(true);
    setOpen(false);
    await persistOnboardingDone(true);
  }, []);

  return { open, run, start, finish, initialStep: run === 0 ? initial.step : 1 };
}

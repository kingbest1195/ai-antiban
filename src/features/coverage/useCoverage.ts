import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { CoverageSnapshot } from "../../types";
import { getCoverageSnapshot, onWindowFocusChanged, recheckCoverage } from "../../utils/api";
import { pollInterval, resolveWaiting, startWaiting } from "./coverageModel";
import type { WaitingMap } from "./coverageModel";

const isVisible = () => typeof document === "undefined" || document.visibilityState !== "hidden";

/**
 * Состояние секции покрытия. Живёт, пока секция на экране (вкладка открыта):
 * обновляет снимок при возврате фокуса, по таймеру (5 с при неподтверждённых, 30 с иначе, ничего при скрытом окне)
 * и по кнопке «Проверить снова». Клиентское «ожидаем подтверждения» держит здесь же.
 */
export function useCoverage(initial?: CoverageSnapshot | null) {
  const [snapshot, setSnapshot] = useState<CoverageSnapshot | null>(initial ?? null);
  const [failed, setFailed] = useState(false);
  const [checking, setChecking] = useState(false);
  const [waiting, setWaiting] = useState<WaitingMap>({});
  const [now, setNow] = useState(() => Date.now());
  const [visible, setVisible] = useState(isVisible);
  // Ответы приходят не по порядку: применяем только самый свежий запрос.
  const seq = useRef(0);
  const applied = useRef(0);
  const alive = useRef(true);

  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  const apply = useCallback((snap: CoverageSnapshot, id: number) => {
    if (!alive.current || id < applied.current) return;
    applied.current = id;
    setSnapshot(snap);
    setFailed(false);
    setNow(Date.now());
    setWaiting((prev) => resolveWaiting(prev, snap.apps));
  }, []);

  const refresh = useCallback(async () => {
    const id = ++seq.current;
    try {
      apply(await getCoverageSnapshot(), id);
    } catch {
      if (alive.current && id >= applied.current) setFailed(true);
    }
  }, [apply]);

  /** «Проверить снова»: шлюз заново читает ОС и файлы; приложения «Настроено» переходят в «Ожидаем подтверждения…». */
  const recheck = useCallback(async () => {
    const id = ++seq.current;
    setChecking(true);
    try {
      const snap = await recheckCoverage();
      if (alive.current) setWaiting((prev) => startWaiting(prev, snap.apps, "configured", Date.now()));
      apply(snap, id);
    } catch {
      if (alive.current && id >= applied.current) setFailed(true);
    } finally {
      if (alive.current) setChecking(false);
    }
  }, [apply]);

  /** «Я настроил»: ждём первый запрос от этого приложения и сразу перечитываем состояние. */
  const confirmSetup = useCallback(
    async (appId: string) => {
      const id = ++seq.current;
      setWaiting((prev) => (snapshot ? startWaiting(prev, snapshot.apps, [appId], Date.now()) : prev));
      try {
        const snap = await recheckCoverage();
        apply(snap, id);
      } catch {
        if (alive.current && id >= applied.current) setFailed(true);
      }
    },
    [apply, snapshot],
  );

  // Первое чтение при открытии секции.
  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Возврат фокуса и видимость окна.
  useEffect(() => {
    const onVisibility = () => {
      const v = isVisible();
      setVisible(v);
      if (v) void refresh();
    };
    const onFocus = () => void refresh();
    document.addEventListener("visibilitychange", onVisibility);
    window.addEventListener("focus", onFocus);
    let unlisten: (() => void) | null = null;
    let cancelled = false;
    void onWindowFocusChanged((focused) => {
      if (focused) void refresh();
    }).then((off) => {
      if (cancelled) off();
      else unlisten = off;
    });
    return () => {
      cancelled = true;
      document.removeEventListener("visibilitychange", onVisibility);
      window.removeEventListener("focus", onFocus);
      unlisten?.();
    };
  }, [refresh]);

  const apps = snapshot?.apps;
  const cliMode = snapshot?.cli_mode;
  const interval = useMemo(() => pollInterval(visible, apps, cliMode), [visible, apps, cliMode]);

  // Таймер: 5 с / 30 с, при скрытом окне не тикает.
  useEffect(() => {
    if (interval <= 0) return;
    const timer = window.setInterval(() => void refresh(), interval);
    return () => window.clearInterval(timer);
  }, [interval, refresh]);

  return { snapshot, failed, checking, waiting, now, refresh, recheck, confirmSetup };
}

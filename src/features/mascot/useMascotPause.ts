import { useEffect, useState } from "react";
import { onWindowFocusChanged } from "../../utils/api/events";

export interface MascotPauseInput {
  visibilityState: DocumentVisibilityState | "visible" | "hidden";
  windowFocused: boolean;
  reducedMotion: boolean;
  forcePaused?: boolean;
}

/**
 * Чистая функция расчёта паузы анимаций маскота:
 * приостанавливает все циклы при скрытии вкладки/окна, потере фокуса или prefers-reduced-motion.
 */
export function shouldPauseMascot({
  visibilityState,
  windowFocused,
  reducedMotion,
  forcePaused = false,
}: MascotPauseInput): boolean {
  return Boolean(forcePaused || reducedMotion || visibilityState === "hidden" || !windowFocused);
}

function readInitialPauseState(forcePaused: boolean): MascotPauseInput {
  const hasDoc = typeof document !== "undefined";
  const hasWin = typeof window !== "undefined";
  const visibilityState = hasDoc ? document.visibilityState : "visible";
  const windowFocused = hasDoc && typeof document.hasFocus === "function" ? document.hasFocus() : true;
  const reducedMotion =
    hasWin && typeof window.matchMedia === "function"
      ? window.matchMedia("(prefers-reduced-motion: reduce)").matches
      : false;
  return { visibilityState, windowFocused, reducedMotion, forcePaused };
}

/**
 * Автоматически ставит анимации маскота и схем на паузу (.zs-mascot--paused),
 * когда окно свёрнуто в трей, потеряло фокус, страница скрыта или включён prefers-reduced-motion.
 * Поддерживает как браузерные события, так и Tauri-фокус через src/utils/api/events.
 */
export function useMascotPause(forcePaused = false): {
  paused: boolean;
  pauseClassName: string;
} {
  const [state, setState] = useState<MascotPauseInput>(() => readInitialPauseState(forcePaused));

  useEffect(() => {
    setState((prev) => ({ ...prev, forcePaused }));
  }, [forcePaused]);

  useEffect(() => {
    if (typeof document === "undefined" || typeof window === "undefined") {
      return;
    }

    const onVisibility = () => {
      setState((prev) => ({ ...prev, visibilityState: document.visibilityState }));
    };
    const onFocus = () => {
      setState((prev) => ({ ...prev, windowFocused: true }));
    };
    const onBlur = () => {
      setState((prev) => ({ ...prev, windowFocused: false }));
    };

    document.addEventListener("visibilitychange", onVisibility);
    window.addEventListener("focus", onFocus);
    window.addEventListener("blur", onBlur);

    const mediaQuery =
      typeof window.matchMedia === "function" ? window.matchMedia("(prefers-reduced-motion: reduce)") : null;
    const onMotionChange = (e: MediaQueryListEvent) => {
      setState((prev) => ({ ...prev, reducedMotion: e.matches }));
    };
    if (mediaQuery) {
      if (typeof mediaQuery.addEventListener === "function") {
        mediaQuery.addEventListener("change", onMotionChange);
      } else if (typeof mediaQuery.addListener === "function") {
        mediaQuery.addListener(onMotionChange);
      }
    }

    let active = true;
    let unlistenTauri: (() => void) | null = null;
    void onWindowFocusChanged((focused) => {
      if (!active) return;
      setState((prev) => ({ ...prev, windowFocused: focused }));
    }).then((unlisten) => {
      if (active) {
        unlistenTauri = unlisten;
      } else {
        unlisten();
      }
    });

    return () => {
      active = false;
      document.removeEventListener("visibilitychange", onVisibility);
      window.removeEventListener("focus", onFocus);
      window.removeEventListener("blur", onBlur);
      if (mediaQuery) {
        if (typeof mediaQuery.removeEventListener === "function") {
          mediaQuery.removeEventListener("change", onMotionChange);
        } else if (typeof mediaQuery.removeListener === "function") {
          mediaQuery.removeListener(onMotionChange);
        }
      }
      if (unlistenTauri) {
        unlistenTauri();
      }
    };
  }, []);

  const paused = shouldPauseMascot(state);
  return {
    paused,
    pauseClassName: paused ? "zs-mascot--paused" : "",
  };
}

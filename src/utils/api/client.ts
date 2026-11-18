import { invoke, isTauri as tauriIsTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

export function isTauri(): boolean {
  try {
    return typeof window !== "undefined" && tauriIsTauri();
  } catch {
    return false;
  }
}

export async function tauriInvoke<T>(
  cmd: string,
  args?: Record<string, unknown>,
): Promise<T> {
  return args === undefined ? await invoke<T>(cmd) : await invoke<T>(cmd, args);
}

export async function tauriListen<T>(
  event: string,
  handler: (payload: T) => void,
): Promise<() => void> {
  return await listen<T>(event, (e) => handler(e.payload));
}

export async function tauriOnWindowFocusChanged(
  handler: (focused: boolean) => void,
): Promise<() => void> {
  if (!isTauri()) return () => {};
  try {
    const { getCurrentWindow } = await import("@tauri-apps/api/window");
    return await getCurrentWindow().onFocusChanged(({ payload }) => handler(payload));
  } catch {
    return () => {};
  }
}

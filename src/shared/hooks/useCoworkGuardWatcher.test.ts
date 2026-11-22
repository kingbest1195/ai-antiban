import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { CoworkGuardStatus } from "../../types";

vi.mock("../../utils/api/events", () => ({
  onCoworkGuardStatus: vi.fn(async () => () => {}),
}));

vi.mock("../../utils/api/sysproxy", () => ({
  getCoworkGuardStatus: vi.fn(),
  installOrRepairCoworkGuard: vi.fn(),
}));

import { onCoworkGuardStatus } from "../../utils/api/events";
import { getCoworkGuardStatus, installOrRepairCoworkGuard } from "../../utils/api/sysproxy";
import {
  isCoworkGuardNeedsRepair,
  runCoworkGuardRepair,
  startCoworkGuardWatcher,
  useCoworkGuardWatcher,
  type CoworkGuardWatcherState,
} from "./useCoworkGuardWatcher";

const mockedGetStatus = vi.mocked(getCoworkGuardStatus);
const mockedRepair = vi.mocked(installOrRepairCoworkGuard);
const mockedSubscribe = vi.mocked(onCoworkGuardStatus);

function makeStatus(over: Partial<CoworkGuardStatus> = {}): CoworkGuardStatus {
  return {
    platform: "windows",
    supported: true,
    service_present: true,
    start_type: 2,
    service_running: true,
    task_installed: true,
    task_healthy: false,
    needs_repair: true,
    summary: "Служба CoworkVMService переключилась на автозапуск (Start = 2).",
    detected_ai_apps: [],
    ...over,
  };
}

function flushMicrotasks(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

describe("useCoworkGuardWatcher (Bug #7 global watcher)", () => {
  beforeEach(() => {
    mockedGetStatus.mockReset();
    mockedRepair.mockReset();
    mockedSubscribe.mockReset();
  });

  it("немедленно вызывает getCoworkGuardStatus() на mount без задержки и выставляет needsRepair", async () => {
    const degraded = makeStatus({ needs_repair: true, start_type: 2 });
    mockedGetStatus.mockResolvedValue(degraded);
    mockedSubscribe.mockResolvedValue(() => {});

    let current: CoworkGuardStatus | null = null;
    const stop = startCoworkGuardWatcher({
      getStatus: mockedGetStatus,
      subscribe: mockedSubscribe,
      onStatus: (next) => {
        current = next;
      },
    });

    // Вызов должен произойти синхронно в момент старта, без ожидания 5 секунд.
    expect(mockedGetStatus).toHaveBeenCalledTimes(1);
    expect(mockedSubscribe).toHaveBeenCalledTimes(1);

    await flushMicrotasks();

    expect(current).toEqual(degraded);
    expect(isCoworkGuardNeedsRepair(current)).toBe(true);
    stop();
  });

  it("обновляет статус по живому событию cowork-guard://status и отписывается при размонтировании", async () => {
    const healthy = makeStatus({ needs_repair: false, start_type: 4, task_healthy: true });
    const degraded = makeStatus({ needs_repair: true, start_type: 2, task_healthy: false });
    const unlisten = vi.fn();
    const listenerRef: { current: ((s: CoworkGuardStatus) => void) | null } = { current: null };

    mockedGetStatus.mockResolvedValue(healthy);
    mockedSubscribe.mockImplementation(async (cb) => {
      listenerRef.current = cb;
      return unlisten;
    });

    let current: CoworkGuardStatus | null = null;
    const stop = startCoworkGuardWatcher({
      getStatus: mockedGetStatus,
      subscribe: mockedSubscribe,
      onStatus: (next) => {
        current = next;
      },
    });

    await flushMicrotasks();
    expect(isCoworkGuardNeedsRepair(current)).toBe(false);

    listenerRef.current?.(degraded);
    expect(current).toEqual(degraded);
    expect(isCoworkGuardNeedsRepair(current)).toBe(true);

    stop();
    expect(unlisten).toHaveBeenCalledTimes(1);

    // После остановки поздние события не должны мутировать состояние.
    listenerRef.current?.(healthy);
    expect(current).toEqual(degraded);
  });

  it("repair() вызывает installOrRepairCoworkGuard и очищает предупреждение при needs_repair === false", async () => {
    const degraded = makeStatus({ needs_repair: true, start_type: 2 });
    const fixed = makeStatus({ needs_repair: false, start_type: 4, service_running: false, task_healthy: true });

    let current: CoworkGuardStatus | null = degraded;
    const repairingLog: boolean[] = [];
    const errors: (string | null)[] = [];
    mockedRepair.mockResolvedValue(fixed);

    const res = await runCoworkGuardRepair({
      installOrRepair: mockedRepair,
      onStatus: (next) => {
        current = next;
      },
      onRepairingChange: (val) => repairingLog.push(val),
      onError: (msg) => errors.push(msg),
    });

    expect(mockedRepair).toHaveBeenCalledTimes(1);
    expect(res).toEqual(fixed);
    expect(repairingLog).toEqual([true, false]);
    expect(errors).toEqual([null]);
    expect(isCoworkGuardNeedsRepair(current)).toBe(false);
  });

  it("runCoworkGuardRepair выставляет error = updated.summary, если updated.needs_repair === true", async () => {
    const stillBroken = makeStatus({
      needs_repair: true,
      start_type: 2,
      summary: "Задача планировщика создана, но служба всё ещё на автозапуске.",
    });
    let current: CoworkGuardStatus | null = null;
    const errors: (string | null)[] = [];
    mockedRepair.mockResolvedValue(stillBroken);

    const res = await runCoworkGuardRepair({
      installOrRepair: mockedRepair,
      onStatus: (next) => {
        current = next;
      },
      onRepairingChange: vi.fn(),
      onError: (msg) => errors.push(msg),
    });

    expect(res).toEqual(stillBroken);
    expect(current).toEqual(stillBroken);
    expect(errors).toEqual([null, stillBroken.summary]);
  });

  it("хук useCoworkGuardWatcher возвращает ожидаемый интерфейс и repair() вызывает installOrRepairCoworkGuard", async () => {
    const fixed = makeStatus({ needs_repair: false, start_type: 4, task_healthy: true });
    mockedRepair.mockResolvedValue(fixed);

    let hookState: CoworkGuardWatcherState | null = null;
    const Probe = () => {
      hookState = useCoworkGuardWatcher();
      return null;
    };
    renderToStaticMarkup(createElement(Probe));

    expect(hookState).not.toBeNull();
    expect(hookState!.status).toBeNull();
    expect(hookState!.needsRepair).toBe(false);
    expect(hookState!.repairing).toBe(false);

    const updated = await hookState!.repair();
    expect(mockedRepair).toHaveBeenCalledTimes(1);
    expect(updated).toEqual(fixed);
  });
});

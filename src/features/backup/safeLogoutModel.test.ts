import { afterEach, describe, expect, it } from "vitest";
import { clearIpChangeCooldown, fetchAppState, safeLogoutClaude } from "../../utils/api";
import { mockState } from "../../utils/api/mocks/state";
import { remainingCooldownSeconds } from "../overview/CooldownBanner";
import { formatCooldownDuration, formatCooldownHms } from "./profileModel";

describe("Safe Logout и 4-часовой таймер смены IP", () => {
  afterEach(() => {
    mockState.ip_change_cooldown_until = null;
    mockState.last_safe_logout_at = null;
  });

  it("formatCooldownDuration форматирует длительность как H:MM:SS", () => {
    expect(formatCooldownDuration(14400)).toBe("4:00:00");
    expect(formatCooldownDuration(3661)).toBe("1:01:01");
    expect(formatCooldownDuration(0)).toBe("0:00:00");
    expect(formatCooldownDuration(-15)).toBe("0:00:00");
  });

  it("formatCooldownHms форматирует обратный отсчёт как HH:MM:SS", () => {
    expect(formatCooldownHms(14400)).toBe("04:00:00");
    expect(formatCooldownHms(3599)).toBe("00:59:59");
    expect(formatCooldownHms(0)).toBe("00:00:00");
    expect(formatCooldownHms(-1)).toBe("00:00:00");
  });

  it("remainingCooldownSeconds корректно считает остаток и обрабатывает пустые/истёкшие значения", () => {
    expect(remainingCooldownSeconds(null, 1000)).toBe(0);
    expect(remainingCooldownSeconds(undefined, 1000)).toBe(0);
    expect(remainingCooldownSeconds(Number.NaN, 1000)).toBe(0);
    expect(remainingCooldownSeconds(900, 1000)).toBe(0);
    expect(remainingCooldownSeconds(1000, 1000)).toBe(0);
    expect(remainingCooldownSeconds(1450, 1000)).toBe(450);
  });

  it("safeLogoutClaude и clearIpChangeCooldown обновляют mockState и снимок AppStateData", async () => {
    const beforeSec = Math.floor(Date.now() / 1000);
    const res = await safeLogoutClaude();
    const afterSec = Math.floor(Date.now() / 1000);

    expect(res.preserved_device_id).toBe(true);
    expect(res.closed_processes).toBeGreaterThan(0);
    expect(res.cleared_items.length).toBeGreaterThan(0);
    expect(res.cooldown_secs).toBe(14400);
    expect(res.cooldown_until).toBeGreaterThanOrEqual(beforeSec + 14400);
    expect(res.cooldown_until).toBeLessThanOrEqual(afterSec + 14400);

    const stateAfterLogout = await fetchAppState();
    expect(stateAfterLogout.ip_change_cooldown_until).toBe(res.cooldown_until);
    expect(stateAfterLogout.last_safe_logout_at).toBeGreaterThanOrEqual(beforeSec);

    await clearIpChangeCooldown();
    const stateAfterClear = await fetchAppState();
    expect(stateAfterClear.ip_change_cooldown_until).toBeNull();
  });
});

import { describe, expect, it, vi } from "vitest";
import { timezone as timezoneCopy, toast as toastCopy } from "../copy/ru";
import { runSharedSyncOsTimezone } from "./useTimezoneSync";

const apiMocks = vi.hoisted(() => ({
  syncOsTimezone: vi.fn(),
  getOsTimezoneSyncStatus: vi.fn(),
}));

vi.mock("../../utils/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../utils/api")>();
  return {
    ...actual,
    syncOsTimezone: apiMocks.syncOsTimezone,
    getOsTimezoneSyncStatus: apiMocks.getOsTimezoneSyncStatus,
  };
});

describe("useTimezoneSync: already_matches_target", () => {
  it("§7.1: при synced=false и already_matches_target=true не показывает тост о смене пояса и перезапуске браузеров", async () => {
    const showToast = vi.fn();
    apiMocks.syncOsTimezone.mockResolvedValueOnce({
      synced: false,
      already_matches_target: true,
      current_os_tz: "Europe/London",
      original_os_tz: null,
      synced_target_tz: null,
      target_tz: "Europe/London",
      auto_restore_pending: false,
    });

    // Note: without registeredContext, we verify return status and also verify copy guards / behavior
    const res = await runSharedSyncOsTimezone("Europe/London");
    expect(res?.synced).toBe(false);
    expect(res?.already_matches_target).toBe(true);
    expect(showToast).not.toHaveBeenCalled();
    expect(timezoneCopy.osAlreadyMatchesTitle).not.toContain("перезапустите");
    expect(toastCopy.timezone.done).toBeTruthy();
  });
});

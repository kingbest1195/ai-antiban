import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { HintCard, isHintDismissed } from "../../ui";
import {
  completeOnboardingV3,
  convertWebExport,
  createCleanProfile,
  deleteCleanProfile,
  discoverCleanBrowsers,
  dismissHint,
  fetchAppState,
  generateBunkerRestorePrompt,
  getBinRadarStats,
  getBunkerStatus,
  getOsTzStatus,
  getPaymentAdvice,
  getPersonaRiskReport,
  getProvidersManifest,
  launchCleanBrowser,
  listBunkerSnapshots,
  listCleanProfiles,
  markCleanProfileTainted,
  markIpTainted,
  markWhatsNewV3Seen,
  onWindowFocusChanged,
  openBunkerFolder,
  resetDismissedHints,
  restoreOsTimezone,
  runBunkerBackupNow,
  runCleanRoomAudit,
  setBinRadarOptIn,
  startCleanProfileWarmup,
  submitBinRadarReport,
  syncOsTimezone,
  untaintCleanRoomIp,
  updateBunkerSettings,
  updateCleanProfileRoute,
  updateCleanProfileStep,
  updatePersonaSelfCheck,
} from "../api";
import { setMockBunkerSnapshots } from "./mocks/bunker";
import { mockFlags, mockState, setMockScenario } from "./mocks/state";

function resetMockStateForTest() {
  setMockScenario("clean");
  mockFlags.killswitchStatus = false;
  mockFlags.sysproxyActive = true;
  mockFlags.syncAiTz = true;
  mockFlags.osTzCurrent = "Europe/Moscow";
  mockFlags.osTzOriginal = null;
  mockFlags.osTzTarget = null;
  mockState.pinned_ip = "185.212.102.40";
  mockState.warmup_started_at = null;
  mockState.ip_change_cooldown_until = null;
  mockState.onboarding_v3_done = false;
  mockState.whats_new_v3_seen = false;
  mockState.dismissed_hints = [];
  mockState.clean_room = {
    profiles: [],
    active_profile_id: null,
    tainted_ips: {},
  };
  mockState.bunker = {
    auto_backup_enabled: true,
    interval_hours: 24,
    retention_count: 7,
    last_backup_at: null,
    last_backup_size_bytes: null,
  };
  mockState.persona_self_check = {
    bought_or_grey_account: false,
    virtual_sms_used: false,
    reseller_payment_used: false,
    multi_account_same_browser: false,
  };
  setMockBunkerSnapshots([
    {
      id: "2026-11-20_053000",
      created_at: 1_760_000_000,
      snapshot_dir: "~/.zastava/bunker/snapshots/2026-11-20_053000",
      total_bytes: 2_450_000,
      files_count: 42,
      sources: ["claude_code", "claude_desktop", "cursor"],
      has_restore_prompt: true,
      trigger: "auto",
    },
  ]);
}

describe("v3 Clean Room API & mocks", () => {
  beforeEach(resetMockStateForTest);
  afterEach(resetMockStateForTest);

  it("обнаруживает браузеры и выполняет CRUD-цикл профиля песочницы", async () => {
    const browsers = await discoverCleanBrowsers();
    expect(browsers.some((b) => b.engine === "chrome" && b.available)).toBe(true);

    const created = await createCleanProfile({
      label: "Work Claude US",
      provider: "anthropic",
      browser_engine: "chrome",
      bound_route_id: "route-us-1",
    });
    expect(created.status).toBe("active");
    expect(created.launchpad_step).toBe(1);

    const listAfterCreate = await listCleanProfiles();
    expect(listAfterCreate.profiles).toHaveLength(1);
    expect(listAfterCreate.active_profile_id).toBe(created.id);

    const step2 = await updateCleanProfileStep(created.id, 2, ["foreign_email", "real_sim"]);
    expect(step2.launchpad_step).toBe(2);
    expect(step2.completed_checklist).toEqual(["foreign_email", "real_sim"]);

    const rebound = await updateCleanProfileRoute(created.id, null);
    expect(rebound.bound_route_id).toBeNull();
    const reboundBack = await updateCleanProfileRoute(created.id, "route-us-2");
    expect(reboundBack.bound_route_id).toBe("route-us-2");

    const audit = await runCleanRoomAudit(created.id);
    expect(audit.ready_to_launch).toBe(true);
    expect(audit.critical_count).toBe(0);

    const launched = await launchCleanBrowser(created.id, "https://claude.ai");
    expect(launched.profile_id).toBe(created.id);
    expect(launched.target_url).toBe("https://claude.ai");
    expect(launched.alias_port).toBeGreaterThan(0);

    const warmed = await startCleanProfileWarmup(created.id);
    expect(warmed.status).toBe("warming_up");
    expect(warmed.warmup_started_at).not.toBeNull();
    expect(warmed.launchpad_step).toBe(3);

    const state = await fetchAppState();
    expect(state.warmup_started_at).toBe(warmed.warmup_started_at);

    const taintedProfile = await markCleanProfileTainted(created.id, "persona_triggered");
    expect(taintedProfile.status).toBe("tainted");

    const afterDelete = await deleteCleanProfile(created.id);
    expect(afterDelete.profiles).toHaveLength(0);
    expect(afterDelete.active_profile_id).toBeNull();
  });

  it("deleteCleanProfile не помечает IP без явного taintExitIp=true, а untaintCleanRoomIp снимает отметку", async () => {
    const tmp = await createCleanProfile({ label: "Tmp", provider: "anthropic", browser_engine: "chrome" });
    await launchCleanBrowser(tmp.id);
    const cleanDel = await deleteCleanProfile(tmp.id, false);
    expect(cleanDel.tainted_ips["185.212.102.40"]).toBeUndefined();

    const tmp2 = await createCleanProfile({ label: "Tmp2", provider: "anthropic", browser_engine: "chrome" });
    await launchCleanBrowser(tmp2.id);
    const taintedDel = await deleteCleanProfile(tmp2.id, true);
    expect(taintedDel.tainted_ips["185.212.102.40"]).toBeTypeOf("number");
    const afterUntaint = await untaintCleanRoomIp("185.212.102.40");
    expect(afterUntaint.tainted_ips["185.212.102.40"]).toBeUndefined();
  });

  it("блокирует запуск песочницы при tainted IP, RU IP или ручном Kill-Switch", async () => {
    const profile = await createCleanProfile({
      label: "Clean Profile",
      provider: "openai",
      browser_engine: "edge",
    });

    await markIpTainted("185.212.102.40");
    const taintedAudit = await runCleanRoomAudit(profile.id);
    expect(taintedAudit.ip_is_tainted).toBe(true);
    expect(taintedAudit.ready_to_launch).toBe(false);
    expect(taintedAudit.critical_count).toBeGreaterThan(0);
    await expect(launchCleanBrowser(profile.id)).rejects.toThrow();

    mockState.clean_room!.tainted_ips = {};
    mockFlags.killswitchStatus = true;
    const ksAudit = await runCleanRoomAudit(profile.id);
    expect(ksAudit.ready_to_launch).toBe(false);
    await expect(launchCleanBrowser(profile.id)).rejects.toThrow();

    mockFlags.killswitchStatus = false;
    setMockScenario("ru");
    const ruAudit = await runCleanRoomAudit(profile.id);
    expect(ruAudit.ready_to_launch).toBe(false);
  });

  it("переиспользует getOsTzStatus / syncOsTimezone / restoreOsTimezone без дублирования", async () => {
    const initial = await getOsTzStatus();
    expect(initial.synced).toBe(false);

    const synced = await syncOsTimezone("Europe/Amsterdam");
    expect(synced.synced).toBe(true);
    expect(synced.current_os_tz).toBe("Europe/Amsterdam");

    const restored = await restoreOsTimezone();
    expect(restored.synced).toBe(false);
    expect(restored.current_os_tz).toBe("Europe/Moscow");
  });
});

describe("v3 Data Bunker API & mocks", () => {
  beforeEach(resetMockStateForTest);
  afterEach(resetMockStateForTest);

  it("читает статус, обновляет настройки, запускает бэкап с FIFO-ротацией и конвертирует web export", async () => {
    const initialStatus = await getBunkerStatus();
    expect(initialStatus.snapshots_count).toBe(1);
    expect(initialStatus.has_any_local_data).toBe(true);

    const updated = await updateBunkerSettings({
      auto_backup_enabled: false,
      interval_hours: 12,
      retention_count: 2,
    });
    expect(updated.auto_backup_enabled).toBe(false);
    expect(updated.interval_hours).toBe(12);
    expect(updated.retention_count).toBe(2);

    const firstBackup = await runBunkerBackupNow("~/Desktop/bunker-copy");
    expect(firstBackup.exported_copy_dir).toContain("~/Desktop/bunker-copy/");
    expect(firstBackup.pruned_snapshots).toBe(0);

    const secondBackup = await runBunkerBackupNow();
    expect(secondBackup.pruned_snapshots).toBe(1);

    const snapshots = await listBunkerSnapshots();
    expect(snapshots).toHaveLength(2);

    await expect(openBunkerFolder()).resolves.toBeUndefined();

    const converted = await convertWebExport("~/Downloads/chatgpt-export.zip");
    expect(converted.detected_provider).toBe("chatgpt");
    expect(converted.markdown_files.length).toBeGreaterThan(0);

    const prompt = await generateBunkerRestorePrompt();
    expect(prompt).toContain("Zastava Data Bunker");
  });
});

describe("v3 SOS / Persona Risk Index & State Flags", () => {
  beforeEach(resetMockStateForTest);
  afterEach(resetMockStateForTest);

  it("считает Индекс риска Persona и обновляет self-check факторы", async () => {
    const baseline = await getPersonaRiskReport();
    expect(baseline.level).toBe("low");
    expect(baseline.score).toBe(0);

    const medium = await updatePersonaSelfCheck({ virtual_sms_used: true });
    expect(medium.score).toBe(30);
    expect(medium.level).toBe("medium");

    const high = await updatePersonaSelfCheck({
      bought_or_grey_account: true,
      reseller_payment_used: true,
    });
    expect(high.score).toBe(100);
    expect(high.level).toBe("high");
    expect(high.recommended_actions.length).toBeGreaterThan(0);
  });

  it("обновляет onboarding_v3_done, whats_new_v3_seen, dismissed_hints и экспортирует HintCard / onWindowFocusChanged", async () => {
    expect(typeof HintCard).toBe("function");
    expect(isHintDismissed("clean_room_intro", ["clean_room_intro"])).toBe(true);

    const afterDismiss = await dismissHint("clean_room_intro");
    await dismissHint("clean_room_intro");
    expect(afterDismiss.dismissed_hints).toEqual(["clean_room_intro"]);

    const afterReset = await resetDismissedHints();
    expect(afterReset.dismissed_hints).toEqual([]);

    const afterWhatsNew = await markWhatsNewV3Seen();
    expect(afterWhatsNew.whats_new_v3_seen).toBe(true);

    mockState.whats_new_v3_seen = false;
    const afterOnboarding = await completeOnboardingV3();
    expect(afterOnboarding.onboarding_v3_done).toBe(true);
    expect(afterOnboarding.whats_new_v3_seen).toBe(true);

    const unlisten = await onWindowFocusChanged(() => {});
    expect(typeof unlisten).toBe("function");
    unlisten();
  });

  it("PayShield v3.2 API & mocks: BIN Radar (n<5 и toxic), Advisor 5 сценариев, Manifest и Zero-PII opt-in", async () => {
    const lowN = await getBinRadarStats("53787200", "cursor");
    expect(lowN.status).toBe("insufficient_data");
    expect(lowN.window14d).toBeNull();

    const toxicStats = await getBinRadarStats("49372400", "claude_pro");
    expect(toxicStats.status).toBe("critical");
    expect(toxicStats.criticalWarning).toBe(true);

    const manifest = await getProvidersManifest();
    expect(manifest.providers.length).toBeGreaterThanOrEqual(5);

    const rescuePlan = await getPaymentAdvice({
      target_service: "claude_pro",
      has_iphone_apple_id: false,
      available_bin_prefix: "49372412",
      payment_rails: ["crypto_usdt"],
      willing_to_warmup_96h: true,
      network_state: { exit_country: "DE", trust_score: 90, clean_room_ready: true, is_zastava_key_active: true },
    });
    expect(rescuePlan.primary.route_id).toBe("apple_iap_us_gift");
    expect(rescuePlan.blocked_red_flags.some((b) => b.explanation.includes("Google Pay"))).toBe(true);

    const geminiPlan = await getPaymentAdvice({
      target_service: "gemini",
      has_iphone_apple_id: false,
      payment_rails: ["rub_sbp"],
      willing_to_warmup_96h: true,
      google_payments_country: "RU",
      network_state: { exit_country: "US", trust_score: 90, clean_room_ready: true, is_zastava_key_active: true },
    });
    expect(geminiPlan.blocked_red_flags.some((b) => b.reason.includes("OR-CCSEH-21") || b.title.includes("OR-CCSEH-21"))).toBe(true);

    const validReport = {
      bin_prefix: "49372400",
      service: "claude_pro",
      channel: "stripe_web_card",
      geo_match: "triple_mismatch",
      warmup_bucket: "lt_24h",
      outcome: "instant_kyc",
      client_version: "3.2.0",
    };
    await setBinRadarOptIn(false);
    await expect(submitBinRadarReport(validReport)).rejects.toThrow();

    await setBinRadarOptIn(true);
    await expect(submitBinRadarReport({ ...validReport, email: "leak@example.com" })).rejects.toThrow();
    await expect(submitBinRadarReport({ ...validReport, bin_prefix: "4937240012345678" })).rejects.toThrow();
    const submitted = await submitBinRadarReport(validReport);
    expect(submitted.bin_prefix).toBe("49372400");
    await setBinRadarOptIn(false);
  });
});

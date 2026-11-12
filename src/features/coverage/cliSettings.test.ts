import { describe, expect, it } from "vitest";
import { disableCliProtection, enableCliProtection, getCliSettings, getCoverageSnapshot, recheckCoverage, setCliMode, setSyncAiTzEnabled } from "../../utils/api";

describe("мок настроек CLI и TZ (браузер, isTauri() == false)", () => {
  it("тумблер подмены TZ/локали переключается независимо от защиты CLI", async () => {
    await enableCliProtection();
    const before = await getCliSettings();
    expect(before.cli_protection_enabled).toBe(true);

    const on = await setSyncAiTzEnabled(true);
    expect(on.sync_ai_tz_enabled).toBe(true);
    expect(on.cli_protection_enabled).toBe(true);

    await disableCliProtection();
    const afterCli = await getCliSettings();
    expect(afterCli.cli_protection_enabled).toBe(false);
    expect(afterCli.sync_ai_tz_enabled).toBe(true);

    const off = await setSyncAiTzEnabled(false);
    expect(off.sync_ai_tz_enabled).toBe(false);
    expect(off.cli_protection_enabled).toBe(false);
    await enableCliProtection();
  });

  it("режим CLI меняется отдельно и попадает в снимок покрытия вместе с шагами", async () => {
    await enableCliProtection();
    await setCliMode("ai_only");
    const ai = await getCoverageSnapshot();
    const nodeAi = ai.apps.find((a) => a.id === "node-cli");
    expect(ai.cli_mode).toBe("ai_only");
    expect(nodeAi?.status).toBe("off");
    expect(nodeAi?.manual_steps).toEqual(["set_env_proxy"]);

    const res = await setCliMode("global_terminal");
    expect(res.cli_mode).toBe("global_terminal");
    const global = await getCoverageSnapshot();
    expect(global.apps.find((a) => a.id === "node-cli")?.status).toBe("configured");
    await setCliMode("ai_only");
  });

  it("recheck продвигает статусы, адрес шлюза в снимке не равен 8899", async () => {
    const first = await getCoverageSnapshot();
    expect(first.gateway_addr).not.toContain("8899");
    expect(first.pac_url).toBe(`http://${first.gateway_addr}/proxy.pac`);
    const jb1 = first.apps.find((a) => a.id === "jetbrains");
    expect(["unknown", "configured"]).toContain(jb1?.status);
    const next = await recheckCoverage();
    expect(next.apps.find((a) => a.id === "jetbrains")?.status).toBe("configured");
  });
});

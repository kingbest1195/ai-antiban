import { describe, expect, it } from "vitest";
import {
  decodeZastavaKeyPreview,
  formatRemainingTimeRu,
  getBotRenewUrl,
  getRouteExpiryUrgency,
  ZASTAVA_BOT_URL,
} from "./zastavaKey";

function encodeBase64Url(json: unknown): string {
  const utf8 = new TextEncoder().encode(JSON.stringify(json));
  let bin = "";
  for (const byte of utf8) bin += String.fromCharCode(byte);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

describe("zastavaKey", () => {
  it("decodes v2 zastava:// key preview without leaking credentials", () => {
    const raw =
      "zastava://" +
      encodeBase64Url({
        v: 2,
        id: "nl-edge-1",
        label: "Нидерланды Pro",
        country: "nl",
        exit_ip: "185.10.10.5",
        expires_at: 1800000000,
        entry: [
          { proto: "https", host: "entry.example.com", port: 443, username: "u1", password: "secret" },
          { proto: "socks5", host: "hop2.example.com", port: 1080 },
        ],
      });

    const preview = decodeZastavaKeyPreview(raw);
    expect(preview).toEqual({
      kind: "zastava",
      id: "nl-edge-1",
      label: "Нидерланды Pro",
      country: "NL",
      exit_ip: "185.10.10.5",
      expires_at: 1800000000,
      entrySummary: "https://entry.example.com:443 (+1)",
    });
    expect(JSON.stringify(preview)).not.toContain("secret");
  });

  it("decodes bare proxy url with fragment label and strips credentials", () => {
    const preview = decodeZastavaKeyPreview("socks5://alice:s3cret@198.51.100.4:1080#Germany%20VPS");
    expect(preview).toEqual({
      kind: "url",
      label: "Germany VPS",
      entrySummary: "socks5://198.51.100.4:1080",
    });
  });

  it("computes expiry urgency thresholds (<3d soon, <1d critical, <=0 expired)", () => {
    const now = 1_700_000_000;
    expect(getRouteExpiryUrgency(null, now)).toBe("none");
    expect(getRouteExpiryUrgency(now + 5 * 86_400, now)).toBe("none");
    expect(getRouteExpiryUrgency(now + 2 * 86_400, now)).toBe("soon");
    expect(getRouteExpiryUrgency(now + 12 * 3600, now)).toBe("critical");
    expect(getRouteExpiryUrgency(now - 10, now)).toBe("expired");
    expect(formatRemainingTimeRu(now + 5 * 3600, now)).toBe("осталось 5 ч.");
  });

  it("builds @zastava_app_bot renew URLs", () => {
    expect(getBotRenewUrl()).toBe(ZASTAVA_BOT_URL);
    expect(getBotRenewUrl("nl-edge-1")).toBe("https://t.me/zastava_app_bot?start=renew_nl-edge-1");
  });
});

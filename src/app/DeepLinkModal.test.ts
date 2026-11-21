import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("../ui/Modal", () => ({
  Modal: ({ open, title, children, footer }: { open: boolean; title: string; children?: unknown; footer?: unknown }) =>
    open ? createElement("div", { "data-modal": title }, children as never, footer as never) : null,
}));

vi.mock("../utils/api", async () => {
  const actual = await vi.importActual<typeof import("../utils/api")>("../utils/api");
  return {
    ...actual,
    listClaudeProfiles: vi.fn(async () => ({ profiles: [], active_profile_id: null })),
  };
});

const previewMock = vi.hoisted(() => ({
  value: {
    label: "NL Edge",
    country: "NL",
    exit_ip: "185.212.102.40",
    entrySummary: "socks5://95.165.10.22:1080",
    expires_at: null as number | null,
  },
}));

vi.mock("../shared/lib/zastavaKey", async () => {
  const actual = await vi.importActual<typeof import("../shared/lib/zastavaKey")>("../shared/lib/zastavaKey");
  return {
    ...actual,
    decodeZastavaKeyPreview: () => previewMock.value,
  };
});

import { DeepLinkModal } from "./DeepLinkModal";

describe("DeepLinkModal — hideIpMode masking", () => {
  it("маскирует IPv4 в exit_ip и entrySummary при hideIpMode=true и показывает их при hideIpMode=false", () => {
    previewMock.value = {
      label: "NL Edge",
      country: "NL",
      exit_ip: "185.212.102.40",
      entrySummary: "socks5://95.165.10.22:1080",
      expires_at: null,
    };

    const maskedHtml = renderToStaticMarkup(
      createElement(DeepLinkModal, {
        deepLinkKey: "zastava://test-v4",
        hideIpMode: true,
        onClose: vi.fn(),
        onConfirm: vi.fn(),
      }),
    );

    expect(maskedHtml).not.toContain("185.212.102.40");
    expect(maskedHtml).not.toContain("95.165.10.22");
    expect(maskedHtml).toContain("•••.•••.•••.40");
    expect(maskedHtml).toContain("•••.•••.•••.22");

    const plainHtml = renderToStaticMarkup(
      createElement(DeepLinkModal, {
        deepLinkKey: "zastava://test-v4",
        hideIpMode: false,
        onClose: vi.fn(),
        onConfirm: vi.fn(),
      }),
    );

    expect(plainHtml).toContain("185.212.102.40");
    expect(plainHtml).toContain("95.165.10.22");
  });

  it("маскирует IPv6 в exit_ip и entrySummary при hideIpMode=true", () => {
    previewMock.value = {
      label: "DE IPv6",
      country: "DE",
      exit_ip: "2001:db8:85a3::8a2e:370:7334",
      entrySummary: "https://[2a01:4f8:c0c:1234::1]:443",
      expires_at: null,
    };

    const maskedHtml = renderToStaticMarkup(
      createElement(DeepLinkModal, {
        deepLinkKey: "zastava://test-v6",
        hideIpMode: true,
        onClose: vi.fn(),
        onConfirm: vi.fn(),
      }),
    );

    expect(maskedHtml).not.toContain("2001:db8:85a3::8a2e:370:7334");
    expect(maskedHtml).not.toContain("2a01:4f8:c0c:1234::1");
    expect(maskedHtml).toContain("••••:••••:…:7334");
    expect(maskedHtml).toContain("••••:••••:…:1");
  });
});

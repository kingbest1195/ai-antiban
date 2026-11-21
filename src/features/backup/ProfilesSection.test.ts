import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("../../ui/Modal", () => ({
  Modal: ({ open, title, children, footer }: { open: boolean; title: string; children?: unknown; footer?: unknown }) =>
    open ? createElement("div", { "data-modal": title }, children as never, footer as never) : null,
}));

import { ProfileModals } from "./ProfileModals";
import {
  hasProfileKeyBinding,
  isProfileRouteMissing,
  KEY_OPTION_NEW,
  KEY_OPTION_NONE,
  resolveCreateProfileIpBinding,
  resolveInitialBindChoice,
} from "./ProfilesSection";

describe("ProfilesSection: привязка ключей и маршрутов к профилям", () => {
  const routes = [{ id: "r-nl" }, { id: "r-de" }];

  it("hasProfileKeyBinding учитывает и bound_upstream_key, и bound_route_id", () => {
    expect(hasProfileKeyBinding({ bound_upstream_key: null, bound_route_id: null })).toBe(false);
    expect(hasProfileKeyBinding({ bound_upstream_key: "zastava://abc", bound_route_id: null })).toBe(true);
    expect(hasProfileKeyBinding({ bound_upstream_key: null, bound_route_id: "r-nl" })).toBe(true);
  });

  it("resolveInitialBindChoice выбирает KEY_OPTION_NONE для непривязанного профиля (а не routes[0])", () => {
    expect(resolveInitialBindChoice({ bound_upstream_key: null, bound_route_id: null }, routes)).toEqual({
      choice: KEY_OPTION_NONE,
      keyInput: "",
    });
  });

  it("resolveInitialBindChoice выбирает bound_route_id, если маршрут существует, иначе bound_upstream_key", () => {
    expect(resolveInitialBindChoice({ bound_upstream_key: "zastava://abc", bound_route_id: "r-de" }, routes)).toEqual({
      choice: "r-de",
      keyInput: "",
    });
    expect(
      resolveInitialBindChoice({ bound_upstream_key: "zastava://custom", bound_route_id: "missing-route" }, routes),
    ).toEqual({
      choice: KEY_OPTION_NEW,
      keyInput: "zastava://custom",
    });
  });

  it("isProfileRouteMissing отмечает профиль, у которого маршрут удалён, а ключ сброшен", () => {
    expect(isProfileRouteMissing({ bound_upstream_key: null, bound_route_id: "deleted-id" }, routes, true)).toBe(true);
    expect(isProfileRouteMissing({ bound_upstream_key: null, bound_route_id: "r-nl" }, routes, true)).toBe(false);
    expect(isProfileRouteMissing({ bound_upstream_key: null, bound_route_id: "deleted-id" }, routes, false)).toBe(false);
    expect(isProfileRouteMissing({ bound_upstream_key: "zastava://k", bound_route_id: "deleted-id" }, routes, true)).toBe(
      false,
    );
  });

  it("resolveCreateProfileIpBinding не привязывает локальный IP, если для профиля выбран ключ Заставы", () => {
    expect(resolveCreateProfileIpBinding(true, true, "185.10.10.10", "DE", "r-nl")).toEqual({
      ip: null,
      country: null,
    });
    expect(resolveCreateProfileIpBinding(true, true, "185.10.10.10", "DE", KEY_OPTION_NEW)).toEqual({
      ip: null,
      country: null,
    });
    expect(resolveCreateProfileIpBinding(true, true, "185.10.10.10", "DE", KEY_OPTION_NONE)).toEqual({
      ip: "185.10.10.10",
      country: "DE",
    });
    expect(resolveCreateProfileIpBinding(false, true, "185.10.10.10", "DE", KEY_OPTION_NONE)).toEqual({
      ip: null,
      country: null,
    });
  });

  it("ProfileModals маскирует currentIp, routes[].exit_ip и preview при hideIpMode=true", () => {
    const html = renderToStaticMarkup(
      createElement(ProfileModals, {
        routes: [
          {
            id: "r-1",
            label: "NL",
            country: "NL",
            exit_ip: "185.212.102.40",
            enabled: true,
            added_at: 1,
            entries: [],
            status: "active",
            is_default: true,
            bound_providers: [],
            is_profile_route: false,
            health: null,
          },
        ],
        ipKnown: true,
        currentIp: "95.165.10.22",
        hideIpMode: true,
        createOpen: true,
        creating: false,
        newName: "",
        bindCurrentOnCreate: true,
        createKeyChoice: KEY_OPTION_NONE,
        createKeyInput: "",
        onCloseCreate: vi.fn(),
        onNewNameChange: vi.fn(),
        onBindCurrentOnCreateChange: vi.fn(),
        onCreateKeyChoiceChange: vi.fn(),
        onCreateKeyInputChange: vi.fn(),
        onCreate: vi.fn(),
        bindingTarget: {
          id: "p1",
          name: "P1",
          is_active: true,
          bound_ip: "95.165.10.22",
          bound_country: "RU",
          bound_upstream_key: null,
          bound_route_id: null,
          isolated_device_id: "dev-1",
          created_at: 1,
          last_used_at: 1,
          has_saved_session: true,
        },
        savingBind: false,
        bindChoice: KEY_OPTION_NONE,
        bindKeyInput: "",
        onCloseBind: vi.fn(),
        onBindChoiceChange: vi.fn(),
        onBindKeyInputChange: vi.fn(),
        onSaveBindKey: vi.fn(),
        removing: null,
        removeBusy: false,
        onConfirmRemove: vi.fn(),
        onCancelRemove: vi.fn(),
        safeLogoutOpen: false,
        safeLogoutBusy: false,
        onConfirmSafeLogout: vi.fn(),
        onCancelSafeLogout: vi.fn(),
      }),
    );

    expect(html).not.toContain("95.165.10.22");
    expect(html).not.toContain("185.212.102.40");
    expect(html).toContain("•••.•••.•••.22");
    expect(html).toContain("•••.•••.•••.40");
  });

  it("ProfileModals маскирует IPv6 в currentIp и routes[].exit_ip при hideIpMode=true", () => {
    const html = renderToStaticMarkup(
      createElement(ProfileModals, {
        routes: [
          {
            id: "r-v6",
            label: "DE IPv6",
            country: "DE",
            exit_ip: "2001:db8:85a3::7334",
            enabled: true,
            added_at: 1,
            entries: [],
            status: "active",
            is_default: true,
            bound_providers: [],
            is_profile_route: false,
            health: null,
          },
        ],
        ipKnown: true,
        currentIp: "2a01:4f8:c0c::1",
        hideIpMode: true,
        createOpen: true,
        creating: false,
        newName: "",
        bindCurrentOnCreate: true,
        createKeyChoice: KEY_OPTION_NONE,
        createKeyInput: "",
        onCloseCreate: vi.fn(),
        onNewNameChange: vi.fn(),
        onBindCurrentOnCreateChange: vi.fn(),
        onCreateKeyChoiceChange: vi.fn(),
        onCreateKeyInputChange: vi.fn(),
        onCreate: vi.fn(),
        bindingTarget: {
          id: "p1",
          name: "P1",
          is_active: true,
          bound_ip: "2a01:4f8:c0c::1",
          bound_country: "DE",
          bound_upstream_key: null,
          bound_route_id: null,
          isolated_device_id: "dev-1",
          created_at: 1,
          last_used_at: 1,
          has_saved_session: true,
        },
        savingBind: false,
        bindChoice: KEY_OPTION_NONE,
        bindKeyInput: "",
        onCloseBind: vi.fn(),
        onBindChoiceChange: vi.fn(),
        onBindKeyInputChange: vi.fn(),
        onSaveBindKey: vi.fn(),
        removing: null,
        removeBusy: false,
        onConfirmRemove: vi.fn(),
        onCancelRemove: vi.fn(),
        safeLogoutOpen: false,
        safeLogoutBusy: false,
        onConfirmSafeLogout: vi.fn(),
        onCancelSafeLogout: vi.fn(),
      }),
    );

    expect(html).not.toContain("2a01:4f8:c0c::1");
    expect(html).not.toContain("2001:db8:85a3::7334");
    expect(html).toContain("••••:••••:…:1");
    expect(html).toContain("••••:••••:…:7334");
  });
});

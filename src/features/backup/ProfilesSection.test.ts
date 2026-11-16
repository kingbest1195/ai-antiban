import { describe, expect, it } from "vitest";
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
});

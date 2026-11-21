import type { ReactElement } from "react";
import { describe, expect, it, vi } from "vitest";
import type { ClaudeProfile } from "../../types";

const hookRuntime = vi.hoisted(() => {
  type Slot = { kind: "state"; value: unknown } | { kind: "effect"; deps?: unknown[] };
  const slots: Slot[] = [];
  let cursor = 0;
  let pending: Array<() => void> = [];
  let renderFn: (() => void) | null = null;

  function flush() {
    const q = pending;
    pending = [];
    for (const fn of q) fn();
  }

  return {
    reset(fn: () => void) {
      slots.length = 0;
      cursor = 0;
      pending = [];
      renderFn = fn;
    },
    beginRender() {
      cursor = 0;
    },
    flush,
    useState<T>(initial: T | (() => T)): [T, (next: T | ((prev: T) => T)) => void] {
      const idx = cursor++;
      if (idx >= slots.length) {
        const val = typeof initial === "function" ? (initial as () => T)() : initial;
        slots.push({ kind: "state", value: val });
      }
      const slot = slots[idx] as { kind: "state"; value: unknown };
      const setState = (next: T | ((prev: T) => T)) => {
        const resolved = typeof next === "function" ? (next as (prev: T) => T)(slot.value as T) : next;
        if (!Object.is(slot.value, resolved)) {
          slot.value = resolved;
          if (renderFn) {
            renderFn();
            flush();
          }
        }
      };
      return [slot.value as T, setState];
    },
    useEffect(fn: () => void | (() => void), deps?: unknown[]) {
      const idx = cursor++;
      if (idx >= slots.length) {
        slots.push({ kind: "effect", deps });
        pending.push(() => {
          fn();
        });
      }
    },
  };
});

vi.mock("react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react")>();
  return {
    ...actual,
    useState: hookRuntime.useState.bind(hookRuntime),
    useEffect: hookRuntime.useEffect.bind(hookRuntime),
  };
});

const mockProfiles: ClaudeProfile[] = [
  {
    id: "p-v4",
    name: "Claude Work",
    is_active: true,
    bound_ip: "185.212.102.40",
    bound_country: "NL",
    bound_upstream_key: null,
    bound_route_id: null,
    isolated_device_id: "dev-1",
    created_at: 1,
    last_used_at: 1,
    has_saved_session: true,
  },
  {
    id: "p-v6",
    name: "Claude IPv6",
    is_active: false,
    bound_ip: "2001:db8:85a3::7334",
    bound_country: "DE",
    bound_upstream_key: null,
    bound_route_id: null,
    isolated_device_id: "dev-2",
    created_at: 1,
    last_used_at: 1,
    has_saved_session: false,
  },
];

vi.mock("../../utils/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../utils/api")>();
  return {
    ...actual,
    listClaudeProfiles: vi.fn(async () => ({ profiles: mockProfiles, active_profile_id: "p-v4" })),
    getRoutesSnapshot: vi.fn(async () => ({ routes: [], provider_routes: {}, effective: {}, dangling: [] })),
    bindIpToClaudeProfile: vi.fn(async () => ({ profiles: mockProfiles })),
  };
});

import { ProfilesSection } from "./ProfilesSection";

function collectText(node: unknown): string {
  if (node == null || typeof node === "boolean") return "";
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(collectText).join(" ");
  if (typeof node === "object" && "props" in (node as ReactElement)) {
    const props = (node as ReactElement<Record<string, unknown>>).props;
    return [props.title, props.sub, props.children].map(collectText).join(" ");
  }
  return "";
}

describe("ProfilesSection mounted — hideIpMode", () => {
  it("маскирует bound_ip (IPv4 и IPv6) в списке профилей при hideIpMode=true", async () => {
    let tree: ReactElement | null = null;
    const render = () => {
      hookRuntime.beginRender();
      tree = ProfilesSection({
        currentIp: "95.165.10.22",
        currentCountry: "NL",
        hideIpMode: true,
        routesSnapshot: { routes: [], default_route_id: null, provider_routes: {}, effective: {}, dangling: [] } as never,
        onProfileSwitched: vi.fn(async () => {}),
        onToast: vi.fn(),
      }) as ReactElement;
    };

    hookRuntime.reset(render);
    render();
    hookRuntime.flush();
    await Promise.resolve();
    await Promise.resolve();

    const text = collectText(tree);
    expect(text).not.toContain("185.212.102.40");
    expect(text).not.toContain("2001:db8:85a3::7334");
    expect(text).toContain("•••.•••.•••.40");
    expect(text).toContain("••••:••••:…:7334");
  });

  it("P1 #3: маскирует currentIp в тосте ipBoundText при bindIpToClaudeProfile и hideIpMode=true", async () => {
    const onToast = vi.fn();
    let tree: ReactElement | null = null;
    const render = () => {
      hookRuntime.beginRender();
      tree = ProfilesSection({
        currentIp: "95.165.10.22",
        currentCountry: "NL",
        hideIpMode: true,
        routesSnapshot: { routes: [], default_route_id: null, provider_routes: {}, effective: {}, dangling: [] } as never,
        onProfileSwitched: vi.fn(async () => {}),
        onToast,
      }) as ReactElement;
    };

    hookRuntime.reset(render);
    render();
    hookRuntime.flush();
    await Promise.resolve();
    await Promise.resolve();

    const findBindSelect = (node: unknown): ((() => void) | null) => {
      if (!node || typeof node !== "object") return null;
      if (Array.isArray(node)) {
        for (const item of node) {
          const hit = findBindSelect(item);
          if (hit) return hit;
        }
        return null;
      }
      const obj = node as Record<string, unknown>;
      if (obj.id === "bind-ip" && typeof obj.onSelect === "function") {
        return obj.onSelect as () => void;
      }
      if (obj.props && typeof obj.props === "object") {
        for (const val of Object.values(obj.props as Record<string, unknown>)) {
          const hit = findBindSelect(val);
          if (hit) return hit;
        }
      }
      return null;
    };

    const onSelect = findBindSelect(tree);
    expect(onSelect).toBeTypeOf("function");
    await onSelect!();
    await Promise.resolve();

    expect(onToast).toHaveBeenCalledTimes(1);
    const toastBody = String(onToast.mock.calls[0][1]);
    expect(toastBody).not.toContain("95.165.10.22");
    expect(toastBody).toContain("•••.•••.•••.22");
  });
});

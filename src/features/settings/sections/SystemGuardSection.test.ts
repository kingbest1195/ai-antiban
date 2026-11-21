import type { ReactElement } from "react";
import { describe, expect, it, vi } from "vitest";

const hookRuntime = vi.hoisted(() => {
  const slots: Array<{ kind: "state"; value: unknown }> = [];
  let cursor = 0;
  let currentRender: (() => void) | null = null;
  return {
    reset(renderFn: () => void) {
      slots.length = 0;
      cursor = 0;
      currentRender = renderFn;
    },
    beginRender() {
      cursor = 0;
    },
    useState<T>(initial: T | (() => T)): [T, (next: T | ((prev: T) => T)) => void] {
      const idx = cursor++;
      if (idx >= slots.length) {
        const val = typeof initial === "function" ? (initial as () => T)() : initial;
        slots.push({ kind: "state", value: val });
      }
      const slot = slots[idx];
      const setState = (next: T | ((prev: T) => T)) => {
        const resolved = typeof next === "function" ? (next as (prev: T) => T)(slot.value as T) : next;
        if (!Object.is(slot.value, resolved)) {
          slot.value = resolved;
          currentRender?.();
        }
      };
      return [slot.value as T, setState];
    },
  };
});

vi.mock("react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react")>();
  return {
    ...actual,
    useState: hookRuntime.useState.bind(hookRuntime),
  };
});

import { settings as copy } from "../../../shared/copy/ru";
import { ExpandRow } from "../../../ui";
import { SystemGuardSection } from "./SystemGuardSection";

function collectElements(node: unknown, predicate: (el: ReactElement) => boolean, out: ReactElement[] = []): ReactElement[] {
  if (!node || typeof node !== "object") return out;
  if (Array.isArray(node)) {
    for (const item of node) collectElements(item, predicate, out);
    return out;
  }
  const el = node as ReactElement<Record<string, unknown>>;
  if ("type" in el && "props" in el) {
    if (predicate(el)) out.push(el);
    if (el.props?.children) collectElements(el.props.children, predicate, out);
  }
  return out;
}

function collectText(node: unknown): string {
  if (node == null || typeof node === "boolean") return "";
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(collectText).join(" ");
  if (typeof node === "object" && "props" in (node as ReactElement)) {
    const props = (node as ReactElement<Record<string, unknown>>).props;
    return [props.title, props.sub, props.action, props.description, props.target, props.children].map(collectText).join(" ");
  }
  return "";
}

describe("SystemGuardSection Tier 2 («Под капотом / Для специалистов»)", () => {
  it("свёрнут по умолчанию и раскрывает «Что Застава настраивает в системе» + «Куда Застава обращается в сеть» при клике", () => {
    let tree: ReactElement | null = null;
    const onTogglePreview = vi.fn();

    const render = () => {
      hookRuntime.beginRender();
      tree = SystemGuardSection({
        autoUpdateEnabled: true,
        coworkStatus: null,
        coworkBusy: false,
        onInstallCoworkGuard: vi.fn(),
        onRefreshCoworkGuard: vi.fn(),
        exportBusy: false,
        onExportDiagnostics: vi.fn(async () => {}),
        previewItems: [
          {
            category: "sysproxy",
            action: "Локальный прокси-фильтр",
            description: "Направляет только домены ИИ через локальный шлюз.",
            target: "127.0.0.1:8899/proxy.pac",
            reversible: true,
          },
        ],
        previewLoading: false,
        previewError: null,
        previewOpen: false,
        onTogglePreview,
        cleaningProxy: false,
        proxyResult: null,
        onRequestCleanProxy: vi.fn(),
      }) as ReactElement;
    };

    hookRuntime.reset(render);
    render();

    const expandRowBefore = collectElements(
      tree,
      (el) => el.type === ExpandRow && (el.props as Record<string, unknown>).title === copy.advanced.title,
    )[0];
    expect(expandRowBefore).toBeTruthy();
    expect((expandRowBefore.props as Record<string, unknown>).open).toBe(false);

    // Кликаем по ExpandRow (onToggle)
    (expandRowBefore.props as { onToggle: () => void }).onToggle();
    expect(onTogglePreview).toHaveBeenCalledTimes(1);

    const expandRowAfter = collectElements(
      tree,
      (el) => el.type === ExpandRow && (el.props as Record<string, unknown>).title === copy.advanced.title,
    )[0];
    expect((expandRowAfter.props as Record<string, unknown>).open).toBe(true);

    const expandedText = collectText((expandRowAfter.props as Record<string, unknown>).children);
    expect(expandedText).toContain(copy.diagnostics.previewTitle);
    expect(expandedText).toContain(copy.privacy.networkTitle);
    expect(expandedText).toContain("Локальный прокси-фильтр");
  });
});

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { shutdown as copy } from "../shared/copy/ru";
import { ShutdownOverlay } from "./ShutdownOverlay";

describe("ShutdownOverlay: прелоадер завершения работы и обновления", () => {
  it("ничего не рендерит, пока прогресс равен null", () => {
    expect(renderToStaticMarkup(createElement(ShutdownOverlay, { progress: null }))).toBe("");
  });

  it("в режиме quit показывает заголовок выхода, диалог alertdialog, процент и активный шаг", () => {
    const html = renderToStaticMarkup(
      createElement(ShutdownOverlay, {
        progress: {
          mode: "quit",
          step: 2,
          total: 4,
          label: "Восстановление системного прокси и политик браузеров...",
          done: false,
        },
      }),
    );

    expect(html).toContain('role="alertdialog"');
    expect(html).toContain('aria-modal="true"');
    expect(html).toContain('aria-busy="true"');
    expect(html).toContain(copy.titleQuit);
    expect(html).toContain(copy.description);
    expect(html).toContain("50%");
    expect(html).toContain("zs-shutdown__step--done");
    expect(html).toContain("zs-shutdown__step--active");
    expect(html).toContain("zs-shutdown__step--pending");
    for (const stage of copy.stages) {
      expect(html).toContain(stage);
    }
  });

  it("в режиме update при done=true показывает заголовок обновления и 100%", () => {
    const html = renderToStaticMarkup(
      createElement(ShutdownOverlay, {
        progress: {
          mode: "update",
          step: 4,
          total: 4,
          label: "Перезапуск после обновления...",
          done: true,
        },
      }),
    );

    expect(html).toContain(copy.titleUpdate);
    expect(html).toContain("100%");
    expect(html).not.toContain("zs-shutdown__step--pending");
    expect(html).not.toContain("zs-shutdown__step--active");
  });
});

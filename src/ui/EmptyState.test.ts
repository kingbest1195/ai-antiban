import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { Button } from "./Button";
import { EmptyState } from "./EmptyState";

describe("EmptyState", () => {
  it("сохраняет обратную совместимость с icon, children и action", () => {
    const html = renderToStaticMarkup(
      createElement(
        EmptyState,
        {
          icon: "folder",
          title: "Копий нет",
          action: createElement(Button, { variant: "primary", children: "Создать" }),
        },
        "Пояснение для пользователя",
      ),
    );

    expect(html).toContain("zs-empty__icon");
    expect(html).toContain("Копий нет");
    expect(html).toContain("Пояснение для пользователя");
    expect(html).toContain("Создать");
  });

  it("поддерживает mascotState, description, primaryAction и secondaryAction", () => {
    const html = renderToStaticMarkup(
      createElement(EmptyState, {
        mascotState: "scanning",
        mascotSize: 48,
        title: "Профили не созданы",
        description: "Создайте первый изолированный профиль для чистого запуска.",
        primaryAction: createElement(Button, { variant: "primary", children: "Создать профиль" }),
        secondaryAction: createElement(Button, { children: "Как это работает" }),
      }),
    );

    expect(html).toContain("zs-empty__mascot");
    expect(html).toContain("zs-mascot--scanning");
    expect(html).toContain("Профили не созданы");
    expect(html).toContain("Создайте первый изолированный профиль");
    expect(html).toContain("Создать профиль");
    expect(html).toContain("Как это работает");
  });
});

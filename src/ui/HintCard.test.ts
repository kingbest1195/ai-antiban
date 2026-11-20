import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { HintCard, isHintDismissed } from "./HintCard";

describe("HintCard", () => {
  it("рендерит заголовок, текст и кнопку закрытия, когда hintId не скрыт", () => {
    const html = renderToStaticMarkup(
      createElement(HintCard, {
        hintId: "clean_room_intro",
        title: "С чего начать",
        body: "Сначала запустите проверку следов на диске.",
        dismissedHints: ["other_hint"],
        onDismiss: () => {},
        action: { label: "Проверить", onClick: () => {} },
      }),
    );

    expect(html).toContain('data-hint-id="clean_room_intro"');
    expect(html).toContain("С чего начать");
    expect(html).toContain("Сначала запустите проверку следов на диске.");
    expect(html).toContain("Проверить");
    expect(html).toContain('aria-label="Скрыть подсказку"');
  });

  it("возвращает null, когда hintId присутствует в dismissedHints", () => {
    expect(isHintDismissed("clean_room_intro", ["clean_room_intro"])).toBe(true);
    const html = renderToStaticMarkup(
      createElement(HintCard, {
        hintId: "clean_room_intro",
        body: "Текст подсказки",
        dismissedHints: ["clean_room_intro"],
        onDismiss: () => {},
      }),
    );

    expect(html).toBe("");
  });
});

import { useState } from "react";
import type { AppCoverageItem } from "../../types";
import { Badge, Icon } from "../../ui";
import type { BadgeTone, IconName, RowTone } from "../../ui";
import { coverage as copy } from "../../shared/copy/ru";
import type { CoverageView } from "./coverageModel";

export interface BadgeView {
  tone: BadgeTone;
  icon?: IconName;
  label: string;
}

export const COVERAGE_BADGES: Record<Exclude<CoverageView, "not_installed">, BadgeView> = {
  confirmed: { tone: "ok", icon: "check", label: copy.status.confirmed },
  configured: { tone: "info", label: copy.status.configured },
  waiting: { tone: "info", icon: "refresh", label: copy.status.waiting },
  waiting_timeout: { tone: "neutral", icon: "help", label: copy.status.waitingTimeout },
  unknown: { tone: "neutral", icon: "help", label: copy.status.unknown },
  off: { tone: "warn", icon: "alert", label: copy.status.off },
  direct: { tone: "neutral", label: copy.status.direct },
};

export const COVERAGE_ICONS: Record<AppCoverageItem["category"], IconName> = {
  browser: "globe",
  desktop: "shield",
  ide: "term",
  cli: "term",
};

export const coverageRowTone = (view: CoverageView): RowTone =>
  view === "confirmed" ? "ok" : view === "off" ? "warn" : "neutral";

const LEGEND: { view: Exclude<CoverageView, "not_installed">; text: string }[] = [
  { view: "confirmed", text: "Подключено — запросы приложения уже идут через Заставу." },
  { view: "configured", text: "Настроено — ждёт запрос от приложения." },
  { view: "off", text: "Не подключено к Заставе." },
  { view: "direct", text: "Напрямую (норма) — обычная программа терминала, идёт мимо Заставы специально." },
];

export function CoverageLegend() {
  const [open, setOpen] = useState(false);
  return (
    <div className="zs-cov__legend">
      <button type="button" className="zs-cov__legend-toggle" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
        Что значат статусы
        <Icon name="chev" className="zs-cov__legend-chev" />
      </button>
      {open && (
        <ul className="zs-cov__legend-list">
          {LEGEND.map((l) => {
            const b = COVERAGE_BADGES[l.view];
            return (
              <li key={l.view}>
                <Badge tone={b.tone} icon={b.icon}>
                  {b.label}
                </Badge>
                <span>{l.text}</span>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

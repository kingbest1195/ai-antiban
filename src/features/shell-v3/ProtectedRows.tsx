import { Badge, InfoTip, Row, Rows, Spinner, Switch } from "../../ui";
import type { OverviewScreenProps } from "../overview/OverviewScreen";

function PendingBadge() {
  return (
    <Badge>
      <Spinner size={12} />
      Проверяем…
    </Badge>
  );
}

/**
 * «Что защищено» (без view-layer polling!):
 * Браузеры и десктопные приложения — единый статус sysproxyActive;
 * Редакторы кода и терминал — централизованный cliProtected из useProtectionToggles.
 */
export function ProtectedRows({ p }: { p: OverviewScreenProps }) {
  const pending = Boolean(p.startupPending);
  const off = !pending && !p.sysproxyActive;
  const terminalOn = p.sysproxyActive && p.cliProtected;

  const sysBadge = pending ? (
    <PendingBadge />
  ) : (
    <Badge tone={p.sysproxyActive ? "ok" : "danger"}>{p.sysproxyActive ? "Защищены" : "Без защиты"}</Badge>
  );
  const linked = (
    <InfoTip text="Браузеры и десктопные приложения включаются вместе главным выключателем защиты — в Заставе это одна системная настройка." />
  );

  return (
    <Rows>
      <Row
        icon="globe"
        tone={pending ? "neutral" : p.sysproxyActive ? "ok" : "danger"}
        title={
          <span className="zs-v3-trust-row">
            Браузеры {linked}
          </span>
        }
        sub="Chrome, Safari, Arc, Edge, Яндекс"
        trail={sysBadge}
      />
      <Row
        icon="shield"
        tone={pending ? "neutral" : p.sysproxyActive ? "ok" : "danger"}
        title={
          <span className="zs-v3-trust-row">
            Десктопные приложения {linked}
          </span>
        }
        sub="Claude и ChatGPT для компьютера"
        trail={sysBadge}
      />
      <Row
        icon="term"
        tone={pending ? "neutral" : terminalOn ? "ok" : off ? "danger" : "warn"}
        title="Редакторы кода и терминал"
        sub={off ? "Включите защиту, чтобы настроить" : "Cursor, VS Code, Windsurf, Antigravity, Claude Code, Gemini CLI"}
        trail={
          pending ? (
            <PendingBadge />
          ) : off ? (
            <Badge tone="danger">Без защиты</Badge>
          ) : (
            <Switch checked={terminalOn} onChange={p.onToggleCli} aria-label="Редакторы кода и терминал" />
          )
        }
      />
    </Rows>
  );
}

export function protectedSummary(p: OverviewScreenProps): { text: string; tone?: "ok" | "warn" | "danger" } {
  if (p.startupPending) return { text: "Проверяем…" };
  if (!p.sysproxyActive) return { text: "Без защиты", tone: "danger" };
  if (p.cliProtected) return { text: "Всё защищено", tone: "ok" };
  return { text: "Без терминала", tone: "warn" };
}

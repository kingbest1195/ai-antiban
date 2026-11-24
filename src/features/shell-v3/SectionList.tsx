import type { ReactNode } from "react";
import { Card, Row, Rows } from "../../ui";
import type { IconName } from "../../ui";
import { providers as providerCopy } from "../../shared/copy/ru";
import type { Route } from "../../shared/hooks";
import type { AppStateData, PersonaRiskReport } from "../../types";
import type { OverviewScreenProps } from "../overview/OverviewScreen";
import type { OverviewView } from "./types";

function Sum({ tone, children }: { tone?: "ok" | "warn" | "danger"; children: ReactNode }) {
  return <span className={`zs-v3-sum${tone ? ` zs-v3-sum--${tone}` : ""}`}>{children}</span>;
}

export interface SectionListProps {
  overview: OverviewScreenProps;
  view: OverviewView;
  state: AppStateData | null;
  personaRisk: PersonaRiskReport | null;
  onPushRoute: (route: Route) => void;
}

/** 5 семантических разделов Home Hub (~220px). */
export function SectionList({ overview, view, state, personaRisk, onPushRoute }: SectionListProps) {
  const { model } = view;
  const off = !overview.startupPending && !overview.sysproxyActive;
  const blocked = model.services.filter((s) => s.status === "critical");
  const review = model.services.filter((s) => s.status === "warn" || s.status === "missing");
  const checking = model.services.some((s) => s.status === "checking");
  const names = (list: typeof blocked) => list.map((s) => providerCopy[s.id].name).join(", ");

  const servicesSum = overview.killswitchFrozen ? (
    <Sum tone="danger">Остановлены</Sum>
  ) : off ? (
    <Sum tone="danger">Без защиты</Sum>
  ) : blocked.length === model.services.length ? (
    <Sum tone="danger">Все заблокированы</Sum>
  ) : blocked.length ? (
    <Sum tone="danger">Заблокированы: {names(blocked)}</Sum>
  ) : checking ? (
    <Sum>Проверяем…</Sum>
  ) : review.length ? (
    <Sum tone="warn">Проверить: {names(review)}</Sum>
  ) : !overview.cliProtected ? (
    <Sum tone="warn">Без терминала</Sum>
  ) : (
    <Sum tone="ok">Все доступны</Sum>
  );

  const cleanState = state?.clean_room;
  const activeClean =
    cleanState?.profiles.find((p) => p.id === cleanState.active_profile_id) ?? cleanState?.profiles[0];
  const cleanRoomSum = activeClean?.warmup_started_at ? (
    <Sum tone="ok">Прогрев запущен</Sum>
  ) : cleanState && cleanState.profiles.length > 0 ? (
    <Sum tone="ok">Готова ({cleanState.profiles.length})</Sum>
  ) : (
    <Sum>Аудит и запуск</Sum>
  );

  const riskScore = personaRisk?.score ?? null;
  const riskBand = riskScore == null ? null : riskScore >= 55 ? "danger" : riskScore >= 25 ? "warn" : "ok";
  const backupSum =
    riskBand === "danger" ? (
      <Sum tone="danger">SOS · Риск высокий</Sum>
    ) : riskBand === "warn" ? (
      <Sum tone="warn">Риск: Средний</Sum>
    ) : riskBand === "ok" ? (
      <Sum tone="ok">Риск: Низкий</Sum>
    ) : (
      <Sum>Бункер и профили</Sum>
    );

  const hasRoute = Boolean(
    state?.upstream_proxy?.enabled ||
      (overview.routesSnapshot &&
        (Object.values(overview.routesSnapshot.effective || {}).some(Boolean) ||
          overview.routesSnapshot.routes.some((r) => r.enabled && r.status === "active"))),
  );
  const connectSum = <Sum>{hasRoute ? "Ключ Заставы" : "Через ваш VPN"}</Sum>;

  const allPassed = model.checksTotal > 0 && model.checksPassed === model.checksTotal;
  const checksSum = off ? (
    <Sum>Не действуют</Sum>
  ) : model.checksTotal ? (
    <Sum tone={allPassed ? "ok" : "warn"}>{model.checksLabel}</Sum>
  ) : (
    <Sum>Проверяем…</Sum>
  );

  const rows: { id: string; route: Route; icon: IconName; title: string; sum: ReactNode }[] = [
    { id: "services", route: { page: "services" }, icon: "shield", title: "Нейросети и защита", sum: servicesSum },
    {
      id: "clean-room",
      route: { page: "clean-room", cleanRoomTab: "launchpad" },
      icon: "zap",
      title: "Чистая комната",
      sum: cleanRoomSum,
    },
    { id: "backup", route: { page: "backup" }, icon: "folder", title: "Аккаунты, Бункер и SOS", sum: backupSum },
    { id: "connect", route: { page: "connect" }, icon: "key", title: "VPN и ключи", sum: connectSum },
    { id: "checks", route: { page: "checks" }, icon: "pulse", title: "Проверки и гайды", sum: checksSum },
  ];

  return (
    <Card className="zs-v3-sections">
      <Rows>
        {rows.map((r) => (
          <Row key={r.id} icon={r.icon} title={r.title} trail={r.sum} onClick={() => onPushRoute(r.route)} />
        ))}
      </Rows>
    </Card>
  );
}

import { useEffect, useMemo, useRef, useState } from "react";
import type { ProviderId, RiskReport } from "../../types";
import { Badge, Banner, Card, EmptyState, Progress, Row, Rows, Skeleton, StatusHero } from "../../ui";
import { onboarding as copy } from "../../shared/copy/ru";
import { checksWord } from "../../shared/lib/format";
import { SmartScreenGuide, SplitRoutingAnim } from "../mascot";
import { evaluateNetwork } from "./networkVerdict";
import { StepFooter, StepFrame } from "./parts";

/** Отчёту старше двух минут не верим: при повторном знакомстве проверяем заново. */
const STALE_SECONDS = 120;

export interface StepNetworkProps {
  reports: Partial<Record<ProviderId, RiskReport>>;
  activeReport: RiskReport | null;
  refreshing: boolean;
  auditError: string | null;
  currentIp: string;
  trustScore: number;
  /** Перезапуск того же аудита, что и на «Обзоре» (runFullAudit). */
  onRecheck: () => void;
  onNext: () => void;
  onBack: () => void;
  onOpenConnect: () => void;
}

/**
 * Шаг 2: живой вердикт аудита, который шлюз уже запустил при старте, плюс пояснение по-сервисной маршрутизации.
 * Новых запросов нет, пока отчёт свежий; повторяем только по кнопке или если отчёт устарел.
 */
export function StepNetwork({
  reports,
  activeReport,
  refreshing,
  auditError,
  currentIp,
  trustScore,
  onRecheck,
  onNext,
  onBack,
  onOpenConnect,
}: StepNetworkProps) {
  const [startedStale] = useState(() => {
    const at = activeReport?.telemetry?.resolved_at;
    return Boolean(at) && Date.now() / 1000 - (at as number) > STALE_SECONDS;
  });
  const requested = useRef(false);
  const [sawRefresh, setSawRefresh] = useState(false);

  useEffect(() => {
    if (startedStale && !requested.current) {
      requested.current = true;
      onRecheck();
    }
  }, [startedStale, onRecheck]);
  useEffect(() => {
    if (refreshing) setSawRefresh(true);
  }, [refreshing]);

  const waitingFresh = startedStale && !(sawRefresh && !refreshing);
  const loading = waitingFresh || (!activeReport && (refreshing || !auditError));
  const failed = !loading && !activeReport;

  const verdict = useMemo(() => evaluateNetwork(reports, activeReport), [reports, activeReport]);

  let footer;
  if (loading) {
    footer = <StepFooter back={onBack} primary={{ disabled: true, children: copy.network.loadingButton }} />;
  } else if (failed) {
    footer = (
      <StepFooter
        back={onBack}
        primary={{ icon: "refresh", onClick: onRecheck, disabled: refreshing, children: copy.network.error.retry }}
        secondary={{ onClick: onNext, children: copy.network.error.anyway }}
      />
    );
  } else if (verdict.good || verdict.reason === "timezone") {
    footer = <StepFooter back={onBack} primary={{ onClick: onNext, children: copy.network.next }} />;
  } else {
    footer = (
      <StepFooter
        back={onBack}
        primary={{ icon: "arrow", onClick: onOpenConnect, children: copy.network.vpn }}
        secondary={{ onClick: onNext, children: copy.skipAnyway }}
      />
    );
  }

  return (
    <StepFrame title={copy.network.title} lead={copy.network.lead} footer={footer}>
      <SplitRoutingAnim compact active={loading || failed || verdict.good} />
      <div className="zs-onb__result" aria-live="polite" aria-atomic="true">
        {loading ? (
          <Loading />
        ) : failed ? (
          <Card>
            <EmptyState icon="alert" title={copy.network.error.title}>
              {copy.network.error.text}
            </EmptyState>
          </Card>
        ) : (
          <>
            <StatusHero
              score={trustScore}
              tone={verdict.tone}
              title={copy.network.verdict[verdict.verdict]}
              ip={currentIp !== "--" ? currentIp : undefined}
              country={currentIp !== "--" ? verdict.country || undefined : undefined}
              facts={
                <Badge
                  tone={verdict.passed === verdict.total ? "ok" : verdict.good ? "neutral" : "warn"}
                  icon={verdict.passed === verdict.total ? "check" : verdict.good ? undefined : "alert"}
                >
                  {copy.network.checks(verdict.passed, verdict.total, checksWord(verdict.total))}
                </Badge>
              }
            />
            {verdict.good && verdict.passed < verdict.total && <p className="zs-onb__note">{copy.network.advice}</p>}
            {!verdict.good && verdict.reason && <Reason verdict={verdict} />}
            <Card>
              <Rows>
                <Row icon="key" title={copy.network.routing.title} sub={copy.network.routing.sub} />
              </Rows>
            </Card>
          </>
        )}
      </div>
      <SmartScreenGuide collapsible defaultExpanded={false} />
    </StepFrame>
  );
}

function Reason({ verdict }: { verdict: ReturnType<typeof evaluateNetwork> }) {
  const reason = copy.network.reasons[verdict.reason ?? "other"];
  const country = verdict.reason === "restricted" && verdict.country ? `${copy.network.reasons.restricted.country(verdict.country)} ` : "";
  return (
    <Banner tone={verdict.tone === "danger" ? "danger" : "warn"} title={reason.title}>
      {country}
      {reason.text}
    </Banner>
  );
}

function Loading() {
  return (
    <>
      <Progress label={copy.network.loading} />
      <Card>
        <div className="zs-hero">
          <Skeleton variant="circle" width={64} />
          <div className="zs-hero__body">
            <Skeleton width="70%" height={22} />
            <Skeleton width="50%" className="mt-2" />
          </div>
        </div>
        <Skeleton variant="block" height={24} className="mt-3" />
      </Card>
    </>
  );
}

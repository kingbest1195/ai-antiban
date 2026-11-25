import { useState } from "react";
import type { ReactNode } from "react";
import type { AppStateData, ProviderId, RiskReport } from "../../types";
import { Badge, Button, ExpandRow, Row } from "../../ui";
import { overview as copy, providers as providerCopy, status as words } from "../../shared/copy/ru";
import { maskIpsInText } from "../../shared/lib/format";
import { failedChecks } from "../checks/checksModel";
import { needsForceConfirm } from "./useOverviewModel";
import type { ServiceModel } from "./useOverviewModel";

interface ServiceRowProps {
  service: ServiceModel;
  report: RiskReport | undefined;
  state: AppStateData | null;
  blockedByUser: boolean;
  verifying?: boolean;
  hideIpMode?: boolean;
  defaultOpen?: boolean;
  onFix: (provider: ProviderId) => void;
  onAllow: (service: ServiceModel, report: RiskReport | undefined, blockedByUser: boolean) => void;
}

export function ServiceRow({
  service,
  report,
  state,
  blockedByUser,
  verifying,
  hideIpMode = false,
  defaultOpen = false,
  onFix,
  onAllow,
}: ServiceRowProps) {
  const [open, setOpen] = useState(defaultOpen);
  const meta = providerCopy[service.id];
  const { status } = service;

  let badge: ReactNode;
  let note: string | null = null;
  let tone: "neutral" | "ok" | "warn" | "danger" = "ok";

  switch (status) {
    case "ok":
      badge = <Badge tone="ok">{words.available}</Badge>;
      break;
    case "allowed":
      badge = <Badge tone="ok">{words.available}</Badge>;
      note =
        service.allowReason === "trusted_exception"
          ? copy.service.session
          : service.allowReason === "pinned_travel"
            ? copy.service.pinnedTravel
            : copy.service.sessionOnly;
      break;
    case "warn":
      badge = (
        <Badge tone="warn" icon="alert">
          {copy.service.warnBadge}
        </Badge>
      );
      note = blockedByUser ? copy.service.blocked : copy.service.warnNote;
      tone = "warn";
      break;
    case "critical":
      badge = (
        <Badge tone="danger" icon="alert">
          {words.blocked}
        </Badge>
      );
      tone = "danger";
      break;
    case "checking":
      badge = <Badge busy>{copy.service.checking}</Badge>;
      tone = "neutral";
      break;
    case "disabled":
      badge = <Badge tone="neutral">{copy.service.monitoringDisabled}</Badge>;
      note = copy.service.monitoringDisabledNote;
      tone = "neutral";
      break;
    case "missing":
      badge = (
        <Badge tone="warn" icon="alert">
          {words.review}
        </Badge>
      );
      note = copy.service.missing;
      tone = "warn";
      break;
  }

  const sub = (
    <>
      <span className="block">{meta.domains}</span>
      {note && <span className="block">{note}</span>}
    </>
  );

  // Решение по сервису принимается здесь: раскрываем только строки, где есть проблема.
  if (status !== "warn" && status !== "critical") {
    return (
      <Row
        icon={status === "ok" || status === "allowed" || status === "checking" || status === "disabled" ? "shield" : "alert"}
        tone={tone}
        title={meta.name}
        sub={sub}
        trail={badge}
      />
    );
  }

  const first = report ? failedChecks(report, state)[0] : undefined;
  const reason = first
    ? `${first.title}. ${maskIpsInText(first.result.message, hideIpMode)}`
    : status === "critical"
      ? copy.service.blocked
      : copy.service.noReason;

  return (
    <ExpandRow
      icon="alert"
      tone={tone}
      title={meta.name}
      sub={sub}
      trail={badge}
      open={open}
      onToggle={() => setOpen((v) => !v)}
      detailLabel={copy.service.detailLabel}
    >
      <p className="zs-t-body">{reason}</p>
      <div className="flex flex-wrap gap-2">
        {report && (
          <Button size="sm" onClick={() => onFix(service.id)}>
            {copy.service.fix}
          </Button>
        )}
        <Button variant="quiet" size="sm" disabled={verifying} onClick={() => onAllow(service, report, blockedByUser)}>
          {blockedByUser ? copy.service.unblock : copy.service.forceAllow}
        </Button>
      </div>
      <p className="zs-t-caption">
        {blockedByUser && !needsForceConfirm(service.status, report) ? copy.service.unblockHint : copy.service.forceHint}
      </p>
    </ExpandRow>
  );
}

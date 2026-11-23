import { useEffect, useState } from "react";
import type { ProviderId } from "../../types";
import { Badge, Banner, Button, Card, ConfirmModal, HintCard, Row, Rows, Section } from "../../ui";
import { overview as copy, providers as providerCopy } from "../../shared/copy/ru";
import { CoverageSection } from "../coverage/CoverageSection";
import { executeAllowSequence } from "../overview/OverviewScreen";
import type { OverviewScreenProps } from "../overview/OverviewScreen";
import { ServiceRow } from "../overview/ServiceRow";
import { needsForceConfirm } from "../overview/useOverviewModel";
import { ProtectedRows } from "./ProtectedRows";
import type { OverviewView } from "./types";

/** Страница раздела 1 «Нейросети и защита»: ServicesList (с executeAllowSequence) + ProtectedRows + 4-state CoverageSection. */
export function ServicesPage({
  overview,
  view,
  onDismissHint,
}: {
  overview: OverviewScreenProps;
  view: OverviewView;
  onDismissHint?: (hintId: string) => Promise<unknown> | void;
}) {
  const [forceAllowTarget, setForceAllowTarget] = useState<ProviderId | null>(null);
  const [persistForceException, setPersistForceException] = useState<boolean>(false);
  const [verifyingAllow, setVerifyingAllow] = useState<ProviderId | null>(null);
  const [localDismissed, setLocalDismissed] = useState<string[]>(
    () => overview.state?.dismissed_hints ?? [],
  );
  useEffect(() => {
    if (overview.state?.dismissed_hints) {
      setLocalDismissed(overview.state.dismissed_hints);
    }
  }, [overview.state?.dismissed_hints]);
  const handleDismiss = (id: string) => {
    setLocalDismissed((prev) => (prev.includes(id) ? prev : [...prev, id]));
    void onDismissHint?.(id);
  };
  const { model, failed } = view;
  const off = !overview.startupPending && !overview.sysproxyActive;
  const adminAuth = overview.protection?.adminAuthMessage;

  const requestAllow = (service: import("../overview/useOverviewModel").ServiceModel, report: import("../../types").RiskReport | undefined, blockedByUser: boolean) => {
    const provider = service.id;
    if (needsForceConfirm(service.status, report)) {
      setPersistForceException(false);
      setForceAllowTarget(provider);
      return;
    }
    if (blockedByUser && overview.onVerifyAndUnblockProvider) {
      setVerifyingAllow(provider);
      void Promise.resolve(overview.onVerifyAndUnblockProvider(provider)).finally(() => {
        setVerifyingAllow(null);
      });
      return;
    }
    void executeAllowSequence(provider, blockedByUser, overview.onUnblockProvider, overview.onAllowProvider);
  };

  return (
    <>
      <HintCard
        hintId="services_intro"
        body="Статус защиты нейросетей, браузеров, редакторов и терминала на этом устройстве."
        dismissedHints={localDismissed}
        onDismiss={handleDismiss}
      />
      {adminAuth && (
        <Banner
          tone="warn"
          title="Нужны права администратора"
          action={
            <Button
              size="sm"
              variant="secondary"
              disabled={overview.protection?.retryingAdminAuth}
              onClick={() => void overview.protection?.enableSysproxyPrivileged()}
            >
              Разрешить с паролем
            </Button>
          }
        >
          {adminAuth}
        </Banner>
      )}

      {!failed && (
        <Section title={copy.sectionServices}>
          <Card>
            {overview.killswitchFrozen ? (
              <Rows>
                {model.services.map((service) => {
                  const isDisabled = service.status === "disabled";
                  return (
                    <Row
                      key={service.id}
                      icon={isDisabled ? "shield" : "alert"}
                      tone={isDisabled ? "neutral" : "danger"}
                      title={providerCopy[service.id].name}
                      sub={providerCopy[service.id].domains}
                      trail={
                        <Badge tone={isDisabled ? "neutral" : "danger"} icon={isDisabled ? undefined : "alert"}>
                          {isDisabled ? copy.service.monitoringDisabled : copy.service.stopped}
                        </Badge>
                      }
                    />
                  );
                })}
              </Rows>
            ) : off ? (
              <>
                <p className="zs-services-off-note" role="status">
                  {copy.service.unprotectedNote}
                </p>
                <Rows>
                  {model.services.map((service) => {
                    const isDisabled = service.status === "disabled";
                    return (
                      <Row
                        key={service.id}
                        icon="shield"
                        tone="neutral"
                        title={providerCopy[service.id].name}
                        sub={providerCopy[service.id].domains}
                        trail={
                          <Badge tone="neutral">
                            {isDisabled ? copy.service.monitoringDisabled : copy.service.unprotected}
                          </Badge>
                        }
                      />
                    );
                  })}
                </Rows>
              </>
            ) : (
              <Rows>
                {model.services.map((service) => (
                  <ServiceRow
                    key={service.id}
                    service={service}
                    report={overview.reports[service.id]}
                    state={overview.state}
                    onFix={overview.onFixService}
                    onAllow={requestAllow}
                    blockedByUser={Boolean(overview.state?.blocked_providers?.includes(service.id))}
                    verifying={verifyingAllow === service.id}
                  />
                ))}
              </Rows>
            )}
          </Card>
        </Section>
      )}

      <Section title="Что защищено">
        <Card>
          <ProtectedRows p={overview} />
        </Card>
      </Section>

      <CoverageSection
        variant="overview"
        initialSnapshot={overview.coverageSnapshot}
        pending={overview.startupPending}
        protection={overview.protection}
        onToast={overview.onToast}
        legend
      />

      <ConfirmModal
        open={forceAllowTarget !== null}
        title={forceAllowTarget ? copy.service.confirm.title(providerCopy[forceAllowTarget].name) : ""}
        confirmLabel={copy.service.confirm.action}
        onConfirm={() => {
          if (forceAllowTarget) {
            const target = forceAllowTarget;
            const persist = persistForceException;
            const blockedByUser = Boolean(overview.state?.blocked_providers?.includes(target));
            setForceAllowTarget(null);
            setPersistForceException(false);
            void executeAllowSequence(
              target,
              blockedByUser,
              overview.onUnblockProvider,
              (p) => overview.onAllowProvider(p, persist),
            );
          }
        }}
        onCancel={() => {
          setForceAllowTarget(null);
          setPersistForceException(false);
        }}
      >
        {forceAllowTarget ? (
          <>
            <p>{copy.service.confirm.text(providerCopy[forceAllowTarget].name)}</p>
            <label className="zs-t-caption mt-2 flex items-start gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={persistForceException}
                onChange={(e) => setPersistForceException(e.target.checked)}
              />
              <span>{copy.service.confirm.persistLabel}</span>
            </label>
          </>
        ) : ""}
      </ConfirmModal>
    </>
  );
}

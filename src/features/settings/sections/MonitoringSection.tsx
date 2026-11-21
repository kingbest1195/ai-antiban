import type { FormEvent } from "react";
import type { ProviderId } from "../../../types";
import { Badge, Button, Field, Mono, Row, Rows, Section, Switch } from "../../../ui";
import { providers as providerCopy, settings as copy } from "../../../shared/copy/ru";
import { formatIp } from "../../../shared/lib/format";
import { MONITORED_PROVIDERS } from "../useSettingsController";

interface MonitoringSectionProps {
  disabledSet: Set<string>;
  monitoringBusy: ProviderId | null;
  exceptionEntries: { provider: string; ip: string }[];
  exceptionsBusy: boolean;
  hideIpMode?: boolean;
  customDomains: string[];
  newDomainInput: string;
  domainBusy: boolean;
  providerLabel: (provider: string) => string;
  onToggleProviderMonitoring: (id: ProviderId, next: boolean) => Promise<void>;
  onRemoveTrustedException: (provider: string, ip: string) => Promise<void>;
  onClearTrustedExceptions: () => Promise<void>;
  onNewDomainInputChange: (val: string) => void;
  onAddDomain: (e: FormEvent) => Promise<void>;
  onRemoveDomain: (domain: string) => Promise<void>;
}

export function MonitoringSection({
  disabledSet,
  monitoringBusy,
  exceptionEntries,
  exceptionsBusy,
  hideIpMode = false,
  customDomains,
  newDomainInput,
  domainBusy,
  providerLabel,
  onToggleProviderMonitoring,
  onRemoveTrustedException,
  onClearTrustedExceptions,
  onNewDomainInputChange,
  onAddDomain,
  onRemoveDomain,
}: MonitoringSectionProps) {
  return (
    <>
      <Section title={copy.monitoring.section}>
        <p className="zs-t-body zs-settings__lead">{copy.monitoring.text}</p>
        <Rows className="zs-settings__rows">
          {MONITORED_PROVIDERS.map((id) => {
            const enabled = !disabledSet.has(id);
            const statusText = enabled ? copy.monitoring.enabledSub : copy.monitoring.disabledSub;
            const sub =
              id === "gemini"
                ? `${statusText}. ${copy.monitoring.geminiNote}`
                : `${statusText} (${providerCopy[id].domains})`;
            return (
              <Row
                key={id}
                icon="shield"
                tone={enabled ? "ok" : "neutral"}
                title={providerCopy[id].name}
                sub={sub}
                trail={
                  <Switch
                    checked={enabled}
                    disabled={monitoringBusy !== null}
                    onChange={(next) => void onToggleProviderMonitoring(id, next)}
                    aria-label={copy.monitoring.toggleLabel(providerCopy[id].name)}
                  />
                }
              />
            );
          })}
        </Rows>
      </Section>

      <Section title={copy.trustedExceptions.section}>
        <p className="zs-t-body zs-settings__lead">{copy.trustedExceptions.text}</p>
        {exceptionEntries.length > 0 ? (
          <>
            <div className="zs-settings__exc-actions">
              <Button
                size="sm"
                variant="secondary"
                disabled={exceptionsBusy}
                onClick={() => void onClearTrustedExceptions()}
              >
                {copy.trustedExceptions.clearAll}
              </Button>
            </div>
            <Rows className="zs-settings__rows">
              {exceptionEntries.map(({ provider, ip }) => {
                const label = providerLabel(provider);
                const displayIp = formatIp(ip, hideIpMode);
                return (
                  <Row
                    key={`${provider}:${ip}`}
                    icon="lock"
                    title={label}
                    sub={<Mono>{displayIp}</Mono>}
                    trail={
                      <Button
                        variant="quiet"
                        size="sm"
                        iconOnly
                        icon="x"
                        aria-label={copy.trustedExceptions.remove(label, displayIp)}
                        disabled={exceptionsBusy}
                        onClick={() => void onRemoveTrustedException(provider, ip)}
                      />
                    }
                  />
                );
              })}
            </Rows>
          </>
        ) : (
          <p className="zs-settings__empty">{copy.trustedExceptions.empty}</p>
        )}
      </Section>

      <Section title={copy.domains.section}>
        <p className="zs-t-body zs-settings__lead">{copy.domains.text}</p>
        <p className="zs-settings__sub">{copy.domains.builtinTitle}</p>
        <ul className="zs-settings__list">
          {copy.domains.builtin.map((name) => (
            <li key={name}>{name}</li>
          ))}
        </ul>

        <p className="zs-settings__sub">
          {copy.domains.ownTitle} <Badge>{copy.domains.ownCount(customDomains.length)}</Badge>
        </p>
        <form className="zs-settings__form" onSubmit={onAddDomain}>
          <Field
            label={copy.domains.fieldLabel}
            placeholder={copy.domains.placeholder}
            help={copy.domains.help}
            value={newDomainInput}
            onChange={(e) => onNewDomainInputChange(e.target.value)}
            autoComplete="off"
            autoCapitalize="off"
            spellCheck={false}
            action={
              <Button type="submit" disabled={domainBusy || !newDomainInput.trim()}>
                {domainBusy ? copy.domains.adding : copy.domains.add}
              </Button>
            }
          />
        </form>
        {customDomains.length > 0 ? (
          <Rows className="zs-settings__rows">
            {customDomains.map((domain) => (
              <Row
                key={domain}
                icon="globe"
                title={<Mono>{domain}</Mono>}
                trail={
                  <Button
                    variant="quiet"
                    size="sm"
                    iconOnly
                    icon="x"
                    aria-label={copy.domains.remove(domain)}
                    disabled={domainBusy}
                    onClick={() => void onRemoveDomain(domain)}
                  />
                }
              />
            ))}
          </Rows>
        ) : (
          <p className="zs-settings__empty">{copy.domains.empty}</p>
        )}
      </Section>
    </>
  );
}

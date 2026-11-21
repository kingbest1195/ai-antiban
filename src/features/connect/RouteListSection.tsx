import type { RouteView, UpstreamProxyConfig } from "../../types";
import { openZastavaBot } from "../../utils/opener";
import {
  Badge,
  Button,
  Card,
  Field,
  Mono,
  Row,
  Rows,
  Segmented,
  Switch,
} from "../../ui";
import type { BadgeTone, RowTone, SegmentedOption } from "../../ui";
import { connect as copy } from "../../shared/copy/ru";
import { formatCountryWithCode } from "../../shared/lib/country";
import { formatIp } from "../../shared/lib/format";
import { formatRemainingTimeRu, getRouteExpiryUrgency } from "../../shared/lib/zastavaKey";

export type AddKeyScope = "all" | "save_only";

const ADD_SCOPE_OPTIONS: SegmentedOption<AddKeyScope>[] = [
  { value: "all", label: copy.key.scopeOptions.all },
  { value: "save_only", label: copy.key.scopeOptions.save_only },
];

interface AddKeyFormProps {
  addScope: AddKeyScope;
  setAddScope: (scope: AddKeyScope) => void;
  inputKey: string;
  onInputKeyChange: (val: string) => void;
  error: string | null;
  connecting: boolean;
  onAddKey: () => void;
  suppressPrimaryCta?: boolean;
}

function AddKeyForm({
  addScope,
  setAddScope,
  inputKey,
  onInputKeyChange,
  error,
  connecting,
  onAddKey,
  suppressPrimaryCta = false,
}: AddKeyFormProps) {
  return (
    <div className="zs-stack gap-3">
      <div className="zs-stack gap-1">
        <span className="zs-t-label text-ink-2">{copy.key.scopeLabel}</span>
        <Segmented
          aria-label={copy.key.scopeLabel}
          options={ADD_SCOPE_OPTIONS}
          value={addScope}
          onChange={setAddScope}
        />
      </div>
      <Field
        label={copy.key.fieldLabel}
        placeholder={copy.key.placeholder}
        value={inputKey}
        onChange={(e) => onInputKeyChange(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter") onAddKey();
        }}
        autoComplete="off"
        spellCheck={false}
        help={copy.key.caption}
        error={error ?? undefined}
        action={
          <Button onClick={onAddKey} disabled={connecting}>
            {connecting ? copy.key.connecting : copy.key.connect}
          </Button>
        }
      />
      <Button variant={suppressPrimaryCta ? "secondary" : "primary"} block onClick={() => openZastavaBot()}>
        {copy.key.get}
      </Button>
    </div>
  );
}

interface RouteListSectionProps {
  routes: RouteView[];
  upstream: UpstreamProxyConfig | null;
  currentIp: string;
  currentCountry: string;
  hideIpMode: boolean;
  addScope: AddKeyScope;
  setAddScope: (scope: AddKeyScope) => void;
  inputKey: string;
  onInputKeyChange: (val: string) => void;
  error: string | null;
  connecting: boolean;
  testingId: string | null;
  togglingId: string | null;
  deletingId: string | null;
  onAddKey: () => void;
  onToggleRoute: (routeId: string, enabled: boolean) => void;
  onTestRoute: (routeId: string) => void;
  onSetDefaultRoute: (routeId: string) => void;
  onRemoveRoute: (routeId: string) => void;
  onLegacyToggle: () => void;
  onLegacyDisconnect: () => void;
  suppressPrimaryCta?: boolean;
}

export function RouteListSection({
  routes,
  upstream,
  currentIp,
  currentCountry,
  hideIpMode,
  addScope,
  setAddScope,
  inputKey,
  onInputKeyChange,
  error,
  connecting,
  testingId,
  togglingId,
  deletingId,
  onAddKey,
  onToggleRoute,
  onTestRoute,
  onSetDefaultRoute,
  onRemoveRoute,
  onLegacyToggle,
  onLegacyDisconnect,
  suppressPrimaryCta = false,
}: RouteListSectionProps) {
  const hasRoutes = routes.length > 0;
  const isLegacyConfigured = Boolean(upstream);
  const isLegacyActive = upstream?.enabled ?? false;
  const exitKnown = currentIp !== "--";

  return (
    <Card title={copy.key.title}>
      <p className="zs-t-body mb-3 text-ink-2">{copy.key.text}</p>

      {hasRoutes ? (
        <>
          <Rows>
            {routes.map((r) => {
              const isTesting = testingId === r.id;
              const isToggling = togglingId === r.id;
              const isDeleting = deletingId === r.id;
              const expiryUrgency = getRouteExpiryUrgency(r.expires_at);
              const isExpired = r.status === "expired" || expiryUrgency === "expired";
              const showRenew = expiryUrgency !== "none" || isExpired;

              const statusTone: BadgeTone =
                r.status === "active"
                  ? "ok"
                  : r.status === "unreachable" || isExpired
                  ? "danger"
                  : r.status === "exit_ip_mismatch"
                  ? "warn"
                  : "neutral";
              const rowTone: RowTone = statusTone;
              const statusText =
                r.status === "active"
                  ? copy.key.switchOn
                  : isExpired
                  ? copy.key.expired
                  : r.status === "unreachable"
                  ? copy.key.unreachable
                  : r.status === "exit_ip_mismatch"
                  ? copy.key.ipMismatch
                  : copy.key.switchOff;

              const locationText = r.country ? formatCountryWithCode(r.country) || r.country : "";
              const latencyText = r.health?.latency_ms ? copy.key.latency(r.health.latency_ms) : "";
              const dateText = r.expires_at ? copy.key.expires(new Date(r.expires_at * 1000).toLocaleDateString()) : "";

              return (
                <div key={r.id} className="zs-stack gap-2 py-2 border-b border-line last:border-b-0">
                  <Row
                    icon="key"
                    tone={rowTone}
                    title={
                      <span className="inline-flex items-center gap-2 flex-wrap">
                        <span>{r.label || copy.key.defaultLabel}</span>
                        {r.is_default && <Badge tone="info">{copy.key.defaultBadge}</Badge>}
                        {r.is_profile_route && <Badge tone="neutral">{copy.key.profileBadge}</Badge>}
                        <Badge tone={statusTone}>{statusText}</Badge>
                        {(expiryUrgency === "soon" || expiryUrgency === "critical") && r.expires_at && (
                          <Badge tone={expiryUrgency === "critical" ? "danger" : "warn"}>
                            {copy.key.expiringSoon(formatRemainingTimeRu(r.expires_at))}
                          </Badge>
                        )}
                      </span>
                    }
                    sub={
                      <span className="inline-flex items-center gap-2 flex-wrap">
                        {r.exit_ip && <Mono>{formatIp(r.exit_ip, hideIpMode)}</Mono>}
                        {locationText && <span>· {locationText}</span>}
                        {latencyText && <span>· {latencyText}</span>}
                        {dateText && <span>· {dateText}</span>}
                      </span>
                    }
                    trail={
                      <Switch
                        checked={r.enabled}
                        disabled={isToggling}
                        onChange={() => onToggleRoute(r.id, !r.enabled)}
                        aria-label={copy.key.switchLabel}
                      />
                    }
                  />

                  <div className="flex items-center gap-2 pl-9 flex-wrap">
                    <Button size="sm" variant="secondary" disabled={isTesting} onClick={() => onTestRoute(r.id)}>
                      {isTesting ? copy.key.testing : copy.key.test}
                    </Button>
                    {showRenew && (
                      <Button
                        size="sm"
                        variant={!suppressPrimaryCta && (expiryUrgency === "critical" || isExpired) ? "primary" : "secondary"}
                        onClick={() => openZastavaBot(r.id)}
                      >
                        {copy.key.renew}
                      </Button>
                    )}
                    {!r.is_default && (
                      <Button size="sm" variant="quiet" onClick={() => onSetDefaultRoute(r.id)}>
                        {copy.key.makeDefault}
                      </Button>
                    )}
                    <Button size="sm" variant="quiet" disabled={isDeleting} onClick={() => onRemoveRoute(r.id)}>
                      {copy.key.remove}
                    </Button>
                  </div>
                </div>
              );
            })}
          </Rows>

          <div className="mt-4 pt-3 border-t border-line">
            <AddKeyForm
              addScope={addScope}
              setAddScope={setAddScope}
              inputKey={inputKey}
              onInputKeyChange={onInputKeyChange}
              error={error}
              connecting={connecting}
              onAddKey={onAddKey}
              suppressPrimaryCta={suppressPrimaryCta}
            />
          </div>
        </>
      ) : isLegacyConfigured && upstream ? (
        <>
          <Rows>
            <Row
              icon="key"
              tone={isLegacyActive ? "ok" : "neutral"}
              title={upstream.label || copy.key.defaultLabel}
              sub={isLegacyActive ? copy.key.switchOn : copy.key.switchOff}
              trail={
                <Switch
                  checked={isLegacyActive}
                  onChange={onLegacyToggle}
                  aria-label={copy.key.switchLabel}
                />
              }
            />
            <Row
              icon="globe"
              title={copy.key.exit}
              sub={
                exitKnown ? (
                  <>
                    <Mono>{formatIp(currentIp, hideIpMode)}</Mono>
                    {formatCountryWithCode(currentCountry) ? ` · ${formatCountryWithCode(currentCountry)}` : ""}
                  </>
                ) : (
                  copy.key.exitUnknown
                )
              }
            />
          </Rows>
          <Button variant="danger" block className="mt-3" onClick={onLegacyDisconnect}>
            {copy.key.disconnect}
          </Button>
        </>
      ) : (
        <AddKeyForm
          addScope={addScope}
          setAddScope={setAddScope}
          inputKey={inputKey}
          onInputKeyChange={onInputKeyChange}
          error={error}
          connecting={connecting}
          onAddKey={onAddKey}
          suppressPrimaryCta={suppressPrimaryCta}
        />
      )}
    </Card>
  );
}

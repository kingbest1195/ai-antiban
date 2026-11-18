import type { ProviderId, RouteView, RoutesSnapshot } from "../../types";
import { DIRECT_ROUTE_ID } from "../../utils/api";
import { Banner, Card, Select } from "../../ui";
import { connect as copy } from "../../shared/copy/ru";
import {
  formatCountryWithCode,
  formatRouteOptionLabel,
  isCountryBlockedForProvider,
} from "../../shared/lib/country";
import { formatIp } from "../../shared/lib/format";
import { resolveProviderExitCountry } from "./ConnectScreen";

const PROVIDERS: { id: ProviderId; name: string }[] = [
  { id: "anthropic", name: copy.routes.services.anthropic },
  { id: "openai", name: copy.routes.services.openai },
  { id: "gemini", name: copy.routes.services.gemini },
];

interface ProviderRoutesSectionProps {
  snapshot: RoutesSnapshot | null;
  routes: RouteView[];
  currentCountry: string;
  hideIpMode: boolean;
  onBindProvider: (provider: ProviderId, target: string) => void;
}

export function ProviderRoutesSection({
  snapshot,
  routes,
  currentCountry,
  hideIpMode,
  onBindProvider,
}: ProviderRoutesSectionProps) {
  return (
    <Card title={copy.routes.title}>
      <p className="zs-t-body mb-3 text-ink-2">{copy.routes.text}</p>
      <div className="zs-stack gap-3">
        {PROVIDERS.map((p) => {
          const explicitBinding = snapshot?.provider_routes[p.id];
          const isDirectSentinel = explicitBinding === DIRECT_ROUTE_ID;
          const isDefaultEffective = !explicitBinding && Boolean(snapshot?.default_route_id);
          const currentValue = isDirectSentinel
            ? "direct"
            : explicitBinding || (isDefaultEffective ? "default" : "direct");

          const selectOptions = [
            { value: "direct", label: copy.routes.direct },
            ...(snapshot?.default_route_id
              ? [{ value: "default", label: copy.routes.default }]
              : []),
            ...routes.map((r) => {
              const rawIpOrHost = r.exit_ip || r.entries[0]?.host || "";
              const ipOrHost = rawIpOrHost ? formatIp(rawIpOrHost, hideIpMode) : "";
              return {
                value: r.id,
                label: formatRouteOptionLabel({
                  label: r.label,
                  country: r.country,
                  ipOrHost,
                  fallbackLabel: copy.key.defaultLabel,
                }),
              };
            }),
          ];

          const exitCountry = resolveProviderExitCountry(p.id, snapshot, routes, currentCountry);
          const blockedCountry =
            exitCountry && exitCountry !== "--" && isCountryBlockedForProvider(p.id, exitCountry)
              ? exitCountry
              : null;

          return (
            <div key={p.id} className="zs-stack gap-2 p-2 rounded-lg bg-bg-2">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <span className="font-medium text-ink">{p.name}</span>
                <div className="w-full sm:w-64">
                  <Select
                    options={selectOptions}
                    value={currentValue}
                    onChange={(e) => onBindProvider(p.id, e.target.value)}
                    aria-label={p.name}
                  />
                </div>
              </div>
              {blockedCountry && (
                <Banner
                  tone="warn"
                  title={copy.routes.blockedCountryTitle(
                    p.name,
                    formatCountryWithCode(blockedCountry) || blockedCountry,
                  )}
                >
                  {copy.routes.blockedCountryText}
                </Banner>
              )}
            </div>
          );
        })}
      </div>
    </Card>
  );
}

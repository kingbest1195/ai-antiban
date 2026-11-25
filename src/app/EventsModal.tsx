import type { GatewayStatsSnapshot } from "../types";
import { Badge, Button, Modal, Mono, Row, Rows } from "../ui";
import { overview as copy, status as words } from "../shared/copy/ru";
import { formatCountryWithCode, isBlockedGeoCode } from "../shared/lib/country";
import { formatClock } from "../shared/lib/format";

interface EventsModalProps {
  open: boolean;
  onClose: () => void;
  stats: GatewayStatsSnapshot | null;
}

/** Лента событий шлюза: хосты, время и что с ними сделала Застава. */
export function EventsModal({ open, onClose, stats }: EventsModalProps) {
  const events = (stats?.recent_events ?? [])
    .filter((ev) => ev.host?.trim().toLowerCase() !== "all")
    .slice()
    .reverse();
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={copy.events.title}
      footer={<Button onClick={onClose}>{copy.events.close}</Button>}
    >
      <p className="zs-modal-text">
        {copy.events.tunnels(stats?.active_ai_tunnels ?? 0)}
        {stats?.last_protected_host && (
          <>
            {" · "}
            {copy.events.last}: <Mono>{stats.last_protected_host}</Mono>
          </>
        )}
      </p>
      {events.length === 0 ? (
        <p className="zs-modal-text">{copy.events.waiting}</p>
      ) : (
        <Rows>
          {events.map((ev, idx) => {
            const action = ev.action?.trim().toUpperCase() ?? "";
            const isDirect =
              action === "DIRECT" ||
              ev.kind === "direct" ||
              ev.provider?.toLowerCase() === "non-ai" ||
              ev.country === "DIRECT";
            const isManualAllow =
              action === "MANUAL_ALLOW" || (action === "PROTECTED" && isBlockedGeoCode(ev.country));
            const isProtected = action === "PROTECTED" && !isManualAllow;
            const countryLabel = ev.country ? formatCountryWithCode(ev.country) || ev.country : "";
            return (
              <Row
                key={idx}
                title={<Mono>{ev.host}</Mono>}
                sub={formatClock(ev.timestamp)}
                trail={
                  isDirect ? (
                    <Badge>{words.direct}</Badge>
                  ) : isManualAllow ? (
                    <Badge tone="warn" icon="alert">
                      {words.manualAllow}
                      {countryLabel ? ` · ${countryLabel}` : ""}
                    </Badge>
                  ) : isProtected ? (
                    <Badge tone="ok" icon="check">
                      {words.protected}
                      {countryLabel ? ` · ${countryLabel}` : ""}
                    </Badge>
                  ) : (
                    <Badge tone="danger" icon="alert">
                      {words.blocked}
                    </Badge>
                  )
                }
              />
            );
          })}
        </Rows>
      )}
    </Modal>
  );
}

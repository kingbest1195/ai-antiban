import type { GatewayStatsSnapshot } from "../types";
import { Badge, Button, Modal, Mono, Row, Rows } from "../ui";
import { overview as copy, status as words } from "../shared/copy/ru";
import { formatCountryWithCode } from "../shared/lib/country";
import { formatClock } from "../shared/lib/format";

interface EventsModalProps {
  open: boolean;
  onClose: () => void;
  stats: GatewayStatsSnapshot | null;
}

/** Лента событий шлюза: хосты, время и что с ними сделала Застава. */
export function EventsModal({ open, onClose, stats }: EventsModalProps) {
  const events = (stats?.recent_events ?? []).slice().reverse();
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
            const isDirect =
              ev.action?.toUpperCase() === "DIRECT" ||
              ev.kind === "direct" ||
              ev.provider?.toLowerCase() === "non-ai" ||
              ev.country === "DIRECT";
            const isProtected = ev.action?.toUpperCase() === "PROTECTED";
            return (
              <Row
                key={idx}
                title={<Mono>{ev.host}</Mono>}
                sub={formatClock(ev.timestamp)}
                trail={
                  isDirect ? (
                    <Badge>{words.direct}</Badge>
                  ) : isProtected ? (
                    <Badge tone="ok" icon="check">
                      {words.protected}
                      {ev.country ? ` · ${formatCountryWithCode(ev.country) || ev.country}` : ""}
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

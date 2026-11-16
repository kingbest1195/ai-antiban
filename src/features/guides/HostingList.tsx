import { Badge, Button, Row } from "../../ui";
import { common, guides } from "../../shared/copy/ru";
import { openExternal } from "../../utils/opener";
import { VPS_PROVIDERS } from "./providers";
import type { VpsProvider } from "./providers";
import { useGuide } from "./context";

/**
 * Хостинги: строка с кнопкой перехода на сайт (партнёрская ссылка без изменений).
 * compact — название, конфигурация, цена; full — ещё описание, бейдж и локации.
 */
export function HostingList({ variant }: { variant: "compact" | "full" }) {
  const { onToast } = useGuide();

  const open = (vps: VpsProvider) => {
    openExternal(vps.url);
    onToast?.(guides.toast.openHosting, guides.toast.openHostingText(vps.name), "info");
  };

  return (
    <ul className="guides-offers">
      {VPS_PROVIDERS.map((vps) => (
        <li key={vps.id} className="guides-offer">
          <Row
            as="div"
            icon="globe"
            title={vps.name}
            sub={variant === "compact" ? `${vps.specs} · ${vps.locations.join(", ")}` : vps.tier}
            trail={
              <Button size="sm" variant="secondary" onClick={() => open(vps)}>
                {common.goTo}
              </Button>
            }
          />
          {variant === "full" && (
            <>
              <p className="guides-offer__text">{vps.description}</p>
              <p className="guides-offer__facts">
                <strong>{vps.price}</strong> · {vps.specs}
              </p>
              <div className="guides-offer__chips">
                {vps.locations.map((loc) => (
                  <Badge key={loc} mono>
                    {loc}
                  </Badge>
                ))}
              </div>
            </>
          )}
          <div className="guides-offer__meta">
            {variant === "compact" ? <Badge tone="info">{vps.price}</Badge> : <Badge tone="info">{vps.badge}</Badge>}
          </div>
        </li>
      ))}
    </ul>
  );
}

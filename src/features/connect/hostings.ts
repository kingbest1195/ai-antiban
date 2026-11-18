import { VPS_PROVIDERS } from "../guides/providers";
import { connect as copy } from "../../shared/copy/ru";

export interface Hosting {
  id: "hostvds" | "vultr" | "timeweb";
  name: string;
  sub: string;
  /** Партнёрская ссылка из GuideViewer, со всеми параметрами, без изменений. */
  url: string;
}

/** Три хостинга карточки «Свой VPN»: названия и ссылки берутся из данных гайда, подписи — из copy. */
export const HOSTINGS: Hosting[] = (["hostvds", "vultr", "timeweb"] as const).map((id) => {
  const vps = VPS_PROVIDERS.find((p) => p.id === id);
  return { id, name: vps?.name ?? id, sub: copy.vpn.hostings[id], url: vps?.url ?? "" };
});

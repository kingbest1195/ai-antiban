import type { VpnSetupMethod } from "./providers";

export type GuideSection = "vps" | "payment" | "os";
/** Способы настройки своего VPS. «Терминал (WireGuard)» прежнего GuideViewer показывал то же, что и «Каскад», поэтому слит с ним. */
export type VpsMethod = "amnezia" | "vless_one_cmd" | "cascade";
export type OsPart = "tz" | "geo";

export interface GuideTarget {
  section: GuideSection;
  /** Не задан — оставить выбранный способ как есть (так вёл себя прежний GuideViewer). */
  method?: VpsMethod;
  part?: OsPart;
}

const FROM_LEGACY_METHOD: Record<VpnSetupMethod, VpsMethod> = {
  amnezia: "amnezia",
  vless_one_cmd: "vless_one_cmd",
  terminal: "cascade",
  cascade: "cascade",
};

/**
 * Идентификатор гайда из «Обзора», «Подключения», диалога обрыва и трея → раздел и способ.
 * Понимает прежние id: 01-personal-vpn-15min, 01-personal-vpn-amnezia, vless_one_cmd, cascade, terminal,
 * 02-safe-payment-cards, 03-os-privacy-setup, 03-os-privacy-setup#geo, 03-os-network-dns, os-geo.
 * Неизвестный id открывает «Свой VPS».
 */
export function resolveGuide(id: string | null | undefined): GuideTarget {
  switch (id) {
    case "02-safe-payment-cards":
    case "payment":
      return { section: "payment" };
    case "03-os-privacy-setup#geo":
    case "03-os-network-dns":
    case "os-geo":
      return { section: "os", part: "geo" };
    case "03-os-privacy-setup":
    case "os":
      return { section: "os", part: "tz" };
    case "vless_one_cmd":
    case "terminal":
    case "cascade":
    case "amnezia":
      return { section: "vps", method: FROM_LEGACY_METHOD[id] };
    case "01-personal-vpn-amnezia":
      return { section: "vps", method: "amnezia" };
    default:
      return { section: "vps" };
  }
}

const URL_GUIDE = readGuideFromUrl();
let urlGuideUsed = false;

function readGuideFromUrl(): string | null {
  try {
    return new URLSearchParams(window.location.search).get("guide");
  } catch {
    return null;
  }
}

/** ?guide= в адресе страницы (для отладки и скриншотов): перекрывает цель только при первом показе экрана. */
export function peekUrlGuide(): string | null {
  return urlGuideUsed ? null : URL_GUIDE;
}

/** Вызывается после первого показа: дальше ?guide= не действует, цель задаёт вызывающий. */
export function markUrlGuideUsed(): void {
  urlGuideUsed = true;
}

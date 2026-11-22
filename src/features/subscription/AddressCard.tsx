import { useState } from "react";
import { Banner, Button, Card, Mono, Row, Rows, TabPanel, Tabs } from "../../ui";
import { subscription } from "../../shared/copy/ru";
import type { ShowToast } from "../../shared/hooks";
import { countryName } from "../../shared/lib/country";
import { useCopy } from "../guides/useCopy";
import {
  normalizeCountryCode,
  shouldShowUsTaxFreeAddresses,
  TAX_FREE_ADDRESSES,
  type AddressScenario,
} from "./addresses";

const copy = subscription.address;
const PREFIX = "subs-state";

export interface AddressCardProps {
  /** Страна выпуска карты (ISO-2, из проверки карты). */
  cardCountry?: string | null;
  /** Явный сценарий оплаты; без него для не-US карты выбирается `card`, иначе `apple_iap`. */
  scenario?: AddressScenario;
  onScenarioChange?: (scenario: AddressScenario) => void;
  onToast?: ShowToast;
}

/** Контекстный адрес для оплаты: безналоговые штаты США только для App Store США или американской карты. */
export function AddressCard({
  cardCountry,
  scenario: controlledScenario,
  onToast,
}: AddressCardProps) {
  const normalizedCardCc = normalizeCountryCode(cardCountry);
  const [index, setIndex] = useState<number>(0);
  const { copiedId, copy: copyText } = useCopy(onToast, 2000);

  const effectiveScenario: AddressScenario =
    controlledScenario ?? (normalizedCardCc && normalizedCardCc !== "US" ? "card" : "apple_iap");

  const showUsAddresses = shouldShowUsTaxFreeAddresses({
    cardCountry: normalizedCardCc,
    scenario: effectiveScenario,
  });

  const address = TAX_FREE_ADDRESSES[index];
  const copyValue = (id: string, value: string, label: string) =>
    copyText(id, value, { title: copy.toast.copied, text: `${label}: ${value}` });

  const cityZip = `${address.city}, ${address.code} ${address.zip}`;
  const full = `${address.street}, ${address.city}, ${address.code} ${address.zip}, United States`;
  const cardCountryRu = normalizedCardCc ? countryName(normalizedCardCc) || normalizedCardCc : null;

  return (
    <Card title={showUsAddresses ? copy.title : copy.nonUsTitle}>
      {showUsAddresses ? (
        <>
          <p className="zs-t-body subs-lead">
            {effectiveScenario === "apple_iap" ? copy.textApple : copy.textCard}
          </p>

          <Tabs
            items={TAX_FREE_ADDRESSES.map((a) => ({ id: a.code, label: a.code }))}
            value={address.code}
            onChange={(code) =>
              setIndex(Math.max(0, TAX_FREE_ADDRESSES.findIndex((a) => a.code === code)))
            }
            idPrefix={PREFIX}
            aria-label={copy.statesLabel}
            className="subs-states"
          />

          <TabPanel idPrefix={PREFIX} id={address.code} selected className="subs-panel">
            <Rows>
              <Row icon="globe" title={address.stateName} sub={copy.state} />
              <Row
                icon="folder"
                title={<Mono>{address.street}</Mono>}
                sub={copy.street}
                trail={
                  <Button
                    variant="quiet"
                    size="sm"
                    iconOnly
                    icon={copiedId === "street" ? "check" : "copy"}
                    aria-label={copy.copyStreetAria}
                    onClick={() => copyValue("street", address.street, copy.toast.street)}
                  />
                }
              />
              <Row
                icon="folder"
                title={<Mono>{cityZip}</Mono>}
                sub={copy.cityZip}
                trail={
                  <Button
                    variant="quiet"
                    size="sm"
                    iconOnly
                    icon={copiedId === "city-zip" ? "check" : "copy"}
                    aria-label={copy.copyCityZipAria}
                    onClick={() => copyValue("city-zip", cityZip, copy.toast.cityZip)}
                  />
                }
              />
            </Rows>
            <Button
              block
              icon={copiedId === "full" ? "check" : "copy"}
              className="subs-full"
              onClick={() => copyValue("full", full, copy.toast.full)}
            >
              {copiedId === "full" ? copy.copyFullDone : copy.copyFull}
            </Button>
            <span className="zs-sr" role="status">
              {copiedId ? copy.copyFullDone : ""}
            </span>
          </TabPanel>
        </>
      ) : (
        <Banner
          tone={cardCountryRu ? "warn" : "info"}
          icon={cardCountryRu ? "alert" : "info"}
          role={cardCountryRu ? "alert" : "status"}
          title={cardCountryRu ? copy.nonUsTitleBanner(cardCountryRu) : copy.nonUsTitle}
        >
          {cardCountryRu ? copy.nonUsText(cardCountryRu) : copy.nonUsUnknownText}
        </Banner>
      )}
    </Card>
  );
}

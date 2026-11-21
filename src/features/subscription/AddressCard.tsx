import { useState } from "react";
import { Button, Card, InfoTip, Mono, Row, Rows, TabPanel, Tabs } from "../../ui";
import { subscription } from "../../shared/copy/ru";
import type { ShowToast } from "../../shared/hooks";
import { useCopy } from "../guides/useCopy";
import { TAX_FREE_ADDRESSES } from "./addresses";

const copy = subscription.address;
const PREFIX = "subs-state";

export interface AddressCardProps {
  onToast?: ShowToast;
}

/** Адрес без налога штата для Stripe AVS: выбор штата, копирование улицы, города и полного адреса. */
export function AddressCard({ onToast }: AddressCardProps) {
  const [index, setIndex] = useState<number>(0);
  const { copiedId, copy: copyText } = useCopy(onToast, 2000);
  const address = TAX_FREE_ADDRESSES[index];

  const copyValue = (id: string, value: string, label: string) =>
    copyText(id, value, { title: copy.toast.copied, text: `${label}: ${value}` });

  const cityZip = `${address.city}, ${address.code} ${address.zip}`;
  const full = `${address.street}, ${address.city}, ${address.code} ${address.zip}, United States`;

  return (
    <Card
      title={copy.title}
      aside={
        <span className="zs-field-row">
          <span>{copy.aside}</span>
          <InfoTip
            title="Проверка адреса Stripe (AVS) и 0% налог США"
            text="Пять штатов США (DE, OR, NH, MT, AK) не взимают налог с продаж на цифровые подписки. Для карт США это снижает риск отказа при проверке индекса (AVS) и экономит +8–10%."
          />
        </span>
      }
    >
      <p className="zs-t-body subs-lead">{copy.text}</p>

      <Tabs
        items={TAX_FREE_ADDRESSES.map((a) => ({ id: a.code, label: a.code }))}
        value={address.code}
        onChange={(code) => setIndex(Math.max(0, TAX_FREE_ADDRESSES.findIndex((a) => a.code === code)))}
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
          {copiedId ? subscription.address.copyFullDone : ""}
        </span>
      </TabPanel>
    </Card>
  );
}

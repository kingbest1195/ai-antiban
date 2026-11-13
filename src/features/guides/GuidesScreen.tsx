import { useEffect, useRef, useState } from "react";
import { Card, Row, Rows, Segmented } from "../../ui";
import { guides as copy } from "../../shared/copy/ru";
import type { ShowToast } from "../../shared/hooks";
import { openTelegramSupport } from "../../utils/opener";
import { GuideContext } from "./context";
import type { GuideContextValue } from "./context";
import { Rich } from "./Rich";
import { OsGuide } from "./OsGuide";
import { PaymentGuide } from "./PaymentGuide";
import { markUrlGuideUsed, peekUrlGuide, resolveGuide } from "./routing";
import type { GuideSection, OsPart, VpsMethod } from "./routing";
import { useCopy } from "./useCopy";
import { VpsGuide } from "./VpsGuide";
import "./guides.css";

export interface GuidesScreenProps {
  /** Какой гайд открыть: «Обзор», «Подключение», диалог обрыва и трей передают id (см. resolveGuide). */
  initialGuide?: string;
  currentIp?: string;
  currentCountry?: string;
  currentTimezone?: string;
  onPinIp?: (ip: string) => void;
  onToast?: ShowToast;
}

/** Экран «Гайды»: три раздела (Свой VPS, Оплата, Защита ОС), внутри — способы и части с переключением. */
export function GuidesScreen({
  initialGuide = "01-personal-vpn-15min",
  currentIp = "185.212.102.40",
  currentCountry = "NL",
  currentTimezone,
  onPinIp,
  onToast,
}: GuidesScreenProps) {
  // ?guide= из адреса применяется только при первом показе, дальше действует цель от вызывающего.
  const [first] = useState(() => resolveGuide(peekUrlGuide() ?? initialGuide));
  const [section, setSection] = useState<GuideSection>(first.section);
  const [method, setMethod] = useState<VpsMethod>(first.method ?? "amnezia");
  const [part, setPart] = useState<OsPart>(first.part ?? "tz");

  // Реагируем только на смену цели от вызывающего (в StrictMode эффект запускается дважды — сравниваем с прошлым значением).
  useEffect(markUrlGuideUsed, []);
  const lastTarget = useRef(initialGuide);
  useEffect(() => {
    if (lastTarget.current === initialGuide) return;
    lastTarget.current = initialGuide;
    const target = resolveGuide(initialGuide);
    setSection(target.section);
    if (target.method) setMethod(target.method);
    if (target.part) setPart(target.part);
  }, [initialGuide]);

  const { copiedId, copy: copyText } = useCopy(onToast);
  const resolvedCountry = currentCountry && currentCountry !== "--" ? currentCountry : "NL";

  const ctx: GuideContextValue = {
    currentIp,
    currentCountry: resolvedCountry,
    currentTimezone,
    onPinIp,
    onToast,
    copiedId,
    copy: copyText,
  };

  const openSupport = () => {
    onToast?.(copy.toast.support, copy.toast.supportText, "info");
    openTelegramSupport();
  };

  return (
    <GuideContext.Provider value={ctx}>
      <div className="zs-stack">
        <Segmented<GuideSection>
          aria-label={copy.nav.label}
          value={section}
          onChange={setSection}
          options={[
            { value: "vps", label: copy.nav.vps },
            { value: "payment", label: copy.nav.payment },
            { value: "os", label: copy.nav.os },
          ]}
        />

        {section === "vps" && <VpsGuide method={method} onMethodChange={setMethod} />}
        {section === "payment" && <PaymentGuide />}
        {section === "os" && <OsGuide part={part} onPartChange={setPart} />}

        <Card>
          <Rows>
            <Row icon="info" tone="neutral" title={copy.support.title} sub={<Rich text={copy.support.text} />} onClick={openSupport} />
          </Rows>
        </Card>
      </div>
    </GuideContext.Provider>
  );
}

import { useState } from "react";
import { Badge, Banner, Button, Card, Mono, Row, Rows, Segmented, Steps } from "../../ui";
import { common, guides as copy } from "../../shared/copy/ru";
import { openExternal } from "../../utils/opener";
import { CopyBlock } from "./CopyBlock";
import {
  AMNEZIA_DOWNLOAD_URL,
  CMD_3XUI_IPV6,
  CMD_3XUI_VLESS,
  CMD_SSH,
  CMD_VLESS_AUTO,
  CMD_XRAY_CASCADE,
  CMD_XRAY_CORE,
  XHTTP_SETTINGS_LINES,
} from "./commands";
import { useGuide } from "./context";
import { HostingList } from "./HostingList";
import { Rich } from "./Rich";
import type { VpsMethod } from "./routing";

interface VpsGuideProps {
  method: VpsMethod;
  onMethodChange: (method: VpsMethod) => void;
}

/** Кнопка «Закрепить IP»: единственная заливка brand на экране, видна на шаге закрепления. */
function PinButton() {
  const { currentIp, onPinIp } = useGuide();
  return (
    <Button variant="primary" onClick={() => onPinIp?.(currentIp)}>
      {copy.actions.pinIp}
    </Button>
  );
}

/** Раздел «Свой VPS»: зачем он нужен и три способа настройки на выбор. */
export function VpsGuide({ method, onMethodChange }: VpsGuideProps) {
  return (
    <>
      <Banner tone="info" icon="shield" title={copy.vps.pitchTitle}>
        {copy.vps.pitchText}
      </Banner>

      <Segmented<VpsMethod>
        aria-label={copy.vps.methodLabel}
        value={method}
        onChange={onMethodChange}
        options={[
          { value: "amnezia", label: copy.vps.methods.amnezia },
          { value: "vless_one_cmd", label: copy.vps.methods.vless },
          { value: "cascade", label: copy.vps.methods.cascade },
        ]}
      />
      <p className="guides-note">{copy.vps.methodHints[method]}</p>

      {method === "amnezia" && <AmneziaMethod onMethodChange={onMethodChange} />}
      {method === "vless_one_cmd" && <VlessMethod />}
      {method === "cascade" && <CascadeMethod />}
    </>
  );
}

function AmneziaMethod({ onMethodChange }: { onMethodChange: (method: VpsMethod) => void }) {
  const { currentIp } = useGuide();
  const t = copy.vps.amnezia;
  return (
    <>
      <Card>
        <Steps
          collapsible
          nextLabel={common.next}
          items={[
            {
              title: t.step1Title,
              text: t.step1Text,
              body: (
                <>
                  <HostingList variant="compact" />
                  <div className="guides-mail">
                    <div className="guides-mail__head">
                      <span className="guides-label">{t.mailTitle}</span>
                      <Badge tone="ok" icon="check">
                        {t.mailReady}
                      </Badge>
                    </div>
                    <Rows>
                      <Row as="li" title={t.mailIp} trail={<Mono>{t.mailIpValue}</Mono>} />
                      <Row as="li" title={t.mailLogin} trail={<Mono>{t.mailLoginValue}</Mono>} />
                      <Row as="li" title={t.mailPassword} trail={<Mono>{t.mailPasswordValue}</Mono>} />
                    </Rows>
                  </div>
                </>
              ),
            },
            {
              title: t.step2Title,
              body: (
                <>
                  <Button icon="arrow" onClick={() => openExternal(AMNEZIA_DOWNLOAD_URL)}>
                    {t.download}
                  </Button>
                  <Rows className="guides-screens">
                    {t.screens.map((screen) => (
                      <Row key={screen.title} title={screen.title} sub={<Rich text={screen.text} />} />
                    ))}
                  </Rows>
                </>
              ),
            },
            {
              title: t.step3Title,
              text: <Rich text={t.step3Text(currentIp)} />,
              body: <PinButton />,
            },
          ]}
        />
      </Card>

      <Card>
        <Rows>
          <Row
            icon="alert"
            tone="warn"
            title={t.fallbackTitle}
            sub={t.fallbackText}
            onClick={() => onMethodChange("vless_one_cmd")}
          />
        </Rows>
      </Card>
    </>
  );
}

function VlessMethod() {
  const { currentIp } = useGuide();
  const t = copy.vps.vless;
  return (
    <Card title={t.title}>
      <p className="guides-note guides-note--tight">
        <Mono>{t.os}</Mono>
      </p>
      <p className="guides-lead">
        <Rich text={t.intro} />
      </p>
      <Steps
        collapsible
        nextLabel={common.next}
        items={[
          {
            title: t.step1Title,
            text: <Rich text={t.step1Text} />,
            body: <CopyBlock id={CMD_SSH.id} lines={[CMD_SSH.command]} label={CMD_SSH.label} />,
          },
          {
            title: t.step2Title,
            body: (
              <>
                <p className="guides-label">{t.variantA}</p>
                <CopyBlock id={CMD_VLESS_AUTO.id} lines={[CMD_VLESS_AUTO.command]} label={CMD_VLESS_AUTO.label} />
                <p className="guides-label">{t.variantB}</p>
                <CopyBlock id={CMD_3XUI_VLESS.id} lines={[CMD_3XUI_VLESS.command]} label={CMD_3XUI_VLESS.label} />
              </>
            ),
          },
          {
            title: t.step3Title,
            text: <Rich text={t.step3Text(currentIp)} />,
            body: <PinButton />,
          },
        ]}
      />
    </Card>
  );
}

function CascadeMethod() {
  const { currentIp } = useGuide();
  const t = copy.vps.cascade;
  const [way, setWay] = useState<1 | 2 | 3>(1);

  return (
    <Card>
      <Steps
        collapsible
        nextLabel={common.next}
        items={[
          {
            title: t.step1Title,
            text: t.step1Text,
            body: <HostingList variant="full" />,
          },
          {
            title: t.step2Title,
            text: <Mono>{t.step2Text}</Mono>,
            body: (
              <>
                <Rows>
                  {t.blurbs.map((b) => (
                    <Row key={b.title} title={b.title} sub={b.text} />
                  ))}
                </Rows>
                <Segmented<"1" | "2" | "3">
                  aria-label={t.waysLabel}
                  value={String(way) as "1" | "2" | "3"}
                  onChange={(v) => setWay(Number(v) as 1 | 2 | 3)}
                  options={[
                    { value: "1", label: t.ways[0] },
                    { value: "2", label: t.ways[1] },
                    { value: "3", label: t.ways[2] },
                  ]}
                />
                <p className="guides-note">{t.waysHints[way - 1]}</p>
                {way === 1 && <WayOne />}
                {way === 2 && <WayTwo />}
                {way === 3 && <WayThree />}
              </>
            ),
          },
          {
            title: t.step3Title,
            text: <Rich text={t.step3Text(currentIp)} />,
            body: <PinButton />,
          },
        ]}
      />
    </Card>
  );
}

function WayOne() {
  const t = copy.vps.cascade.way1;
  return (
    <div className="guides-way">
      <p className="guides-lead">
        <Rich text={t.intro} />
      </p>
      <p className="guides-label">{t.s21}</p>
      <CopyBlock id={CMD_XRAY_CORE.id} lines={[CMD_XRAY_CORE.command]} label={CMD_XRAY_CORE.label} />
      <p className="guides-label">{t.s22}</p>
      <CopyBlock id={CMD_XRAY_CASCADE.id} lines={[CMD_XRAY_CASCADE.command]} label={CMD_XRAY_CASCADE.label} />
      <p className="guides-lead">
        <Rich text={t.s23} />
      </p>
    </div>
  );
}

function WayTwo() {
  const t = copy.vps.cascade.way2;
  return (
    <div className="guides-way">
      <p className="guides-lead">
        <Rich text={t.intro} />
      </p>
      <ol className="guides-list">
        {t.items.map((item) => (
          <li key={item}>
            <Rich text={item} />
          </li>
        ))}
      </ol>
      <CopyBlock id="cmd-xhttp-settings" lines={XHTTP_SETTINGS_LINES} label="Настройки xhttpSettings" />
    </div>
  );
}

function WayThree() {
  const t = copy.vps.cascade.way3;
  return (
    <div className="guides-way">
      <p className="guides-lead">
        <Rich text={t.intro} />
      </p>
      <p className="guides-label">{t.install}</p>
      <CopyBlock id={CMD_3XUI_IPV6.id} lines={[CMD_3XUI_IPV6.command]} label={CMD_3XUI_IPV6.label} />
      <p className="guides-lead">
        <Rich text={t.outro} />
      </p>
    </div>
  );
}

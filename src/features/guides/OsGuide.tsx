import { useState } from "react";
import { Badge, Banner, Button, Card, Segmented } from "../../ui";
import { guides as copy } from "../../shared/copy/ru";
import { openOsDatetimeSettings, setSyncAiTzEnabled, syncAiAgentsTimezone } from "../../utils/api";
import { CopyBlock } from "./CopyBlock";
import { CMD_TZ_MAC, PROXY_EXPORT_LINE } from "./commands";
import { useGuide } from "./context";
import { Rich } from "./Rich";
import type { OsPart } from "./routing";

interface OsGuideProps {
  part: OsPart;
  onPartChange: (part: OsPart) => void;
}

/** Раздел «Защита ОС»: часовой пояс отдельно, геолокация, IPv6 и защита редакторов — отдельно. */
export function OsGuide({ part, onPartChange }: OsGuideProps) {
  return (
    <>
      <Banner tone="warn" icon="lock" title={copy.os.pitchTitle}>
        {copy.os.pitchText}
      </Banner>

      <Segmented<OsPart>
        aria-label={copy.os.partsLabel}
        value={part}
        onChange={onPartChange}
        options={[
          { value: "tz", label: copy.os.parts.tz },
          { value: "geo", label: copy.os.parts.geo },
        ]}
      />

      {part === "tz" ? <TimezoneCard /> : <GeoCards />}
    </>
  );
}

function TimezoneCard() {
  const { currentTimezone, onToast } = useGuide();
  const t = copy.os.tz;
  const [syncing, setSyncing] = useState(false);
  const [synced, setSynced] = useState(false);

  // Вызовы api те же, что в прежнем GuideViewer: syncAiAgentsTimezone и openOsDatetimeSettings.
  const syncTz = async () => {
    const tz = currentTimezone || "Europe/London";
    setSyncing(true);
    try {
      // Явное нажатие кнопки: сначала включаем подмену, иначе зона только сохранится.
      await setSyncAiTzEnabled(true);
      const res = await syncAiAgentsTimezone(tz);
      setSynced(true);
      onToast?.(copy.toast.tzDone, res, "success");
    } catch (err: unknown) {
      onToast?.(copy.toast.tzError, err instanceof Error ? err.message : String(err), "error");
    } finally {
      setSyncing(false);
    }
  };

  const openClock = async () => {
    try {
      await openOsDatetimeSettings();
      onToast?.(copy.toast.osClock, copy.toast.osClockText, "info");
    } catch (err: unknown) {
      onToast?.(copy.toast.osClockError, err instanceof Error ? err.message : String(err), "error");
    }
  };

  return (
    <Card title={t.title} aside={<Badge tone="warn" icon="alert">{t.badge}</Badge>}>
      <p className="guides-lead">{t.text}</p>

      <section className="guides-way" aria-label={t.wayA}>
        <p className="guides-label">{t.wayA}</p>
        <Button variant="primary" icon={synced ? "check" : "zap"} disabled={syncing} onClick={syncTz}>
          {synced ? t.synced : syncing ? t.syncing : t.syncButton}
        </Button>
        <p className="guides-note">
          <Rich text={t.wayAText(currentTimezone || "Europe/London")} />
        </p>
      </section>

      <section className="guides-way" aria-label={t.wayB}>
        <p className="guides-label">{t.wayB}</p>
        <div>
          <Button icon="arrow" onClick={openClock}>
            {t.openClock}
          </Button>
        </div>
        <CopyBlock id={CMD_TZ_MAC.id} lines={[CMD_TZ_MAC.command]} label={CMD_TZ_MAC.label} />
        <p className="guides-note">{t.wayBText}</p>
      </section>
    </Card>
  );
}

function GeoCards() {
  const { mac, win, ipv6, cli } = copy.os;
  return (
    <>
      <Card title={mac.title} aside={<Badge>{mac.badge}</Badge>}>
        <p className="guides-lead">
          <Rich text={mac.text} />
        </p>
      </Card>

      <Card title={win.title} aside={<Badge>{win.badge}</Badge>}>
        <p className="guides-lead">{win.text}</p>
      </Card>

      <Card title={ipv6.title} aside={<Badge tone="danger" icon="alert">{ipv6.badge}</Badge>}>
        <p className="guides-lead">{ipv6.text}</p>
      </Card>

      <Card title={cli.title} aside={<Badge tone="info" icon="zap">{cli.badge}</Badge>}>
        <p className="guides-lead">
          <Rich text={cli.text} />
        </p>
        <CopyBlock id="cmd-proxy-export" lines={[PROXY_EXPORT_LINE]} label="Переменные прокси для ~/.zshrc" />
        <p className="guides-note">{cli.note}</p>
      </Card>
    </>
  );
}

import { Banner, Card } from "../../ui";
import { sosCopy as copy } from "../../shared/copy/ru/sos";
import "./sos.css";

/** Ветка 2 SOS: SMS на номер — предупреждение о VoIP и рекомендации по физической SIM/eSIM. */
export function SmsBranch() {
  const t = copy.sms;
  return (
    <Card title={t.title}>
      <Banner tone="warn" icon="alert" title={t.voipTitle}>
        {t.voipBody}
      </Banner>
      <div className="zs-sos__block">
        <p className="zs-t-heading">{t.guidanceTitle}</p>
        <ul className="zs-t-body zs-sos__list">
          {t.guidanceSteps.map((step) => (
            <li key={step}>{step}</li>
          ))}
        </ul>
      </div>
    </Card>
  );
}

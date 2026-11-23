import { useEffect, useState } from "react";
import { HintCard, Section, TabPanel, Tabs } from "../../ui";
import { sosCopy as copy } from "../../shared/copy/ru/sos";
import type { ShowToast } from "../../shared/hooks";
import { BannedBranch } from "./BannedBranch";
import { Gemini403Card } from "./Gemini403Card";
import { PaymentBranch } from "./PaymentBranch";
import { PersonaBranch } from "./PersonaBranch";
import { SmsBranch } from "./SmsBranch";
import "./sos.css";

export type SosBranchId = "persona" | "sms" | "payment" | "banned";

export interface SosScreenProps {
  initialBranch?: SosBranchId;
  navKey?: number;
  currentCountry?: string;
  embedded?: boolean;
  dismissedHints?: readonly string[];
  onDismissHint?: (hintId: string) => void;
  onNavigateToCleanRoom?: (step?: number) => void;
  onNavigateToPaymentGuide?: () => void;
  onBackupCreated?: () => void;
  onToast?: ShowToast;
}

/** Интерактивное дерево решений «SOS / Верификация» из 4 веток. */
export function SosScreen({
  initialBranch = "persona",
  navKey,
  currentCountry,
  embedded = false,
  dismissedHints,
  onDismissHint,
  onNavigateToCleanRoom,
  onNavigateToPaymentGuide,
  onBackupCreated,
  onToast,
}: SosScreenProps) {
  const [branch, setBranch] = useState<SosBranchId>(initialBranch);

  useEffect(() => {
    setBranch(initialBranch);
  }, [initialBranch, navKey]);

  return (
    <Section title={copy.section}>
      <div className="zs-stack">
        {!embedded && onDismissHint && (
          <HintCard
            hintId="sos_intro"
            body={copy.hint.body}
            dismissedHints={dismissedHints}
            onDismiss={onDismissHint}
          />
        )}

        <Tabs
          idPrefix="sos"
          aria-label={copy.title}
          items={[...copy.tabs]}
          value={branch}
          onChange={setBranch}
        />

        <TabPanel idPrefix="sos" id="persona" selected={branch === "persona"}>
          <PersonaBranch
            ctaVariant={embedded ? "secondary" : "primary"}
            onToast={onToast}
            onBackupCreated={onBackupCreated}
          />
        </TabPanel>

        <TabPanel idPrefix="sos" id="sms" selected={branch === "sms"}>
          <SmsBranch />
        </TabPanel>

        <TabPanel idPrefix="sos" id="payment" selected={branch === "payment"}>
          <PaymentBranch
            currentCountry={currentCountry}
            ctaVariant={embedded ? "secondary" : "primary"}
            onToast={onToast}
            onNavigateToPaymentGuide={onNavigateToPaymentGuide}
          />
        </TabPanel>

        <TabPanel idPrefix="sos" id="banned" selected={branch === "banned"}>
          <BannedBranch
            ctaVariant={embedded ? "secondary" : "primary"}
            onToast={onToast}
            onNavigateToCleanRoom={onNavigateToCleanRoom}
          />
        </TabPanel>

        <Gemini403Card onToast={onToast} />
      </div>
    </Section>
  );
}

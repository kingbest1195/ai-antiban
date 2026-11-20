import { useEffect, useState } from "react";
import { HintCard, Section, TabPanel, Tabs } from "../../ui";
import { sosCopy as copy } from "../../shared/copy/ru/sos";
import type { ShowToast } from "../../shared/hooks";
import { BannedBranch } from "./BannedBranch";
import { PaymentBranch } from "./PaymentBranch";
import { PersonaBranch } from "./PersonaBranch";
import { SmsBranch } from "./SmsBranch";
import "./sos.css";

export type SosBranchId = "persona" | "sms" | "payment" | "banned";

export interface SosScreenProps {
  initialBranch?: SosBranchId;
  navKey?: number;
  currentCountry?: string;
  dismissedHints?: readonly string[];
  onDismissHint?: (hintId: string) => void;
  onNavigateToCleanRoom?: (step?: number) => void;
  onNavigateToPaymentGuide?: () => void;
  onBackupCreated?: () => void;
  onToast?: ShowToast;
}

/** Интерактивное дерево решений «🚨 SOS / Верификация» из 4 веток. */
export function SosScreen({
  initialBranch = "persona",
  navKey,
  currentCountry,
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
        {onDismissHint && (
          <HintCard
            hintId="sos_intro"
            title={copy.hint.title}
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
          <PersonaBranch onToast={onToast} onBackupCreated={onBackupCreated} />
        </TabPanel>

        <TabPanel idPrefix="sos" id="sms" selected={branch === "sms"}>
          <SmsBranch />
        </TabPanel>

        <TabPanel idPrefix="sos" id="payment" selected={branch === "payment"}>
          <PaymentBranch
            currentCountry={currentCountry}
            onToast={onToast}
            onNavigateToPaymentGuide={onNavigateToPaymentGuide}
          />
        </TabPanel>

        <TabPanel idPrefix="sos" id="banned" selected={branch === "banned"}>
          <BannedBranch
            onToast={onToast}
            onNavigateToCleanRoom={onNavigateToCleanRoom}
          />
        </TabPanel>
      </div>
    </Section>
  );
}

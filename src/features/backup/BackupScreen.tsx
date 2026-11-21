import { useEffect, useState } from "react";
import type { ClaudeBackup, ShowToast } from "../../shared/hooks";
import type { PersonaRiskFixTarget, RoutesSnapshot } from "../../types";
import { HintCard } from "../../ui";
import { BunkerCard, PersonaRiskCard } from "../bunker";
import { CooldownBanner } from "../overview/CooldownBanner";
import { SosScreen } from "../sos";
import type { SosBranchId } from "../sos";
import { CacheSection } from "./CacheSection";
import { ProfilesSection } from "./ProfilesSection";
import "./backup.css";

export interface BackupScreenProps {
  backup: ClaudeBackup;
  currentIp: string;
  currentCountry: string;
  hideIpMode?: boolean;
  activeUpstreamKey?: string | null;
  routesSnapshot?: RoutesSnapshot | null;
  profileRefreshTrigger?: number;
  /** 4-часовой таймер после безопасного выхода из Claude (Zero-Regression). */
  ipChangeCooldownUntil?: number | null;
  dismissedHints?: readonly string[];
  initialSosBranch?: SosBranchId;
  sosNavKey?: number;
  visible?: boolean;
  personaRefreshKey?: number;
  onCooldownCleared?: () => Promise<unknown> | void;
  onDismissHint?: (hintId: string) => void;
  onNavigateToCleanRoom?: (step?: number) => void;
  onNavigateToPaymentGuide?: () => void;
  onPersonaFixTarget?: (target: PersonaRiskFixTarget) => void;
  onRoutesUpdated?: () => Promise<unknown> | void;
  onProfileSwitched: (profileName: string, pinnedIp?: string | null) => Promise<unknown> | void;
  onToast: ShowToast;
}

/** Экран «Аккаунты, Бункер и SOS»: риск KYC и блокировки Claude, Бункер данных, SOS-дерево и профили Claude Desktop. */
export function BackupScreen({
  backup,
  currentIp,
  currentCountry,
  hideIpMode = false,
  activeUpstreamKey,
  routesSnapshot,
  profileRefreshTrigger,
  ipChangeCooldownUntil,
  dismissedHints,
  initialSosBranch,
  sosNavKey,
  visible,
  personaRefreshKey,
  onCooldownCleared,
  onDismissHint,
  onNavigateToCleanRoom,
  onNavigateToPaymentGuide,
  onPersonaFixTarget,
  onRoutesUpdated,
  onProfileSwitched,
  onToast,
}: BackupScreenProps) {
  const [bunkerRefreshTrigger, setBunkerRefreshTrigger] = useState(0);
  const [localDismissed, setLocalDismissed] = useState<string[]>(() => [...(dismissedHints ?? [])]);
  useEffect(() => {
    if (dismissedHints) setLocalDismissed([...dismissedHints]);
  }, [dismissedHints]);
  const handleDismiss = (id: string) => {
    setLocalDismissed((prev) => (prev.includes(id) ? prev : [...prev, id]));
    onDismissHint?.(id);
  };
  const bumpBunker = () => setBunkerRefreshTrigger((n) => n + 1);

  return (
    <div className="zs-stack">
      <CooldownBanner
        cooldownUntil={ipChangeCooldownUntil}
        onCleared={onCooldownCleared}
        onToast={onToast}
      />

      <HintCard
        hintId="backup_intro"
        body="Проверяйте риск KYC и блокировки Claude перед оплатой, сохраняйте бэкап истории в Бункер и держите профили раздельно."
        dismissedHints={localDismissed}
        onDismiss={handleDismiss}
      />

      <PersonaRiskCard
        ctaVariant="secondary"
        onToast={onToast}
        onFixTarget={onPersonaFixTarget}
        onNavigateToCleanRoom={onNavigateToCleanRoom}
        onBackupCreated={bumpBunker}
        visible={visible}
        refreshKey={personaRefreshKey}
      />

      <div id="bunker-section">
        <BunkerCard backup={backup} onToast={onToast} refreshTrigger={bunkerRefreshTrigger} />
      </div>

      <SosScreen
        initialBranch={initialSosBranch}
        navKey={sosNavKey}
        currentCountry={currentCountry}
        embedded
        dismissedHints={localDismissed}
        onDismissHint={handleDismiss}
        onNavigateToCleanRoom={onNavigateToCleanRoom}
        onNavigateToPaymentGuide={onNavigateToPaymentGuide}
        onBackupCreated={bumpBunker}
        onToast={onToast}
      />

      <div id="claude-profiles-section" className="zs-stack">
        <ProfilesSection
          currentIp={currentIp}
          currentCountry={currentCountry}
          hideIpMode={hideIpMode}
          activeUpstreamKey={activeUpstreamKey}
          routesSnapshot={routesSnapshot}
          refreshTrigger={profileRefreshTrigger}
          onRoutesUpdated={onRoutesUpdated}
          onProfileSwitched={onProfileSwitched}
          onToast={onToast}
        />
        <div id="claude-cache-section">
          <CacheSection backup={backup} />
        </div>
      </div>
    </div>
  );
}

import { useEffect, useState } from "react";
import type { ClaudeBackup, ShowToast } from "../../shared/hooks";
import type { PersonaRiskFixTarget, RoutesSnapshot } from "../../types";
import { HintCard, Section } from "../../ui";
import { BunkerCard, PersonaRiskCard } from "../bunker";
import { CooldownBanner } from "../overview/CooldownBanner";
import { SosScreen } from "../sos";
import type { SosBranchId } from "../sos";
import { ArchiveSection } from "./ArchiveSection";
import { CacheSection } from "./CacheSection";
import { ProfilesSection } from "./ProfilesSection";
import "./backup.css";

export interface BackupScreenProps {
  backup: ClaudeBackup;
  currentIp: string;
  currentCountry: string;
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

const DESKTOP_PROFILES_SECTION_TITLE = "Профили Claude Desktop и безопасный выход";

/** Экран «Аккаунты, Бункер и SOS»: риск Persona, Бункер данных, SOS-дерево и профили Claude Desktop. */
export function BackupScreen({
  backup,
  currentIp,
  currentCountry,
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
        title="Антифрод-гигиена, локальный Бункер и экстренная помощь"
        body="Проверяйте индекс риска Persona перед оплатой, сохраняйте историю диалогов в бесплатный локальный Бункер и держите профили Claude раздельно."
        dismissedHints={localDismissed}
        onDismiss={handleDismiss}
      />

      <PersonaRiskCard
        onToast={onToast}
        onFixTarget={onPersonaFixTarget}
        onNavigateToCleanRoom={onNavigateToCleanRoom}
        onBackupCreated={bumpBunker}
        visible={visible}
        refreshKey={personaRefreshKey}
      />

      <div id="bunker-section">
        <BunkerCard onToast={onToast} refreshTrigger={bunkerRefreshTrigger} />
      </div>

      <SosScreen
        initialBranch={initialSosBranch}
        navKey={sosNavKey}
        currentCountry={currentCountry}
        dismissedHints={localDismissed}
        onDismissHint={handleDismiss}
        onNavigateToCleanRoom={onNavigateToCleanRoom}
        onNavigateToPaymentGuide={onNavigateToPaymentGuide}
        onBackupCreated={bumpBunker}
        onToast={onToast}
      />

      <Section title={DESKTOP_PROFILES_SECTION_TITLE}>
        <div id="claude-profiles-section" className="zs-stack">
          <ProfilesSection
            currentIp={currentIp}
            currentCountry={currentCountry}
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
      </Section>

      <ArchiveSection backup={backup} onToast={onToast} />
    </div>
  );
}

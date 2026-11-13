import type { ClaudeBackup, ShowToast } from "../../shared/hooks";
import type { RoutesSnapshot } from "../../types";
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
  onRoutesUpdated?: () => Promise<unknown> | void;
  onProfileSwitched: (profileName: string, pinnedIp?: string | null) => void;
  onToast: ShowToast;
}

/** Экран «Бэкап»: архив данных Claude, профили аккаунтов, сброс кэша. */
export function BackupScreen({
  backup,
  currentIp,
  currentCountry,
  activeUpstreamKey,
  routesSnapshot,
  onRoutesUpdated,
  onProfileSwitched,
  onToast,
}: BackupScreenProps) {
  return (
    <div className="zs-stack">
      <ArchiveSection backup={backup} />
      {/* Якорь профилей сохранён из прежней разметки. */}
      <div id="claude-profiles-section">
        <ProfilesSection
          currentIp={currentIp}
          currentCountry={currentCountry}
          activeUpstreamKey={activeUpstreamKey}
          routesSnapshot={routesSnapshot}
          onRoutesUpdated={onRoutesUpdated}
          onProfileSwitched={onProfileSwitched}
          onToast={onToast}
        />
      </div>
      <CacheSection backup={backup} />
    </div>
  );
}

import { useCallback, useEffect, useState } from "react";
import { Badge, Banner, Button, Card, Icon, InfoTip, Section, Skeleton, Switch, cx } from "../../ui";
import type { Tone } from "../../ui";
import { bunkerCopy as copy } from "../../shared/copy/ru/bunker";
import type { ShowToast } from "../../shared/hooks";
import { runBunkerBackupNow } from "../../utils/api/bunker";
import { getPersonaRiskReport, updatePersonaSelfCheck } from "../../utils/api/sos";
import type {
  PersonaRiskFixTarget,
  PersonaRiskLevel,
  PersonaRiskReport,
  PersonaSelfCheck,
} from "../../types";
import "./bunker.css";

export interface PersonaRiskCardProps {
  ctaVariant?: "primary" | "secondary";
  onToast?: ShowToast;
  /** Навигация по 1-click fix кнопкам или High-risk CTA в Чистую комнату. */
  onFixTarget?: (target: PersonaRiskFixTarget) => void;
  onNavigateToCleanRoom?: (step?: number) => void;
  onBackupCreated?: () => void;
  visible?: boolean;
  refreshKey?: number;
}

export function personaLevelBadgeTone(level: PersonaRiskLevel): Tone {
  if (level === "high") return "danger";
  if (level === "medium") return "warn";
  return "ok";
}

export function personaLevelLabel(level: PersonaRiskLevel): string {
  return copy.personaRisk.levels[level];
}

/** Проактивный «Индекс риска Persona» (0..100): технические факторы + 4 тумблера самооценки. */
export function PersonaRiskCard({
  ctaVariant = "primary",
  onToast,
  onFixTarget,
  onNavigateToCleanRoom,
  onBackupCreated,
  visible,
  refreshKey,
}: PersonaRiskCardProps) {
  const t = copy.personaRisk;
  const [report, setReport] = useState<PersonaRiskReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [updatingKey, setUpdatingKey] = useState<keyof PersonaSelfCheck | null>(null);
  const [backingUp, setBackingUp] = useState(false);

  const loadReport = useCallback(async () => {
    setLoading(true);
    try {
      const next = await getPersonaRiskReport();
      setReport(next);
    } catch (err) {
      onToast?.(copy.loadError, err instanceof Error ? err.message : String(err), "error");
    } finally {
      setLoading(false);
    }
  }, [onToast]);

  useEffect(() => {
    if (visible === false) return;
    void loadReport();
  }, [loadReport, visible, refreshKey]);

  const handleToggleSelfCheck = async (key: keyof PersonaSelfCheck, value: boolean) => {
    setUpdatingKey(key);
    try {
      const updated = await updatePersonaSelfCheck({ [key]: value });
      setReport(updated);
    } catch (err) {
      onToast?.(copy.toasts.settingsErrTitle, err instanceof Error ? err.message : String(err), "error");
    } finally {
      setUpdatingKey(null);
    }
  };

  const handleEmergencyBackup = async () => {
    if (backingUp) return;
    setBackingUp(true);
    try {
      const res = await runBunkerBackupNow();
      onToast?.(
        copy.toasts.backupOkTitle,
        copy.toasts.backupOkText(res.snapshot.files_count),
        "success",
      );
      onBackupCreated?.();
    } catch (err) {
      onToast?.(copy.toasts.backupErrTitle, err instanceof Error ? err.message : String(err), "error");
    } finally {
      setBackingUp(false);
    }
  };

  const activeFactors = report?.factors.filter((f) => f.active) ?? [];

  return (
    <Section title={t.section}>
      <Card
        title={t.title}
        aside={<InfoTip title={t.tipTitle} text={t.tipText} />}
      >
        {loading && !report ? (
          <Skeleton variant="block" height={96} />
        ) : report ? (
          <>
            <div className="zs-bunker__risk-head">
              <div className="zs-bunker__risk-score">
                <span className="zs-t-metric">{report.score}</span>
                <span className="zs-t-caption">{t.scoreSuffix}</span>
              </div>
              <Badge tone={personaLevelBadgeTone(report.level)}>
                {personaLevelLabel(report.level)}
              </Badge>
            </div>

            <p className="zs-t-body zs-bunker__subtitle">{t.levelHints[report.level]}</p>

            {report.level === "high" && (
              <Banner tone="danger" icon="alert" title={t.levels.high} className="zs-bunker__block">
                <p className="zs-t-body">{t.highRiskWarning}</p>
                <div className="zs-bunker__row-actions">
                  <Button
                    size="sm"
                    variant={ctaVariant}
                    icon="shield"
                    disabled={backingUp}
                    onClick={() => void handleEmergencyBackup()}
                  >
                    {t.highRiskBackupBtn}
                  </Button>
                  {onNavigateToCleanRoom && (
                    <Button
                      size="sm"
                      variant="secondary"
                      icon="arrow"
                      onClick={() => onNavigateToCleanRoom(1)}
                    >
                      {t.highRiskCleanRoomBtn}
                    </Button>
                  )}
                </div>
              </Banner>
            )}

            <div className="zs-bunker__block">
              <p className="zs-t-caption zs-bunker__section-label">{t.factorsTitle}</p>
              {activeFactors.length === 0 ? (
                <p className="zs-t-caption zs-bunker__subtitle">{t.noActiveFactors}</p>
              ) : (
                <ul className="zs-bunker__factors">
                  {activeFactors.map((factor) => (
                    <li key={factor.id} className="zs-bunker__factor">
                      <div className="zs-bunker__factor-head">
                        <span
                          className={cx(
                            "zs-row__icon",
                            factor.weight >= 35 ? "zs-row__icon--danger" : "zs-row__icon--warn",
                          )}
                          aria-hidden="true"
                        >
                          <Icon name="alert" />
                        </span>
                        <div className="zs-bunker__factor-body">
                          <p className="zs-bunker__factor-title">{`${factor.label} (+${factor.weight})`}</p>
                          <p className="zs-bunker__factor-detail">{factor.detail}</p>
                        </div>
                      </div>
                      {factor.fix_target && onFixTarget && (
                        <div className="zs-bunker__factor-action">
                          <Button
                            size="sm"
                            variant="secondary"
                            onClick={() => onFixTarget(factor.fix_target!)}
                          >
                            {t.fixButtonLabels[factor.fix_target] ?? factor.fix_target}
                          </Button>
                        </div>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div className="zs-bunker__block">
              <p className="zs-t-caption zs-bunker__section-label">{t.selfCheckTitle}</p>
              <div className="zs-bunker__risk-checks">
                {t.selfCheckItems.map((item) => {
                  const checked = report.self_check[item.key];
                  return (
                    <div key={item.key} className="zs-bunker__check-item">
                      <div className="zs-bunker__check-label">
                        <span className="zs-t-body">{item.label}</span>
                        <span className="zs-t-caption">{item.weight}</span>
                      </div>
                      <Switch
                        checked={checked}
                        disabled={updatingKey === item.key}
                        aria-label={item.label}
                        onChange={(next) => void handleToggleSelfCheck(item.key, next)}
                      />
                    </div>
                  );
                })}
              </div>
            </div>
          </>
        ) : null}
      </Card>
    </Section>
  );
}

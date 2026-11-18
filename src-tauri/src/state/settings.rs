//! UI preferences, feature flags, timezone/CLI settings, custom domains, and manual kill-switch flag.

use super::AppState;
use super::schema::{
    AppStateData, CliMode, DEFAULT_IP_CHANGE_COOLDOWN_SECS, InterceptionBehavior, PopupPosition,
    StateError,
};

impl AppStateData {
    /// Starts or extends the IP-change cooldown window starting at `now` for `secs` seconds.
    pub fn start_ip_change_cooldown(&mut self, now: i64, secs: u64) -> i64 {
        let effective = if secs == 0 {
            DEFAULT_IP_CHANGE_COOLDOWN_SECS
        } else {
            secs
        };
        let delta = i64::try_from(effective).unwrap_or(i64::MAX);
        let until = now.saturating_add(delta);
        self.ip_change_cooldown_until = Some(until);
        until
    }

    /// Clears any active IP-change cooldown.
    pub fn clear_ip_change_cooldown(&mut self) {
        self.ip_change_cooldown_until = None;
    }

    /// Returns remaining seconds of the post-logout IP-change cooldown relative to `now`, if active.
    pub fn ip_change_cooldown_remaining_secs(&self, now: i64) -> Option<u64> {
        let until = self.ip_change_cooldown_until?;
        let rem = until.saturating_sub(now);
        (rem > 0).then_some(rem as u64)
    }
}

impl AppState {
    pub async fn is_onboarding_v2_2_done(&self) -> bool {
        self.inner.read().await.onboarding_v2_2_done
    }

    pub async fn set_onboarding_v2_2_done(&self, done: bool) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.onboarding_v2_2_done = done;
        }
        self.save_async().await
    }

    pub async fn is_hide_ip_mode(&self) -> bool {
        self.inner.read().await.hide_ip_mode
    }

    pub async fn set_hide_ip_mode(&self, enabled: bool) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.hide_ip_mode = enabled;
        }
        self.save_async().await
    }

    pub async fn is_strict_pinning_enabled(&self) -> bool {
        self.inner.read().await.strict_pinning_enabled
    }

    pub async fn set_strict_pinning_enabled(&self, enabled: bool) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.strict_pinning_enabled = enabled;
        }
        self.save_async().await
    }

    pub async fn is_auto_update_enabled(&self) -> bool {
        self.inner.read().await.auto_update_enabled
    }

    pub async fn set_auto_update_enabled(&self, enabled: bool) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.auto_update_enabled = enabled;
        }
        self.save_async().await
    }

    pub async fn is_autostart_enabled(&self) -> bool {
        self.inner.read().await.autostart_enabled
    }

    pub async fn set_autostart_enabled(&self, enabled: bool) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.autostart_enabled = enabled;
        }
        self.save_async().await
    }

    pub async fn is_cowork_guard_enabled(&self) -> bool {
        self.inner.read().await.cowork_guard_enabled
    }

    pub async fn set_cowork_guard_enabled(&self, enabled: bool) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.cowork_guard_enabled = enabled;
        }
        self.save_async().await
    }

    pub async fn is_split_tunnel_mode(&self) -> bool {
        self.inner.read().await.split_tunnel_mode
    }

    pub async fn set_split_tunnel_mode(&self, enabled: bool) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.split_tunnel_mode = enabled;
        }
        self.save_async().await
    }

    // --- Manual kill-switch persistence ---

    pub async fn is_manual_killswitch_saved(&self) -> bool {
        self.inner.read().await.manual_killswitch
    }

    pub async fn set_manual_killswitch_saved(&self, on: bool) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.manual_killswitch = on;
        }
        self.save_async().await
    }

    // --- Warmup Timer ---

    pub async fn get_warmup_started_at(&self) -> Option<u64> {
        self.inner.read().await.warmup_started_at
    }

    pub async fn set_warmup_started_at(&self, started_at: Option<u64>) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.warmup_started_at = started_at;
        }
        self.save_async().await
    }

    // --- Synced AI Timezone (CLI / IDE AI Agent TZ) ---

    pub async fn get_synced_ai_timezone(&self) -> Option<String> {
        self.inner.read().await.synced_ai_timezone.clone()
    }

    pub async fn set_synced_ai_timezone(&self, tz: Option<String>) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.synced_ai_timezone = tz;
        }
        self.save_async().await
    }

    // --- Time zone / locale switch and CLI coverage mode ---

    pub async fn get_sync_ai_tz_enabled(&self) -> bool {
        self.inner.read().await.sync_ai_tz_enabled
    }

    pub async fn set_sync_ai_tz_enabled(&self, enabled: bool) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.sync_ai_tz_enabled = enabled;
        }
        self.save_async().await
    }

    pub async fn get_cli_mode(&self) -> CliMode {
        self.inner.read().await.cli_mode
    }

    pub async fn set_cli_mode(&self, mode: CliMode) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.cli_mode = mode;
        }
        self.save_async().await
    }

    /// The zone to apply now (see [`AppStateData::effective_sync_tz`]).
    pub async fn effective_sync_tz(&self) -> Option<String> {
        self.inner.read().await.effective_sync_tz()
    }

    // --- Preset Interception Behavior & Popup Position ---

    pub async fn get_interception_behavior(&self) -> InterceptionBehavior {
        self.inner.read().await.interception_behavior
    }

    pub async fn set_interception_behavior(
        &self,
        b: InterceptionBehavior,
    ) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.interception_behavior = b;
        }
        self.save_async().await
    }

    pub async fn get_popup_position(&self) -> PopupPosition {
        self.inner.read().await.popup_position
    }

    pub fn get_popup_position_sync(&self) -> PopupPosition {
        self.inner
            .try_read()
            .map(|d| d.popup_position)
            .unwrap_or_default()
    }

    pub async fn set_popup_position(&self, p: PopupPosition) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.popup_position = p;
        }
        self.save_async().await
    }

    // --- Custom AI Domains ---

    pub async fn get_custom_ai_domains(&self) -> Vec<String> {
        self.inner.read().await.custom_ai_domains.clone()
    }

    pub async fn add_custom_ai_domain(&self, domain: String) -> Result<Vec<String>, StateError> {
        let clean = domain
            .trim()
            .trim_start_matches("*.")
            .trim_start_matches('.')
            .to_lowercase();
        let updated = {
            let mut w = self.inner.write().await;
            if !clean.is_empty() && !w.custom_ai_domains.iter().any(|d| d == &clean) {
                w.custom_ai_domains.push(clean);
            }
            w.custom_ai_domains.clone()
        };
        self.save_async().await?;
        Ok(updated)
    }

    pub async fn remove_custom_ai_domain(&self, domain: &str) -> Result<Vec<String>, StateError> {
        let clean = domain
            .trim()
            .trim_start_matches("*.")
            .trim_start_matches('.')
            .to_lowercase();
        let updated = {
            let mut w = self.inner.write().await;
            w.custom_ai_domains.retain(|d| d != &clean);
            w.custom_ai_domains.clone()
        };
        self.save_async().await?;
        Ok(updated)
    }

    // --- Post-Logout IP-Change Cooldown ---

    /// Starts the IP-change cooldown for `secs` seconds (defaults to 4h / 14400s if `0`).
    pub async fn start_ip_change_cooldown(&self, secs: u64) -> Result<i64, StateError> {
        let now = crate::auditor::network::current_timestamp() as i64;
        let until = {
            let mut w = self.inner.write().await;
            w.start_ip_change_cooldown(now, secs)
        };
        self.save_async().await?;
        Ok(until)
    }

    /// Records `last_safe_logout_at = now` and starts the IP-change cooldown for `secs` seconds.
    pub async fn record_safe_logout(&self, now: i64, secs: u64) -> Result<i64, StateError> {
        let until = {
            let mut w = self.inner.write().await;
            w.last_safe_logout_at = Some(now);
            w.start_ip_change_cooldown(now, secs)
        };
        self.save_async().await?;
        Ok(until)
    }

    /// Clears the active IP-change cooldown.
    pub async fn clear_ip_change_cooldown(&self) -> Result<(), StateError> {
        {
            let mut w = self.inner.write().await;
            w.clear_ip_change_cooldown();
        }
        self.save_async().await
    }

    /// Returns remaining seconds of the active IP-change cooldown relative to `now`, if any.
    pub async fn ip_change_cooldown_remaining_secs(&self, now: i64) -> Option<u64> {
        self.inner
            .read()
            .await
            .ip_change_cooldown_remaining_secs(now)
    }
}

//! Structured refusal of the user's "allow" (network alert). The interface decides by `code`;
//! `message` is a technical text for the log and is never shown to the user.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowErrorCode {
    /// The network guard is not started yet.
    GuardNotRunning,
    /// The manual kill-switch is engaged: nothing may be allowed until it is released.
    BlockedByManualKillswitch,
    /// The alert is not the current one any more (a newer network change replaced it).
    AlertStale,
    /// The audit behind the alert has not finished (or failed): "allow" is not offered yet.
    AuditPending,
    /// Anything else (state could not be saved, ...).
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AllowError {
    pub code: AllowErrorCode,
    pub message: String,
}

impl AllowError {
    pub fn new(code: AllowErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for AllowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Lets `?` turn the plain-text errors of the state layer into `Internal`.
impl From<String> for AllowError {
    fn from(message: String) -> Self {
        Self::new(AllowErrorCode::Internal, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_as_code_and_message_with_snake_case_codes() {
        let cases = [
            (AllowErrorCode::GuardNotRunning, "guard_not_running"),
            (AllowErrorCode::BlockedByManualKillswitch, "blocked_by_manual_killswitch"),
            (AllowErrorCode::AlertStale, "alert_stale"),
            (AllowErrorCode::AuditPending, "audit_pending"),
            (AllowErrorCode::Internal, "internal"),
        ];
        for (code, text) in cases {
            let v = serde_json::to_value(AllowError::new(code, "m")).unwrap();
            assert_eq!(v, serde_json::json!({ "code": text, "message": "m" }));
        }
    }

    #[test]
    fn a_plain_string_error_is_internal() {
        let e: AllowError = String::from("disk full").into();
        assert_eq!(e.code, AllowErrorCode::Internal);
        assert_eq!(e.message, "disk full");
    }
}

//! Isolated execution of one check: a timeout or a panic turns into `Unknown`, never into a
//! silent `Ok`, and never takes the other checks down.

use std::future::Future;
use std::time::Duration;

use crate::auditor::geo_matrix::{CheckResult, UnknownReason};
use crate::auditor::network::current_timestamp;

/// Result code of a check that did not finish within its time limit.
pub const CODE_CHECK_TIMEOUT: &str = "CHECK_TIMEOUT";
/// Result code of a check whose task panicked or was cancelled.
pub const CODE_CHECK_INTERNAL_ERROR: &str = "CHECK_INTERNAL_ERROR";

/// Runs `fut` as its own task with a time limit. A finished result is stamped with `checked_at`.
/// A timeout yields `Unknown(timeout)` (the task is aborted), a panic `Unknown(internal_error)`.
pub async fn run_check<F>(name: &'static str, limit: Duration, fut: F) -> CheckResult
where
    F: Future<Output = CheckResult> + Send + 'static,
{
    let handle = tokio::spawn(fut);
    let abort = handle.abort_handle();
    let mut result = match tokio::time::timeout(limit, handle).await {
        Ok(Ok(result)) => result,
        Ok(Err(join_err)) => {
            eprintln!(
                "Застава: проверка «{name}» завершилась с ошибкой ({})",
                if join_err.is_panic() {
                    "паника"
                } else {
                    "отменена"
                }
            );
            CheckResult::unknown(
                CODE_CHECK_INTERNAL_ERROR,
                format!("Проверка «{name}» завершилась внутренней ошибкой, результата нет."),
                UnknownReason::InternalError,
            )
        }
        Err(_) => {
            abort.abort();
            eprintln!(
                "Застава: проверка «{name}» не уложилась в {} мс",
                limit.as_millis()
            );
            CheckResult::unknown(
                CODE_CHECK_TIMEOUT,
                format!(
                    "Проверка «{name}» не завершилась за {} с.",
                    limit.as_secs_f32()
                ),
                UnknownReason::Timeout,
            )
        }
    };
    if result.checked_at.is_none() {
        result.checked_at = Some(current_timestamp());
    }
    result
}

/// Runs blocking `f` (e.g. a child process) off the async workers; a panic becomes
/// `Unknown(internal_error)`.
pub async fn blocking_check<F>(f: F) -> CheckResult
where
    F: FnOnce() -> CheckResult + Send + 'static,
{
    tokio::task::spawn_blocking(f).await.unwrap_or_else(|_| {
        CheckResult::unknown(
            CODE_CHECK_INTERNAL_ERROR,
            "Проверка завершилась внутренней ошибкой, результата нет.",
            UnknownReason::InternalError,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditor::geo_matrix::CheckStatus;

    const LIMIT: Duration = Duration::from_secs(1);

    #[tokio::test(start_paused = true)]
    async fn slow_check_becomes_unknown_timeout() {
        let r = run_check("slow", LIMIT, async {
            tokio::time::sleep(Duration::from_secs(60)).await;
            CheckResult::ok("LATE", "late")
        })
        .await;
        assert_eq!(r.status, CheckStatus::Unknown);
        assert_eq!(r.reason, Some(UnknownReason::Timeout));
        assert_eq!(r.code, CODE_CHECK_TIMEOUT);
        assert!(r.checked_at.is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn finished_check_is_passed_through_and_stamped() {
        let r = run_check("fast", LIMIT, async { CheckResult::ok("A", "a") }).await;
        assert_eq!(r.status, CheckStatus::Ok);
        assert_eq!(r.code, "A");
        assert!(r.checked_at.is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn panic_is_internal_error_and_the_other_twelve_finish() {
        let mut checks = Vec::new();
        for i in 0..13usize {
            checks.push(tokio::spawn(async move {
                run_check("c", LIMIT, async move {
                    if i == 5 {
                        panic!("boom in check {i}");
                    }
                    CheckResult::ok("OK", "ok")
                })
                .await
            }));
        }
        let mut results = Vec::new();
        for c in checks {
            results.push(c.await.expect("run_check itself never panics"));
        }
        assert_eq!(results.len(), 13);
        assert_eq!(results[5].status, CheckStatus::Unknown);
        assert_eq!(results[5].reason, Some(UnknownReason::InternalError));
        let finished_ok = results
            .iter()
            .enumerate()
            .filter(|(i, r)| *i != 5 && r.status == CheckStatus::Ok)
            .count();
        assert_eq!(finished_ok, 12);
    }

    #[tokio::test]
    async fn blocking_panic_is_internal_error() {
        let r = blocking_check(|| panic!("boom")).await;
        assert_eq!(r.reason, Some(UnknownReason::InternalError));
    }
}

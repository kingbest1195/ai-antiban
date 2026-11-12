//! Live VPN crash-test commands.

use crate::{auditor, proxy, state};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashTestStepResult {
    pub passed_through: bool,
    pub intercepted_by_killswitch: bool,
    pub latency_ms: f64,
    pub current_ip: String,
    pub current_country: String,
    pub status_text: String,
}

#[tauri::command]
pub async fn run_vpn_crash_test_step(
    proxy_manager: tauri::State<'_, proxy::ProxyManager>,
    auditor: tauri::State<'_, auditor::Auditor>,
    state: tauri::State<'_, state::AppState>,
) -> Result<CrashTestStepResult, String> {
    let proxy_addr = proxy_manager.server.bound_addr;
    let start = std::time::Instant::now();

    let connect_fut = async {
        let mut stream = tokio::net::TcpStream::connect(proxy_addr).await?;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let req = b"CONNECT canary-test.anthropic.zastava.local:443 HTTP/1.1\r\nHost: canary-test.anthropic.zastava.local:443\r\n\r\n";
        stream.write_all(req).await?;
        stream.flush().await?;

        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await?;
        let resp = String::from_utf8_lossy(&buf[..n]);
        Ok::<String, std::io::Error>(resp.to_string())
    };

    let (current_ip, current_country) = {
        if let Ok(tel) = auditor
            .resolve_for_provider(auditor::ProviderId::Anthropic, &state, false)
            .await
        {
            (tel.ip, tel.country_code)
        } else {
            let st = state.get_data().await;
            (st.pinned_ip.unwrap_or_else(|| "127.0.0.1".to_string()), "??".to_string())
        }
    };

    match tokio::time::timeout(Duration::from_millis(800), connect_fut).await {
        Ok(Ok(resp)) => {
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
            if resp.contains("200 OK") || resp.contains("PROTECTED") {
                Ok(CrashTestStepResult {
                    passed_through: true,
                    intercepted_by_killswitch: false,
                    latency_ms,
                    current_ip,
                    current_country,
                    status_text: format!("Защищено · Маршрут чист ({:.1} мс)", latency_ms),
                })
            } else {
                Ok(CrashTestStepResult {
                    passed_through: false,
                    intercepted_by_killswitch: true,
                    latency_ms,
                    current_ip,
                    current_country,
                    status_text: format!("Мгновенно перехвачено Kill-Switch ({:.1} мс)", latency_ms),
                })
            }
        }
        Ok(Err(_io_err)) => {
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
            Ok(CrashTestStepResult {
                passed_through: false,
                intercepted_by_killswitch: true,
                latency_ms,
                current_ip,
                current_country,
                status_text: format!("Перехвачено на уровне сокета ({:.1} мс)", latency_ms),
            })
        }
        Err(_timeout) => {
            Ok(CrashTestStepResult {
                passed_through: false,
                intercepted_by_killswitch: true,
                latency_ms: 800.0,
                current_ip,
                current_country,
                // Not a count of anything: the test only sees that the gateway gave no answer in time.
                status_text: "Таймаут сокета · Запрос не прошёл через шлюз".to_string(),
            })
        }
    }
}

#[tauri::command]
pub async fn trigger_crash_test_drop(
    proxy_manager: tauri::State<'_, proxy::ProxyManager>,
) -> Result<(), String> {
    proxy_manager.guard.freeze_for_test().await;
    Ok(())
}

#[tauri::command]
pub async fn reset_crash_test_drop(
    proxy_manager: tauri::State<'_, proxy::ProxyManager>,
) -> Result<(), String> {
    proxy_manager.guard.accept_current().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The interface (`CrashTestStepResult` in `src/types/index.ts`, `crashTestModel.test.ts`) reads exactly
    /// these keys: a change here must change both.
    #[test]
    fn the_answer_has_exactly_the_keys_the_interface_reads() {
        let v = serde_json::to_value(CrashTestStepResult {
            passed_through: true,
            intercepted_by_killswitch: false,
            latency_ms: 0.5,
            current_ip: "203.0.113.7".into(),
            current_country: "NL".into(),
            status_text: "x".into(),
        })
        .unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "current_country",
                "current_ip",
                "intercepted_by_killswitch",
                "latency_ms",
                "passed_through",
                "status_text"
            ]
        );
    }
}

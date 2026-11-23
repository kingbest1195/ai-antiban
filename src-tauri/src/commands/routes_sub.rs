//! Route subscription metadata resolver (`sub_url` / `subscription-userinfo` / `KeyV2` JSON).

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::AppContext;
use crate::auditor::network::current_timestamp;
use crate::routing::{self, Route, RouteView};
use crate::{auditor, proxy};

const SUB_FETCH_TIMEOUT: Duration = Duration::from_secs(6);
const SUB_MAX_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionMetadata {
    pub expires_at: Option<u64>,
    pub updated_route: Option<Route>,
}

/// Parses `expire=<unix_ts>` from a `subscription-userinfo` HTTP response header.
pub fn parse_subscription_userinfo_expire(header_val: &str) -> Option<u64> {
    for part in header_val.split([';', ',', ' ']) {
        let trimmed = part.trim();
        if let Some((k, v)) = trimmed.split_once('=')
            && k.trim().eq_ignore_ascii_case("expire")
            && let Ok(ts) = v.trim().parse::<u64>()
            && ts > 0
        {
            return Some(ts);
        }
    }
    None
}

/// Parses subscription response headers/body (`zastava://...`, `KeyV2` JSON, or `{"expires_at":...}`).
pub fn parse_subscription_response(
    header_expire: Option<u64>,
    body: &str,
    now: u64,
) -> Result<SubscriptionMetadata, String> {
    let trimmed = body.trim();
    if trimmed
        .get(..routing::key::ZASTAVA_SCHEME.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(routing::key::ZASTAVA_SCHEME))
    {
        let mut route = routing::parse_route_key(trimmed, now)?;
        if route.expires_at.is_none() {
            route.expires_at = header_expire;
        }
        return Ok(SubscriptionMetadata {
            expires_at: route.expires_at,
            updated_route: Some(route),
        });
    }

    if trimmed.starts_with('{') {
        let val: serde_json::Value = serde_json::from_str(trimmed)
            .map_err(|_| "Некорректный JSON в ответе подписки".to_string())?;
        if val.get("entry").is_some() {
            let encoded = format!(
                "{}{}",
                routing::key::ZASTAVA_SCHEME,
                URL_SAFE_NO_PAD.encode(trimmed.as_bytes())
            );
            let mut route = routing::parse_route_key(&encoded, now)?;
            if route.expires_at.is_none() {
                route.expires_at = header_expire;
            }
            return Ok(SubscriptionMetadata {
                expires_at: route.expires_at,
                updated_route: Some(route),
            });
        }
        let body_expire = val
            .get("expires_at")
            .or_else(|| val.get("expire"))
            .and_then(|v| v.as_u64())
            .filter(|&ts| ts > 0);
        let expires_at = body_expire.or(header_expire);
        if expires_at.is_some() {
            return Ok(SubscriptionMetadata {
                expires_at,
                updated_route: None,
            });
        }
    }

    if let Some(ts) = header_expire {
        return Ok(SubscriptionMetadata {
            expires_at: Some(ts),
            updated_route: None,
        });
    }

    Err("Ответ подписки не содержит срока действия или обновлённого ключа".to_string())
}

pub async fn fetch_subscription_metadata_from(
    client: &reqwest::Client,
    url: &str,
    now: u64,
) -> Result<SubscriptionMetadata, String> {
    let resp = client
        .get(url)
        .timeout(SUB_FETCH_TIMEOUT)
        .send()
        .await
        .map_err(|e| format!("Не удалось загрузить метаданные подписки: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "Сервер подписки вернул статус HTTP {}",
            resp.status().as_u16()
        ));
    }
    let header_expire = resp
        .headers()
        .get("subscription-userinfo")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_subscription_userinfo_expire);

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("Не удалось прочитать ответ подписки: {e}"))?;
    if bytes.len() > SUB_MAX_BODY_BYTES {
        return Err("Ответ подписки превышает допустимый размер".to_string());
    }
    let body = std::str::from_utf8(&bytes)
        .map_err(|_| "Ответ подписки не является корректным UTF-8".to_string())?;
    parse_subscription_response(header_expire, body, now)
}

pub async fn refresh_route_subscription_inner(
    state: &AppContext,
    id: &str,
    client: Option<&reqwest::Client>,
    override_url: Option<&str>,
) -> Result<bool, String> {
    let route = state
        .get_route(id)
        .await
        .ok_or_else(|| format!("Маршрут не найден: {id}"))?;
    let target_url = match override_url {
        Some(u) => u.to_string(),
        None => {
            let raw = route
                .sub_url
                .as_deref()
                .ok_or_else(|| "У этого ключа нет ссылки автообновления подписки".to_string())?;
            routing::key::validate_sub_url(Some(raw.to_string()))?
                .ok_or_else(|| "У этого ключа нет ссылки автообновления подписки".to_string())?
        }
    };

    let owned_client;
    let http = match client {
        Some(c) => c,
        None => {
            owned_client = reqwest::Client::builder()
                .timeout(SUB_FETCH_TIMEOUT)
                .build()
                .map_err(|e| format!("Не удалось создать HTTP-клиент: {e}"))?;
            &owned_client
        }
    };

    let meta = fetch_subscription_metadata_from(http, &target_url, current_timestamp()).await?;
    state
        .apply_route_subscription_update(id, meta.updated_route, meta.expires_at)
        .await
        .map_err(|e| e.to_string())
}

/// Refreshes all routes that declare `sub_url` in the background on startup (best-effort).
pub async fn refresh_all_route_subscriptions_bg(
    state: &AppContext,
    auditor: &auditor::Auditor,
) -> bool {
    let routes = state.get_routes().await;
    let Ok(client) = reqwest::Client::builder()
        .timeout(SUB_FETCH_TIMEOUT)
        .build()
    else {
        return false;
    };
    let mut any_changed = false;
    for route in routes {
        if route.sub_url.is_none() {
            continue;
        }
        if matches!(
            refresh_route_subscription_inner(state, &route.id, Some(&client), None).await,
            Ok(true)
        ) {
            auditor.resolver.invalidate_route(&route.id).await;
            any_changed = true;
        }
    }
    any_changed
}

#[tauri::command]
pub async fn refresh_route_subscription(
    id: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppContext>,
    auditor: tauri::State<'_, auditor::Auditor>,
    guard: tauri::State<'_, std::sync::Arc<proxy::NetworkGuard>>,
) -> Result<RouteView, String> {
    let changed = refresh_route_subscription_inner(&state, &id, None, None).await?;
    if changed {
        auditor.resolver.invalidate_route(&id).await;
        if let Some(updated) = state.get_route(&id).await
            && let Ok(Some(active_key)) = auditor::profile_switcher::sync_profiles_for_route_update(
                &id,
                Some(&updated.raw_key),
            )
        {
            let _ = crate::commands::claude::sync_active_profile_route_to_runtime(
                &state,
                &guard,
                active_key.as_deref(),
            )
            .await;
            crate::tray::menu::refresh_profiles_submenu(&app);
        }
    }
    let data = state.get_data().await;
    let route = data
        .routes
        .iter()
        .find(|r| r.id == id)
        .ok_or("Маршрут не найден")?;
    Ok(routing::route_view(
        route,
        &data,
        state.route_health().get(&id),
        current_timestamp(),
    ))
}

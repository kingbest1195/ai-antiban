//! Deep-link registration, single-instance launch handling, and startup profile reconciliation.

use crate::{auditor, commands, state};
use tauri::Manager;

pub(super) fn handle_single_instance_launch(app: &tauri::AppHandle, argv: &[String]) {
    let mut found_deep_link = false;
    let minimized = argv.iter().any(|arg| arg == "--minimized");
    for arg in argv {
        if arg.starts_with("zastava://") {
            commands::deeplink::handle_deep_link(app, arg);
            found_deep_link = true;
        }
    }
    if !found_deep_link
        && !minimized
        && let Some(win) = app.get_webview_window("main")
    {
        let _ = win.show();
        let _ = win.unminimize();
        let _ = win.set_focus();
    }
}

pub(super) fn register_deep_link_handlers(app: &tauri::App) {
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    {
        use tauri_plugin_deep_link::DeepLinkExt;
        let _ = app.deep_link().register_all();
    }

    {
        use tauri_plugin_deep_link::DeepLinkExt;
        let dl_handle = app.handle().clone();
        app.deep_link().on_open_url(move |event| {
            for url in event.urls() {
                commands::deeplink::handle_deep_link(&dl_handle, url.as_str());
            }
        });
    }
}

pub(super) fn handle_initial_deep_links(app: &tauri::App) {
    for arg in std::env::args() {
        if arg.starts_with("zastava://") {
            commands::deeplink::handle_deep_link(app.handle(), &arg);
        }
    }
}

/// Reconciles the active Claude profile's route and `"anthropic"` pinned IP from
/// `profiles.json` into `state.json` before the proxy server and guard start.
pub async fn reconcile_active_profile_binding_async(
    app_state: &state::AppState,
    binding: auditor::profile_switcher::ActiveProfileBindingState,
) {
    let st = app_state.get_data().await;
    let current_anthropic_pin = st
        .pinned_ips
        .get(state::PROVIDER_ANTHROPIC)
        .map(String::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let target_pin = binding
        .bound_ip
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if current_anthropic_pin != target_pin
        && let Err(err) = app_state
            .set_pinned_ip_for(state::PROVIDER_ANTHROPIC, target_pin.map(str::to_string))
            .await
    {
        crate::diagnostics::record("startup_profile", &err.to_string());
    }

    if let Some(ref key) = binding.bound_upstream_key {
        let route_matches = binding.bound_route_id.as_deref().is_some_and(|rid| {
            st.routes
                .iter()
                .any(|r| r.id == rid && r.raw_key == *key)
        });
        let needs_apply = st.profile_route_invalid.is_some()
            || st.profile_route_id.as_deref() != binding.bound_route_id.as_deref()
            || !route_matches;
        if needs_apply
            && let Err(err) = crate::routing::apply_profile_key(app_state, Some(key)).await
        {
            crate::diagnostics::record("startup_profile", &err);
        }
        // Clear any stale local-VPN block on Anthropic left from before restart when the active
        // profile has a valid Zastava key route (non-profile providers stay intact).
        let st_after = app_state.get_data().await;
        if st_after.profile_route_invalid.is_none()
            && st_after.profile_route_id.is_some()
            && st_after.blocked_providers.contains(state::PROVIDER_ANTHROPIC)
            && let Err(err) = app_state.unblock_provider(state::PROVIDER_ANTHROPIC).await
        {
            crate::diagnostics::record("startup_profile", &err.to_string());
        }
    } else if let Some(ref dangling_rid) = binding.bound_route_id {
        if st.profile_route_id.as_deref() != Some(dangling_rid.as_str())
            && let Err(err) = app_state
                .set_profile_route_dangling(dangling_rid.clone())
                .await
        {
            crate::diagnostics::record("startup_profile", &err.to_string());
        }
    } else if st.profile_route_id.is_some()
        && let Err(err) = crate::routing::apply_profile_key(app_state, None).await
    {
        crate::diagnostics::record("startup_profile", &err);
    }
}

pub(super) fn reconcile_active_profile_on_startup(app_state: &state::AppState) {
    let binding = match auditor::profile_switcher::active_profile_binding_state() {
        Ok(Some(b)) => b,
        Ok(None) => return,
        Err(err) => {
            crate::diagnostics::record("startup_profile", &err);
            return;
        }
    };

    tauri::async_runtime::block_on(reconcile_active_profile_binding_async(app_state, binding));
}

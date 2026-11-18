#![cfg(any(test, feature = "test-support"))]

use super::*;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Operations that [`FakePlatform::fail_next`] can break.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PlatOp {
    ListServices,
    GetPac,
    SetPac,
    GetChain,
    SetChain,
    GetBypass,
    SetBypass,
    TempDns,
    VpnList,
    EffectiveProxy,
    GetEnv,
    SetEnv,
    UnsetEnv,
    ListEnv,
    GetInet,
    SetInet,
    DeleteInet,
    NotifyInet,
    BroadcastEnv,
    ExcludeBackup,
}

#[derive(Default)]
struct State {
    services: Vec<ServiceId>,
    pac: BTreeMap<String, PacState>,
    chain: BTreeMap<String, ChainState>,
    bypass: BTreeMap<String, Vec<String>>,
    env: BTreeMap<String, String>,
    inet: BTreeMap<String, RegValue>,
    temp_dns: bool,
    vpn: Vec<VpnConnection>,
    service_kinds: BTreeMap<String, ServiceKind>,
    effective: Option<EffectiveProxy>,
    calls: Vec<String>,
    os_writes: usize,
    fail: BTreeMap<PlatOp, usize>,
    fail_auth: BTreeMap<PlatOp, usize>,
    excluded: Vec<PathBuf>,
    /// The next `set_chain` writes the HTTP side only and then fails (a process killed
    /// between the two commands).
    tear_chain: bool,
    /// How the "OS" rewrites a PAC URL it stores (case, default port, ...).
    pac_normalizer: Option<PacNormalizer>,
}

type PacNormalizer = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// In-memory OS. `Clone` shares the state. The call log records operation names and resource
/// ids only, never values.
#[derive(Clone, Default)]
pub struct FakePlatform {
    st: Arc<Mutex<State>>,
}

impl FakePlatform {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a service (initial state: PAC and chain absent).
    pub fn add_service(&self, svc: ServiceId) {
        self.st.lock().unwrap().services.push(svc);
    }

    pub fn remove_service(&self, key: &str) {
        self.st.lock().unwrap().services.retain(|s| s.key() != key);
    }

    /// Renames a service while keeping its device/port (the stable key).
    pub fn rename_service(&self, key: &str, new_name: &str) {
        for s in self.st.lock().unwrap().services.iter_mut() {
            if s.key() == key {
                s.name = new_name.to_string();
            }
        }
    }

    // Seeding / external modification: not OS writes of ours, never counted.
    pub fn seed_pac(&self, svc: &ServiceId, pac: PacState) {
        self.st.lock().unwrap().pac.insert(svc.key(), pac);
    }
    pub fn seed_chain(&self, svc: &ServiceId, chain: ChainState) {
        self.st.lock().unwrap().chain.insert(svc.key(), chain);
    }
    pub fn seed_bypass(&self, svc: &ServiceId, domains: &[&str]) {
        self.st
            .lock()
            .unwrap()
            .bypass
            .insert(svc.key(), domains.iter().map(|d| d.to_string()).collect());
    }
    pub fn seed_env(&self, key: &str, value: &str) {
        self.st
            .lock()
            .unwrap()
            .env
            .insert(key.to_string(), value.to_string());
    }
    pub fn seed_inet(&self, name: &str, v: RegValue) {
        self.st.lock().unwrap().inet.insert(name.to_string(), v);
    }
    pub fn remove_env_externally(&self, key: &str) {
        self.st.lock().unwrap().env.remove(key);
    }
    /// Adds a VPN service: it is in the service list (without a device, like a real
    /// NetworkExtension service) and in the connection list.
    pub fn add_vpn_service(&self, name: &str, connected: bool) -> ServiceId {
        let svc = ServiceId::new("", &format!("com.vpn.{}", name.replace(' ', "")), name);
        self.add_service(svc.clone());
        self.set_vpn_connection(name, connected);
        svc
    }

    /// Sets (or adds) the state of a connection in the `scutil --nc list` of the fake.
    pub fn set_vpn_connection(&self, name: &str, connected: bool) {
        let mut s = self.st.lock().unwrap();
        match s.vpn.iter_mut().find(|c| c.name == name) {
            Some(c) => c.connected = connected,
            None => s.vpn.push(VpnConnection {
                name: name.to_string(),
                connected,
            }),
        }
    }

    /// What `scutil --proxy` will show: the PAC of the global proxy dictionary.
    pub fn set_effective_pac(&self, url: Option<&str>, enabled: bool) {
        self.st.lock().unwrap().effective = Some(EffectiveProxy {
            pac_enabled: Some(enabled),
            pac_url: url.map(str::to_string),
        });
    }

    pub fn set_temp_dns(&self, on: bool) {
        self.st.lock().unwrap().temp_dns = on;
    }

    /// Overrides [`Platform::service_kind`] for `svc` (test helper).
    /// For VPN kinds, also updates `vpn_connections` so `classify_services` sees the state.
    pub fn set_service_kind(&self, svc: &ServiceId, kind: ServiceKind) {
        self.st
            .lock()
            .unwrap()
            .service_kinds
            .insert(svc.key(), kind);
        if let ServiceKind::Vpn { connected } = kind {
            self.set_vpn_connection(&svc.name, connected);
        }
    }

    pub fn pac_of(&self, svc: &ServiceId) -> PacState {
        self.st
            .lock()
            .unwrap()
            .pac
            .get(&svc.key())
            .cloned()
            .unwrap_or_default()
    }
    pub fn chain_of(&self, svc: &ServiceId) -> ChainState {
        self.st
            .lock()
            .unwrap()
            .chain
            .get(&svc.key())
            .cloned()
            .unwrap_or_default()
    }
    pub fn bypass_of(&self, svc: &ServiceId) -> Vec<String> {
        self.st
            .lock()
            .unwrap()
            .bypass
            .get(&svc.key())
            .cloned()
            .unwrap_or_default()
    }
    pub fn env_of(&self, key: &str) -> Option<String> {
        self.st.lock().unwrap().env.get(key).cloned()
    }
    pub fn inet_of(&self, name: &str) -> Option<RegValue> {
        self.st.lock().unwrap().inet.get(name).cloned()
    }

    /// Next call of `op` fails with `PlatformError::Failed` (once).
    pub fn fail_next(&self, op: PlatOp) {
        self.fail_next_n(op, 1);
    }
    pub fn fail_next_n(&self, op: PlatOp, n: usize) {
        self.st.lock().unwrap().fail.insert(op, n);
    }
    /// Next `n` calls of `op` fail with `PlatformError::AdminAuthRequired`.
    pub fn fail_next_auth(&self, op: PlatOp) {
        self.fail_next_auth_n(op, 1);
    }
    pub fn fail_next_auth_n(&self, op: PlatOp, n: usize) {
        self.st.lock().unwrap().fail_auth.insert(op, n);
    }

    /// The next `set_chain` lands its HTTP side and fails before the HTTPS side, as if the
    /// process had been killed between the two `networksetup` commands (the call after it
    /// fails as well).
    pub fn tear_next_set_chain(&self) {
        self.st.lock().unwrap().tear_chain = true;
    }

    /// From now on the (fake) OS stores every PAC URL after passing it through `f`.
    pub fn normalize_pac_urls_with(&self, f: impl Fn(&str) -> String + Send + Sync + 'static) {
        self.st.lock().unwrap().pac_normalizer = Some(Arc::new(f));
    }

    /// Number of writes of settings into the (fake) OS: set/unset/delete calls that succeeded.
    pub fn os_writes(&self) -> usize {
        self.st.lock().unwrap().os_writes
    }
    /// Operation log, e.g. `set_user_env:HTTPS_PROXY`; no values.
    pub fn calls(&self) -> Vec<String> {
        self.st.lock().unwrap().calls.clone()
    }
    pub fn clear_calls(&self) {
        self.st.lock().unwrap().calls.clear();
    }
    pub fn excluded_paths(&self) -> Vec<PathBuf> {
        self.st.lock().unwrap().excluded.clone()
    }

    fn enter(&self, op: PlatOp, name: &'static str, res: &str, write: bool) -> PResult<()> {
        let mut s = self.st.lock().unwrap();
        s.calls.push(if res.is_empty() {
            name.to_string()
        } else {
            format!("{name}:{res}")
        });
        if let Some(n) = s.fail_auth.get_mut(&op)
            && *n > 0
        {
            *n -= 1;
            if *n == 0 {
                s.fail_auth.remove(&op);
            }
            return Err(PlatformError::AdminAuthRequired(name));
        }
        if let Some(n) = s.fail.get_mut(&op)
            && *n > 0
        {
            *n -= 1;
            if *n == 0 {
                s.fail.remove(&op);
            }
            return Err(PlatformError::Failed(name));
        }
        if write {
            s.os_writes += 1;
        }
        Ok(())
    }

    fn has_service(&self, svc: &ServiceId) -> bool {
        self.st
            .lock()
            .unwrap()
            .services
            .iter()
            .any(|s| s.key() == svc.key())
    }
}

impl Platform for FakePlatform {
    fn list_services(&self) -> PResult<Vec<ServiceId>> {
        self.enter(PlatOp::ListServices, "list_services", "", false)?;
        Ok(self.st.lock().unwrap().services.clone())
    }

    fn get_pac(&self, svc: &ServiceId) -> PResult<PacState> {
        self.enter(PlatOp::GetPac, "get_pac", &svc.key(), false)?;
        if !self.has_service(svc) {
            return Err(PlatformError::NotFound("get_pac"));
        }
        Ok(self.pac_of(svc))
    }

    fn set_pac(&self, svc: &ServiceId, pac: &PacState) -> PResult<()> {
        self.enter(PlatOp::SetPac, "set_pac", &svc.key(), true)?;
        if !self.has_service(svc) {
            self.st.lock().unwrap().os_writes -= 1;
            return Err(PlatformError::NotFound("set_pac"));
        }
        let mut s = self.st.lock().unwrap();
        let norm = s.pac_normalizer.clone();
        let cur = s.pac.entry(svc.key()).or_default();
        if let Some(u) = &pac.url {
            // networksetup cannot unset a URL: an empty string reads back as absent.
            cur.url = if u.is_empty() {
                None
            } else {
                Some(norm.as_ref().map_or_else(|| u.clone(), |f| f(u)))
            };
        }
        if let Some(e) = pac.enabled {
            cur.enabled = Some(e);
        }
        Ok(())
    }

    fn get_chain(&self, svc: &ServiceId) -> PResult<ChainState> {
        self.enter(PlatOp::GetChain, "get_chain", &svc.key(), false)?;
        if !self.has_service(svc) {
            return Err(PlatformError::NotFound("get_chain"));
        }
        Ok(self.chain_of(svc))
    }

    fn set_chain(&self, svc: &ServiceId, chain: &ChainState) -> PResult<()> {
        self.enter(PlatOp::SetChain, "set_chain", &svc.key(), true)?;
        if !self.has_service(svc) {
            self.st.lock().unwrap().os_writes -= 1;
            return Err(PlatformError::NotFound("set_chain"));
        }
        let mut s = self.st.lock().unwrap();
        let tear = std::mem::take(&mut s.tear_chain);
        let cur = s.chain.entry(svc.key()).or_default();
        let sides = [(&mut cur.http, &chain.http), (&mut cur.https, &chain.https)];
        for (n, (dst, src)) in sides.into_iter().enumerate() {
            if tear && n == 1 {
                break; // only the HTTP side landed
            }
            if src.server.is_some() && src.port.is_some() {
                dst.server = src.server.clone();
                dst.port = src.port;
            }
            if src.enabled.is_some() {
                dst.enabled = src.enabled;
            }
        }
        if tear {
            // The process is gone: the write-back that would follow fails too.
            s.fail.insert(PlatOp::SetChain, 1);
            return Err(PlatformError::Failed("set_chain"));
        }
        Ok(())
    }

    fn get_proxy_bypass_domains(&self, svc: &ServiceId) -> PResult<Vec<String>> {
        self.enter(
            PlatOp::GetBypass,
            "get_proxy_bypass_domains",
            &svc.key(),
            false,
        )?;
        if !self.has_service(svc) {
            return Err(PlatformError::NotFound("get_proxy_bypass_domains"));
        }
        Ok(self.bypass_of(svc))
    }

    fn set_proxy_bypass_domains(&self, svc: &ServiceId, domains: &[String]) -> PResult<()> {
        // Like the real one: no call and no write when the list already is as wanted.
        if self.has_service(svc) && self.bypass_of(svc) == domains {
            self.st
                .lock()
                .unwrap()
                .calls
                .push(format!("set_proxy_bypass_domains:{}:same", svc.key()));
            return Ok(());
        }
        self.enter(
            PlatOp::SetBypass,
            "set_proxy_bypass_domains",
            &svc.key(),
            true,
        )?;
        if !self.has_service(svc) {
            self.st.lock().unwrap().os_writes -= 1;
            return Err(PlatformError::NotFound("set_proxy_bypass_domains"));
        }
        self.st
            .lock()
            .unwrap()
            .bypass
            .insert(svc.key(), domains.to_vec());
        Ok(())
    }

    fn vpn_connections(&self) -> PResult<Vec<VpnConnection>> {
        self.enter(PlatOp::VpnList, "vpn_connections", "", false)?;
        Ok(self.st.lock().unwrap().vpn.clone())
    }

    fn service_kind(&self, svc: &ServiceId) -> ServiceKind {
        if let Some(&kind) = self.st.lock().unwrap().service_kinds.get(&svc.key()) {
            return kind;
        }
        let nc = self.vpn_connections().ok();
        classify_service(svc, nc.as_deref())
    }

    fn effective_proxy(&self) -> PResult<EffectiveProxy> {
        self.enter(PlatOp::EffectiveProxy, "effective_proxy", "", false)?;
        self.st
            .lock()
            .unwrap()
            .effective
            .clone()
            .ok_or(PlatformError::Unsupported("effective_proxy"))
    }

    fn temp_dns_overrides(&self) -> PResult<bool> {
        self.enter(PlatOp::TempDns, "temp_dns_overrides", "", false)?;
        Ok(self.st.lock().unwrap().temp_dns)
    }

    fn get_user_env(&self, key: &str) -> PResult<Option<String>> {
        self.enter(PlatOp::GetEnv, "get_user_env", key, false)?;
        Ok(self.env_of(key))
    }

    fn set_user_env(&self, key: &str, value: &str) -> PResult<()> {
        self.enter(PlatOp::SetEnv, "set_user_env", key, true)?;
        self.st
            .lock()
            .unwrap()
            .env
            .insert(key.to_string(), value.to_string());
        Ok(())
    }

    fn unset_user_env(&self, key: &str) -> PResult<()> {
        self.enter(PlatOp::UnsetEnv, "unset_user_env", key, true)?;
        self.st.lock().unwrap().env.remove(key);
        Ok(())
    }

    fn list_user_env_names(&self) -> PResult<Vec<String>> {
        self.enter(PlatOp::ListEnv, "list_user_env_names", "", false)?;
        Ok(self.st.lock().unwrap().env.keys().cloned().collect())
    }

    fn get_inet(&self, name: &str) -> PResult<Option<RegValue>> {
        self.enter(PlatOp::GetInet, "get_inet", name, false)?;
        Ok(self.inet_of(name))
    }

    fn set_inet(&self, name: &str, value: &RegValue) -> PResult<()> {
        self.enter(PlatOp::SetInet, "set_inet", name, true)?;
        self.st
            .lock()
            .unwrap()
            .inet
            .insert(name.to_string(), value.clone());
        Ok(())
    }

    fn delete_inet(&self, name: &str) -> PResult<()> {
        self.enter(PlatOp::DeleteInet, "delete_inet", name, true)?;
        self.st.lock().unwrap().inet.remove(name);
        Ok(())
    }

    fn notify_inet_refresh(&self) -> PResult<()> {
        self.enter(PlatOp::NotifyInet, "notify_inet_refresh", "", false)
    }

    fn broadcast_env_change(&self) -> PResult<()> {
        self.enter(PlatOp::BroadcastEnv, "broadcast_env_change", "", false)
    }

    fn exclude_from_backup(&self, path: &Path) -> PResult<()> {
        self.enter(PlatOp::ExcludeBackup, "exclude_from_backup", "", false)?;
        self.st.lock().unwrap().excluded.push(path.to_path_buf());
        Ok(())
    }
}

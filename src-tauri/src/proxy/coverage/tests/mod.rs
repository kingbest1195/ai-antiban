//! Coverage tests: canned OS output, `FakePlatform`, `FakeFs`, a manual clock. No process is
//! started and no real user directory is read.

use super::*;
use crate::sysproxy::browser_policies::FakePolicyStore;
use crate::sysproxy::fs::{FakeFs, Fs};
use crate::sysproxy::platform::{FakePlatform, PacState, ServiceId};
use std::sync::atomic::{AtomicU64, Ordering};

// ----- doubles ---------------------------------------------------------------------------------

#[derive(Default)]
struct FakeProbe {
    calls: Mutex<Vec<String>>,
    /// Output for every call (`None` = the program "failed").
    output: Mutex<Option<String>>,
}

impl FakeProbe {
    fn answering(text: &str) -> Arc<Self> {
        let p = Self::default();
        *p.output.lock().unwrap() = Some(text.to_string());
        Arc::new(p)
    }
    fn failing() -> Arc<Self> {
        Arc::new(Self::default())
    }
    fn count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

impl SystemProbe for FakeProbe {
    fn run(&self, program: &str, args: &[&str]) -> Option<String> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("{program} {}", args.join(" ")));
        self.output.lock().unwrap().clone()
    }
}

const LSOF_CLAUDE: &str = "p501\ncClaude\nn127.0.0.1:50000->127.0.0.1:8899\n";

fn clock_at(ms: u64) -> (Arc<AtomicU64>, Clock) {
    let t = Arc::new(AtomicU64::new(ms));
    let t2 = Arc::clone(&t);
    (t, Arc::new(move || t2.load(Ordering::SeqCst)))
}

fn tracker(probe: Arc<FakeProbe>) -> (Arc<AtomicU64>, CoverageTracker) {
    let (t, clock) = clock_at(10_000_000);
    (t, CoverageTracker::with_parts(clock, probe, Os::Macos))
}

fn gw(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

fn home() -> PathBuf {
    Path::new("home").join("user")
}

fn editor_root() -> PathBuf {
    home().join("support")
}

fn ctx_with(fs: &FakeFs) -> FileCtx {
    FileCtx::new(Arc::new(fs.clone()), home(), vec![editor_root()])
}

fn make_editor(fs: &FakeFs, folder: &str, settings: Option<&str>) {
    let user = editor_root().join(folder).join("User");
    fs.create_private_dir_all(&user).unwrap();
    if let Some(text) = settings {
        fs.put(&user.join("settings.json"), text.as_bytes(), 0o600);
    }
}

struct Rig {
    platform: FakePlatform,
    policy_store: Arc<FakePolicyStore>,
    ctx: FileCtx,
    fs: FakeFs,
}

impl Rig {
    fn new() -> Self {
        let fs = FakeFs::new();
        Self {
            platform: FakePlatform::new(),
            policy_store: FakePolicyStore::new(),
            ctx: ctx_with(&fs),
            fs,
        }
    }

    fn env(&self, source: PacSource, cli: bool) -> CoverageEnv<'_> {
        CoverageEnv {
            platform: &self.platform,
            policy_store: &*self.policy_store,
            files: Some(&self.ctx),
            pac_source: source,
            sysproxy_enabled: true,
            cli_protection_enabled: cli,
            chained_proxy: None,
            jetbrains_xml_confirmed: JETBRAINS_XML_CONFIRMED,
        }
    }

    fn wifi() -> ServiceId {
        ServiceId::new("en0", "Wi-Fi", "Wi-Fi")
    }

    fn seed_wifi_pac(&self, url: &str, enabled: bool) {
        let svc = Self::wifi();
        self.platform.add_service(svc.clone());
        self.platform.seed_pac(
            &svc,
            PacState {
                url: Some(url.to_string()),
                enabled: Some(enabled),
            },
        );
    }
}

fn app<'a>(snap: &'a CoverageSnapshot, id: &str) -> &'a AppCoverageItem {
    snap.apps.iter().find(|a| a.id == id).unwrap()
}

const OUR_PAC: &str = "http://127.0.0.1:8899/proxy.pac";

mod process_and_traffic;
mod apps_and_cli;
mod vpn_and_antigravity;
mod browser_policies_and_opencode;

//! Disposable KVM sessions. Admission covers collection and verified destruction,
//! rather than merely the lifetime of the agent process. Existing persistent VM
//! routes are deliberately separate from this profile's admission boundary.
use crate::disposable_gateway::GatewayStore;
use chrono::{DateTime, Duration, Timelike, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Component, Path, PathBuf},
    sync::Arc,
};
use tokio::process::Command;

pub const MAX_SOURCE: usize = 100 * 1024 * 1024;
pub const MAX_REPORT: u64 = 2 * 1024 * 1024;
const CLEANUP_RESERVE: i64 = 300;
pub const MAX_MEMORY_MB: u32 = 32768;
pub const MAX_VCPUS: u8 = 8;
fn lifetime() -> String {
    "timed".into()
}
#[derive(Clone, Debug, Serialize)]
pub struct ResourceUsage {
    pub memory_mb_used: u64,
    pub memory_mb_available: u64,
    pub memory_mb_limit: u32,
    pub vcpus_used: u64,
    pub vcpus_available: u64,
    pub vcpus_limit: u8,
    pub blocked: bool,
}
fn usage(sessions: &BTreeMap<String, Session>) -> ResourceUsage {
    let active: Vec<_> = sessions.values().filter(|s| !s.terminal()).collect();
    let memory_mb_used = active.iter().map(|s| u64::from(s.request.memory_mb)).sum();
    let vcpus_used = active.iter().map(|s| u64::from(s.request.vcpus)).sum();
    ResourceUsage {
        memory_mb_used,
        vcpus_used,
        memory_mb_available: u64::from(MAX_MEMORY_MB).saturating_sub(memory_mb_used),
        vcpus_available: u64::from(MAX_VCPUS).saturating_sub(vcpus_used),
        memory_mb_limit: MAX_MEMORY_MB,
        vcpus_limit: MAX_VCPUS,
        blocked: active.iter().any(|s| s.state == "cleanup_failed"),
    }
}
fn fits(sessions: &BTreeMap<String, Session>, memory: u32, cpus: u8) -> bool {
    let u = usage(sessions);
    !u.blocked && u.memory_mb_available >= memory.into() && u.vcpus_available >= cpus.into()
}
fn memory() -> u32 {
    16384
}
fn cpus() -> u8 {
    6
}
fn duration() -> u32 {
    18000
}
fn model() -> String {
    "studio".into()
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRequest {
    pub kind: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default = "lifetime")]
    pub lifetime: String,
    pub repository: Option<String>,
    pub commit: Option<String>,
    pub run_id: Option<String>,
    pub ref_name: Option<String>,
    #[serde(default)]
    pub audit_profile: AuditProfile,
    pub deadline: Option<DateTime<Utc>>,
    #[serde(default = "duration")]
    pub duration_seconds: u32,
    #[serde(default = "memory")]
    pub memory_mb: u32,
    #[serde(default = "cpus")]
    pub vcpus: u8,
    #[serde(default = "model")]
    pub model_id: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditProfile {
    #[serde(default)]
    pub test_commands: Vec<Vec<String>>,
    #[serde(default = "default_scanners")]
    pub scanners: Vec<String>,
    #[serde(default)]
    pub scope: Vec<String>,
    #[serde(default)]
    pub exclusions: Vec<String>,
}
fn default_scanners() -> Vec<String> {
    ["semgrep", "gitleaks", "trivy"]
        .into_iter()
        .map(String::from)
        .collect()
}
impl Default for AuditProfile {
    fn default() -> Self {
        Self {
            test_commands: Vec::new(),
            scanners: default_scanners(),
            scope: Vec::new(),
            exclusions: Vec::new(),
        }
    }
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryPolicy {
    pub allowed_refs: Vec<String>,
    #[serde(default)]
    pub audit_profile: AuditProfile,
}
impl CreateRequest {
    pub fn validated_deadline(&self, now: DateTime<Utc>) -> Result<DateTime<Utc>, String> {
        self.validated_deadline_for(now, false)?
            .ok_or_else(|| "until_deleted sessions have no deadline".into())
    }
    fn validated_deadline_for(
        &self,
        now: DateTime<Utc>,
        local_schedule: bool,
    ) -> Result<Option<DateTime<Utc>>, String> {
        if !["audit", "interactive"].contains(&self.kind.as_str()) {
            return Err("kind must be audit or interactive".into());
        }
        if ![(8192, 2), (12288, 4), (16384, 6)].contains(&(self.memory_mb, self.vcpus))
            || (self.kind == "audit" && (self.memory_mb, self.vcpus) != (16384, 6))
        {
            return Err("choose Small (8192 MiB/2 vCPUs), Medium (12288 MiB/4 vCPUs), or Security (16384 MiB/6 vCPUs); audits require Security".into());
        }
        if !["timed", "until_deleted"].contains(&self.lifetime.as_str())
            || (self.kind == "audit" && self.lifetime != "timed")
        {
            return Err("until_deleted is only available for interactive sessions".into());
        }
        if self
            .name
            .as_ref()
            .is_some_and(|n| n.is_empty() || n.len() > 100 || n.chars().any(char::is_control))
        {
            return Err("name must be 1..100 bytes without control characters".into());
        }
        if self.duration_seconds == 0 || self.duration_seconds > 18000 {
            return Err("duration_seconds must be 1..18000".into());
        }
        if self.model_id.is_empty() || self.model_id.len() > 100 {
            return Err("select an administrator-configured model preset".into());
        }
        if let Some(repo) = &self.repository {
            let parts: Vec<_> = repo.split('/').collect();
            if parts.len() != 2
                || parts.iter().any(|s| {
                    s.is_empty()
                        || s.len() > 100
                        || !s
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
                        || *s == "."
                        || *s == ".."
                })
            {
                return Err("repository must be owner/name".into());
            }
            if !self
                .commit
                .as_ref()
                .is_some_and(|s| s.len() == 40 && s.bytes().all(|c| c.is_ascii_hexdigit()))
            {
                return Err("repository requires a full 40 character commit SHA".into());
            }
        }
        if self.kind == "audit"
            && (self.ref_name.is_none()
                || self.repository.is_none()
                || !self.run_id.as_ref().is_some_and(|s| {
                    !s.is_empty()
                        && s.len() < 128
                        && s.bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"-_:".contains(&c))
                }))
        {
            return Err("audit requires repository, commit and bounded run_id".into());
        }
        if self.lifetime == "until_deleted" {
            if self.deadline.is_some() {
                return Err("until_deleted sessions cannot set a deadline".into());
            }
            return Ok(None);
        }
        let mut deadline = now + Duration::seconds(self.duration_seconds.into());
        if let Some(requested) = self.deadline {
            deadline = deadline.min(requested);
        }
        if self.kind == "audit" && !local_schedule {
            let local = now.with_timezone(&chrono_tz::America::Detroit);
            if !(1..6).contains(&local.hour()) {
                return Err("audit admission is restricted to 01:00-06:00 America/Detroit".into());
            }
            let cutoff = local
                .date_naive()
                .and_hms_opt(6, 0, 0)
                .unwrap()
                .and_local_timezone(chrono_tz::America::Detroit)
                .single()
                .ok_or("ambiguous audit cutoff")?
                .with_timezone(&Utc);
            deadline = deadline.min(cutoff);
            if deadline <= now + Duration::seconds(CLEANUP_RESERVE + 60) {
                return Err("insufficient audit window before 06:00; collection and cleanup reserve 300 seconds".into());
            }
        } else if deadline <= now + Duration::seconds(30) {
            return Err("deadline must allow at least 30 seconds".into());
        }
        Ok(Some(deadline))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub state: String,
    pub request: CreateRequest,
    pub created_at: DateTime<Utc>,
    pub deadline: Option<DateTime<Utc>>,
    #[serde(default)]
    pub network_slot: u8,
    pub finished_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
    #[serde(default)]
    pub cancelled: bool,
}
impl Session {
    pub fn terminal(&self) -> bool {
        ["completed", "failed", "cancelled", "deleted"].contains(&self.state.as_str())
    }
}
#[derive(Debug)]
pub enum Error {
    Busy,
    Invalid(String),
    Unavailable(String),
    NotFound,
    Internal(String),
}
pub struct DisposableController {
    root: PathBuf,
    script: PathBuf,
    sessions: Mutex<BTreeMap<String, Session>>,
    pub gateway: GatewayStore,
    repository_policies: BTreeMap<String, RepositoryPolicy>,
    operator_operation: tokio::sync::Mutex<()>,
    grant_persistence: Mutex<()>,
    _process_lock: fs::File,
}
impl DisposableController {
    pub async fn from_env(gateway: GatewayStore) -> anyhow::Result<Option<Arc<Self>>> {
        if std::env::var("DISPOSABLE_ENABLED").as_deref() != Ok("1") {
            return Ok(None);
        }
        let root = PathBuf::from(
            std::env::var("DISPOSABLE_STATE_ROOT")
                .unwrap_or_else(|_| "/var/lib/agentic-sandbox/disposable".into()),
        );
        let script = PathBuf::from(std::env::var("DISPOSABLE_RUNTIME_SCRIPT").map_err(|_| {
            anyhow::anyhow!("DISPOSABLE_RUNTIME_SCRIPT must be explicitly configured")
        })?);
        anyhow::ensure!(
            root.is_absolute() && script.is_absolute(),
            "disposable paths must be absolute"
        );
        Self::open(root, script, gateway).await.map(Some)
    }
    pub async fn open(
        root: PathBuf,
        script: PathBuf,
        gateway: GatewayStore,
    ) -> anyhow::Result<Arc<Self>> {
        fs::create_dir_all(&root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o711))?;
        }

        let mut lock_options = fs::OpenOptions::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            lock_options.mode(0o600);
        }
        let process_lock = lock_options
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(root.join("controller.lock"))?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            anyhow::ensure!(
                unsafe { libc::flock(process_lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }
                    == 0,
                "another disposable controller owns this state root"
            );
        }
        let mut sessions = BTreeMap::new();
        for item in fs::read_dir(&root)? {
            let item = item?;
            if !item.file_type()?.is_dir()
                || uuid::Uuid::parse_str(&item.file_name().to_string_lossy()).is_err()
            {
                continue;
            }
            let record = item.path().join("session.json");
            // Corrupted state cannot silently release a VM admission slot.
            let session: Session = match fs::read(&record) {
                Ok(bytes) => serde_json::from_slice(&bytes)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    let request = fs::read(item.path().join("request.json"))
                        .ok()
                        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                        .unwrap_or_else(|| CreateRequest {
                            kind: "interactive".into(),
                            name: None,
                            lifetime: lifetime(),
                            repository: None,
                            commit: None,
                            run_id: None,
                            ref_name: None,
                            audit_profile: AuditProfile::default(),
                            deadline: Some(Utc::now()),
                            duration_seconds: 3600,
                            memory_mb: 16384,
                            vcpus: 6,
                            model_id: "studio".into(),
                        });
                    Session {
                        id: item.file_name().to_string_lossy().into_owned(),
                        state: "cleaning".into(),
                        request,
                        created_at: Utc::now(),
                        deadline: Some(Utc::now()),
                        network_slot: 0,
                        finished_at: None,
                        error: Some("partial provisioning metadata recovered for cleanup".into()),
                        cancelled: false,
                    }
                }
                Err(e) => return Err(e.into()),
            };
            anyhow::ensure!(
                session.id == item.file_name().to_string_lossy(),
                "session state identity mismatch"
            );
            sessions.insert(session.id.clone(), session);
        }
        let repository_policies: BTreeMap<String, RepositoryPolicy> =
            match std::env::var("AUDIT_REPOSITORIES_FILE") {
                Ok(path) => {
                    let bytes = fs::read(path)?;
                    anyhow::ensure!(
                        bytes.len() <= 1024 * 1024,
                        "audit repository policies exceed 1 MiB"
                    );
                    serde_json::from_slice(&bytes)?
                }
                Err(_) => BTreeMap::new(),
            };
        for policy in repository_policies.values() {
            anyhow::ensure!(
                !policy.allowed_refs.is_empty()
                    && policy.allowed_refs.len() <= 20
                    && policy
                        .allowed_refs
                        .iter()
                        .all(|r| r.starts_with("refs/heads/") && r.len() < 200),
                "audit policies require explicit trusted branch refs"
            );
            anyhow::ensure!(
                policy.audit_profile.test_commands.len() <= 20
                    && policy
                        .audit_profile
                        .test_commands
                        .iter()
                        .all(|argv| !argv.is_empty()
                            && argv.len() <= 100
                            && argv.iter().all(|s| !s.is_empty() && s.len() <= 4096)),
                "audit test commands exceed their bound"
            );
            anyhow::ensure!(
                policy
                    .audit_profile
                    .scanners
                    .iter()
                    .all(|s| ["semgrep", "gitleaks", "trivy"].contains(&s.as_str())),
                "unknown scanner in audit policy"
            );
        }
        let controller = Arc::new(Self {
            root,
            script,
            sessions: Mutex::new(sessions),
            gateway,
            repository_policies,
            operator_operation: tokio::sync::Mutex::new(()),
            grant_persistence: Mutex::new(()),
            _process_lock: process_lock,
        });
        controller.prune_history();
        let pending: Vec<_> = controller
            .list()
            .into_iter()
            .filter(|s| !s.terminal())
            .map(|s| s.id)
            .collect();
        for id in pending {
            let c = controller.clone();
            let session = c.get(&id).unwrap();
            if session.request.kind == "interactive"
                && session.request.lifetime == "until_deleted"
                && ["running", "unavailable"].contains(&session.state.as_str())
                && !session.cancelled
            {
                let restored = async {
                    let status = c.command("status", &c.dir(&id), 20).await?;
                    if status["state"] != "running" {
                        return Err("persistent VM is not running".to_string());
                    }
                    let bytes = fs::read(c.dir(&id).join("gateway-state.json"))
                        .map_err(|e| e.to_string())?;
                    if bytes.len() > 65536 {
                        return Err("gateway state exceeds bound".into());
                    }
                    let v: serde_json::Value =
                        serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                    let token = v["token"].as_str().ok_or("missing capability")?;
                    let grants =
                        serde_json::from_value(v["grants"].clone()).map_err(|e| e.to_string())?;
                    c.gateway
                        .restore_github_token(&id, &c.dir(&id).join("github-token.key"))?;
                    c.gateway.restore_session(&id, None, token, grants)?;
                    Ok::<_, String>(())
                }
                .await;
                if restored.is_err() {
                    let _ = c.update(&id, "unavailable", Some("Workspace recovery needs attention; files and capacity retained until deletion".into()));
                }
                tokio::spawn(async move {
                    c.monitor(&id).await;
                });
                continue;
            }
            tokio::spawn(async move {
                c.cleanup_loop(
                    &id,
                    "failed",
                    Some("management restarted; recovered by destroying the previous VM".into()),
                )
                .await;
            });
        }
        Ok(controller)
    }
    pub fn list(&self) -> Vec<Session> {
        self.sessions.lock().values().cloned().collect()
    }
    pub fn resource_usage(&self) -> ResourceUsage {
        usage(&self.sessions.lock())
    }
    pub fn can_admit(&self, memory: u32, cpus: u8) -> bool {
        fits(&self.sessions.lock(), memory, cpus)
    }
    pub fn get(&self, id: &str) -> Result<Session, Error> {
        self.sessions.lock().get(id).cloned().ok_or(Error::NotFound)
    }
    fn dir(&self, id: &str) -> PathBuf {
        self.root.join(id)
    }
    fn persist(&self, s: &Session) -> Result<(), Error> {
        write_json(&self.dir(&s.id).join("session.json"), s)
            .map_err(|e| Error::Internal(e.to_string()))
    }
    fn update(&self, id: &str, state: &str, error: Option<String>) -> Result<(), Error> {
        let mut sessions = self.sessions.lock();
        let previous = sessions.get(id).ok_or(Error::NotFound)?;
        let mut next = previous.clone();
        next.state = state.into();
        if error.is_some() {
            next.error = error;
        }
        if next.terminal() {
            next.finished_at = Some(Utc::now());
        }
        self.persist(&next)?;
        sessions.insert(id.to_string(), next);
        Ok(())
    }
    pub async fn create(self: &Arc<Self>, request: CreateRequest) -> Result<Session, Error> {
        self.create_inner(request, false, None).await
    }
    /// Only the authenticated host-owned scheduler may select its own profile/window.
    /// This method is never exposed by the disposable session HTTP API.
    pub(crate) async fn create_local_audit(
        self: &Arc<Self>,
        request: CreateRequest,
    ) -> Result<Session, Error> {
        if request.kind != "audit" {
            return Err(Error::Invalid("local scheduler requires audit kind".into()));
        }
        self.create_inner(request, true, None).await
    }
    pub async fn create_with_github_token(
        self: &Arc<Self>,
        request: CreateRequest,
        token: Option<String>,
    ) -> Result<Session, Error> {
        if token.is_some() && request.kind != "interactive" {
            return Err(Error::Invalid(
                "GitHub tokens are only accepted for interactive sessions".into(),
            ));
        }
        self.create_inner(request, false, token).await
    }
    async fn create_inner(
        self: &Arc<Self>,
        mut request: CreateRequest,
        local_schedule: bool,
        github_token: Option<String>,
    ) -> Result<Session, Error> {
        if request.kind == "audit" && !local_schedule {
            let policy = self
                .repository_policies
                .get(request.repository.as_deref().unwrap_or(""))
                .ok_or_else(|| {
                    Error::Invalid("repository is not enabled in the host audit allowlist".into())
                })?;
            if !policy
                .allowed_refs
                .iter()
                .any(|r| Some(r) == request.ref_name.as_ref())
            {
                return Err(Error::Invalid(
                    "workflow ref is not in the host trusted-ref allowlist".into(),
                ));
            }
            request.audit_profile = policy.audit_profile.clone();
        } else if request.kind != "audit" {
            request.audit_profile = AuditProfile::default();
        }
        if request.kind == "audit" {
            if let Some(existing) = self.list().into_iter().find(|s| {
                s.request.repository == request.repository && s.request.run_id == request.run_id
            }) {
                if existing.request.commit != request.commit
                    || existing.request.ref_name != request.ref_name
                {
                    return Err(Error::Invalid(
                        "run_id already belongs to a different commit/ref".into(),
                    ));
                }
                return Ok(existing);
            }
        }
        let now = Utc::now();
        let deadline = request
            .validated_deadline_for(now, local_schedule)
            .map_err(Error::Invalid)?;
        request.deadline = deadline;
        // Fast rejection precedes slow runtime preflight. Recheck atomically after it.
        if !self.can_admit(request.memory_mb, request.vcpus) {
            return Err(Error::Busy);
        }
        if !self
            .gateway
            .presets()
            .iter()
            .any(|p| p.id == request.model_id && p.kind == "model")
        {
            return Err(Error::Unavailable("model preset is not configured".into()));
        }
        self.command("check", &self.root, 30)
            .await
            .map_err(Error::Unavailable)?;
        request
            .validated_deadline_for(Utc::now(), local_schedule)
            .map_err(Error::Invalid)?;
        let s = {
            let mut sessions = self.sessions.lock();
            if !fits(&sessions, request.memory_mb, request.vcpus) {
                return Err(Error::Busy);
            }
            let network_slot = (0..4)
                .find(|slot| {
                    !sessions
                        .values()
                        .any(|s| !s.terminal() && s.network_slot == *slot)
                })
                .ok_or(Error::Busy)?;
            let id = uuid::Uuid::new_v4().to_string();
            let s = Session {
                id: id.clone(),
                state: if request.repository.is_some() {
                    "awaiting_source"
                } else {
                    "starting"
                }
                .into(),
                request,
                created_at: now,
                deadline,
                network_slot,
                finished_at: None,
                error: None,
                cancelled: false,
            };
            fs::create_dir(self.dir(&id)).map_err(|e| Error::Internal(e.to_string()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(self.dir(&id), fs::Permissions::from_mode(0o700))
                    .map_err(|e| Error::Internal(e.to_string()))?;
            }
            let mut runtime_request =
                serde_json::to_value(&s.request).map_err(|e| Error::Internal(e.to_string()))?;
            runtime_request["network_slot"] = serde_json::json!(network_slot);
            write_json(&self.dir(&id).join("request.json"), &runtime_request)
                .map_err(|e| Error::Internal(e.to_string()))?;
            self.persist(&s)?;
            if let Some(token) = github_token.as_deref() {
                if let Err(error) = self.gateway.set_github_token(
                    &id,
                    token,
                    &self.dir(&id).join("github-token.key"),
                ) {
                    // No VM has started yet; a failed credential save cannot leave an untracked allocation.
                    fs::remove_dir_all(self.dir(&id))
                        .map_err(|e| Error::Internal(e.to_string()))?;
                    return Err(Error::Invalid(error));
                }
            }
            sessions.insert(id, s.clone());
            s
        };
        let c = self.clone();
        let id = s.id.clone();
        tokio::spawn(async move {
            c.run(&id).await;
        });
        Ok(s)
    }
    pub fn cancel(&self, id: &str) -> Result<Session, Error> {
        let mut sessions = self.sessions.lock();
        let mut next = sessions.get(id).cloned().ok_or(Error::NotFound)?;
        if !next.terminal() {
            next.cancelled = true;
            self.gateway.revoke_session(id);
            self.persist(&next)?;
            sessions.insert(id.to_string(), next.clone());
        }
        Ok(next)
    }
    pub async fn upload(&self, id: &str, bytes: Vec<u8>) -> Result<Session, Error> {
        if bytes.len() > MAX_SOURCE {
            return Err(Error::Invalid("source archive exceeds 100 MiB".into()));
        }
        tokio::task::spawn_blocking(move || validate_archive(&bytes).map(|_| bytes))
            .await
            .map_err(|e| Error::Internal(e.to_string()))?
            .and_then(|bytes| {
                let mut sessions = self.sessions.lock();
                let s = sessions.get_mut(id).ok_or(Error::NotFound)?;
                if s.state != "awaiting_source" || s.cancelled {
                    return Err(Error::Invalid("session is not awaiting source".into()));
                }
                use std::io::Write;
                let mut options = fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let temp = self.dir(id).join("source.tar.part");
                let mut file = options
                    .open(&temp)
                    .map_err(|e| Error::Internal(e.to_string()))?;
                file.write_all(&bytes)
                    .and_then(|_| file.sync_all())
                    .and_then(|_| fs::rename(&temp, self.dir(id).join("source.tar")))
                    .map_err(|e| Error::Internal(e.to_string()))?;
                let mut next = s.clone();
                next.state = "starting".into();
                self.persist(&next)?;
                *s = next;
                Ok(s.clone())
            })
    }
    async fn command(
        &self,
        action: &str,
        dir: &Path,
        seconds: u64,
    ) -> Result<serde_json::Value, String> {
        let mut command = Command::new(&self.script);
        command.arg(action);
        if action != "check" {
            command.arg(dir);
        }
        command
            .kill_on_drop(true)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let child = command
            .spawn()
            .map_err(|_| format!("could not execute configured runtime {action}"))?;
        // Cancellation drops the live Child (kill_on_drop). The Linux runtime
        // gives external subprocesses parent-death signals and stop() quiesces
        // a recorded provisioner with a pidfd before removing VM/network state.
        // Never signal a reaped PID/PGID: it may identify an unrelated process.
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(seconds),
            child.wait_with_output(),
        )
        .await
        .map_err(|_| format!("runtime {action} timed out"))?
        .map_err(|_| format!("could not wait for runtime {action}"))?;
        if !output.stderr.is_empty() {
            use std::io::Write;
            let mut options = fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            if let Ok(mut log) = options.open(dir.join("runtime-controller.log")) {
                let _ = log.write_all(&output.stderr[..output.stderr.len().min(64 * 1024)]);
            }
        }
        if !output.status.success() {
            return Err(format!(
                "runtime {action} failed (exit {:?}); consult host runtime log",
                output.status.code()
            ));
        }
        if output.stdout.len() > MAX_REPORT as usize {
            return Err("runtime response exceeds bound".into());
        }
        if output.stdout.is_empty() {
            Ok(serde_json::json!({}))
        } else {
            serde_json::from_slice(&output.stdout)
                .map_err(|_| "runtime returned invalid JSON".into())
        }
    }
    async fn run(self: Arc<Self>, id: &str) {
        loop {
            let Ok(s) = self.get(id) else { return };
            if s.cancelled
                || s.deadline.is_some_and(|d| {
                    Utc::now()
                        >= d - Duration::seconds(
                            CLEANUP_RESERVE.min((s.request.duration_seconds / 4).into()),
                        )
                })
                || (s.state == "awaiting_source"
                    && Utc::now() >= s.created_at + Duration::minutes(10))
            {
                self.cleanup_loop(
                    id,
                    if s.cancelled {
                        if s.request.lifetime == "until_deleted" {
                            "deleted"
                        } else {
                            "cancelled"
                        }
                    } else {
                        "failed"
                    },
                    Some("cancelled or source staging deadline reached".into()),
                )
                .await;
                return;
            }
            if s.state == "starting" {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        let s = self.get(id).unwrap();
        let setup = (|| -> Result<(), String> {
            self.gateway.create_session(id, s.deadline)?;
            self.gateway
                .create_grant(id, &s.request.model_id, s.deadline)?;
            for preset in self.gateway.presets().into_iter().filter(|p| {
                p.id == "exa" || (p.id == "github" && self.gateway.github_token_configured(id))
            }) {
                self.gateway.create_grant(id, &preset.id, s.deadline)?;
            }
            self.write_gateway_config(id)
                .map_err(|_| "could not write scoped gateway configuration".to_string())
        })();
        if let Err(e) = setup {
            self.cleanup_loop(id, "failed", Some(e)).await;
            return;
        }
        let start_limit = s
            .deadline
            .map(|d| (d - Utc::now()).num_seconds().clamp(1, 600) as u64)
            .unwrap_or(600);
        let start_result = {
            let session_dir = self.dir(id);
            let start = self.command("start", &session_dir, start_limit);
            tokio::pin!(start);
            loop {
                tokio::select! {
                    result=&mut start=>break result,
                    _=tokio::time::sleep(std::time::Duration::from_secs(1))=>{
                        let session=self.get(id).unwrap();
                        if session.cancelled || session.deadline.is_some_and(|d| Utc::now()>=d-Duration::seconds(if session.request.kind=="audit"{CLEANUP_RESERVE}else{30})) {
                            break Err("provisioning cancelled or exceeded workload deadline".into());
                        }
                    }
                }
            }
        }; // Drops the live runtime Child before identity-verified cleanup starts.
        if let Err(e) = start_result {
            let cancelled = self.get(id).is_ok_and(|s| s.cancelled);
            self.cleanup_loop(id, if cancelled { "cancelled" } else { "failed" }, Some(e))
                .await;
            return;
        }

        if self.update(id, "running", None).is_err() {
            self.cleanup_loop(
                id,
                "failed",
                Some("could not durably record running state".into()),
            )
            .await;
            return;
        }
        self.monitor(id).await;
    }
    async fn monitor(self: Arc<Self>, id: &str) {
        let mut outcome = "completed";
        let mut failure = None;
        loop {
            let s = self.get(id).unwrap();
            if s.cancelled {
                outcome = if s.request.lifetime == "until_deleted" {
                    "deleted"
                } else {
                    "cancelled"
                };
                break;
            }
            let reserve = if s.request.kind == "audit" {
                CLEANUP_RESERVE
            } else {
                30
            };
            if s.deadline
                .is_some_and(|d| Utc::now() >= d - Duration::seconds(reserve))
            {
                outcome = if s.request.kind == "audit" {
                    "failed"
                } else {
                    "cancelled"
                };
                failure =
                    Some("session reached workload cutoff; retained report is partial".into());
                break;
            }
            let status = self.command("status", &self.dir(id), 20).await;
            if s.request.lifetime == "until_deleted" {
                // A stopped process or temporary transport failure must not erase user work.
                if status.as_ref().is_ok_and(|v| v["state"] == "running")
                    && self.gateway.guest_capability(id).is_some()
                {
                    if s.state != "running" {
                        let _ = self.update(id, "running", None);
                    }
                } else {
                    let _ = self.update(id, "unavailable", Some("Guest tools are unavailable; VM storage and capacity are retained until you delete it".into()));
                }
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                continue;
            }
            match status {
                Ok(v) => match v.get("state").and_then(|v| v.as_str()) {
                    Some("completed") => break,
                    Some("failed" | "stopped") => {
                        outcome = "failed";
                        failure = Some("guest workload exited unsuccessfully".into());
                        break;
                    }
                    Some("running") => {}
                    _ => {
                        outcome = "failed";
                        failure = Some("runtime returned an unknown workload state".into());
                        break;
                    }
                },
                Err(e) => {
                    outcome = "failed";
                    failure = Some(e);
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
        let _ = self.update(id, "collecting", None);
        if self.get(id).is_ok_and(|s| s.request.kind == "audit") {
            if let Err(e) = self.command("collect", &self.dir(id), 60).await {
                if outcome == "completed" {
                    outcome = "failed";
                }
                failure = Some(e);
            }
            if outcome != "completed" {
                if let Ok(bytes) = self.bounded_file(id, "report.json") {
                    if let Ok(mut report) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        if report.get("completion").and_then(|v| v.as_str()) == Some("complete") {
                            report["completion"] = serde_json::Value::String("partial".into());
                            let _ = write_json(&self.dir(id).join("report.json"), &report);
                        }
                    }
                }
            }
        }
        self.cleanup_loop(id, outcome, failure).await;
    }
    async fn cleanup_loop(&self, id: &str, outcome: &str, error: Option<String>) {
        // Revocation also terminates active streaming responses before disk deletion.
        self.gateway.revoke_session(id);
        let _ = self.update(id, "cleaning", error);
        loop {
            let operation = self.operator_operation.lock().await;
            let stop = self.command("stop", &self.dir(id), 120).await;
            drop(operation);
            match stop {
                Ok(_) => {
                    if self.get(id).is_ok_and(|s| s.request.kind == "interactive") {
                        if let Err(e) = self.purge_interactive(id) {
                            let _ = self.update(
                                id,
                                "cleanup_failed",
                                Some(format!("VM stopped but storage removal failed: {e}")),
                            );
                            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                            continue;
                        }
                    }
                    if self.update(id, outcome, None).is_ok() {
                        self.prune_history();
                        return;
                    }
                    let _=self.update(id,"cleanup_failed",Some("containment succeeded but terminal state could not be durably recorded".into()));
                }
                Err(e) => {
                    let _ = self.update(id, "cleanup_failed", Some(e));
                }
            }
            // Never release admission while a VM or network policy may remain.
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    }
    fn purge_interactive(&self, id: &str) -> std::io::Result<()> {
        // Keep only a small, bounded deletion receipt. Never unlink a live disk.
        for entry in fs::read_dir(self.dir(id))? {
            let entry = entry?;
            if entry.file_name() == "session.json" {
                continue;
            }
            let kind = entry.file_type()?;
            if kind.is_dir() {
                fs::remove_dir_all(entry.path())?;
            } else {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }
    fn prune_history(&self) {
        let mut sessions = self.sessions.lock();
        let mut terminal: Vec<_> = sessions
            .values()
            .filter(|s| s.terminal())
            .map(|s| (s.finished_at, s.id.clone()))
            .collect();
        terminal.sort();
        let excess = terminal.len().saturating_sub(200);
        for (_, id) in terminal.into_iter().take(excess) {
            if fs::remove_dir_all(self.dir(&id)).is_ok() {
                sessions.remove(&id);
            }
        }
    }
    pub fn bounded_file(&self, id: &str, name: &str) -> Result<Vec<u8>, Error> {
        use std::io::Read;
        self.get(id)?;
        if !["report.json", "events.jsonl"].contains(&name) {
            return Err(Error::Invalid("unknown artifact".into()));
        }
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let file = options
            .open(self.dir(id).join(name))
            .map_err(|_| Error::NotFound)?;
        let metadata = file
            .metadata()
            .map_err(|e| Error::Internal(e.to_string()))?;
        if !metadata.is_file() || metadata.len() > MAX_REPORT {
            return Err(Error::Invalid(
                "artifact is not a bounded regular file".into(),
            ));
        }
        let mut bytes = Vec::new();
        file.take(MAX_REPORT + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| Error::Internal(e.to_string()))?;
        if bytes.len() > MAX_REPORT as usize {
            return Err(Error::Invalid("artifact grew beyond its limit".into()));
        }
        if name == "events.jsonl" {
            let mut text = String::from_utf8_lossy(&bytes).into_owned();
            if let Some(token) = self.gateway.guest_capability(id) {
                text = text.replace(&token, "[redacted session capability]");
            }
            let bearer = regex::Regex::new(r"(?i)bearer[ \t]+[A-Za-z0-9._~+/=-]+").unwrap();
            text = bearer.replace_all(&text, "Bearer [redacted]").into_owned();
            let keys = regex::Regex::new(
                r#"(?i)(api[_-]?key|token|password|secret)(["' ]*[:=]["' ]*)[^\s"',}]+"#,
            )
            .unwrap();
            text = keys.replace_all(&text, "$1$2[redacted]").into_owned();
            bytes = text.into_bytes();
        }
        Ok(bytes)
    }
    pub fn persist_grants(&self, id: &str) -> Result<(), Error> {
        let _serial = self.grant_persistence.lock();
        self.get(id)?;
        let token = self
            .gateway
            .guest_capability(id)
            .ok_or_else(|| Error::Invalid("session capability revoked".into()))?;
        write_json(
            &self.dir(id).join("gateway-state.json"),
            &serde_json::json!({"token":token,"grants":self.gateway.list_grants(id)}),
        )
        .map_err(|e| Error::Internal(e.to_string()))
    }
    fn write_gateway_config(&self, id: &str) -> Result<(), Error> {
        self.persist_grants(id)?;
        let session = self.get(id)?;
        let token = self
            .gateway
            .guest_capability(id)
            .ok_or_else(|| Error::Invalid("session capability revoked".into()))?;
        let grants = self.gateway.list_grants(id);
        let model = grants
            .iter()
            .find(|g| g.kind == "model" && g.preset_id == session.request.model_id)
            .ok_or_else(|| Error::Invalid("model grant revoked; create a fresh session".into()))?;
        let base: std::net::Ipv4Addr = std::env::var("DISPOSABLE_GATEWAY_IP")
            .unwrap_or_else(|_| "192.0.2.1".into())
            .parse()
            .map_err(|_| Error::Invalid("invalid gateway address".into()))?;
        let ip = std::net::Ipv4Addr::from(
            u32::from(base)
                .checked_add(4 * u32::from(session.network_slot))
                .ok_or_else(|| Error::Invalid("gateway address overflow".into()))?,
        );
        let port = std::env::var("DISPOSABLE_GATEWAY_PORT").unwrap_or_else(|_| "8123".into());
        let url = format!("http://{ip}:{port}");
        let mcp:Vec<_>=grants.iter().filter(|g|g.kind=="mcp").map(|g|serde_json::json!({"id":g.id,"preset_id":g.preset_id,"url":format!("{url}{}{}",g.gateway_path,g.base_path)})).collect();
        write_json(&self.dir(id).join("gateway.json"),&serde_json::json!({"session_id":id,"grants":grants,"url":url,"token":token,"model_id":self.gateway.presets().into_iter().find(|p|p.id==session.request.model_id).and_then(|p|p.model_name).ok_or_else(||Error::Invalid("model preset lacks configured model name".into()))?,"model_path":format!("{}{}",model.gateway_path,model.base_path),"mcp":mcp})).map_err(|e|Error::Internal(e.to_string()))
    }
    pub async fn refresh_grants(&self, id: &str) -> Result<(), Error> {
        let _operation = self
            .operator_operation
            .try_lock()
            .map_err(|_| Error::Busy)?;
        if self.get(id)?.state != "running" {
            return Err(Error::Invalid("session is no longer running".into()));
        }
        self.write_gateway_config(id)?;
        self.command("grants", &self.dir(id), 20)
            .await
            .map_err(Error::Unavailable)?;
        Ok(())
    }
    pub async fn refresh_output(&self, id: &str) -> Result<(), Error> {
        let _operation = self
            .operator_operation
            .try_lock()
            .map_err(|_| Error::Busy)?;
        let s = self.get(id)?;
        if !s.terminal() && s.state == "running" {
            self.command("logs", &self.dir(id), 15)
                .await
                .map_err(Error::Unavailable)?;
        }
        Ok(())
    }
    pub async fn message(&self, id: &str, prompt: String) -> Result<(), Error> {
        let _operation = self
            .operator_operation
            .try_lock()
            .map_err(|_| Error::Busy)?;
        let s = self.get(id)?;
        if s.request.kind != "interactive" || s.state != "running" || s.cancelled {
            return Err(Error::Invalid("interactive session must be running".into()));
        }
        if prompt.is_empty() || prompt.len() > 65520 {
            return Err(Error::Invalid("prompt must be 1..65520 bytes".into()));
        }
        use crate::disposable_console::Control;
        let console = self.gateway.console();
        let client_id = format!("message-{}", uuid::Uuid::new_v4());
        console
            .control(
                id,
                Control::Attach {
                    client_id: client_id.clone(),
                },
            )
            .map_err(|_| Error::Busy)?;
        // Paste into the real guest TUI, then submit. Do not retain prompt files on the host.
        let text = format!("\x1b[200~{prompt}\x1b[201~\r");
        let result = (|| {
            for chunk in text.as_bytes().chunks(16 * 1024) {
                console
                    .control(
                        id,
                        Control::Input {
                            client_id: client_id.clone(),
                            hex: hex::encode(chunk),
                        },
                    )
                    .map_err(|_| {
                        Error::Unavailable("terminal input queue did not accept the prompt".into())
                    })?;
            }
            Ok(())
        })();
        let _ = console.control(id, Control::Detach { client_id });
        result
    }
}
fn write_json(path: &Path, value: &impl Serialize) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec(value)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(tmp, path)?;
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}
fn validate_archive(bytes: &[u8]) -> Result<(), Error> {
    let mut total = 0u64;
    let mut archive = tar::Archive::new(bytes);
    for entry in archive
        .entries()
        .map_err(|_| Error::Invalid("invalid tar archive".into()))?
    {
        let entry = entry.map_err(|_| Error::Invalid("invalid tar entry".into()))?;
        let path = entry
            .path()
            .map_err(|_| Error::Invalid("invalid archive path".into()))?;
        if path
            .components()
            .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
            || path.components().any(|c| c.as_os_str() == ".git")
        {
            return Err(Error::Invalid(
                "source must be relative and contain no .git credentials or hooks".into(),
            ));
        }
        let kind = entry.header().entry_type();
        if !kind.is_file() && !kind.is_dir() {
            return Err(Error::Invalid(
                "source links and special files are forbidden".into(),
            ));
        }
        total = total
            .checked_add(entry.size())
            .ok_or_else(|| Error::Invalid("archive size overflow".into()))?;
        if total > MAX_SOURCE as u64 {
            return Err(Error::Invalid("expanded source exceeds 100 MiB".into()));
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> CreateRequest {
        serde_json::from_value(serde_json::json!({"kind":"audit","repository":"owner/repo","commit":"a".repeat(40),"run_id":"123","ref_name":"refs/heads/main"})).unwrap()
    }
    #[test]
    fn detroit_cutoff_and_dst() {
        for (now, expected) in [
            ("2026-01-06T08:00:00Z", "2026-01-06T11:00:00Z"),
            ("2026-07-06T07:00:00Z", "2026-07-06T10:00:00Z"),
        ] {
            assert_eq!(
                request().validated_deadline(now.parse().unwrap()).unwrap(),
                expected.parse::<DateTime<Utc>>().unwrap()
            );
        }
    }
    #[test]
    fn late_and_outside_window_rejected() {
        for now in [
            "2026-07-06T09:55:00Z",
            "2026-07-06T11:00:00Z",
            "2026-07-06T04:00:00Z",
        ] {
            assert!(request().validated_deadline(now.parse().unwrap()).is_err());
        }
    }
    #[test]
    fn archive_rejects_git_credentials() {
        let mut bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            let mut header = tar::Header::new_gnu();
            header.set_size(1);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, ".git/config", &b"x"[..])
                .unwrap();
            builder.finish().unwrap();
        }
        assert!(validate_archive(&bytes).is_err());
    }
    #[test]
    fn cleanup_failure_retains_admission() {
        let mut r = request();
        r.kind = "interactive".into();
        let mut s = Session {
            id: "id".into(),
            state: "cleanup_failed".into(),
            request: r,
            created_at: Utc::now(),
            deadline: Some(Utc::now()),
            network_slot: 0,
            finished_at: None,
            error: None,
            cancelled: false,
        };
        assert!(!s.terminal());
        s.state = "cancelled".into();
        assert!(s.terminal());
    }
    fn gateway() -> GatewayStore {
        let preset=serde_json::from_value(serde_json::json!({"id":"studio","kind":"model","model_name":"fixture/model","base_url":"https://example.com/v1","path_prefixes":["/v1"],"methods":["POST"],"allow_private":false})).unwrap();
        GatewayStore::new(vec![preset]).unwrap()
    }
    fn fixture_script(root: &Path, fail_stop: bool, slow_start: bool) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let script = root.join("fixture-runtime.sh");
        let stop = if fail_stop {
            "exit 1"
        } else {
            "touch \"$2/stopped\""
        };
        let start = if slow_start {
            "touch \"$2/provisioning\"; exec sleep 30"
        } else {
            ":"
        };
        fs::write(&script,format!("#!/bin/sh\ncase \"$1\" in\ncheck) echo '{{}}';;\nstart) {start};;\nstatus) echo '{{\"state\":\"running\"}}';;\nstop) {stop};;\n*) :;;\nesac\n")).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        script
    }
    fn interactive(repository: bool) -> CreateRequest {
        let mut r = request();
        r.kind = "interactive".into();
        r.run_id = None;
        r.duration_seconds = 3600;
        if !repository {
            r.repository = None;
            r.commit = None;
        }
        r
    }
    async fn wait_state(c: &DisposableController, id: &str, expected: &str) {
        for _ in 0..300 {
            if c.get(id).unwrap().state == expected {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("expected {expected}, got {:?}", c.get(id).unwrap());
    }
    #[tokio::test]
    async fn simultaneous_admissions_only_one_reserves() {
        let temp = tempfile::tempdir().unwrap();
        let script = fixture_script(temp.path(), false, false);
        let c = DisposableController::open(temp.path().join("state"), script, gateway())
            .await
            .unwrap();
        let (a, b) = tokio::join!(c.create(interactive(true)), c.create(interactive(true)));
        assert_eq!(
            [a.is_ok(), b.is_ok()].into_iter().filter(|ok| *ok).count(),
            1
        );
        assert!(matches!(a, Err(Error::Busy)) || matches!(b, Err(Error::Busy)));
        let session = a.or(b).unwrap();
        c.cancel(&session.id).unwrap();
        wait_state(&c, &session.id, "cancelled").await;
        assert_eq!(fs::read_dir(c.dir(&session.id)).unwrap().count(), 1);
    }
    #[tokio::test]
    async fn failed_cleanup_blocks_next_session() {
        let temp = tempfile::tempdir().unwrap();
        let script = fixture_script(temp.path(), true, false);
        let c = DisposableController::open(temp.path().join("state"), script, gateway())
            .await
            .unwrap();
        let s = c.create(interactive(true)).await.unwrap();
        c.cancel(&s.id).unwrap();
        wait_state(&c, &s.id, "cleanup_failed").await;
        assert!(matches!(
            c.create(interactive(true)).await,
            Err(Error::Busy)
        ));
    }
    #[tokio::test]
    async fn restart_recovers_partial_provisioning_directory() {
        let temp = tempfile::tempdir().unwrap();
        let script = fixture_script(temp.path(), false, false);
        let root = temp.path().join("state");
        let id = uuid::Uuid::new_v4().to_string();
        fs::create_dir_all(root.join(&id)).unwrap();
        write_json(&root.join(&id).join("request.json"), &interactive(false)).unwrap();
        let c = DisposableController::open(root, script, gateway())
            .await
            .unwrap();
        wait_state(&c, &id, "failed").await;
        assert_eq!(fs::read_dir(c.dir(&id)).unwrap().count(), 1);
    }
    #[tokio::test]
    async fn cancel_interrupts_provisioning_before_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        let script = fixture_script(temp.path(), false, true);
        let c = DisposableController::open(temp.path().join("state"), script, gateway())
            .await
            .unwrap();
        let s = c.create(interactive(false)).await.unwrap();
        for _ in 0..50 {
            if c.dir(&s.id).join("provisioning").exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(c.dir(&s.id).join("provisioning").exists());
        c.cancel(&s.id).unwrap();
        wait_state(&c, &s.id, "cancelled").await;
        assert_eq!(fs::read_dir(c.dir(&s.id)).unwrap().count(), 1);
    }
    #[tokio::test]
    async fn durable_terminal_write_failure_keeps_old_state() {
        let temp = tempfile::tempdir().unwrap();
        let script = fixture_script(temp.path(), false, false);
        let c = DisposableController::open(temp.path().join("state"), script, gateway())
            .await
            .unwrap();
        let s = c.create(interactive(true)).await.unwrap();
        fs::create_dir(c.dir(&s.id).join("session.json.tmp")).unwrap();
        assert!(c.update(&s.id, "completed", None).is_err());
        assert_eq!(c.get(&s.id).unwrap().state, "awaiting_source");
    }
    #[tokio::test]
    async fn restart_reads_full_persisted_session_and_cleans_it() {
        let temp = tempfile::tempdir().unwrap();
        let script = fixture_script(temp.path(), false, false);
        let root = temp.path().join("state");
        let id = uuid::Uuid::new_v4().to_string();
        fs::create_dir_all(root.join(&id)).unwrap();
        let mut request = interactive(true);
        request.audit_profile.test_commands = vec![vec!["cargo".into(), "test".into()]];
        let session = Session {
            id: id.clone(),
            state: "running".into(),
            request,
            created_at: Utc::now(),
            deadline: Some(Utc::now() + Duration::seconds(300)),
            network_slot: 0,
            finished_at: None,
            error: None,
            cancelled: false,
        };
        write_json(&root.join(&id).join("session.json"), &session).unwrap();
        let controller = DisposableController::open(root, script, gateway())
            .await
            .unwrap();
        wait_state(&controller, &id, "failed").await;
        assert_eq!(
            controller
                .get(&id)
                .unwrap()
                .request
                .audit_profile
                .test_commands,
            vec![vec!["cargo".to_string(), "test".to_string()]]
        );
        assert_eq!(fs::read_dir(controller.dir(&id)).unwrap().count(), 1);
    }
    fn medium() -> CreateRequest {
        let mut request = interactive(false);
        request.memory_mb = 12288;
        request.vcpus = 4;
        request.lifetime = "until_deleted".into();
        request.deadline = None;
        request.name = Some("Long task".into());
        request
    }
    #[test]
    fn persistent_lifetime_only_for_interactive_and_exact_presets() {
        assert_eq!(
            medium().validated_deadline_for(Utc::now(), false).unwrap(),
            None
        );
        let mut r = request();
        r.lifetime = "until_deleted".into();
        assert!(r.validated_deadline_for(Utc::now(), true).is_err());
        let mut r = medium();
        r.vcpus = 3;
        assert!(r.validated_deadline_for(Utc::now(), false).is_err());
    }
    #[tokio::test]
    async fn two_medium_vms_fit_and_delete_purges_work_and_restores_capacity() {
        let temp = tempfile::tempdir().unwrap();
        let script = fixture_script(temp.path(), false, false);
        let c = DisposableController::open(temp.path().join("state"), script, gateway())
            .await
            .unwrap();
        let (a, b) = tokio::join!(c.create(medium()), c.create(medium()));
        let a = a.unwrap();
        let b = b.unwrap();
        assert_ne!(a.network_slot, b.network_slot);
        assert_eq!(c.resource_usage().vcpus_used, 8);
        assert!(!c.can_admit(16384, 6));
        assert!(matches!(c.create(medium()).await, Err(Error::Busy)));
        wait_state(&c, &a.id, "running").await;
        wait_state(&c, &b.id, "running").await;
        assert!(c.get(&a.id).unwrap().deadline.is_none());
        fs::create_dir_all(c.dir(&a.id).join("vm")).unwrap();
        fs::write(c.dir(&a.id).join("vm/disk.qcow2"), b"temporary work").unwrap();
        fs::write(c.dir(&a.id).join("events.jsonl"), b"private transcript").unwrap();
        c.cancel(&a.id).unwrap();
        wait_state(&c, &a.id, "deleted").await;
        assert_eq!(fs::read_dir(c.dir(&a.id)).unwrap().count(), 1);
        assert!(c.can_admit(12288, 4));
        assert!(!c.can_admit(16384, 6));
        c.cancel(&b.id).unwrap();
        wait_state(&c, &b.id, "deleted").await;
        assert!(c.can_admit(16384, 6));
    }
    #[tokio::test]
    async fn confirmed_persistent_vm_restores_gateway_after_management_restart() {
        let temp = tempfile::tempdir().unwrap();
        let script = fixture_script(temp.path(), false, false);
        let root = temp.path().join("state");
        let id = uuid::Uuid::new_v4().to_string();
        fs::create_dir_all(root.join(&id)).unwrap();
        let old_gateway = gateway();
        old_gateway.create_session(&id, None).unwrap();
        old_gateway.create_grant(&id, "studio", None).unwrap();
        let token = old_gateway.guest_capability(&id).unwrap();
        write_json(
            &root.join(&id).join("gateway-state.json"),
            &serde_json::json!({"token":token,"grants":old_gateway.list_grants(&id)}),
        )
        .unwrap();
        let session = Session {
            id: id.clone(),
            state: "running".into(),
            request: medium(),
            created_at: Utc::now(),
            deadline: None,
            network_slot: 0,
            finished_at: None,
            error: None,
            cancelled: false,
        };
        write_json(&root.join(&id).join("session.json"), &session).unwrap();
        let c = DisposableController::open(root, script, gateway())
            .await
            .unwrap();
        for _ in 0..100 {
            if c.gateway.guest_capability(&id).is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(c.gateway.guest_capability(&id).unwrap(), token);
        assert_eq!(c.get(&id).unwrap().state, "running");
        c.cancel(&id).unwrap();
        wait_state(&c, &id, "deleted").await;
    }
    #[tokio::test]
    async fn persistent_guest_failure_keeps_disk_until_explicit_delete() {
        let temp = tempfile::tempdir().unwrap();
        let script = fixture_script(temp.path(), false, false);
        let c = DisposableController::open(temp.path().join("state"), script.clone(), gateway())
            .await
            .unwrap();
        let session = c.create(medium()).await.unwrap();
        wait_state(&c, &session.id, "running").await;
        fs::create_dir_all(c.dir(&session.id).join("vm")).unwrap();
        let disk = c.dir(&session.id).join("vm/disk.qcow2");
        fs::write(&disk, b"user work").unwrap();
        fs::write(&script,"#!/bin/sh\ncase \"$1\" in\nstatus) echo '{\"state\":\"failed\"}';;\n*) echo '{}';;\nesac\n").unwrap();
        wait_state(&c, &session.id, "unavailable").await;
        assert!(disk.exists());
        assert_eq!(c.resource_usage().vcpus_used, 4);
        c.cancel(&session.id).unwrap();
        wait_state(&c, &session.id, "deleted").await;
        assert!(!disk.exists());
    }
    #[tokio::test]
    async fn four_small_vms_fit_on_unique_networks_and_one_small_leaves_audit_capacity() {
        let temp = tempfile::tempdir().unwrap();
        let script = fixture_script(temp.path(), false, false);
        let c = DisposableController::open(temp.path().join("state"), script, gateway())
            .await
            .unwrap();
        let mut request = medium();
        request.memory_mb = 8192;
        request.vcpus = 2;
        let mut sessions = Vec::new();
        for index in 0..4 {
            let session = c.create(request.clone()).await.unwrap();
            if index == 0 {
                assert!(c.can_admit(16384, 6));
            }
            assert!(!sessions
                .iter()
                .any(|old: &Session| old.network_slot == session.network_slot));
            sessions.push(session);
        }
        assert_eq!(c.resource_usage().memory_mb_used, 32768);
        assert_eq!(c.resource_usage().vcpus_used, 8);
        assert!(matches!(c.create(request).await, Err(Error::Busy)));
        for session in sessions {
            c.cancel(&session.id).unwrap();
            wait_state(&c, &session.id, "deleted").await;
        }
        assert_eq!(c.resource_usage().vcpus_used, 0);
    }
}

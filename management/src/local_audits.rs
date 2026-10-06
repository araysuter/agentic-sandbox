//! Host-owned weekly audits. Secrets and GitHub writes stay outside the guest.
use crate::disposable::{
    AuditProfile, CreateRequest, DisposableController, Error as VmError, MAX_SOURCE,
};
use chrono::{DateTime, Datelike, Duration, NaiveTime, TimeZone, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{io::AsyncReadExt, process::Command};

fn timezone() -> String {
    "America/Detroit".into()
}
fn start_time() -> String {
    "01:00".into()
}
fn end_time() -> String {
    "06:00".into()
}
fn model() -> String {
    "studio".into()
}
fn enabled() -> bool {
    true
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeeklySchedule {
    /// Monday=0 through Sunday=6.
    pub weekday: u32,
    #[serde(default = "start_time")]
    pub start_time: String,
    #[serde(default = "end_time")]
    pub end_time: String,
    #[serde(default = "timezone")]
    pub timezone: String,
}
impl Default for WeeklySchedule {
    fn default() -> Self {
        Self {
            weekday: 0,
            start_time: start_time(),
            end_time: end_time(),
            timezone: timezone(),
        }
    }
}
impl WeeklySchedule {
    fn parsed(&self) -> Result<(chrono_tz::Tz, NaiveTime, NaiveTime), Error> {
        let tz = self
            .timezone
            .parse()
            .map_err(|_| Error::Invalid("select a valid IANA timezone".into()))?;
        let start = NaiveTime::parse_from_str(&self.start_time, "%H:%M")
            .map_err(|_| Error::Invalid("start_time must be HH:MM".into()))?;
        let end = NaiveTime::parse_from_str(&self.end_time, "%H:%M")
            .map_err(|_| Error::Invalid("end_time must be HH:MM".into()))?;
        let span = end.signed_duration_since(start).num_seconds();
        if self.weekday > 6 || !(600..=18000).contains(&span) {
            return Err(Error::Invalid(
                "weekly window must be on one day, between 10 minutes and 5 hours".into(),
            ));
        }
        Ok((tz, start, end))
    }
    fn occurrence(&self, date: chrono::NaiveDate) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
        let (tz, start, end) = self.parsed().ok()?;
        if date.weekday().num_days_from_monday() != self.weekday {
            return None;
        }
        // A repeated wall-clock hour is one occurrence, using its first instant.
        // A nonexistent spring-forward start/end is skipped, never moved later.
        let a = tz
            .from_local_datetime(&date.and_time(start))
            .earliest()?
            .with_timezone(&Utc);
        let b = tz
            .from_local_datetime(&date.and_time(end))
            .earliest()?
            .with_timezone(&Utc);
        let b = b.min(a + Duration::hours(5));
        if b - a < Duration::seconds(360) {
            return None;
        }
        Some((a, b))
    }
    pub fn next(&self, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        let (tz, _, _) = self.parsed().ok()?;
        let date = now.with_timezone(&tz).date_naive();
        (0..=14)
            .filter_map(|day| self.occurrence(date + Duration::days(day)))
            .find(|(a, _)| *a > now)
            .map(|(a, _)| a)
    }
    fn due(&self, now: DateTime<Utc>) -> Option<(String, DateTime<Utc>)> {
        let (tz, _, _) = self.parsed().ok()?;
        let date = now.with_timezone(&tz).date_naive();
        let (start, end) = self.occurrence(date)?;
        // No backfill: at most one scheduler interval plus bounded jitter.
        if now < start || now - start > Duration::seconds(60) || end <= now + Duration::seconds(360)
        {
            return None;
        }
        Some((start.to_rfc3339(), end))
    }
    fn duration_seconds(&self) -> u32 {
        self.parsed()
            .map(|(_, a, b)| b.signed_duration_since(a).num_seconds() as u32)
            .unwrap_or(18000)
    }
}
// Do not derive Debug: request bodies may contain credentials.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryInput {
    pub repository: String,
    #[serde(default)]
    pub ref_name: String,
    #[serde(default = "model")]
    pub model_id: String,
    #[serde(default = "enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub schedule: WeeklySchedule,
    #[serde(default)]
    pub publish_issues: bool,
    #[serde(default)]
    pub audit_profile: AuditProfile,
    #[serde(default)]
    pub github_token: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Repository {
    id: String,
    repository: String,
    ref_name: String,
    model_id: String,
    enabled: bool,
    schedule: WeeklySchedule,
    publish_issues: bool,
    audit_profile: AuditProfile,
    credential: String,
    last_slot: Option<String>,
    created_at: DateTime<Utc>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditRun {
    pub id: String,
    pub repository_id: String,
    pub repository: String,
    pub state: String,
    pub created_at: DateTime<Utc>,
    pub deadline: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub session_id: Option<String>,
    pub error: Option<String>,
    pub result: Option<serde_json::Value>,
    #[serde(default)]
    pub cancelled: bool,
}
impl AuditRun {
    fn active(&self) -> bool {
        !["completed", "failed", "cancelled", "interrupted", "busy"].contains(&self.state.as_str())
    }
}
#[derive(Clone, Default, Serialize, Deserialize)]
struct Database {
    repositories: BTreeMap<String, Repository>,
    runs: BTreeMap<String, AuditRun>,
}
#[derive(Debug)]
pub enum Error {
    Invalid(String),
    NotFound,
    Busy,
    Unavailable,
    Storage,
}
pub struct LocalAuditService {
    root: PathBuf,
    worker: PathBuf,
    controller: Arc<DisposableController>,
    data: Mutex<Database>,
    _lock: fs::File,
}
impl LocalAuditService {
    pub async fn from_env(
        controller: Option<Arc<DisposableController>>,
    ) -> anyhow::Result<Option<Arc<Self>>> {
        if std::env::var("LOCAL_AUDITS_ENABLED").as_deref() != Ok("1") {
            return Ok(None);
        }
        let controller = controller
            .ok_or_else(|| anyhow::anyhow!("local audits require enabled disposable runtime"))?;
        let root = PathBuf::from(
            std::env::var("LOCAL_AUDITS_STATE_ROOT")
                .unwrap_or_else(|_| "/var/lib/agentic-sandbox/local-audits".into()),
        );
        let worker = PathBuf::from(
            std::env::var("LOCAL_AUDITS_WORKER")
                .map_err(|_| anyhow::anyhow!("LOCAL_AUDITS_WORKER must be configured"))?,
        );
        let service = Self::open(root, worker, controller)?;
        let weak = Arc::downgrade(&service);
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(std::time::Duration::from_secs(20));
            loop {
                timer.tick().await;
                let Some(s) = weak.upgrade() else { break };
                s.tick(Utc::now());
            }
        });
        Ok(Some(service))
    }
    pub fn open(
        root: PathBuf,
        worker: PathBuf,
        controller: Arc<DisposableController>,
    ) -> anyhow::Result<Arc<Self>> {
        anyhow::ensure!(
            root.is_absolute() && worker.is_absolute(),
            "local audit paths must be absolute"
        );
        private_dir(&root)?;
        private_dir(&root.join("credentials"))?;
        private_dir(&root.join("runs"))?;
        let lock = private_file(&root.join("service.lock"), false)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            anyhow::ensure!(
                unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
                "another local audit scheduler owns this state root"
            );
        }
        let path = root.join("settings.json");
        let mut data: Database = match fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Database::default(),
            Err(e) => return Err(e.into()),
        };
        for repo in data.repositories.values() {
            uuid::Uuid::parse_str(&repo.id)?;
            uuid::Uuid::parse_str(&repo.credential)?;
            repo.schedule
                .parsed()
                .map_err(|_| anyhow::anyhow!("invalid stored weekly schedule"))?;
        }
        for run in data.runs.values_mut() {
            uuid::Uuid::parse_str(&run.id)?;
            if run.active() {
                if let Some(id) = &run.session_id {
                    let _ = controller.cancel(id);
                }
                // Also catch the create->persist gap. Controller independently destroys all restart sessions.
                for session in controller
                    .list()
                    .into_iter()
                    .filter(|s| s.request.run_id.as_deref() == Some(&run.id))
                {
                    let _ = controller.cancel(&session.id);
                }
                run.state = "interrupted".into();
                run.finished_at = Some(Utc::now());
                run.error=Some("management restarted; previous audit is cancelled and is not replayed; review any partial publication".into());
            }
        }
        save(&path, &data)?;
        // A crash between key rotation and metadata commit may leave an unreferenced key.
        for entry in fs::read_dir(root.join("credentials"))? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(id) = name.strip_suffix(".key") {
                if uuid::Uuid::parse_str(id).is_ok()
                    && !data.repositories.values().any(|r| r.credential == id)
                {
                    fs::remove_file(entry.path())?;
                }
            }
        }
        Ok(Arc::new(Self {
            root,
            worker,
            controller,
            data: Mutex::new(data),
            _lock: lock,
        }))
    }
    fn persist(&self, data: &Database) -> Result<(), Error> {
        save(&self.root.join("settings.json"), data).map_err(|_| Error::Storage)
    }
    pub fn snapshot(&self) -> serde_json::Value {
        let data = self.data.lock();
        let now = Utc::now();
        let repositories:Vec<_>=data.repositories.values().map(|r| {
            let latest=data.runs.values().filter(|run|run.repository_id==r.id).max_by_key(|run|run.created_at);
            serde_json::json!({"id":r.id,"repository":r.repository,"ref_name":r.ref_name,"model_id":r.model_id,"enabled":r.enabled,"schedule":r.schedule,"publish_issues":r.publish_issues,"audit_profile":r.audit_profile,"credential_configured":self.token_path(r).is_file(),"next_run_at":if r.enabled {r.schedule.next(now)} else {None},"latest_run":latest,"created_at":r.created_at})
        }).collect();
        let mut runs: Vec<_> = data.runs.values().cloned().collect();
        runs.sort_by_key(|r| std::cmp::Reverse(r.created_at));
        serde_json::json!({"enabled":true,"repositories":repositories,"runs":runs,"busy":runs.iter().any(AuditRun::active)||!self.controller.can_admit(16384, 6)})
    }
    fn token_path(&self, r: &Repository) -> PathBuf {
        self.root
            .join("credentials")
            .join(format!("{}.key", r.credential))
    }
    pub fn upsert(
        &self,
        id: Option<&str>,
        mut input: RepositoryInput,
    ) -> Result<serde_json::Value, Error> {
        validate_input(&input)?;
        if !self
            .controller
            .gateway
            .presets()
            .iter()
            .any(|p| p.id == input.model_id && p.kind == "model")
        {
            return Err(Error::Invalid("select a configured model preset".into()));
        }
        let mut guard = self.data.lock();
        let mut next = guard.clone();
        let previous = id
            .map(|id| next.repositories.get(id).cloned().ok_or(Error::NotFound))
            .transpose()?;
        if previous.as_ref().is_some_and(|r| {
            next.runs
                .values()
                .any(|run| run.repository_id == r.id && run.active())
        }) {
            return Err(Error::Busy);
        }
        if next.repositories.values().any(|r| {
            r.repository.eq_ignore_ascii_case(&input.repository) && Some(r.id.as_str()) != id
        }) {
            return Err(Error::Invalid("repository is already configured".into()));
        }
        let token = input.github_token.take().filter(|s| !s.is_empty());
        if token.is_none() && previous.is_none() {
            return Err(Error::Invalid(
                "a repository-scoped GitHub token is required".into(),
            ));
        }
        let credential = if let Some(token) = token {
            if token.len() < 16
                || token.len() > 4096
                || token
                    .bytes()
                    .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
            {
                return Err(Error::Invalid(
                    "GitHub token must be a bounded value without whitespace".into(),
                ));
            }
            let credential = uuid::Uuid::new_v4().to_string();
            let path = self
                .root
                .join("credentials")
                .join(format!("{credential}.key"));
            atomic_bytes(&path, token.as_bytes()).map_err(|_| Error::Storage)?;
            credential
        } else {
            previous.as_ref().unwrap().credential.clone()
        };
        let id = previous
            .as_ref()
            .map(|r| r.id.clone())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let record = Repository {
            id: id.clone(),
            repository: input.repository,
            ref_name: input.ref_name,
            model_id: input.model_id,
            enabled: input.enabled,
            schedule: input.schedule,
            publish_issues: input.publish_issues,
            audit_profile: input.audit_profile,
            credential: credential.clone(),
            last_slot: previous.as_ref().and_then(|r| r.last_slot.clone()),
            created_at: previous
                .as_ref()
                .map(|r| r.created_at)
                .unwrap_or_else(Utc::now),
        };
        next.repositories.insert(id.clone(), record);
        if let Err(e) = self.persist(&next) {
            if previous.as_ref().map(|r| &r.credential) != Some(&credential) {
                let _ = fs::remove_file(
                    self.root
                        .join("credentials")
                        .join(format!("{credential}.key")),
                );
            }
            return Err(e);
        }
        *guard = next;
        drop(guard);
        if let Some(old) = previous {
            if old.credential != credential {
                let _ = fs::remove_file(self.token_path(&old));
            }
        }
        Ok(self.snapshot()["repositories"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .cloned()
            .unwrap())
    }
    pub fn delete(&self, id: &str) -> Result<(), Error> {
        let mut guard = self.data.lock();
        if guard
            .runs
            .values()
            .any(|r| r.repository_id == id && r.active())
        {
            return Err(Error::Busy);
        }
        let mut next = guard.clone();
        let repo = next.repositories.remove(id).ok_or(Error::NotFound)?;
        // Remove the secret first. A failed unlink retains its configuration so
        // the operator can retry; a failed settings write leaves a visibly missing credential.
        match fs::remove_file(self.token_path(&repo)) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(Error::Storage),
        }
        self.persist(&next)?;
        *guard = next;
        Ok(())
    }
    pub fn run_now(self: &Arc<Self>, id: &str) -> Result<AuditRun, Error> {
        let duration = self
            .data
            .lock()
            .repositories
            .get(id)
            .ok_or(Error::NotFound)?
            .schedule
            .duration_seconds();
        self.admit(id, Utc::now() + Duration::seconds(duration.into()), None)
    }
    fn admit(
        self: &Arc<Self>,
        id: &str,
        deadline: DateTime<Utc>,
        slot: Option<String>,
    ) -> Result<AuditRun, Error> {
        let mut guard = self.data.lock();
        let mut next = guard.clone();
        let repo = next.repositories.get_mut(id).ok_or(Error::NotFound)?;
        if slot
            .as_ref()
            .is_some_and(|s| repo.last_slot.as_ref() == Some(s))
        {
            return Err(Error::Busy);
        }
        if !self.token_path(repo).is_file() {
            return Err(Error::Invalid(
                "repository credential is missing; save a replacement key".into(),
            ));
        }
        if let Some(s) = slot {
            repo.last_slot = Some(s);
        }
        let repo = repo.clone();
        let busy = next.runs.values().any(AuditRun::active) || !self.controller.can_admit(16384, 6);
        let now = Utc::now();
        let run = AuditRun {
            id: uuid::Uuid::new_v4().to_string(),
            repository_id: id.into(),
            repository: repo.repository.clone(),
            state: if busy { "busy" } else { "preparing" }.into(),
            created_at: now,
            deadline,
            finished_at: if busy { Some(now) } else { None },
            session_id: None,
            error: if busy {
                Some("another sandbox is active; this occurrence was skipped".into())
            } else {
                None
            },
            result: None,
            cancelled: false,
        };
        next.runs.insert(run.id.clone(), run.clone());
        // Bound persisted history without pruning active runs.
        let mut pruned = Vec::new();
        while next.runs.len() > 200 {
            let Some(old) = next
                .runs
                .values()
                .filter(|r| !r.active())
                .min_by_key(|r| r.created_at)
                .map(|r| r.id.clone())
            else {
                break;
            };
            next.runs.remove(&old);
            pruned.push(old);
        }
        self.persist(&next)?;
        *guard = next;
        drop(guard);
        for id in pruned {
            let _ = fs::remove_dir_all(self.root.join("runs").join(id));
        }
        if busy {
            return Err(Error::Busy);
        }
        let service = self.clone();
        let clone = run.clone();
        tokio::spawn(async move {
            service.execute(repo, clone).await;
        });
        Ok(run)
    }
    pub fn tick(self: &Arc<Self>, now: DateTime<Utc>) {
        let due: Vec<_> = self
            .data
            .lock()
            .repositories
            .values()
            .filter(|r| r.enabled)
            .filter_map(|r| {
                r.schedule
                    .due(now)
                    .filter(|(slot, _)| r.last_slot.as_ref() != Some(slot))
                    .map(|(slot, end)| (r.id.clone(), slot, end))
            })
            .collect();
        for (id, slot, end) in due {
            let _ = self.admit(&id, end, Some(slot));
        }
    }
    fn update(&self, id: &str, change: impl FnOnce(&mut AuditRun)) -> Result<AuditRun, Error> {
        let mut guard = self.data.lock();
        let mut next = guard.clone();
        let run = next.runs.get_mut(id).ok_or(Error::NotFound)?;
        change(run);
        let run = run.clone();
        self.persist(&next)?;
        *guard = next;
        Ok(run)
    }
    pub fn cancel(&self, id: &str) -> Result<AuditRun, Error> {
        let run = self.update(id, |r| {
            if r.active() {
                r.cancelled = true;
                r.state = "cancelling".into();
            }
        })?;
        if let Some(session) = &run.session_id {
            self.controller.cancel(session).map_err(map_vm)?;
        }
        Ok(run)
    }
    fn cancelled(&self, id: &str) -> bool {
        self.data.lock().runs.get(id).is_none_or(|r| r.cancelled)
    }
    async fn execute(self: Arc<Self>, repo: Repository, run: AuditRun) {
        let outcome = self.execute_inner(&repo, &run).await;
        // The guest owns its separate copy; the host staging archive is no longer needed.
        let _ = fs::remove_file(self.root.join("runs").join(&run.id).join("source.tar"));
        if outcome.is_err() {
            if let Some(id) = self
                .data
                .lock()
                .runs
                .get(&run.id)
                .and_then(|r| r.session_id.clone())
            {
                let _ = self.controller.cancel(&id);
            }
        }
        let cancelled = self.cancelled(&run.id);
        let _ = self.update(&run.id, |r| {
            r.state = if cancelled {
                "cancelled"
            } else if outcome.is_ok() {
                "completed"
            } else {
                "failed"
            }
            .into();
            r.finished_at = Some(Utc::now());
            if let Err(e) = outcome {
                r.error = Some(e);
            }
        });
    }
    async fn execute_inner(&self, repo: &Repository, run: &AuditRun) -> Result<(), String> {
        let dir = self.root.join("runs").join(&run.id);
        private_dir(&dir).map_err(|_| "could not create private audit workspace")?;
        let job = serde_json::json!({"repository":repo.repository,"ref_name":repo.ref_name,"run_id":run.id,"token_file":self.token_path(repo),"deadline":run.deadline,"model_id":repo.model_id,"publication":{"enabled":repo.publish_issues},"started_at":run.created_at,"output_dir":dir});
        let job_path = dir.join("job.json");
        save(&job_path, &job).map_err(|_| "could not persist audit intent")?;
        if self.cancelled(&run.id) {
            return Err("audit cancelled".into());
        }
        let identity = self.helper("prepare", &job_path, run, 120).await?;
        if self.cancelled(&run.id) || Utc::now() + Duration::seconds(360) >= run.deadline {
            return Err("audit cancelled or too late to start".into());
        }
        let commit = identity["commit"]
            .as_str()
            .ok_or("source helper omitted commit")?;
        let ref_name = identity["ref_name"]
            .as_str()
            .ok_or("source helper omitted branch")?;
        let request = CreateRequest {
            kind: "audit".into(),
            name: None,
            lifetime: "timed".into(),
            repository: Some(repo.repository.clone()),
            commit: Some(commit.into()),
            ref_name: Some(ref_name.into()),
            run_id: Some(run.id.clone()),
            audit_profile: repo.audit_profile.clone(),
            deadline: Some(run.deadline),
            duration_seconds: 18000,
            memory_mb: 16384,
            vcpus: 6,
            model_id: repo.model_id.clone(),
        };
        let session = self
            .controller
            .create_local_audit(request)
            .await
            .map_err(|e| match e {
                VmError::Busy => {
                    "another sandbox became active; audit failed without queuing".to_string()
                }
                _ => "sandbox admission failed; check host runtime configuration".to_string(),
            })?;
        if self
            .update(&run.id, |r| {
                r.session_id = Some(session.id.clone());
                r.state = "running".into();
            })
            .is_err()
        {
            let _ = self.controller.cancel(&session.id);
            return Err("could not persist sandbox identity".into());
        }
        if self.cancelled(&run.id) {
            let _ = self.controller.cancel(&session.id);
            return Err("audit cancelled before source upload".into());
        }
        let source = fs::read(dir.join("source.tar"))
            .map_err(|_| "source helper did not stage an archive")?;
        if source.len() > MAX_SOURCE {
            return Err("source archive exceeded limit".into());
        }
        self.controller
            .upload(&session.id, source)
            .await
            .map_err(|_| "source staging failed")?;
        let _ = fs::remove_file(dir.join("source.tar"));
        let terminal_state = loop {
            if self.cancelled(&run.id) || Utc::now() >= run.deadline {
                let _ = self.controller.cancel(&session.id);
            }
            let current = self
                .controller
                .get(&session.id)
                .map_err(|_| "sandbox record unavailable")?;
            if current.terminal() {
                if self.cancelled(&run.id) {
                    return Err("audit cancelled".into());
                }
                break current.state;
            }
            // Cleanup failure deliberately retains both admission boundaries until confirmed.
            if current.state == "cleanup_failed" {
                let _ = self.update(&run.id, |r| r.state = "cleanup_failed".into());
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        };
        let bytes = self
            .controller
            .bounded_file(&session.id, "report.json")
            .map_err(|_| "audit produced no bounded report")?;
        atomic_bytes(&dir.join("report.json"), &bytes).map_err(|_| "could not persist findings")?;
        if self.cancelled(&run.id) {
            return Err("audit cancelled before publication".into());
        }
        let mut publish_job = job;
        publish_job["commit"] = serde_json::json!(commit);
        publish_job["ref_name"] = serde_json::json!(ref_name);
        if terminal_state != "completed" {
            publish_job["publication"]["enabled"] = serde_json::json!(false);
        }
        save(&job_path, &publish_job).map_err(|_| "could not persist report validation intent")?;
        self.update(&run.id, |r| r.state = "publishing".into())
            .map_err(|_| "could not persist publication intent")?;
        let mode = if terminal_state != "completed" || Utc::now() >= run.deadline {
            "validate"
        } else {
            "publish"
        };
        let result = match self.helper(mode, &job_path, run, 180).await {
            Ok(result) => result,
            Err(error) => {
                // Publication can stop after one successful issue write. Retain
                // its durable host checkpoint and leave the run failed, without replay.
                if let Some(result) = publication_checkpoint(&dir.join("result.json"), run, commit)
                {
                    self.update(&run.id, |r| r.result = Some(result))
                        .map_err(|_| "could not persist partial publication result")?;
                }
                return Err(error);
            }
        };
        let complete =
            terminal_state == "completed" && result["completion"].as_str() == Some("complete");
        self.update(&run.id, |r| r.result = Some(result))
            .map_err(|_| "could not persist publication result")?;
        if !complete {
            return Err("audit coverage is partial or failed; review the validated report".into());
        }
        Ok(())
    }
    async fn helper(
        &self,
        mode: &str,
        job: &Path,
        run: &AuditRun,
        seconds: u64,
    ) -> Result<serde_json::Value, String> {
        if self.cancelled(&run.id) || (mode != "validate" && Utc::now() >= run.deadline) {
            return Err("audit helper cancelled or deadline reached".into());
        }
        let mut command = Command::new("python3");
        command
            .arg(&self.worker)
            .arg(mode)
            .arg("--job-file")
            .arg(job)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        #[cfg(target_os = "linux")]
        unsafe {
            let parent = libc::getpid();
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != parent {
                    return Err(std::io::Error::other("audit parent disappeared"));
                }
                Ok(())
            });
        }
        let mut child = command
            .spawn()
            .map_err(|_| "could not start trusted audit helper")?;
        let stdout = child
            .stdout
            .take()
            .ok_or("audit helper output unavailable")?;
        let output = tokio::spawn(async move {
            let mut data = Vec::new();
            stdout
                .take(2 * 1024 * 1024 + 1)
                .read_to_end(&mut data)
                .await
                .map_err(|_| ())?;
            if data.len() > 2 * 1024 * 1024 {
                return Err(());
            }
            Ok(data)
        });
        let expiry = Utc::now() + Duration::seconds(seconds as i64);
        let mut cancelled = false;
        let status = loop {
            if let Some(s) = child.try_wait().map_err(|_| "audit helper wait failed")? {
                break s;
            }
            if self.cancelled(&run.id)
                || Utc::now() > expiry
                || (mode != "validate" && Utc::now() >= run.deadline)
            {
                cancelled = true;
                let _ = child.kill().await;
                break child
                    .wait()
                    .await
                    .map_err(|_| "audit helper termination failed")?;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        };
        let bytes = output
            .await
            .map_err(|_| "audit helper reader failed")?
            .map_err(|_| "audit helper response exceeded bound")?;
        if cancelled || !status.success() {
            return Err("trusted GitHub helper failed or expired; check repository permissions and host configuration".into());
        }
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| "audit helper returned invalid metadata")?;
        if !value.is_object() {
            return Err("audit helper returned invalid metadata".into());
        }
        Ok(value)
    }
    pub fn report(&self, id: &str) -> Result<Vec<u8>, Error> {
        if !self.data.lock().runs.contains_key(id) {
            return Err(Error::NotFound);
        }
        let path = self.root.join("runs").join(id).join("report.safe.json");
        let meta = fs::symlink_metadata(&path).map_err(|_| Error::NotFound)?;
        if !meta.file_type().is_file() || meta.len() > 2 * 1024 * 1024 {
            return Err(Error::Storage);
        }
        let bytes = fs::read(path).map_err(|_| Error::Storage)?;
        serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|_| Error::Storage)?;
        Ok(bytes)
    }
}
fn publication_checkpoint(path: &Path, run: &AuditRun, commit: &str) -> Option<serde_json::Value> {
    use std::io::Read;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > 2 * 1024 * 1024 {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return None;
        }
    }
    let mut bytes = Vec::new();
    file.take(2 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > 2 * 1024 * 1024 {
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    if !value.is_object()
        || value["run_id"] != run.id
        || value["repository"] != run.repository
        || value["commit"] != commit
        || !matches!(
            value["completion"].as_str(),
            Some("complete" | "partial" | "failed")
        )
    {
        return None;
    }
    let mut safe = serde_json::json!({"run_id":run.id,"repository":run.repository,"commit":commit,"completion":value["completion"]});
    for (key, max) in [
        ("created", 5),
        ("updated", 200),
        ("withheld", 200),
        ("deferred", 200),
    ] {
        let n = value[key].as_u64()?;
        if n > max {
            return None;
        }
        safe[key] = serde_json::json!(n);
    }
    let issues = value["issues"].as_array()?;
    if issues.len() > 200 {
        return None;
    }
    let mut clean = Vec::new();
    let (mut created, mut updated) = (0, 0);
    for item in issues {
        let number = item["number"].as_u64()?;
        if number == 0 {
            return None;
        }
        let url = format!("https://github.com/{}/issues/{number}", run.repository);
        if item["url"] != url {
            return None;
        }
        let title = item["title"].as_str()?;
        if title.is_empty() || title.len() > 256 || title.chars().any(char::is_control) {
            return None;
        }
        let action = item["action"].as_str()?;
        match action {
            "created" => created += 1,
            "updated" => updated += 1,
            _ => return None,
        }
        clean.push(serde_json::json!({"number":number,"url":url,"title":title,"action":action}));
    }
    if value["created"] != created || value["updated"] != updated {
        return None;
    }
    safe["issues"] = serde_json::json!(clean);
    for key in ["publication_enabled", "visibility_verified"] {
        safe[key] = serde_json::json!(value[key].as_bool()?);
    }
    if !value["repository_private"].is_null() && !value["repository_private"].is_boolean() {
        return None;
    }
    safe["repository_private"] = value["repository_private"].clone();
    Some(safe)
}

fn validate_input(r: &RepositoryInput) -> Result<(), Error> {
    let parts: Vec<_> = r.repository.split('/').collect();
    if parts.len() != 2
        || parts.iter().any(|p| {
            p.is_empty()
                || p.len() > 100
                || *p == "."
                || *p == ".."
                || !p
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        })
    {
        return Err(Error::Invalid("repository must be owner/name".into()));
    }
    if r.ref_name.len() > 200
        || r.ref_name
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err(Error::Invalid("invalid branch name".into()));
    }
    r.schedule.parsed()?;
    let p = &r.audit_profile;
    if p.test_commands.len() > 50
        || p.test_commands.iter().any(|a| {
            a.is_empty()
                || a.len() > 100
                || a.iter()
                    .any(|s| s.is_empty() || s.len() > 4096 || s.contains('\0'))
        })
        || p.scanners
            .iter()
            .any(|s| !["semgrep", "gitleaks", "trivy"].contains(&s.as_str()))
        || p.scanners.len() > 3
        || p.scope.len() > 100
        || p.exclusions.len() > 100
        || p.scope.iter().chain(p.exclusions.iter()).any(|s| {
            s.is_empty()
                || s.len() > 1024
                || s.starts_with('/')
                || s.contains("..")
                || s.contains('\0')
        })
    {
        return Err(Error::Invalid("audit profile exceeds its bounds".into()));
    }
    Ok(())
}
fn map_vm(e: VmError) -> Error {
    match e {
        VmError::Busy => Error::Busy,
        VmError::NotFound => Error::NotFound,
        _ => Error::Unavailable,
    }
}
fn private_dir(path: &Path) -> std::io::Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if !meta.file_type().is_dir() {
            return Err(std::io::Error::other("private path is not a directory"));
        }
    }
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
fn private_file(path: &Path, truncate: bool) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options
        .create(true)
        .read(true)
        .write(true)
        .truncate(truncate);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = file.metadata()?;
        if !meta.is_file() || meta.nlink() != 1 {
            return Err(std::io::Error::other("private file is not regular"));
        }
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}
fn atomic_bytes(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut f = private_file(&temporary, true)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&temporary, path)?;
        if let Some(parent) = path.parent() {
            fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}
fn save(path: &Path, value: &impl Serialize) -> std::io::Result<()> {
    atomic_bytes(path, &serde_json::to_vec(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn schedule(day: u32, start: &str, end: &str) -> WeeklySchedule {
        WeeklySchedule {
            weekday: day,
            start_time: start.into(),
            end_time: end.into(),
            timezone: timezone(),
        }
    }
    #[test]
    fn dst_schedule_uses_one_fold_and_skips_gap() {
        let fold = schedule(6, "01:00", "05:00");
        let now = "2026-11-01T05:00:20Z".parse().unwrap();
        assert!(fold.due(now).is_some());
        assert!(fold.due("2026-11-01T06:00:20Z".parse().unwrap()).is_none());
        let default = WeeklySchedule {
            weekday: 6,
            ..Default::default()
        };
        let (_, cutoff) = default
            .occurrence(chrono::NaiveDate::from_ymd_opt(2026, 11, 1).unwrap())
            .unwrap();
        assert_eq!(
            cutoff,
            "2026-11-01T10:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
        let gap = schedule(6, "02:30", "06:00");
        assert!(gap
            .occurrence(chrono::NaiveDate::from_ymd_opt(2026, 3, 8).unwrap())
            .is_none());
    }
    #[test]
    fn no_backfill_and_editable_window() {
        let s = schedule(0, "13:00", "15:00");
        assert!(s.due("2026-07-06T17:00:30Z".parse().unwrap()).is_some());
        assert!(s.due("2026-07-06T17:02:00Z".parse().unwrap()).is_none());
        assert!(schedule(0, "01:00", "07:00").parsed().is_err());
    }
    #[test]
    fn private_write_does_not_follow_symlink() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("data");
        atomic_bytes(&p, b"key").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};
            assert_eq!(
                fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let link = t.path().join("link");
            symlink(&p, &link).unwrap();
            assert!(private_file(&link, true).is_err());
            assert_eq!(fs::read(p).unwrap(), b"key");
        }
    }
    async fn fixture() -> (tempfile::TempDir, Arc<LocalAuditService>) {
        use crate::disposable_gateway::GatewayStore;
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let runtime = tmp.path().join("runtime.py");
        fs::write(&runtime,r#"#!/usr/bin/env python3
import sys,json,pathlib
mode=sys.argv[1]
if mode=='status': print('{"state":"completed"}')
elif mode=='collect':
 p=pathlib.Path(sys.argv[2]);r=json.loads((p/'request.json').read_text());(p/'report.json').write_text(json.dumps({'version':1,'repository':r['repository'],'commit':r['commit'],'completion':'complete','findings':[],'coverage':{'scanned_paths':[],'scanners':[],'tests':[],'skipped':[]}})); print('{}')
elif mode=='stop': print('{"contained":true}')
else: print('{}')
"#).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let presets=serde_json::from_value(serde_json::json!([{"id":"studio","kind":"model","base_url":"http://192.168.1.80:8080/v1","path_prefixes":["/v1/chat/completions"],"methods":["POST"],"allow_private":true,"model_name":"fixture"}])).unwrap();
        let controller = DisposableController::open(
            tmp.path().join("disposable"),
            runtime,
            GatewayStore::new(presets).unwrap(),
        )
        .await
        .unwrap();
        let worker = tmp.path().join("worker.py");
        fs::write(&worker,r#"import sys,json,pathlib,tarfile,io,time
job=json.loads(pathlib.Path(sys.argv[3]).read_text());out=pathlib.Path(job['output_dir']);mode=sys.argv[1]
if mode=='prepare':
 if job['repository']=='owner/slow':time.sleep(30)
 with tarfile.open(out/'source.tar','w') as a:
  f=tarfile.TarInfo('source.py');f.size=2;a.addfile(f,io.BytesIO(b'x\n'))
 print(json.dumps({'commit':'a'*40,'ref_name':'refs/heads/main','private':True}))
else:
 report=json.loads((out/'report.json').read_text());(out/'report.safe.json').write_text(json.dumps(report));print(json.dumps({'completion':report['completion'],'created':0,'updated':0,'withheld':0,'issues':[]}))
"#).unwrap();
        let service =
            LocalAuditService::open(tmp.path().join("local"), worker, controller).unwrap();
        (tmp, service)
    }
    fn input(repo: &str) -> RepositoryInput {
        serde_json::from_value(serde_json::json!({"repository":repo,"github_token":"ghp_fixture_token_value","audit_profile":{"test_commands":[["python3","-m","pytest"]]}})).unwrap()
    }
    #[tokio::test]
    async fn secret_crud_rotation_redaction_and_restart_claim() {
        let (_tmp, service) = fixture().await;
        let saved = service.upsert(None, input("owner/repo")).unwrap();
        let id = saved["id"].as_str().unwrap();
        assert!(!service.snapshot().to_string().contains("ghp_fixture"));
        let repo = service.data.lock().repositories[id].clone();
        let old = service.token_path(&repo);
        assert!(old.exists());
        let mut replacement = input("owner/repo");
        replacement.github_token = Some("github_pat_replacement_fixture".into());
        service.upsert(Some(id), replacement).unwrap();
        assert!(!old.exists());
        let mut database = service.data.lock().clone();
        database.repositories.get_mut(id).unwrap().last_slot =
            Some("2026-10-06T05:00:00+00:00".into());
        let run = AuditRun {
            id: uuid::Uuid::new_v4().to_string(),
            repository_id: id.into(),
            repository: "owner/repo".into(),
            state: "preparing".into(),
            created_at: Utc::now(),
            deadline: Utc::now() + Duration::hours(5),
            finished_at: None,
            session_id: None,
            error: None,
            result: None,
            cancelled: false,
        };
        database.runs.insert(run.id.clone(), run);
        service.persist(&database).unwrap();
        let root = service.root.clone();
        let worker = service.worker.clone();
        let controller = service.controller.clone();
        drop(service);
        let reopened = LocalAuditService::open(root, worker, controller).unwrap();
        assert_eq!(
            reopened.data.lock().repositories[id].last_slot.as_deref(),
            Some("2026-10-06T05:00:00+00:00")
        );
        assert_eq!(reopened.snapshot()["runs"][0]["state"], "interrupted");
        let token = reopened.token_path(&reopened.data.lock().repositories[id]);
        reopened.delete(id).unwrap();
        assert!(!token.exists());
    }
    #[tokio::test]
    async fn busy_occurrence_is_consumed_without_backlog() {
        let (_tmp, service) = fixture().await;
        let saved = service.upsert(None, input("owner/repo")).unwrap();
        let id = saved["id"].as_str().unwrap();
        let vm=service.controller.create(serde_json::from_value(serde_json::json!({"kind":"interactive","repository":"owner/other","commit":"a".repeat(40),"duration_seconds":600})).unwrap()).await.unwrap();
        let slot = "2026-10-06T05:00:00Z".to_string();
        assert!(matches!(
            service.admit(id, Utc::now() + Duration::hours(5), Some(slot.clone())),
            Err(Error::Busy)
        ));
        assert_eq!(service.data.lock().repositories[id].last_slot, Some(slot));
        assert_eq!(service.snapshot()["runs"][0]["state"], "busy");
        assert!(service.snapshot()["runs"][0]["session_id"].is_null());
        let _ = service.controller.cancel(&vm.id);
    }
    #[tokio::test]
    async fn cancellation_during_prepare_admits_no_vm() {
        let (_tmp, service) = fixture().await;
        let saved = service.upsert(None, input("owner/slow")).unwrap();
        let run = service.run_now(saved["id"].as_str().unwrap()).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        service.cancel(&run.id).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(4), async {
            loop {
                if !service.data.lock().runs[&run.id].active() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert!(service.controller.list().is_empty());
        assert_eq!(service.data.lock().runs[&run.id].state, "cancelled");
    }
    #[tokio::test]
    async fn local_manual_run_preserves_profile_and_publishes_fixture_report() {
        let (_tmp, service) = fixture().await;
        let saved = service.upsert(None, input("owner/repo")).unwrap();
        let run = service.run_now(saved["id"].as_str().unwrap()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                if !service.data.lock().runs[&run.id].active() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        let current = service.data.lock().runs[&run.id].clone();
        assert_eq!(current.state, "completed", "{:?}", current.error);
        let session = service
            .controller
            .get(current.session_id.as_ref().unwrap())
            .unwrap();
        assert_eq!(
            session.request.audit_profile.test_commands[0],
            vec!["python3", "-m", "pytest"]
        );
        assert!(service.report(&run.id).is_ok());
    }
    #[tokio::test]
    async fn failed_vm_keeps_partial_report_without_publishing() {
        let (tmp, service) = fixture().await;
        let path = tmp.path().join("runtime.py");
        let script = fs::read_to_string(&path)
            .unwrap()
            .replace("{\"state\":\"completed\"}", "{\"state\":\"failed\"}");
        fs::write(path, script).unwrap();
        let worker = fs::read_to_string(&service.worker).unwrap().replace(
            "else:\n report=",
            "else:\n (out/'helper-mode.txt').write_text(mode)\n report=",
        );
        fs::write(&service.worker, worker).unwrap();
        let saved = service.upsert(None, input("owner/repo")).unwrap();
        let run = service.run_now(saved["id"].as_str().unwrap()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                if !service.data.lock().runs[&run.id].active() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        let current = service.data.lock().runs[&run.id].clone();
        assert_eq!(current.state, "failed");
        let report: serde_json::Value =
            serde_json::from_slice(&service.report(&run.id).unwrap()).unwrap();
        assert_eq!(report["completion"], "partial");
        assert_eq!(
            fs::read_to_string(
                service
                    .root
                    .join("runs")
                    .join(&run.id)
                    .join("helper-mode.txt")
            )
            .unwrap(),
            "validate"
        );
    }
    #[tokio::test]
    async fn offline_validation_can_finish_after_deadline() {
        let (_tmp, service) = fixture().await;
        let saved = service.upsert(None, input("owner/repo")).unwrap();
        let id = saved["id"].as_str().unwrap();
        let run = AuditRun {
            id: uuid::Uuid::new_v4().to_string(),
            repository_id: id.into(),
            repository: "owner/repo".into(),
            state: "publishing".into(),
            created_at: Utc::now() - Duration::hours(5),
            deadline: Utc::now() - Duration::seconds(10),
            finished_at: None,
            session_id: None,
            error: None,
            result: None,
            cancelled: false,
        };
        service.data.lock().runs.insert(run.id.clone(), run.clone());
        let dir = service.root.join("runs").join(&run.id);
        private_dir(&dir).unwrap();
        save(
            &dir.join("report.json"),
            &serde_json::json!({"completion":"partial"}),
        )
        .unwrap();
        let job = dir.join("job.json");
        save(&job, &serde_json::json!({"output_dir":dir})).unwrap();
        let result = service.helper("validate", &job, &run, 5).await.unwrap();
        assert_eq!(result["completion"], "partial");
        assert!(service.helper("publish", &job, &run, 5).await.is_err());
    }
    #[tokio::test]
    async fn partial_publication_failure_retains_checkpoint_without_retry() {
        let (_tmp, service) = fixture().await;
        let script = fs::read_to_string(&service.worker).unwrap();
        let prefix = script.split("else:\n report=").next().unwrap();
        let failure = r#"else:
 (out/'report.safe.json').write_text((out/'report.json').read_text())
 value={'run_id':job['run_id'],'repository':job['repository'],'commit':job['commit'],'completion':'complete','created':1,'updated':0,'withheld':0,'deferred':0,'issues':[{'number':12,'url':'https://github.com/'+job['repository']+'/issues/12','title':'Validated weakness','action':'created'}],'publication_enabled':True,'repository_private':True,'visibility_verified':True}
 result=out/'result.json';result.write_text(json.dumps(value));result.chmod(0o600)
 (out/'attempts.txt').write_text('1');sys.exit(1)
"#;
        fs::write(&service.worker, format!("{prefix}{failure}")).unwrap();
        let saved = service.upsert(None, input("owner/repo")).unwrap();
        let run = service.run_now(saved["id"].as_str().unwrap()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                if !service.data.lock().runs[&run.id].active() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        let current = service.data.lock().runs[&run.id].clone();
        assert_eq!(current.state, "failed");
        let result = current.result.unwrap();
        assert_eq!(result["created"], 1);
        assert_eq!(
            result["issues"][0]["url"],
            "https://github.com/owner/repo/issues/12"
        );
        assert_eq!(
            fs::read_to_string(service.root.join("runs").join(&run.id).join("attempts.txt"))
                .unwrap(),
            "1"
        );
        let mut bad = result;
        bad["repository"] = serde_json::json!("other/repo");
        let path = service.root.join("runs").join(&run.id).join("result.json");
        save(&path, &bad).unwrap();
        assert!(publication_checkpoint(&path, &run, &"a".repeat(40)).is_none());
    }
}

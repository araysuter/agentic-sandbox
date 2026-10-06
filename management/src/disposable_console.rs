//! A bounded bridge for a real guest PTY. Neither shell nor user commands execute
//! on the management host. Browser detachment never terminates the guest process.
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const OUTPUT_LIMIT: usize = 1024 * 1024;
const INPUT_LIMIT: usize = 64 * 1024;
const CHUNK_LIMIT: usize = 16 * 1024;
#[derive(Clone, Serialize)]
pub struct Output {
    pub sequence: u64,
    pub hex: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct Command {
    pub sequence: u64,
    #[serde(flatten)]
    pub control: Control,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Control {
    Attach {
        client_id: String,
    },
    Input {
        client_id: String,
        hex: String,
    },
    Resize {
        client_id: String,
        cols: u16,
        rows: u16,
    },
    Detach {
        client_id: String,
    },
    Restart {
        client_id: String,
    },
}
impl Control {
    fn client(&self) -> &str {
        match self {
            Self::Attach { client_id }
            | Self::Input { client_id, .. }
            | Self::Resize { client_id, .. }
            | Self::Detach { client_id }
            | Self::Restart { client_id } => client_id,
        }
    }
}
#[derive(Default)]
struct Slot {
    output: VecDeque<Output>,
    output_bytes: usize,
    sequence: u64,
    commands: VecDeque<Command>,
    command_sequence: u64,
    command_bytes: usize,
    writer: Option<(String, Instant)>,
    guest_sequence: u64,
    seen: Option<Instant>,
    exit: Option<i32>,
    revoked: bool,
    epoch: String,
}
#[derive(Clone, Default)]
pub struct ConsoleStore(Arc<Mutex<BTreeMap<String, Slot>>>);
#[derive(Serialize)]
pub struct Snapshot {
    pub output: Vec<Output>,
    pub sequence: u64,
    pub truncated: bool,
    pub connected: bool,
    pub exit_code: Option<i32>,
    pub revoked: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exchange {
    pub sequence: u64,
    #[serde(default)]
    pub output_hex: String,
    #[serde(default)]
    pub acknowledged_command: u64,
    pub exit_code: Option<i32>,
}
#[derive(Debug, Serialize)]
pub struct ExchangeReply {
    pub epoch: String,
    pub acknowledged_output: u64,
    pub commands: Vec<Command>,
}
impl ConsoleStore {
    pub fn create(&self, id: &str) {
        let mut slots = self.0.lock().unwrap();
        while slots.len() >= 200 {
            let remove = slots
                .iter()
                .find(|(_, s)| s.revoked)
                .map(|(id, _)| id.clone());
            if let Some(old) = remove {
                slots.remove(&old);
            } else {
                break;
            }
        }
        slots.insert(
            id.to_owned(),
            Slot {
                epoch: uuid::Uuid::new_v4().to_string(),
                ..Slot::default()
            },
        );
    }
    pub fn revoke(&self, id: &str) {
        if let Some(s) = self.0.lock().unwrap().get_mut(id) {
            s.revoked = true;
            s.commands.clear();
            s.command_bytes = 0;
            s.writer = None;
            s.output.clear();
            s.output_bytes = 0;
        }
    }
    pub fn snapshot(&self, id: &str, after: u64) -> Result<Snapshot, StatusCode> {
        let slots = self.0.lock().unwrap();
        let s = slots.get(id).ok_or(StatusCode::NOT_FOUND)?;
        Ok(Snapshot {
            output: s
                .output
                .iter()
                .filter(|o| o.sequence > after)
                .cloned()
                .collect(),
            sequence: s.sequence,
            truncated: s
                .output
                .front()
                .is_some_and(|o| after.saturating_add(1) < o.sequence),
            connected: s
                .seen
                .is_some_and(|t| t.elapsed() < Duration::from_secs(10))
                && !s.revoked,
            exit_code: s.exit,
            revoked: s.revoked,
        })
    }
    pub fn control(&self, id: &str, control: Control) -> Result<(), StatusCode> {
        let client = control.client().to_owned();
        if client.is_empty()
            || client.len() > 128
            || !client
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(StatusCode::BAD_REQUEST);
        }
        let mut slots = self.0.lock().unwrap();
        let s = slots.get_mut(id).ok_or(StatusCode::NOT_FOUND)?;
        if s.revoked {
            return Err(StatusCode::GONE);
        }
        if s.exit.is_some()
            && !matches!(
                &control,
                Control::Attach { .. } | Control::Detach { .. } | Control::Restart { .. }
            )
        {
            return Err(StatusCode::GONE);
        }
        if s.writer
            .as_ref()
            .is_some_and(|(_, t)| t.elapsed() > Duration::from_secs(30))
        {
            s.writer = None;
        }
        if s.writer.as_ref().is_some_and(|(owner, _)| owner != &client) {
            return Err(StatusCode::CONFLICT);
        }
        match &control {
            Control::Attach { .. } => {
                s.writer = Some((client, Instant::now()));
                return Ok(());
            }
            Control::Detach { .. } => {
                s.writer = None;
                return Ok(());
            }
            _ => {
                if s.writer.as_ref().is_none_or(|(owner, _)| owner != &client) {
                    return Err(StatusCode::CONFLICT);
                }
                s.writer = Some((client, Instant::now()));
            }
        }
        let bytes = match &control {
            Control::Input { hex, .. } => {
                let data = hex::decode(hex).map_err(|_| StatusCode::BAD_REQUEST)?;
                if data.len() > CHUNK_LIMIT {
                    return Err(StatusCode::PAYLOAD_TOO_LARGE);
                }
                data.len()
            }
            Control::Resize { cols, rows, .. } => {
                if !(10..=500).contains(cols) || !(2..=200).contains(rows) {
                    return Err(StatusCode::BAD_REQUEST);
                }
                32
            }
            Control::Restart { .. } => 32,
            _ => 0,
        };
        if s.command_bytes + bytes > INPUT_LIMIT || s.commands.len() >= 128 {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        s.command_sequence = s.command_sequence.checked_add(1).ok_or(StatusCode::GONE)?;
        s.command_bytes += bytes;
        s.commands.push_back(Command {
            sequence: s.command_sequence,
            control,
        });
        Ok(())
    }
    pub fn exchange(&self, id: &str, request: Exchange) -> Result<ExchangeReply, StatusCode> {
        let data = hex::decode(&request.output_hex).map_err(|_| StatusCode::BAD_REQUEST)?;
        if data.len() > CHUNK_LIMIT {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        let mut slots = self.0.lock().unwrap();
        let s = slots.get_mut(id).ok_or(StatusCode::NOT_FOUND)?;
        if s.revoked {
            return Err(StatusCode::GONE);
        }
        if request.sequence > (1u64 << 53) - 1024
            || request.acknowledged_command > (1u64 << 53) - 1024
        {
            return Err(StatusCode::BAD_REQUEST);
        }
        if s.seen.is_none() {
            // A surviving guest retains its input ACK across management restarts.
            // Rebase fresh host controls above that floor, never discard them as
            // if they belonged to the previous management process.
            let floor = request.acknowledged_command;
            for (index, command) in s.commands.iter_mut().enumerate() {
                command.sequence = floor + index as u64 + 1;
            }
            s.command_sequence = floor + s.commands.len() as u64;
        }
        if request.acknowledged_command > s.command_sequence {
            return Err(StatusCode::BAD_REQUEST);
        }
        if s.seen.is_some() && request.sequence > s.guest_sequence + 1 {
            return Err(StatusCode::CONFLICT);
        }
        if s.seen.is_none() || request.sequence == s.guest_sequence + 1 {
            s.guest_sequence = request.sequence;
            if !data.is_empty() {
                s.sequence = s.sequence.checked_add(1).ok_or(StatusCode::GONE)?;
                s.output_bytes += data.len();
                s.output.push_back(Output {
                    sequence: s.sequence,
                    hex: request.output_hex,
                });
                while s.output_bytes > OUTPUT_LIMIT {
                    if let Some(o) = s.output.pop_front() {
                        s.output_bytes -= o.hex.len() / 2;
                    }
                }
            }
        }
        s.seen = Some(Instant::now());
        s.exit = request.exit_code;
        while s
            .commands
            .front()
            .is_some_and(|c| c.sequence <= request.acknowledged_command)
        {
            let c = s.commands.pop_front().unwrap();
            s.command_bytes = s.command_bytes.saturating_sub(match c.control {
                Control::Input { hex, .. } => hex.len() / 2,
                _ => 32,
            });
        }
        Ok(ExchangeReply {
            epoch: s.epoch.clone(),
            acknowledged_output: s.guest_sequence,
            commands: s.commands.iter().take(1).cloned().collect(),
        })
    }
}
pub fn guest_router(gateway: crate::disposable_gateway::GatewayStore) -> Router {
    Router::new()
        .route("/console/{id}/exchange", post(guest_exchange))
        .with_state(gateway)
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024))
}
async fn guest_exchange(
    State(gateway): State<crate::disposable_gateway::GatewayStore>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<Exchange>,
) -> Result<Json<ExchangeReply>, StatusCode> {
    gateway.authorize_console(&id, &headers)?;
    gateway.console().exchange(&id, request).map(Json)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn exchange(
        s: &ConsoleStore,
        n: u64,
        data: &str,
        ack: u64,
    ) -> Result<ExchangeReply, StatusCode> {
        s.exchange(
            "vm",
            Exchange {
                sequence: n,
                output_hex: hex::encode(data),
                acknowledged_command: ack,
                exit_code: None,
            },
        )
    }
    #[test]
    fn detach_preserves_pty_output_and_single_writer() {
        let s = ConsoleStore::default();
        s.create("vm");
        s.control(
            "vm",
            Control::Attach {
                client_id: "one".into(),
            },
        )
        .unwrap();
        assert_eq!(
            s.control(
                "vm",
                Control::Attach {
                    client_id: "two".into()
                }
            )
            .unwrap_err(),
            StatusCode::CONFLICT
        );
        exchange(&s, 1, "hello", 0).unwrap();
        s.control(
            "vm",
            Control::Detach {
                client_id: "one".into(),
            },
        )
        .unwrap();
        s.control(
            "vm",
            Control::Attach {
                client_id: "two".into(),
            },
        )
        .unwrap();
        assert_eq!(
            s.snapshot("vm", 0).unwrap().output[0].hex,
            hex::encode("hello")
        );
    }
    #[test]
    fn acknowledged_retry_does_not_duplicate_output_or_commands() {
        let s = ConsoleStore::default();
        s.create("vm");
        s.control(
            "vm",
            Control::Attach {
                client_id: "one".into(),
            },
        )
        .unwrap();
        s.control(
            "vm",
            Control::Input {
                client_id: "one".into(),
                hex: hex::encode("hello\n"),
            },
        )
        .unwrap();
        assert_eq!(exchange(&s, 1, "response", 0).unwrap().commands.len(), 1);
        assert_eq!(exchange(&s, 1, "response", 1).unwrap().commands.len(), 0);
        assert_eq!(s.snapshot("vm", 0).unwrap().output.len(), 1);
    }
    #[test]
    fn revoke_blocks_input_and_guest() {
        let s = ConsoleStore::default();
        s.create("vm");
        s.revoke("vm");
        assert_eq!(
            s.control(
                "vm",
                Control::Attach {
                    client_id: "one".into()
                }
            )
            .unwrap_err(),
            StatusCode::GONE
        );
        assert!(exchange(&s, 1, "", 0).is_err());
    }
    #[test]
    fn replay_is_bounded_and_marks_loss() {
        let s = ConsoleStore::default();
        s.create("vm");
        for n in 1..=80 {
            exchange(&s, n, &"x".repeat(CHUNK_LIMIT), 0).unwrap();
        }
        let snap = s.snapshot("vm", 0).unwrap();
        assert!(snap.truncated);
        assert_eq!(snap.output.len(), 64);
    }
    #[tokio::test]
    async fn guest_http_has_only_session_scoped_capability_and_revocation() {
        let gateway = crate::disposable_gateway::GatewayStore::new(vec![]).unwrap();
        let token = gateway.create_session("vm", None).unwrap();
        let other = gateway.create_session("other", None).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://{}/console/vm/exchange",
            listener.local_addr().unwrap()
        );
        let app = guest_router(gateway.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::new();
        let request = serde_json::json!({"sequence":1,"output_hex":hex::encode("guest TTY"),"acknowledged_command":0});
        assert_eq!(
            client
                .post(&url)
                .json(&request)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            client
                .post(&url)
                .bearer_auth(&other)
                .json(&request)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            client
                .post(&url)
                .bearer_auth(&token)
                .json(&request)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(gateway.console().snapshot("vm", 0).unwrap().output.len(), 1);
        // Retry is idempotent even if the guest lost the response.
        client
            .post(&url)
            .bearer_auth(&token)
            .json(&request)
            .send()
            .await
            .unwrap();
        assert_eq!(gateway.console().snapshot("vm", 0).unwrap().output.len(), 1);
        gateway.revoke_session("vm");
        assert!(gateway
            .console()
            .snapshot("vm", 0)
            .unwrap()
            .output
            .is_empty());
        assert_eq!(
            client
                .post(&url)
                .bearer_auth(&token)
                .json(&request)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        server.abort();
    }
    #[test]
    fn reconnect_sequence_can_resume_after_host_restart() {
        let s = ConsoleStore::default();
        s.create("vm");
        exchange(&s, 93, "running task", 0).unwrap();
        assert_eq!(
            exchange(&s, 93, "running task", 0)
                .unwrap()
                .acknowledged_output,
            93
        );
        assert_eq!(s.snapshot("vm", u64::MAX).unwrap().output.len(), 0);
        assert_eq!(s.snapshot("vm", 0).unwrap().output.len(), 1);
        assert_eq!(
            exchange(&s, 95, "gap", 0).unwrap_err(),
            StatusCode::CONFLICT
        );
    }
    #[test]
    fn host_restart_rebases_fresh_input_above_guest_ack_floor() {
        let s = ConsoleStore::default();
        s.create("vm");
        s.control(
            "vm",
            Control::Attach {
                client_id: "browser".into(),
            },
        )
        .unwrap();
        s.control(
            "vm",
            Control::Input {
                client_id: "browser".into(),
                hex: hex::encode("fresh input"),
            },
        )
        .unwrap();
        let reply = exchange(&s, 93, "continued task", 13).unwrap();
        assert_eq!(reply.commands.len(), 1);
        assert_eq!(reply.commands[0].sequence, 14);
        assert!(exchange(&s, 93, "continued task", 14)
            .unwrap()
            .commands
            .is_empty());
        s.control(
            "vm",
            Control::Resize {
                client_id: "browser".into(),
                cols: 100,
                rows: 30,
            },
        )
        .unwrap();
        assert_eq!(exchange(&s, 93, "", 14).unwrap().commands[0].sequence, 15);
    }

    #[test]
    fn hostile_maximum_sequence_does_not_poison_other_sessions() {
        let s = ConsoleStore::default();
        s.create("vm");
        s.create("other");
        assert_eq!(
            exchange(&s, u64::MAX, "bad", 0).unwrap_err(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            exchange(&s, 1, "bad", u64::MAX).unwrap_err(),
            StatusCode::BAD_REQUEST
        );
        s.exchange(
            "other",
            Exchange {
                sequence: 1,
                output_hex: hex::encode("still works"),
                acknowledged_command: 0,
                exit_code: None,
            },
        )
        .unwrap();
        assert_eq!(s.snapshot("other", 0).unwrap().output.len(), 1);
    }
}

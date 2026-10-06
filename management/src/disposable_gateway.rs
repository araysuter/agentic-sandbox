//! Session-scoped streaming relay. This router belongs on the guest data plane,
//! never on the operator API. Host networking must deny direct guest egress.
use axum::{
    body::{to_bytes, Body},
    extract::{Path, State},
    http::{HeaderMap, Method, Request, StatusCode},
    response::Response,
    routing::any,
    Router,
};
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::sync::{watch, Semaphore};

const REQUEST_LIMIT: usize = 4 * 1024 * 1024;
const RESPONSE_LIMIT: usize = 64 * 1024 * 1024;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointPreset {
    pub id: String,
    pub kind: String,
    pub model_name: Option<String>,
    pub base_url: String,
    pub path_prefixes: Vec<String>,
    pub methods: Vec<String>,
    #[serde(default)]
    pub allow_private: bool,
    pub credential_env: Option<String>,
    #[serde(default = "authorization")]
    pub credential_header: String,
    #[serde(default = "bearer")]
    pub credential_prefix: String,
}
fn authorization() -> String {
    "Authorization".into()
}
fn bearer() -> String {
    "Bearer ".into()
}

#[derive(Clone, Serialize)]
pub struct PresetInfo {
    pub id: String,
    pub kind: String,
    pub model_name: Option<String>,
    pub base_url: String,
    pub path_prefixes: Vec<String>,
    pub methods: Vec<String>,
    pub allow_private: bool,
    /// URL policy does not imply an MCP tool is read-only.
    pub credential_mediated: bool,
}

#[derive(Clone, Serialize)]
pub struct GrantInfo {
    pub id: String,
    pub session_id: String,
    pub preset_id: String,
    pub kind: String,
    pub expires_at: DateTime<Utc>,
    pub gateway_path: String,
    pub base_path: String,
}
struct Grant {
    info: GrantInfo,
    preset: EndpointPreset,
    revoked: watch::Sender<bool>,
    pinned: Mutex<Option<BTreeSet<IpAddr>>>,
}
struct Session {
    token: String,
    deadline: DateTime<Utc>,
}
struct Inner {
    presets: BTreeMap<String, EndpointPreset>,
    traffic: Arc<Semaphore>,
    model: Arc<Semaphore>,
    sessions: Mutex<BTreeMap<String, Session>>,
    grants: Mutex<BTreeMap<String, Arc<Grant>>>,
    #[cfg(test)]
    allow_loopback_fixture: bool,
}
#[derive(Clone)]
pub struct GatewayStore(Arc<Inner>);

impl GatewayStore {
    pub fn from_env() -> Result<Self, String> {
        let presets = match std::env::var("AGENTIC_DISPOSABLE_ENDPOINTS_FILE") {
            Ok(path) => serde_json::from_slice::<Vec<EndpointPreset>>(
                &std::fs::read(path).map_err(|_| "cannot read endpoint presets")?,
            )
            .map_err(|_| "invalid endpoint preset JSON")?,
            Err(_) => Vec::new(),
        };
        Self::new(presets)
    }
    pub fn new(presets: Vec<EndpointPreset>) -> Result<Self, String> {
        let mut configured = BTreeMap::new();
        for preset in presets {
            validate_preset(&preset)?;
            if configured.insert(preset.id.clone(), preset).is_some() {
                return Err("duplicate endpoint preset".into());
            }
        }
        Ok(Self(Arc::new(Inner {
            presets: configured,
            traffic: Arc::new(Semaphore::new(8)),
            model: Arc::new(Semaphore::new(1)),
            sessions: Mutex::new(BTreeMap::new()),
            grants: Mutex::new(BTreeMap::new()),
            #[cfg(test)]
            allow_loopback_fixture: false,
        })))
    }
    pub fn presets(&self) -> Vec<PresetInfo> {
        self.0
            .presets
            .values()
            .map(|p| PresetInfo {
                id: p.id.clone(),
                kind: p.kind.clone(),
                model_name: p.model_name.clone(),
                base_url: p.base_url.clone(),
                path_prefixes: p.path_prefixes.clone(),
                methods: p.methods.clone(),
                allow_private: p.allow_private,
                credential_mediated: p.credential_env.is_some(),
            })
            .collect()
    }
    pub fn create_session(&self, id: &str, deadline: DateTime<Utc>) -> Result<String, String> {
        if !identifier(id) || deadline <= Utc::now() {
            return Err("invalid session or deadline".into());
        }
        let mut sessions = self.0.sessions.lock().unwrap();
        if sessions.contains_key(id) {
            return Err("gateway session already exists".into());
        }
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let token = hex::encode(bytes);
        sessions.insert(
            id.to_owned(),
            Session {
                token: token.clone(),
                deadline,
            },
        );
        Ok(token)
    }
    pub fn guest_capability(&self, id: &str) -> Option<String> {
        self.0
            .sessions
            .lock()
            .unwrap()
            .get(id)
            .map(|s| s.token.clone())
    }
    pub fn create_grant(
        &self,
        session: &str,
        preset_id: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<GrantInfo, String> {
        let sessions = self.0.sessions.lock().unwrap();
        let owner = sessions.get(session).ok_or("unknown gateway session")?;
        if expires_at <= Utc::now() || expires_at > owner.deadline {
            return Err("grant must expire within session deadline".into());
        }
        let preset = self
            .0
            .presets
            .get(preset_id)
            .ok_or("unknown endpoint preset")?
            .clone();
        let id = uuid::Uuid::new_v4().to_string();
        let url = reqwest::Url::parse(&preset.base_url).map_err(|_| "invalid preset URL")?;
        let info = GrantInfo {
            id: id.clone(),
            session_id: session.into(),
            preset_id: preset_id.into(),
            kind: preset.kind.clone(),
            expires_at,
            gateway_path: format!("/gateway/{session}/{id}"),
            base_path: url.path().trim_end_matches('/').to_owned(),
        };
        let (revoked, _) = watch::channel(false);
        self.0.grants.lock().unwrap().insert(
            id,
            Arc::new(Grant {
                info: info.clone(),
                preset,
                revoked,
                pinned: Mutex::new(None),
            }),
        );
        Ok(info)
    }
    pub fn list_grants(&self, session: &str) -> Vec<GrantInfo> {
        self.0
            .grants
            .lock()
            .unwrap()
            .values()
            .filter(|g| {
                g.info.session_id == session
                    && g.info.expires_at > Utc::now()
                    && !*g.revoked.borrow()
            })
            .map(|g| g.info.clone())
            .collect()
    }
    pub fn revoke_grant(&self, id: &str) -> bool {
        if let Some(g) = self.0.grants.lock().unwrap().remove(id) {
            g.revoked.send_replace(true);
            true
        } else {
            false
        }
    }
    pub fn revoke_session(&self, session: &str) {
        self.0.sessions.lock().unwrap().remove(session);
        let mut grants = self.0.grants.lock().unwrap();
        grants.retain(|_, g| {
            if g.info.session_id == session {
                g.revoked.send_replace(true);
                false
            } else {
                true
            }
        });
    }
    fn authorize(
        &self,
        session: &str,
        id: &str,
        headers: &HeaderMap,
    ) -> Result<Arc<Grant>, StatusCode> {
        let sessions = self.0.sessions.lock().unwrap();
        let owner = sessions.get(session).ok_or(StatusCode::UNAUTHORIZED)?;
        let supplied = headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .unwrap_or("");
        if !bool::from(owner.token.as_bytes().ct_eq(supplied.as_bytes()))
            || owner.deadline <= Utc::now()
        {
            return Err(StatusCode::UNAUTHORIZED);
        }
        let grant = self
            .0
            .grants
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or(StatusCode::FORBIDDEN)?;
        if grant.info.session_id != session
            || grant.info.expires_at <= Utc::now()
            || *grant.revoked.borrow()
        {
            return Err(StatusCode::FORBIDDEN);
        }
        Ok(grant)
    }
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn validate_preset(p: &EndpointPreset) -> Result<(), String> {
    if !identifier(&p.id) || !["model", "mcp", "dependency"].contains(&p.kind.as_str()) {
        return Err("invalid endpoint id or kind".into());
    }
    if p.kind == "model"
        && p.model_name
            .as_ref()
            .is_none_or(|n| n.is_empty() || n.len() > 256 || n.chars().any(|c| c.is_control()))
    {
        return Err("model endpoint requires a configured exact model_name".into());
    }
    let url = reqwest::Url::parse(&p.base_url).map_err(|_| "invalid endpoint URL")?;
    if !["http", "https"].contains(&url.scheme())
        || url.host_str().is_none()
        || url.host_str().is_some_and(|h| h.contains('*'))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "endpoint must be an absolute HTTP(S) URL without credentials/query/fragment".into(),
        );
    }
    if p.path_prefixes.is_empty()
        || p.path_prefixes.len() > 16
        || p.path_prefixes.iter().any(|s| !safe_path(s))
        || !safe_path(url.path())
        || p.path_prefixes.iter().any(|s| !path_allowed(s, url.path()))
    {
        return Err("invalid endpoint path scope".into());
    }
    if p.methods.is_empty()
        || p.methods.iter().any(|m| {
            !["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"].contains(&m.as_str())
        })
    {
        return Err("invalid endpoint methods (CONNECT denied)".into());
    }
    if [
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "upgrade",
        "proxy-authorization",
    ]
    .contains(&p.credential_header.to_ascii_lowercase().as_str())
        || reqwest::header::HeaderName::from_bytes(p.credential_header.as_bytes()).is_err()
        || p.credential_prefix.contains(['\r', '\n'])
    {
        return Err("invalid credential header".into());
    }
    if p.credential_env.as_ref().is_some_and(|s| !identifier(s)) {
        return Err("invalid credential environment reference".into());
    }
    Ok(())
}
fn safe_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 2048
        && !path.contains(['%', '\\', '?', '#', ';'])
        && !path.contains("//")
        && !path.split('/').any(|p| p == "." || p == "..")
        && !path.chars().any(|c| c.is_control())
}
fn path_allowed(path: &str, prefix: &str) -> bool {
    prefix == "/"
        || path == prefix
        || path
            .strip_prefix(prefix.trim_end_matches('/'))
            .is_some_and(|suffix| suffix.starts_with('/'))
}
/// Always reject local/metadata/special destinations, even with a private-LAN grant.
fn address_allowed(ip: IpAddr, private: bool) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            if v.is_loopback()
                || v.is_link_local()
                || v.is_unspecified()
                || v.is_multicast()
                || o[0] == 0
                || o[0] >= 240
                || o == [255; 4]
                || o == [100, 100, 100, 200]
                || o == [168, 63, 129, 16]
                || o[..3] == [192, 0, 2]
                || o[..3] == [198, 51, 100]
                || o[..3] == [203, 0, 113]
            {
                false
            } else {
                private
                    || !(v.is_private()
                        || o[0] == 100 && (64..=127).contains(&o[1])
                        || o[0] == 192 && o[1] == 0 && o[2] == 0
                        || o[0] == 198 && (o[1] == 18 || o[1] == 19))
            }
        }
        IpAddr::V6(v) => {
            if let Some(mapped) = v.to_ipv4_mapped() {
                return address_allowed(IpAddr::V4(mapped), private);
            }
            let s = v.segments();
            !v.is_loopback()
                && !v.is_unspecified()
                && !v.is_multicast()
                && s != [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254]
                && s[0] != 0
                && !(s[0] == 0x64 && s[1] == 0xff9b)
                && (s[0] & 0xffc0) != 0xfe80
                && (s[0] & 0xffc0) != 0xfec0
                && ((s[0] & 0xe000) == 0x2000 || private && (s[0] & 0xfe00) == 0xfc00)
                && s[0] != 0x2002
                && !(s[0] == 0x2001
                    && (s[1] == 0 || s[1] == 0x0db8 || s[1] == 0x0010 || s[1] == 0x0020))
        }
    }
}

fn subscribe_active(grant: &Grant) -> Result<watch::Receiver<bool>, ()> {
    let receiver = grant.revoked.subscribe();
    if *receiver.borrow() {
        Err(())
    } else {
        Ok(receiver)
    }
}

pub fn router(store: GatewayStore) -> Router {
    Router::new()
        .route("/gateway/{session}/{grant}/{*path}", any(relay))
        .with_state(store)
}
fn error(status: StatusCode, message: &str) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain")
        .body(Body::from(message.to_owned()))
        .unwrap()
}
async fn relay(
    State(store): State<GatewayStore>,
    Path((session, id, _)): Path<(String, String, String)>,
    request: Request<Body>,
) -> Response {
    let grant = match store.authorize(&session, &id, request.headers()) {
        Ok(g) => g,
        Err(s) => return error(s, "gateway capability or grant denied"),
    };
    let traffic_permit = match store.0.traffic.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return error(
                StatusCode::TOO_MANY_REQUESTS,
                "gateway request capacity busy",
            )
        }
    };
    let model_permit = if grant.info.kind == "model" {
        match store.0.model.clone().try_acquire_owned() {
            Ok(p) => Some(p),
            Err(_) => return error(StatusCode::TOO_MANY_REQUESTS, "model request capacity busy"),
        }
    } else {
        None
    };
    let raw = request.uri().path().to_owned();
    let prefix = format!("/gateway/{session}/{id}");
    let path = raw.strip_prefix(&prefix).unwrap_or("").to_owned();
    if !safe_path(&path)
        || !grant
            .preset
            .path_prefixes
            .iter()
            .any(|p| path_allowed(&path, p))
        || !grant
            .preset
            .methods
            .iter()
            .any(|m| m == request.method().as_str())
        || request.method() == Method::CONNECT
    {
        return error(StatusCode::FORBIDDEN, "endpoint method/path denied");
    }
    let mut revoked = match subscribe_active(&grant) {
        Ok(receiver) => receiver,
        Err(()) => return error(StatusCode::FORBIDDEN, "grant revoked"),
    };
    let lifetime = (grant.info.expires_at - Utc::now())
        .to_std()
        .unwrap_or_default();
    let deadline = tokio::time::Instant::now() + lifetime;
    let operation = async {
        let mut url = reqwest::Url::parse(&grant.preset.base_url)
            .map_err(|_| error(StatusCode::BAD_GATEWAY, "invalid endpoint"))?;
        url.set_path(&path);
        url.set_query(request.uri().query());
        let host = url.host_str().unwrap().to_owned();
        let port = url.port_or_known_default().unwrap();
        let addresses: BTreeSet<IpAddr> = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|_| error(StatusCode::BAD_GATEWAY, "endpoint DNS failed"))?
            .map(|a| a.ip())
            .collect();
        if addresses.is_empty()
            || addresses.iter().any(|ip| {
                #[cfg(test)]
                if store.0.allow_loopback_fixture && ip.is_loopback() {
                    return false;
                }
                !address_allowed(*ip, grant.preset.allow_private)
            })
        {
            return Err(error(
                StatusCode::FORBIDDEN,
                "endpoint DNS destination denied",
            ));
        }
        {
            let mut pinned = grant.pinned.lock().unwrap();
            if let Some(original) = pinned.as_ref() {
                if original != &addresses {
                    return Err(error(
                        StatusCode::FORBIDDEN,
                        "endpoint DNS changed; create a new grant",
                    ));
                }
            } else {
                *pinned = Some(addresses.clone());
            }
        }
        let sockets: Vec<SocketAddr> = addresses
            .iter()
            .map(|ip| SocketAddr::new(*ip, port))
            .collect();
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(&host, &sockets)
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| error(StatusCode::BAD_GATEWAY, "endpoint client failed"))?;
        let mut outbound = client.request(request.method().clone(), url);
        for name in [
            "accept",
            "content-type",
            "mcp-protocol-version",
            "mcp-session-id",
            "last-event-id",
        ] {
            if let Some(value) = request.headers().get(name) {
                outbound = outbound.header(name, value);
            }
        }
        let mut redacted_secret = None;
        if let Some(reference) = &grant.preset.credential_env {
            let secret = std::env::var(reference).map_err(|_| {
                error(
                    StatusCode::BAD_GATEWAY,
                    "host endpoint credential unavailable",
                )
            })?;
            if secret.len() < 8 || secret.len() > 8192 {
                return Err(error(
                    StatusCode::BAD_GATEWAY,
                    "host endpoint credential length denied",
                ));
            }
            redacted_secret = Some(secret.as_bytes().to_vec());
            let value = format!("{}{}", grant.preset.credential_prefix, secret);
            let mut header = reqwest::header::HeaderValue::from_str(&value)
                .map_err(|_| error(StatusCode::BAD_GATEWAY, "invalid host endpoint credential"))?;
            header.set_sensitive(true);
            outbound = outbound.header(&grant.preset.credential_header, header);
        }
        let request_method = request.method().clone();
        let body = to_bytes(request.into_body(), REQUEST_LIMIT)
            .await
            .map_err(|_| {
                error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "gateway request exceeds limit",
                )
            })?;
        if grant.info.kind == "model" && request_method == Method::POST {
            let payload: serde_json::Value = serde_json::from_slice(&body)
                .map_err(|_| error(StatusCode::BAD_REQUEST, "model request must be JSON"))?;
            if payload.get("model").and_then(|v| v.as_str()) != grant.preset.model_name.as_deref() {
                return Err(error(StatusCode::FORBIDDEN, "model identifier denied"));
            }
        }
        if *grant.revoked.borrow() || grant.info.expires_at <= Utc::now() {
            return Err(error(StatusCode::FORBIDDEN, "grant revoked or expired"));
        }
        let upstream = outbound
            .body(body)
            .send()
            .await
            .map_err(|_| error(StatusCode::BAD_GATEWAY, "endpoint request failed"))?;
        if upstream.status().is_redirection() {
            return Err(error(StatusCode::FORBIDDEN, "endpoint redirects denied"));
        }
        Ok((upstream, redacted_secret))
    };
    let (upstream, redacted_secret) = tokio::select! {
        biased;
        _=revoked.changed()=>return error(StatusCode::FORBIDDEN,"grant revoked"),
        _=tokio::time::sleep_until(deadline)=>return error(StatusCode::FORBIDDEN,"grant expired"),
        result=operation=>match result{Ok(r)=>r,Err(response)=>return response},
    };
    if *revoked.borrow() {
        return error(StatusCode::FORBIDDEN, "grant revoked");
    }
    let mut builder = Response::builder().status(upstream.status());
    for name in [
        "content-type",
        "cache-control",
        "mcp-session-id",
        "mcp-protocol-version",
        "retry-after",
    ] {
        if let Some(value) = upstream.headers().get(name) {
            builder = builder.header(name, value);
        }
    }
    let mut stream = upstream.bytes_stream();
    let body = async_stream::stream! {
        let _traffic_permit=traffic_permit;
        let _model_permit=model_permit;
        let mut received=0usize;
        let mut redactor=SecretRedactor::new(redacted_secret);
        loop {
            if *revoked.borrow(){break;}
            tokio::select!{
                biased;
                _=revoked.changed()=>break,
                _=tokio::time::sleep_until(deadline)=>break,
                next=stream.next()=>match next{
                    Some(Ok(chunk))=>{received=received.saturating_add(chunk.len());if received>RESPONSE_LIMIT{yield Err(std::io::Error::other("gateway response exceeds limit"));break;}let safe=redactor.push(&chunk,false);if !safe.is_empty(){yield Ok(bytes::Bytes::from(safe));}},
                    Some(Err(_))=>{yield Err(std::io::Error::other("endpoint response interrupted"));break;},
                    None=>{let safe=redactor.push(&[],true);if !safe.is_empty(){yield Ok(bytes::Bytes::from(safe));}break;},
                },
            }
        }
    };
    builder.body(Body::from_stream(body)).unwrap()
}

// Withhold only an incomplete potential secret suffix, including across chunks.
struct SecretRedactor {
    secret: Option<Vec<u8>>,
    pending: Vec<u8>,
}
impl SecretRedactor {
    fn new(secret: Option<Vec<u8>>) -> Self {
        Self {
            secret,
            pending: Vec::new(),
        }
    }
    fn push(&mut self, chunk: &[u8], finish: bool) -> Vec<u8> {
        let Some(secret) = self.secret.as_ref() else {
            return chunk.to_vec();
        };
        self.pending.extend_from_slice(chunk);
        let mut out = Vec::new();
        let mut cursor = 0;
        while cursor < self.pending.len() {
            if self.pending[cursor..].starts_with(secret) {
                out.extend_from_slice(b"[REDACTED]");
                cursor += secret.len();
                continue;
            }
            let remaining = &self.pending[cursor..];
            if !finish && remaining.len() < secret.len() && secret.starts_with(remaining) {
                break;
            }
            out.push(self.pending[cursor]);
            cursor += 1;
        }
        self.pending.drain(..cursor);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::OriginalUri,
        routing::{get, post},
    };
    fn preset(url: &str) -> EndpointPreset {
        EndpointPreset {
            id: "studio".into(),
            kind: "model".into(),
            model_name: Some("fixture-model".into()),
            base_url: format!("{url}/v1"),
            path_prefixes: vec!["/v1".into()],
            methods: vec!["GET".into(), "POST".into(), "DELETE".into()],
            allow_private: false,
            credential_env: None,
            credential_header: authorization(),
            credential_prefix: bearer(),
        }
    }
    fn fixture_store(url: &str) -> GatewayStore {
        let mut store = GatewayStore::new(vec![preset(url)]).unwrap();
        Arc::get_mut(&mut store.0).unwrap().allow_loopback_fixture = true;
        store
    }
    async fn serve(app: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (address, handle)
    }
    fn session(store: &GatewayStore, seconds: i64) -> (String, GrantInfo) {
        let deadline = Utc::now() + chrono::Duration::seconds(seconds);
        let token = store.create_session("test-session", deadline).unwrap();
        let grant = store
            .create_grant("test-session", "studio", deadline)
            .unwrap();
        (token, grant)
    }
    #[test]
    fn private_addresses_require_explicit_permission_and_special_addresses_never_do() {
        for ip in [
            "127.0.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "2002:7f00:1::1",
            "100.100.100.200",
            "168.63.129.16",
            "fd00:ec2::254",
            "64:ff9b::7f00:1",
            "::a00:1",
        ] {
            assert!(!address_allowed(ip.parse().unwrap(), true), "{ip}");
        }
        for ip in ["10.0.0.1", "192.168.1.5", "172.16.1.1", "fc00::5"] {
            assert!(!address_allowed(ip.parse().unwrap(), false));
            assert!(address_allowed(ip.parse().unwrap(), true));
        }
        assert!(address_allowed(
            "2001:4860:4860::8888".parse().unwrap(),
            false
        ));
    }
    #[test]
    fn paths_and_configuration_fail_closed() {
        for path in [
            "/v1/../admin",
            "/v1/%2e%2e/admin",
            "/v1/%252fadmin",
            "/v1\\admin",
            "//v1",
            "/v1/./x",
        ] {
            assert!(!safe_path(path));
        }
        assert!(!path_allowed("/v11/chat", "/v1"));
        assert!(path_allowed("/v1/chat", "/v1"));
        for url in [
            "http://user:secret@host/v1",
            "http://host/v1?query=x",
            "http://host/v1#fragment",
            "file:///v1",
        ] {
            assert!(GatewayStore::new(vec![preset(url)]).is_err());
        }
        let mut broad = preset("https://host");
        broad.methods = vec!["CONNECT".into()];
        assert!(GatewayStore::new(vec![broad]).is_err());
    }
    #[test]
    fn grant_deadlines_and_authorize_subscribe_revocation_race() {
        let store = fixture_store("http://127.0.0.1");
        let (token, info) = session(&store, 60);
        assert!(store
            .create_grant(
                "test-session",
                "studio",
                Utc::now() + chrono::Duration::minutes(2)
            )
            .is_err());
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        let held = store.authorize("test-session", &info.id, &headers).unwrap();
        assert!(store.revoke_grant(&info.id));
        assert!(
            subscribe_active(&held).is_err(),
            "subscriber created after revocation must not launch request"
        );
        assert!(store.authorize("test-session", &info.id, &headers).is_err());
    }
    #[test]
    fn redaction_handles_chunk_boundaries_and_preserves_unrelated_bytes() {
        let mut r = SecretRedactor::new(Some(b"fixture-secret".to_vec()));
        let a = r.push(b"event: fixture-", false);
        assert_eq!(a, b"event: ");
        let b = r.push(b"secret OK", false);
        assert_eq!(b, b"[REDACTED] OK");
        assert_eq!(r.push(b"fixture-", false), b"");
        assert_eq!(r.push(&[], true), b"fixture-");
    }
    #[tokio::test]
    async fn fixture_model_and_mcp_preserve_streams_methods_headers_and_queries() {
        let upstream=Router::new().route("/v1/chat/completions",post(|headers:HeaderMap,body:String|async move{
            assert_eq!(headers.get("authorization"),None);
            assert!(body.contains("tool_calls"));
            Response::builder().header("content-type","text/event-stream").body(Body::from("data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"name\":\"fixture\"}}]}}]}\n\ndata: [DONE]\n\n")).unwrap()
        })).route("/mcp",post(|headers:HeaderMap,OriginalUri(uri):OriginalUri|async move{
            assert_eq!(uri.query(),Some("fixture=1"));
            assert_eq!(headers.get("mcp-session-id").unwrap(),"opaque-request");
            assert_eq!(headers.get("mcp-protocol-version").unwrap(),"2025-03-26");
            Response::builder().header("mcp-session-id","opaque-session").header("content-type","application/json").body(Body::from("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}")).unwrap()
        }));
        let (up_url, up) = serve(upstream).await;
        let mut mcp = preset(&up_url);
        mcp.id = "mcp".into();
        mcp.kind = "mcp".into();
        mcp.model_name = None;
        mcp.base_url = format!("{up_url}/mcp");
        mcp.path_prefixes = vec!["/mcp".into()];
        let mut store = GatewayStore::new(vec![preset(&up_url), mcp]).unwrap();
        Arc::get_mut(&mut store.0).unwrap().allow_loopback_fixture = true;
        let (token, g) = session(&store, 60);
        let mcp_grant = store
            .create_grant("test-session", "mcp", g.expires_at)
            .unwrap();
        let (gw_url, gw) = serve(router(store)).await;
        let client = reqwest::Client::new();
        let r = client
            .post(format!("{gw_url}{}/v1/chat/completions", g.gateway_path))
            .bearer_auth(&token)
            .header("content-type", "application/json")
            .body("{\"model\":\"fixture-model\",\"tool_calls\":[]}")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert!(r.text().await.unwrap().contains("[DONE]"));
        let denied = client
            .post(format!("{gw_url}{}/v1/chat/completions", g.gateway_path))
            .bearer_auth(&token)
            .body("{\"model\":\"another-model\"}")
            .send()
            .await
            .unwrap();
        assert_eq!(denied.status(), 403, "guest cannot change model selection");
        let r = client
            .post(format!("{gw_url}{}/mcp?fixture=1", mcp_grant.gateway_path))
            .bearer_auth(&token)
            .header("mcp-protocol-version", "2025-03-26")
            .header("mcp-session-id", "opaque-request")
            .body("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}")
            .send()
            .await
            .unwrap();
        assert_eq!(r.headers().get("mcp-session-id").unwrap(), "opaque-session");
        assert!(r.text().await.unwrap().contains("tools"));
        up.abort();
        gw.abort();
    }
    #[tokio::test]
    async fn model_sdk_base_can_have_a_narrow_chat_completion_scope() {
        let (url, up) =
            serve(Router::new().route("/v1/models", get(|| async { "unexpected endpoint" }))).await;
        let mut p = preset(&url);
        p.path_prefixes = vec!["/v1/chat/completions".into()];
        let store =
            GatewayStore::new(vec![p]).expect("SDK base /v1 may have a narrower completion scope");
        let (token, g) = session(&store, 60);
        let (gw_url, gw) = serve(router(store)).await;
        let r = reqwest::Client::new()
            .get(format!("{gw_url}{}/v1/models", g.gateway_path))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403);
        let mut outside = preset(&url);
        outside.path_prefixes = vec!["/admin".into()];
        assert!(
            GatewayStore::new(vec![outside]).is_err(),
            "allowed scope must stay below SDK base"
        );
        up.abort();
        gw.abort();
    }
    #[tokio::test]
    async fn credential_is_host_only_and_failure_response_is_preserved() {
        let reference = format!("GATEWAY_TEST_SECRET_{}", uuid::Uuid::new_v4().simple());
        std::env::set_var(&reference, "fixture-host-secret-1234");
        let (url, up) = serve(Router::new().route(
            "/v1",
            post(|headers: HeaderMap| async move {
                assert_eq!(
                    headers.get("authorization").unwrap(),
                    "Bearer fixture-host-secret-1234"
                );
                Response::builder()
                    .status(429)
                    .header("retry-after", "2")
                    .body(Body::from("fixture-host-secret-1234: rate limited"))
                    .unwrap()
            }),
        ))
        .await;
        let mut p = preset(&url);
        p.credential_env = Some(reference.clone());
        let mut store = GatewayStore::new(vec![p]).unwrap();
        Arc::get_mut(&mut store.0).unwrap().allow_loopback_fixture = true;
        let (token, g) = session(&store, 60);
        let (gw_url, gw) = serve(router(store)).await;
        let r = reqwest::Client::new()
            .post(format!("{gw_url}{}/v1", g.gateway_path))
            .bearer_auth(token)
            .body("{\"model\":\"fixture-model\"}")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 429);
        assert_eq!(r.headers().get("retry-after").unwrap(), "2");
        assert_eq!(r.text().await.unwrap(), "[REDACTED]: rate limited");
        std::env::remove_var(reference);
        up.abort();
        gw.abort();
    }
    #[tokio::test]
    async fn redirects_and_loopback_in_production_store_are_denied() {
        let (url, up) = serve(Router::new().route(
            "/v1",
            get(|| async {
                Response::builder()
                    .status(302)
                    .header("location", "http://169.254.169.254/latest/meta-data/")
                    .body(Body::empty())
                    .unwrap()
            }),
        ))
        .await;
        for allow_fixture in [false, true] {
            let store = if allow_fixture {
                fixture_store(&url)
            } else {
                GatewayStore::new(vec![preset(&url)]).unwrap()
            };
            let (token, g) = session(&store, 60);
            let (gw_url, gw) = serve(router(store)).await;
            let r = reqwest::Client::new()
                .get(format!("{gw_url}{}/v1", g.gateway_path))
                .bearer_auth(token)
                .send()
                .await
                .unwrap();
            assert_eq!(r.status(), 403);
            gw.abort();
        }
        up.abort();
    }
    #[tokio::test]
    async fn dns_address_change_is_denied_even_with_private_permission() {
        let (url, up) = serve(Router::new().route("/v1", get(|| async { "unexpected" }))).await;
        let store = fixture_store(&url);
        let (token, g) = session(&store, 60);
        *store
            .0
            .grants
            .lock()
            .unwrap()
            .get(&g.id)
            .unwrap()
            .pinned
            .lock()
            .unwrap() = Some(["10.0.0.1".parse().unwrap()].into_iter().collect());
        let (gw_url, gw) = serve(router(store)).await;
        let r = reqwest::Client::new()
            .get(format!("{gw_url}{}/v1", g.gateway_path))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403);
        assert!(r.text().await.unwrap().contains("DNS changed"));
        up.abort();
        gw.abort();
    }
    #[tokio::test]
    async fn revocation_and_expiry_close_an_active_sse_stream() {
        let (url,up)=serve(Router::new().route("/v1/events",get(||async{
            let body=async_stream::stream! {yield Ok::<_,std::io::Error>(bytes::Bytes::from_static(b"data: first\n\n")); std::future::pending::<()>().await;};
            Response::builder().header("content-type","text/event-stream").body(Body::from_stream(body)).unwrap()
        }))).await;
        for revoke in [true, false] {
            let store = fixture_store(&url);
            let (token, g) = session(&store, if revoke { 60 } else { 1 });
            let (gw_url, gw) = serve(router(store.clone())).await;
            let r = reqwest::Client::new()
                .get(format!("{gw_url}{}/v1/events", g.gateway_path))
                .bearer_auth(token)
                .send()
                .await
                .unwrap();
            let mut stream = r.bytes_stream();
            assert_eq!(
                stream.next().await.unwrap().unwrap(),
                b"data: first\n\n"[..]
            );
            let second = reqwest::Client::new()
                .get(format!("{gw_url}{}/v1/events", g.gateway_path))
                .bearer_auth(store.guest_capability("test-session").unwrap())
                .send()
                .await
                .unwrap();
            assert_eq!(
                second.status(),
                429,
                "model request capacity must fail immediately while a stream is open"
            );
            if revoke {
                store.revoke_grant(&g.id);
            }
            assert!(tokio::time::timeout(Duration::from_secs(3), stream.next())
                .await
                .unwrap()
                .is_none());
            gw.abort();
        }
        up.abort();
    }
}

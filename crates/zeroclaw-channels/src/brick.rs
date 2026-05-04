//! BrickChannel — local WebSocket bridge for the Brick OS Node.js process.
//!
//! Hosts a tokio-tungstenite WebSocket server over a unix domain socket at
//! `socket_path` (default `/run/brick/zeroclaw.sock`). Filesystem perms
//! (mode 0660 + brick user/group) gate access — there is no in-protocol
//! `auth` frame because anyone with mount-namespace access to the socket
//! is already trusted at the local-user level.
//!
//! Owned end-to-end by the Brick fork at <https://github.com/the-tokenry/zeroclaw>;
//! upstream zeroclaw-labs has no analogue. Tracked in `vendor/PATCHES.md`.
//!
//! Protocol (JSON-over-WS) lives in
//! `packages/sdk/src/types/zeroclaw.ts` on the brick side; the on-wire shape
//! is duplicated here so the daemon doesn't depend on TS-only types.

use anyhow::{Context, Result};
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::time::timeout;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{debug, info, warn};
use uuid::Uuid;
use zeroclaw_api::channel::{
    Channel, ChannelApprovalRequest, ChannelApprovalResponse, ChannelMessage, SendMessage,
};
use zeroclaw_infra::session_store::SessionStore;

/// D1/D2 (plan 3): how long the daemon waits for an `ApprovalResponse`
/// frame before defaulting to Deny. The mobile app's modal sheet has
/// ~25s of attention budget in practice; 30s gives a small grace. The
/// vendor `request_approval` is invoked synchronously from the agent
/// loop, so this also caps how long a single tool-call sit blocks.
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(30);

/// Inbound (apps/os → brick.rs) frame discriminated union.
///
/// `serde(tag = "type")` mirrors the JSON shape documented in
/// `packages/sdk/src/types/zeroclaw.ts`.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InboundFrame {
    Hello {
        client: String,
        version: Option<String>,
    },
    /// Defense-in-depth: when the daemon was constructed with an auth
    /// token, every connection must send `HelloAuth { token }` before
    /// any frame other than `Hello` / `Ping` is honored. Filesystem
    /// perms (mode 0660 + brick:brick) remain the primary gate; this
    /// handshake is the secondary line if perms are misconfigured. See
    /// J7 in plan 3.
    HelloAuth {
        token: String,
    },
    Message {
        sender_id: String,
        reply_target: String,
        thread_ts: Option<String>,
        content: String,
        message_id: String,
    },
    Cancel {
        sender_id: String,
        reply_target: String,
        thread_ts: Option<String>,
        message_id: String,
    },
    ModelSet {
        sender_id: String,
        reply_target: String,
        thread_ts: Option<String>,
        model: String,
    },
    ApprovalResponse {
        sender_id: String,
        request_id: String,
        decision: ApprovalDecision,
    },
    HistoryRequest {
        sender_id: String,
        reply_target: String,
        thread_ts: Option<String>,
        limit: Option<usize>,
    },
    /// Read the model hint last set for this session via `model_set`.
    /// Brick-side counterpart to `ModelSet`; the daemon answers with
    /// `OutboundFrame::ModelGetOk` carrying the cached hint or `null`
    /// when the session is on the fleet default.
    ModelGet {
        sender_id: String,
        reply_target: String,
        thread_ts: Option<String>,
    },
    Ping,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalDecision {
    Approve,
    Deny,
    Always,
}

impl From<ApprovalDecision> for ChannelApprovalResponse {
    fn from(value: ApprovalDecision) -> Self {
        match value {
            ApprovalDecision::Approve => ChannelApprovalResponse::Approve,
            ApprovalDecision::Deny => ChannelApprovalResponse::Deny,
            ApprovalDecision::Always => ChannelApprovalResponse::AlwaysApprove,
        }
    }
}

/// Outbound (brick.rs → apps/os) frame.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OutboundFrame {
    HelloOk {
        daemon_version: String,
    },
    DraftStart {
        sender_id: String,
        draft_id: String,
        conversation_id: String,
    },
    DraftDelta {
        draft_id: String,
        text: String,
    },
    ToolProgress {
        draft_id: String,
        text: String,
    },
    /// C3 (plan 3): structured tool-call start. Carries the tool's
    /// name + arg summary so the brick mobile app can render a
    /// `ToolCallCard` instead of falling back to a thinking blob.
    ToolCallStart {
        draft_id: String,
        tool_id: Option<String>,
        tool_name: String,
        arguments_json: String,
    },
    /// C3: structured tool-call result. Truncated upstream to ~4 KB
    /// for wire economy; the full output is recoverable from the
    /// assistant message persisted in session history.
    ToolCallResult {
        draft_id: String,
        tool_id: Option<String>,
        tool_name: String,
        success: bool,
        output: String,
    },
    DraftFinalize {
        draft_id: String,
        text: String,
    },
    DraftCancel {
        draft_id: String,
    },
    ApprovalRequest {
        sender_id: String,
        request_id: String,
        tool_name: String,
        arguments_summary: String,
    },
    TypingStart {
        sender_id: String,
    },
    TypingStop {
        sender_id: String,
    },
    HistoryResponse {
        sender_id: String,
        reply_target: String,
        messages: Vec<HistoryMessage>,
    },
    ModelSetOk {
        sender_id: String,
        reply_target: String,
        model: String,
    },
    /// Reply to `InboundFrame::ModelGet`. `model` is `Some(hint)` when
    /// the session has been switched off the fleet default via a prior
    /// `ModelSet`; `None` when the session is still on the daemon's
    /// configured default. `thread_ts` echoes the request so concurrent
    /// `model_get` calls across different threads can be matched back
    /// to their waiters precisely.
    ModelGetOk {
        sender_id: String,
        reply_target: String,
        thread_ts: Option<String>,
        model: Option<String>,
    },
    /// Terminal outcome: reply-intent precheck returned NO_REPLY. Brick-os
    /// maps this to a relay `ChatEventPayload` so the app does not watchdog-timeout.
    NoReply {
        sender_id: String,
        message_id: String,
        kind: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        elapsed_ms: u64,
        display_text: String,
    },
    Pong,
}

#[derive(Debug, Clone, Serialize)]
pub struct HistoryMessage {
    pub role: String,
    pub content: String,
    pub ts: u64,
}

type ConnId = u64;

/// One connected apps/os client. We multiplex by `sender_id` (the
/// `<userId>:<deviceId>` tuple), so a single physical brick-os process
/// streaming for multiple users still gets routed correctly.
struct ConnectionEntry {
    tx: mpsc::Sender<OutboundFrame>,
    senders: Vec<String>,
}

/// Routing table. `connections` is the source of truth keyed by connection
/// id; `by_sender` is a denormalized index from `sender_id` to connection
/// ids so `send()` can look up which connections care about a given
/// recipient. We keep both behind a single `Arc<Mutex<…>>` to avoid the
/// classic two-lock TOCTOU.
#[derive(Default)]
struct Router {
    connections: HashMap<ConnId, ConnectionEntry>,
    by_sender: HashMap<String, Vec<ConnId>>,
    next_id: ConnId,
}

impl Router {
    fn register(&mut self, tx: mpsc::Sender<OutboundFrame>) -> ConnId {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.connections.insert(
            id,
            ConnectionEntry {
                tx,
                senders: Vec::new(),
            },
        );
        id
    }

    fn associate(&mut self, conn: ConnId, sender_id: String) {
        if let Some(entry) = self.connections.get_mut(&conn) {
            if !entry.senders.iter().any(|s| s == &sender_id) {
                entry.senders.push(sender_id.clone());
            }
        }
        self.by_sender.entry(sender_id).or_default().push(conn);
    }

    fn drop_conn(&mut self, conn: ConnId) {
        let Some(entry) = self.connections.remove(&conn) else {
            return;
        };
        for sender in entry.senders {
            if let Some(list) = self.by_sender.get_mut(&sender) {
                list.retain(|id| id != &conn);
                if list.is_empty() {
                    self.by_sender.remove(&sender);
                }
            }
        }
    }

    /// Brick is a single-device unix-socket channel — at most a couple
    /// of connections, all owned by the brick-os process on the same
    /// device. There is no multi-tenant routing here, so always broadcast
    /// every outbound frame to every live connection. The `recipient`
    /// argument is intentionally ignored: the daemon orchestrator
    /// dispatches with `recipient = msg.reply_target` (the conversation
    /// id), but brick-os connections register themselves under
    /// `sender_id` (`<userId>:<deviceId>`), and the previous keyed lookup
    /// silently dropped reply frames whose recipient key didn't match
    /// any registered sender_id (the broadcast fallback was supposed to
    /// catch this but a subtle race during the message→reply window
    /// could still elide frames). Always-broadcast is correct for this
    /// channel topology and makes the dispatch path unconditional.
    #[allow(unused_variables)]
    fn senders_for(&self, recipient: &str) -> Vec<mpsc::Sender<OutboundFrame>> {
        self.connections.values().map(|e| e.tx.clone()).collect()
    }
}

/// BrickChannel is the device-local WS bridge. Keep this fork-only — the
/// upstream `Channel` trait is the only seam, so a future rebase only
/// touches the cargo features + the 7 wiring sites in §3.2 of the plan.
///
/// Cancellation is delegated to the orchestrator's existing `/stop` fast
/// path: a `cancel` frame is translated to a synthetic `ChannelMessage`
/// with `content = "/stop"` and pushed onto the same `mpsc::Sender` we
/// receive in `listen()`. The orchestrator picks it up at
/// `is_stop_command(&msg.content)` and cancels the in-flight task for
/// that `(channel, reply_target, sender)` scope. We do not maintain a
/// parallel cancellation registry — that path was never threaded into
/// `SendMessage::with_cancellation()` upstream.
///
/// `workspace_dir` is the daemon's `Config.workspace_dir`, passed at
/// construction so `history_request` can read the JSONL `SessionStore`
/// the orchestrator already writes to via `append_sender_turn`.
pub struct BrickChannel {
    socket_path: PathBuf,
    workspace_dir: PathBuf,
    max_connections: u32,
    daemon_version: String,
    /// J7: if `Some`, the daemon enforces a `HelloAuth { token }`
    /// handshake on every connection. `None` skips enforcement (legacy
    /// behavior — relies on filesystem perms only).
    auth_token: Option<Arc<String>>,
    router: Arc<Mutex<Router>>,
    listening: Arc<Mutex<bool>>,
    /// D1/D2: pending approval requests. Key is the `request_id` we
    /// emit in `OutboundFrame::ApprovalRequest`. The agent loop awaits
    /// the matching `ApprovalResponse` here; the read_loop resolves it
    /// when the brick-os client sends one back.
    pending_approvals: Arc<Mutex<HashMap<String, oneshot::Sender<ApprovalDecision>>>>,
    /// Per-session model hints last set via `ModelSet`. Keyed by
    /// `session_key(sender_id, reply_target, thread_ts)`. The
    /// orchestrator's `route_overrides` is the source of truth for
    /// inference; this map is the read API for `ModelGet` so the mobile
    /// picker can display what the user picked. Updated synchronously
    /// when a `ModelSet` arrives (so a `ModelGet` immediately after
    /// `ModelSetOk` returns the new value, even before the orchestrator
    /// drains the synthetic `/model` command). Lost on daemon restart —
    /// same lifecycle as `route_overrides`.
    session_models: Arc<Mutex<HashMap<String, String>>>,
}

/// Composite key that scopes a model hint to one (sender, reply_target,
/// thread) tuple. Mirrors the (channel, reply_target, sender, thread_ts)
/// shape that `conversation_history_key` uses for the orchestrator's
/// `route_overrides`, but joined with `|` so callers can construct it
/// without knowing the orchestrator's exact format.
fn session_key(sender_id: &str, reply_target: &str, thread_ts: Option<&str>) -> String {
    match thread_ts {
        Some(t) => format!("{sender_id}|{reply_target}|{t}"),
        None => format!("{sender_id}|{reply_target}|"),
    }
}

impl BrickChannel {
    pub fn new(
        socket_path: impl Into<PathBuf>,
        max_connections: u32,
        workspace_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
            workspace_dir: workspace_dir.into(),
            max_connections,
            daemon_version: env!("CARGO_PKG_VERSION").to_string(),
            auth_token: None,
            router: Arc::new(Mutex::new(Router::default())),
            listening: Arc::new(Mutex::new(false)),
            pending_approvals: Arc::new(Mutex::new(HashMap::new())),
            session_models: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Enable J7 in-protocol auth. The daemon writes the token to a
    /// per-boot file at `<workspace_dir>/brick-channel.token` (mode
    /// 0600, owner-only) when `listen()` runs, and rejects frames other
    /// than Hello / HelloAuth / Ping until the client supplies it.
    /// Brick-os reads the file and sends the matching `HelloAuth`
    /// frame after its initial `Hello`.
    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(Arc::new(token.into()));
        self
    }

    async fn dispatch(&self, frame: OutboundFrame, recipient: &str) {
        let txs = {
            let router = self.router.lock().await;
            router.senders_for(recipient)
        };
        for tx in txs {
            // Drop frames on any individual disconnected receiver — the
            // connection's read loop will tear down the entry.
            let _ = tx.send(frame.clone()).await;
        }
    }
}

fn cleanup_socket(path: &PathBuf) {
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            warn!(?path, "failed to unlink stale brick socket: {e}");
        }
    }
}

#[cfg(unix)]
fn set_socket_perms(path: &PathBuf) -> Result<()> {
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, Permissions::from_mode(0o660))
        .with_context(|| format!("set_permissions(0o660) on {}", path.display()))
}

#[cfg(not(unix))]
fn set_socket_perms(_path: &PathBuf) -> Result<()> {
    Ok(())
}

#[async_trait]
impl Channel for BrickChannel {
    fn name(&self) -> &str {
        "brick"
    }

    async fn listen(&self, tx: mpsc::Sender<ChannelMessage>) -> Result<()> {
        cleanup_socket(&self.socket_path);
        if let Some(parent) = self.socket_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("mkdir -p {}", parent.display()))?;
        }
        let listener = UnixListener::bind(&self.socket_path)
            .with_context(|| format!("bind {}", self.socket_path.display()))?;
        set_socket_perms(&self.socket_path)?;

        // J7: persist the auth token so brick-os can read it. Mode 0600
        // because only the daemon owner needs to read it (brick-os runs
        // as the same user). No-op when auth_token is None.
        if let Some(token) = self.auth_token.as_ref() {
            let token_path = self.workspace_dir.join("brick-channel.token");
            if let Some(parent) = token_path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("mkdir -p {}", parent.display()))?;
            }
            std::fs::write(&token_path, token.as_bytes())
                .with_context(|| format!("write token {}", token_path.display()))?;
            #[cfg(unix)]
            {
                use std::fs::Permissions;
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&token_path, Permissions::from_mode(0o600))
                    .with_context(|| format!("chmod 0600 {}", token_path.display()))?;
            }
            info!(token_path = ?token_path, "BrickChannel auth token written");
        }

        {
            let mut listening = self.listening.lock().await;
            *listening = true;
        }

        info!(
            socket = ?self.socket_path,
            max_connections = self.max_connections,
            "BrickChannel listening"
        );

        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.max_connections as usize));
        loop {
            let (stream, _addr) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    warn!("brick: accept error: {e}");
                    continue;
                }
            };
            let permit = match semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(e) => {
                    warn!("brick: semaphore closed unexpectedly: {e}");
                    break;
                }
            };
            let router = self.router.clone();
            let inbound_tx = tx.clone();
            let daemon_version = self.daemon_version.clone();
            let workspace_dir = self.workspace_dir.clone();
            let auth_token = self.auth_token.clone();
            let pending_approvals = self.pending_approvals.clone();
            let session_models = self.session_models.clone();

            tokio::spawn(async move {
                if let Err(err) = handle_connection(
                    stream,
                    router,
                    inbound_tx,
                    daemon_version,
                    workspace_dir,
                    auth_token,
                    pending_approvals,
                    session_models,
                )
                .await
                {
                    debug!("brick: connection ended: {err:?}");
                }
                drop(permit);
            });
        }
        Ok(())
    }

    async fn send(&self, message: &SendMessage) -> Result<()> {
        let recipient = message.recipient.clone();
        let frame = OutboundFrame::DraftFinalize {
            draft_id: derive_draft_id(&recipient, message.thread_ts.as_deref()),
            text: message.content.clone(),
        };
        self.dispatch(frame, &recipient).await;
        Ok(())
    }

    fn supports_draft_updates(&self) -> bool {
        true
    }

    async fn send_draft(&self, message: &SendMessage) -> Result<Option<String>> {
        let recipient = message.recipient.clone();
        let draft_id = derive_draft_id(&recipient, message.thread_ts.as_deref());
        self.dispatch(
            OutboundFrame::DraftStart {
                sender_id: recipient.clone(),
                draft_id: draft_id.clone(),
                conversation_id: recipient.clone(),
            },
            &recipient,
        )
        .await;
        if !message.content.is_empty() {
            self.dispatch(
                OutboundFrame::DraftDelta {
                    draft_id: draft_id.clone(),
                    text: message.content.clone(),
                },
                &recipient,
            )
            .await;
        }
        Ok(Some(draft_id))
    }

    async fn update_draft(&self, recipient: &str, message_id: &str, text: &str) -> Result<()> {
        self.dispatch(
            OutboundFrame::DraftDelta {
                draft_id: message_id.to_string(),
                text: text.to_string(),
            },
            recipient,
        )
        .await;
        Ok(())
    }

    async fn update_draft_progress(
        &self,
        recipient: &str,
        message_id: &str,
        text: &str,
    ) -> Result<()> {
        self.dispatch(
            OutboundFrame::ToolProgress {
                draft_id: message_id.to_string(),
                text: text.to_string(),
            },
            recipient,
        )
        .await;
        Ok(())
    }

    async fn tool_call_start(
        &self,
        recipient: &str,
        message_id: &str,
        tool_id: Option<&str>,
        tool_name: &str,
        arguments_json: &str,
    ) -> Result<()> {
        self.dispatch(
            OutboundFrame::ToolCallStart {
                draft_id: message_id.to_string(),
                tool_id: tool_id.map(str::to_string),
                tool_name: tool_name.to_string(),
                arguments_json: arguments_json.to_string(),
            },
            recipient,
        )
        .await;
        Ok(())
    }

    async fn tool_call_result(
        &self,
        recipient: &str,
        message_id: &str,
        tool_id: Option<&str>,
        tool_name: &str,
        success: bool,
        output: &str,
    ) -> Result<()> {
        self.dispatch(
            OutboundFrame::ToolCallResult {
                draft_id: message_id.to_string(),
                tool_id: tool_id.map(str::to_string),
                tool_name: tool_name.to_string(),
                success,
                output: output.to_string(),
            },
            recipient,
        )
        .await;
        Ok(())
    }

    async fn finalize_draft(&self, recipient: &str, message_id: &str, text: &str) -> Result<()> {
        self.dispatch(
            OutboundFrame::DraftFinalize {
                draft_id: message_id.to_string(),
                text: text.to_string(),
            },
            recipient,
        )
        .await;
        Ok(())
    }

    async fn cancel_draft(&self, recipient: &str, message_id: &str) -> Result<()> {
        self.dispatch(
            OutboundFrame::DraftCancel {
                draft_id: message_id.to_string(),
            },
            recipient,
        )
        .await;
        Ok(())
    }

    async fn notify_no_reply(
        &self,
        recipient: &str,
        sender_id: &str,
        user_message_id: &str,
        kind: &str,
        reason: Option<&str>,
        elapsed_ms: u64,
        display_text: &str,
    ) -> Result<()> {
        self.dispatch(
            OutboundFrame::NoReply {
                sender_id: sender_id.to_string(),
                message_id: user_message_id.to_string(),
                kind: kind.to_string(),
                reason: reason.map(str::to_string),
                elapsed_ms,
                display_text: display_text.to_string(),
            },
            recipient,
        )
        .await;
        Ok(())
    }

    async fn request_approval(
        &self,
        recipient: &str,
        request: &ChannelApprovalRequest,
    ) -> Result<Option<ChannelApprovalResponse>> {
        // D1/D2: real round-trip. Emit `ApprovalRequest`, register a
        // oneshot waiter keyed by request_id, await the matching
        // `ApprovalResponse` from brick-os (which proxies the user's
        // tap from the mobile app). Times out at APPROVAL_TIMEOUT and
        // defaults to Deny so the agent doesn't wedge if the mobile
        // app is offline.
        let request_id = Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel::<ApprovalDecision>();
        {
            let mut pending = self.pending_approvals.lock().await;
            pending.insert(request_id.clone(), tx);
        }
        self.dispatch(
            OutboundFrame::ApprovalRequest {
                sender_id: recipient.to_string(),
                request_id: request_id.clone(),
                tool_name: request.tool_name.clone(),
                arguments_summary: request.arguments_summary.clone(),
            },
            recipient,
        )
        .await;

        let decision = match timeout(APPROVAL_TIMEOUT, rx).await {
            Ok(Ok(d)) => d,
            Ok(Err(_)) => {
                warn!(
                    request_id,
                    "brick: approval waiter dropped — defaulting to Deny"
                );
                ApprovalDecision::Deny
            }
            Err(_) => {
                warn!(request_id, "brick: approval timed out — defaulting to Deny");
                // Best-effort cleanup so the entry doesn't leak forever.
                let mut pending = self.pending_approvals.lock().await;
                pending.remove(&request_id);
                ApprovalDecision::Deny
            }
        };
        Ok(Some(ChannelApprovalResponse::from(decision)))
    }

    async fn start_typing(&self, recipient: &str) -> Result<()> {
        self.dispatch(
            OutboundFrame::TypingStart {
                sender_id: recipient.to_string(),
            },
            recipient,
        )
        .await;
        Ok(())
    }

    async fn stop_typing(&self, recipient: &str) -> Result<()> {
        self.dispatch(
            OutboundFrame::TypingStop {
                sender_id: recipient.to_string(),
            },
            recipient,
        )
        .await;
        Ok(())
    }

    async fn health_check(&self) -> bool {
        // True iff `listen()` has bound the socket. Doctor / `/api/health`
        // surface this directly; cargo tests also gate on it.
        *self.listening.lock().await
    }
}

fn derive_draft_id(recipient: &str, thread: Option<&str>) -> String {
    match thread {
        Some(ts) => format!("brick-{recipient}-{ts}"),
        None => format!("brick-{recipient}"),
    }
}

async fn handle_connection(
    stream: UnixStream,
    router: Arc<Mutex<Router>>,
    inbound_tx: mpsc::Sender<ChannelMessage>,
    daemon_version: String,
    workspace_dir: PathBuf,
    auth_token: Option<Arc<String>>,
    pending_approvals: Arc<Mutex<HashMap<String, oneshot::Sender<ApprovalDecision>>>>,
    session_models: Arc<Mutex<HashMap<String, String>>>,
) -> Result<()> {
    let ws: WebSocketStream<UnixStream> = tokio_tungstenite::accept_async(stream)
        .await
        .context("ws accept")?;
    let (mut writer, mut reader) = ws.split();

    let (out_tx, mut out_rx) = mpsc::channel::<OutboundFrame>(64);
    let conn_id = {
        let mut router = router.lock().await;
        router.register(out_tx.clone())
    };

    // Pump outbound frames serialized as text WS messages. J1 (plan 3):
    // each send is wrapped in a 10s timeout — a stuck writer (rare, but
    // possible under unix-socket back-pressure when apps/os is wedged)
    // would otherwise block this task forever and leak the connection.
    // On timeout we drop the connection so the brick-os channel client
    // reconnects and resyncs from history.
    let writer_task = tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            let payload = match serde_json::to_string(&frame) {
                Ok(s) => s,
                Err(e) => {
                    warn!("brick: serialize outbound: {e}");
                    continue;
                }
            };
            let send = writer.send(WsMessage::Text(payload.into()));
            match tokio::time::timeout(std::time::Duration::from_secs(10), send).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    debug!("brick: ws send error: {e}");
                    break;
                }
                Err(_) => {
                    warn!("brick: ws send timed out after 10s, dropping connection");
                    break;
                }
            }
        }
    });

    // Inbound loop.
    let result = read_loop(
        &mut reader,
        &router,
        conn_id,
        &inbound_tx,
        &daemon_version,
        &workspace_dir,
        auth_token.as_deref().map(String::as_str),
        &pending_approvals,
        &session_models,
    )
    .await;

    // Drop the outbound channel + connection registration.
    drop(out_tx);
    {
        let mut router = router.lock().await;
        router.drop_conn(conn_id);
    }
    let _ = writer_task.await;

    result
}

async fn read_loop(
    reader: &mut futures_util::stream::SplitStream<WebSocketStream<UnixStream>>,
    router: &Arc<Mutex<Router>>,
    conn_id: ConnId,
    inbound_tx: &mpsc::Sender<ChannelMessage>,
    daemon_version: &str,
    workspace_dir: &PathBuf,
    auth_token: Option<&str>,
    pending_approvals: &Arc<Mutex<HashMap<String, oneshot::Sender<ApprovalDecision>>>>,
    session_models: &Arc<Mutex<HashMap<String, String>>>,
) -> Result<()> {
    // J7: when auth is enabled, every frame other than Hello / HelloAuth /
    // Ping is rejected until the client sends matching `HelloAuth { token }`.
    let mut authed = auth_token.is_none();
    while let Some(item) = reader.next().await {
        let msg = match item {
            Ok(m) => m,
            Err(e) => {
                debug!("brick: ws read error: {e}");
                break;
            }
        };
        let text = match msg {
            WsMessage::Text(t) => t,
            WsMessage::Close(_) => break,
            WsMessage::Ping(_) | WsMessage::Pong(_) => continue,
            // Binary frames are not part of the BrickChannel protocol —
            // drop the connection so the client doesn't think we silently
            // accepted them.
            WsMessage::Binary(_) | WsMessage::Frame(_) => {
                warn!("brick: rejecting non-text frame");
                break;
            }
        };

        let frame: InboundFrame = match serde_json::from_str(&text) {
            Ok(f) => f,
            Err(e) => {
                warn!("brick: malformed frame: {e}");
                // Per the protocol contract: malformed JSON or an unknown
                // discriminator closes the connection. Apps/os reconnects
                // automatically.
                break;
            }
        };

        // J7: gate non-handshake frames behind auth when enabled. Hello,
        // HelloAuth, and Ping are always allowed pre-auth so the client
        // can complete the handshake and keep connections alive.
        let pre_auth_allowed = matches!(
            frame,
            InboundFrame::Hello { .. } | InboundFrame::HelloAuth { .. } | InboundFrame::Ping
        );
        if !authed && !pre_auth_allowed {
            warn!("brick: dropping pre-auth frame (waiting for HelloAuth)");
            continue;
        }

        match frame {
            InboundFrame::Hello { client, version: _ } => {
                debug!(client, "brick: hello from client");
                let r = router.lock().await;
                if let Some(entry) = r.connections.get(&conn_id) {
                    let _ = entry.tx.try_send(OutboundFrame::HelloOk {
                        daemon_version: daemon_version.to_string(),
                    });
                }
            }
            InboundFrame::HelloAuth { token } => {
                match auth_token {
                    Some(expected) if expected == token => {
                        authed = true;
                        debug!("brick: HelloAuth accepted");
                    }
                    Some(_) => {
                        warn!("brick: HelloAuth token mismatch — closing connection");
                        break;
                    }
                    None => {
                        // Auth disabled — accept silently for forward
                        // compat (the client is fine to send it).
                        authed = true;
                    }
                }
            }
            InboundFrame::Message {
                sender_id,
                reply_target,
                thread_ts,
                content,
                message_id,
            } => {
                {
                    let mut r = router.lock().await;
                    r.associate(conn_id, sender_id.clone());
                }
                let cm = ChannelMessage {
                    id: message_id,
                    sender: sender_id,
                    reply_target,
                    content,
                    channel: "brick".to_string(),
                    timestamp: now_secs(),
                    thread_ts,
                    interruption_scope_id: None,
                    attachments: vec![],
                };
                if inbound_tx.send(cm).await.is_err() {
                    break;
                }
            }
            InboundFrame::Cancel {
                sender_id,
                reply_target,
                thread_ts,
                message_id,
            } => {
                // Inject a synthetic `/stop` ChannelMessage with the same
                // (channel, reply_target, sender) scope as the in-flight
                // turn. The orchestrator's existing `is_stop_command` fast
                // path picks this up and cancels the running task via its
                // already-built `with_cancellation()` plumbing — no
                // parallel cancellation registry needed.
                let cm = ChannelMessage {
                    id: message_id,
                    sender: sender_id,
                    reply_target,
                    content: "/stop".to_string(),
                    channel: "brick".to_string(),
                    timestamp: now_secs(),
                    thread_ts,
                    interruption_scope_id: None,
                    attachments: vec![],
                };
                if inbound_tx.send(cm).await.is_err() {
                    break;
                }
            }
            InboundFrame::ModelSet {
                sender_id,
                reply_target,
                thread_ts,
                model,
            } => {
                // Inject a synthetic `/model hint:<id>` command into the
                // dispatch loop so the orchestrator's existing
                // model-switch path handles it. Suppress the textual
                // ack — the channel's outbound `model_set_ok` is the
                // user-facing response.
                {
                    let mut r = router.lock().await;
                    r.associate(conn_id, sender_id.clone());
                }
                // Update the brick.rs read cache before dispatching the
                // synthetic /model so a `ModelGet` issued immediately
                // after `ModelSetOk` reflects the user's pick — even if
                // the orchestrator hasn't drained the inbound channel
                // yet.
                {
                    let key = session_key(&sender_id, &reply_target, thread_ts.as_deref());
                    let mut models = session_models.lock().await;
                    models.insert(key, model.clone());
                }
                let cm = ChannelMessage {
                    id: format!("brick-model-{}", Uuid::new_v4()),
                    sender: sender_id.clone(),
                    reply_target: reply_target.clone(),
                    content: format!("/model {model}"),
                    channel: "brick".to_string(),
                    timestamp: now_secs(),
                    thread_ts: thread_ts.clone(),
                    interruption_scope_id: None,
                    attachments: vec![],
                };
                if inbound_tx.send(cm).await.is_err() {
                    break;
                }
                let r = router.lock().await;
                if let Some(entry) = r.connections.get(&conn_id) {
                    let _ = entry.tx.try_send(OutboundFrame::ModelSetOk {
                        sender_id,
                        reply_target,
                        model,
                    });
                }
            }
            InboundFrame::ModelGet {
                sender_id,
                reply_target,
                thread_ts,
            } => {
                let key = session_key(&sender_id, &reply_target, thread_ts.as_deref());
                let model = session_models.lock().await.get(&key).cloned();
                let r = router.lock().await;
                if let Some(entry) = r.connections.get(&conn_id) {
                    let _ = entry.tx.try_send(OutboundFrame::ModelGetOk {
                        sender_id,
                        reply_target,
                        thread_ts,
                        model,
                    });
                }
            }
            InboundFrame::ApprovalResponse {
                sender_id: _,
                request_id,
                decision,
            } => {
                // D1/D2: resolve the matching oneshot. If the waiter
                // was already removed (timeout) or unknown, log and
                // drop — the agent loop has already moved on.
                let mut pending = pending_approvals.lock().await;
                match pending.remove(&request_id) {
                    Some(tx) => {
                        if tx.send(decision).is_err() {
                            debug!(request_id, "brick: approval waiter dropped before resolve");
                        }
                    }
                    None => {
                        warn!(
                            request_id,
                            "brick: approval response for unknown request_id"
                        );
                    }
                }
            }
            InboundFrame::HistoryRequest {
                sender_id,
                reply_target,
                thread_ts,
                limit,
            } => {
                // Read from the JSONL `SessionStore` the orchestrator
                // already writes to via `append_sender_turn`. Key shape
                // mirrors `conversation_history_key()` exactly so the
                // brick channel never disagrees with what the agent
                // hydrates on startup.
                let key = match thread_ts.as_deref() {
                    Some(tid) => format!("brick_{reply_target}_{tid}_{sender_id}"),
                    None => format!("brick_{reply_target}_{sender_id}"),
                };
                let mut messages: Vec<HistoryMessage> = match SessionStore::new(workspace_dir) {
                    Ok(store) => store
                        .load(&key)
                        .into_iter()
                        .map(|m| HistoryMessage {
                            role: m.role,
                            content: m.content,
                            // SessionStore JSONL doesn't preserve
                            // per-message timestamps; surface 0 so apps/os
                            // can sort by index instead.
                            ts: 0,
                        })
                        .collect(),
                    Err(e) => {
                        warn!("brick: SessionStore open failed: {e}");
                        Vec::new()
                    }
                };
                if let Some(n) = limit {
                    if messages.len() > n {
                        let drop_count = messages.len() - n;
                        messages.drain(..drop_count);
                    }
                }
                let r = router.lock().await;
                if let Some(entry) = r.connections.get(&conn_id) {
                    let _ = entry.tx.try_send(OutboundFrame::HistoryResponse {
                        sender_id,
                        reply_target,
                        messages,
                    });
                }
            }
            InboundFrame::Ping => {
                let r = router.lock().await;
                if let Some(entry) = r.connections.get(&conn_id) {
                    let _ = entry.tx.try_send(OutboundFrame::Pong);
                }
            }
        }
    }

    Ok(())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;
    use tokio::time::{Duration, timeout};

    #[test]
    fn brick_channel_name() {
        let bc = BrickChannel::new("/tmp/brick-test.sock", 4, "/tmp");
        assert_eq!(bc.name(), "brick");
    }

    #[tokio::test]
    async fn health_check_false_before_listen() {
        let bc = BrickChannel::new("/tmp/brick-not-bound.sock", 4, "/tmp");
        assert!(!bc.health_check().await);
    }

    #[tokio::test]
    async fn listen_binds_socket_with_correct_perms() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("zeroclaw.sock");
        let bc = Arc::new(BrickChannel::new(&sock, 2, dir.path()));
        let bc_clone = bc.clone();
        let (tx, _rx) = mpsc::channel(1);

        let handle = tokio::spawn(async move {
            let _ = bc_clone.listen(tx).await;
        });

        // Wait for `health_check` to flip true (max 1s) — the listener
        // sets `*listening = true` immediately after bind.
        let mut bound = false;
        for _ in 0..50 {
            if bc.health_check().await {
                bound = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(bound, "BrickChannel did not bind socket");

        let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660, "socket perms must be 0660 (got {mode:o})");

        handle.abort();
    }

    #[tokio::test]
    async fn ping_pong_round_trip() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("zeroclaw.sock");
        let bc = Arc::new(BrickChannel::new(&sock, 2, dir.path()));
        let bc_clone = bc.clone();
        let (tx, _rx) = mpsc::channel(8);
        let handle = tokio::spawn(async move {
            let _ = bc_clone.listen(tx).await;
        });

        // Wait for bind.
        for _ in 0..50 {
            if bc.health_check().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let stream = UnixStream::connect(&sock).await.expect("connect");
        let url = format!("ws+unix://{}", sock.display());
        // tokio-tungstenite doesn't speak ws+unix natively — we open the
        // unix stream ourselves and use `client_async` so the WS handshake
        // runs over it.
        let req = format!(
            "ws://localhost{}",
            sock.file_name().unwrap().to_string_lossy()
        );
        let (ws, _resp) = tokio_tungstenite::client_async(req, stream)
            .await
            .expect("client handshake");
        let _ = url;

        let (mut wsx, mut wrx) = ws.split();
        wsx.send(WsMessage::Text("{\"type\":\"ping\"}".into()))
            .await
            .unwrap();

        let pong = timeout(Duration::from_secs(2), wrx.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        match pong {
            WsMessage::Text(t) => {
                assert!(t.contains("pong"), "expected pong, got {t}");
            }
            other => panic!("expected text frame, got {other:?}"),
        }

        handle.abort();
    }

    #[tokio::test]
    async fn malformed_json_closes_connection() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("zeroclaw.sock");
        let bc = Arc::new(BrickChannel::new(&sock, 2, dir.path()));
        let bc_clone = bc.clone();
        let (tx, _rx) = mpsc::channel(8);
        let handle = tokio::spawn(async move {
            let _ = bc_clone.listen(tx).await;
        });

        for _ in 0..50 {
            if bc.health_check().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let stream = UnixStream::connect(&sock).await.expect("connect");
        let req = "ws://localhost/";
        let (ws, _resp) = tokio_tungstenite::client_async(req, stream)
            .await
            .expect("client handshake");
        let (mut wsx, mut wrx) = ws.split();
        wsx.send(WsMessage::Text("not-json".into())).await.unwrap();

        // The next read should resolve to either Close or stream end.
        let next = timeout(Duration::from_secs(2), wrx.next()).await;
        match next {
            Ok(Some(Ok(WsMessage::Close(_)))) | Ok(None) | Ok(Some(Err(_))) => {}
            other => panic!("expected close after malformed frame, got {other:?}"),
        }

        handle.abort();
    }

    #[test]
    fn approval_decision_maps_to_channel_response() {
        assert_eq!(
            ChannelApprovalResponse::from(ApprovalDecision::Approve),
            ChannelApprovalResponse::Approve
        );
        assert_eq!(
            ChannelApprovalResponse::from(ApprovalDecision::Deny),
            ChannelApprovalResponse::Deny
        );
        assert_eq!(
            ChannelApprovalResponse::from(ApprovalDecision::Always),
            ChannelApprovalResponse::AlwaysApprove
        );
    }

    #[test]
    fn outbound_frame_serializes_with_snake_case_tag() {
        let frame = OutboundFrame::Pong;
        let json = serde_json::to_string(&frame).unwrap();
        assert_eq!(json, "{\"type\":\"pong\"}");

        let draft = OutboundFrame::DraftDelta {
            draft_id: "d1".into(),
            text: "hi".into(),
        };
        let json = serde_json::to_string(&draft).unwrap();
        assert!(json.contains("\"type\":\"draft_delta\""), "got {json}");
        assert!(json.contains("\"draft_id\":\"d1\""), "got {json}");
    }

    #[test]
    fn draft_lifecycle_frames_round_trip() {
        // Lock in the on-wire shape for the full draft lifecycle so apps/os
        // can rely on field names not silently changing across rebases.
        let start = OutboundFrame::DraftStart {
            sender_id: "u:d".into(),
            draft_id: "draft-1".into(),
            conversation_id: "u:d".into(),
        };
        let s = serde_json::to_string(&start).unwrap();
        assert!(s.contains("\"type\":\"draft_start\""));
        assert!(s.contains("\"sender_id\":\"u:d\""));
        assert!(s.contains("\"draft_id\":\"draft-1\""));

        let final_ = OutboundFrame::DraftFinalize {
            draft_id: "draft-1".into(),
            text: "done".into(),
        };
        let s = serde_json::to_string(&final_).unwrap();
        assert!(s.contains("\"type\":\"draft_finalize\""));
        assert!(s.contains("\"text\":\"done\""));

        let cancel = OutboundFrame::DraftCancel {
            draft_id: "draft-1".into(),
        };
        let s = serde_json::to_string(&cancel).unwrap();
        assert!(s.contains("\"type\":\"draft_cancel\""));
        assert!(s.contains("\"draft_id\":\"draft-1\""));

        let progress = OutboundFrame::ToolProgress {
            draft_id: "draft-1".into(),
            text: "running tool".into(),
        };
        let s = serde_json::to_string(&progress).unwrap();
        assert!(s.contains("\"type\":\"tool_progress\""));

        let no_reply = OutboundFrame::NoReply {
            sender_id: "u:d".into(),
            message_id: "m1".into(),
            kind: "informational".into(),
            reason: Some("because".into()),
            elapsed_ms: 42,
            display_text: "  🤖 No reply [Informational] (42ms): because".into(),
        };
        let s = serde_json::to_string(&no_reply).unwrap();
        assert!(s.contains("\"type\":\"no_reply\""));
        assert!(s.contains("\"message_id\":\"m1\""));
        assert!(s.contains("\"kind\":\"informational\""));
        assert!(s.contains("\"elapsed_ms\":42"));

        let history = OutboundFrame::HistoryResponse {
            sender_id: "u:d".into(),
            reply_target: "conv1".into(),
            messages: vec![HistoryMessage {
                role: "user".into(),
                content: "hi".into(),
                ts: 0,
            }],
        };
        let s = serde_json::to_string(&history).unwrap();
        assert!(s.contains("\"type\":\"history_response\""));
        assert!(s.contains("\"reply_target\":\"conv1\""));
        assert!(s.contains("\"role\":\"user\""));
    }

    #[tokio::test]
    async fn cancel_frame_injects_synthetic_stop_message() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("zeroclaw.sock");
        let bc = Arc::new(BrickChannel::new(&sock, 2, dir.path()));
        let bc_clone = bc.clone();
        let (tx, mut rx) = mpsc::channel::<ChannelMessage>(8);
        let handle = tokio::spawn(async move {
            let _ = bc_clone.listen(tx).await;
        });

        for _ in 0..50 {
            if bc.health_check().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let stream = UnixStream::connect(&sock).await.expect("connect");
        let req = "ws://localhost/";
        let (ws, _resp) = tokio_tungstenite::client_async(req, stream)
            .await
            .expect("client handshake");
        let (mut wsx, _wrx) = ws.split();

        let cancel_payload = serde_json::json!({
            "type": "cancel",
            "sender_id": "user1:dev1",
            "reply_target": "conv-42",
            "thread_ts": null,
            "message_id": "msg-cancel-1"
        });
        wsx.send(WsMessage::Text(cancel_payload.to_string().into()))
            .await
            .unwrap();

        let cm = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("rx timed out")
            .expect("rx closed");

        assert_eq!(cm.channel, "brick");
        assert_eq!(cm.content, "/stop");
        assert_eq!(cm.sender, "user1:dev1");
        assert_eq!(cm.reply_target, "conv-42");
        assert!(cm.thread_ts.is_none());
        assert_eq!(cm.id, "msg-cancel-1");

        handle.abort();
    }

    #[tokio::test]
    async fn history_request_returns_persisted_jsonl_messages() {
        use zeroclaw_api::provider::ChatMessage;

        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("zeroclaw.sock");

        // Seed the JSONL session store under the brick channel's
        // conversation_history_key shape: brick_<reply_target>_<sender>.
        {
            let store = SessionStore::new(dir.path()).expect("session store");
            let key = "brick_conv-42_user1:dev1";
            store.append(key, &ChatMessage::user("hello")).unwrap();
            store
                .append(key, &ChatMessage::assistant("hi back"))
                .unwrap();
        }

        let bc = Arc::new(BrickChannel::new(&sock, 2, dir.path()));
        let bc_clone = bc.clone();
        let (tx, _rx) = mpsc::channel::<ChannelMessage>(8);
        let handle = tokio::spawn(async move {
            let _ = bc_clone.listen(tx).await;
        });

        for _ in 0..50 {
            if bc.health_check().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let stream = UnixStream::connect(&sock).await.expect("connect");
        let req = "ws://localhost/";
        let (ws, _resp) = tokio_tungstenite::client_async(req, stream)
            .await
            .expect("client handshake");
        let (mut wsx, mut wrx) = ws.split();

        let payload = serde_json::json!({
            "type": "history_request",
            "sender_id": "user1:dev1",
            "reply_target": "conv-42",
            "thread_ts": null,
            "limit": null,
        });
        wsx.send(WsMessage::Text(payload.to_string().into()))
            .await
            .unwrap();

        let response_text = loop {
            let frame = timeout(Duration::from_secs(2), wrx.next())
                .await
                .expect("history response timeout")
                .expect("ws closed")
                .expect("ws error");
            if let WsMessage::Text(t) = frame {
                if t.contains("\"type\":\"history_response\"") {
                    break t;
                }
            }
        };

        let parsed: serde_json::Value =
            serde_json::from_str(&response_text).expect("response is JSON");
        assert_eq!(parsed["sender_id"], "user1:dev1");
        assert_eq!(parsed["reply_target"], "conv-42");
        let messages = parsed["messages"].as_array().expect("messages array");
        assert_eq!(messages.len(), 2, "expected two persisted turns");
        assert_eq!(messages[0]["role"], "user");
        assert_eq!(messages[0]["content"], "hello");
        assert_eq!(messages[1]["role"], "assistant");
        assert_eq!(messages[1]["content"], "hi back");

        handle.abort();
    }

    #[tokio::test]
    async fn approval_round_trip_resolves_with_user_decision() {
        // D1/D2: send ApprovalRequest, register a waiter via
        // request_approval, simulate the brick-os ApprovalResponse, and
        // assert the agent loop's caller observes the right decision.
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("zeroclaw.sock");
        let bc = Arc::new(BrickChannel::new(&sock, 2, dir.path()));
        let bc_clone = bc.clone();
        let (tx, _rx) = mpsc::channel::<ChannelMessage>(8);
        let handle = tokio::spawn(async move {
            let _ = bc_clone.listen(tx).await;
        });

        for _ in 0..50 {
            if bc.health_check().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let stream = UnixStream::connect(&sock).await.expect("connect");
        let req = "ws://localhost/";
        let (ws, _resp) = tokio_tungstenite::client_async(req, stream)
            .await
            .expect("client handshake");
        let (mut wsx, mut wrx) = ws.split();

        // Identify ourselves as the recipient so request_approval's
        // dispatch hits *this* connection. The approval router targets
        // by sender_id (== recipient passed to request_approval).
        let hello_msg = serde_json::json!({
            "type": "message",
            "sender_id": "user1:dev1",
            "reply_target": "conv-approval",
            "thread_ts": null,
            "content": "kick",
            "message_id": "m-1"
        });
        wsx.send(WsMessage::Text(hello_msg.to_string().into()))
            .await
            .unwrap();

        // Spawn the approval request — request_approval blocks until
        // the waiter resolves. Resolve it from this test by reading the
        // ApprovalRequest, parsing the request_id, and sending an
        // ApprovalResponse back.
        let bc_for_request = bc.clone();
        let approval_handle = tokio::spawn(async move {
            bc_for_request
                .request_approval(
                    "user1:dev1",
                    &ChannelApprovalRequest {
                        tool_name: "shell".to_string(),
                        arguments_summary: "ls /tmp".to_string(),
                    },
                )
                .await
        });

        // Pull frames until we see an approval_request, capture its id.
        let request_id = loop {
            let frame = timeout(Duration::from_secs(2), wrx.next())
                .await
                .expect("approval_request timeout")
                .expect("ws closed")
                .expect("ws err");
            if let WsMessage::Text(t) = frame
                && t.contains("\"type\":\"approval_request\"")
            {
                let v: serde_json::Value = serde_json::from_str(&t).unwrap();
                break v["request_id"].as_str().unwrap().to_string();
            }
        };

        // Send the approval response (Approve).
        let response = serde_json::json!({
            "type": "approval_response",
            "sender_id": "user1:dev1",
            "request_id": request_id,
            "decision": "approve"
        });
        wsx.send(WsMessage::Text(response.to_string().into()))
            .await
            .unwrap();

        let decision = timeout(Duration::from_secs(2), approval_handle)
            .await
            .expect("approval still blocked")
            .expect("approval task panicked")
            .expect("approval Result")
            .expect("approval returned None");
        assert_eq!(decision, ChannelApprovalResponse::Approve);

        handle.abort();
    }

    #[tokio::test]
    async fn approval_defaults_to_deny_on_timeout() {
        // D1/D2: when no ApprovalResponse arrives within APPROVAL_TIMEOUT,
        // request_approval defaults to Deny. We can't sleep 30s here —
        // assert the path with a manually-completed oneshot drop.
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("zeroclaw.sock");
        let bc = Arc::new(BrickChannel::new(&sock, 2, dir.path()));
        let bc_clone = bc.clone();
        let (tx, _rx) = mpsc::channel::<ChannelMessage>(8);
        let handle = tokio::spawn(async move {
            let _ = bc_clone.listen(tx).await;
        });
        for _ in 0..50 {
            if bc.health_check().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // Drop the oneshot sender from the pending registry to simulate
        // the timeout path's cleanup. request_approval then observes a
        // dropped sender and defaults to Deny.
        let bc_for_request = bc.clone();
        let approval_handle = tokio::spawn(async move {
            bc_for_request
                .request_approval(
                    "user-noconnect:dev",
                    &ChannelApprovalRequest {
                        tool_name: "shell".to_string(),
                        arguments_summary: "rm -rf".to_string(),
                    },
                )
                .await
        });
        // Allow request_approval to register its waiter then drop it.
        tokio::time::sleep(Duration::from_millis(50)).await;
        {
            let mut pending = bc.pending_approvals.lock().await;
            pending.clear();
        }
        let decision = approval_handle.await.unwrap().unwrap().unwrap();
        assert_eq!(decision, ChannelApprovalResponse::Deny);

        handle.abort();
    }

    #[tokio::test]
    async fn tool_call_frames_round_trip_through_brick_channel() {
        // C3: tool_call_start + tool_call_result emit structured outbound
        // frames the brick mobile app translates to ToolCallCard.
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("zeroclaw.sock");
        let bc = Arc::new(BrickChannel::new(&sock, 2, dir.path()));
        let bc_clone = bc.clone();
        let (tx, _rx) = mpsc::channel::<ChannelMessage>(8);
        let handle = tokio::spawn(async move {
            let _ = bc_clone.listen(tx).await;
        });
        for _ in 0..50 {
            if bc.health_check().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let stream = UnixStream::connect(&sock).await.expect("connect");
        let req = "ws://localhost/";
        let (ws, _resp) = tokio_tungstenite::client_async(req, stream)
            .await
            .expect("client handshake");
        let (mut wsx, mut wrx) = ws.split();

        // Associate this connection with the recipient before dispatching.
        let assoc = serde_json::json!({
            "type": "message",
            "sender_id": "user1:dev1",
            "reply_target": "conv-tool",
            "thread_ts": null,
            "content": "go",
            "message_id": "m-tool-assoc"
        });
        wsx.send(WsMessage::Text(assoc.to_string().into()))
            .await
            .unwrap();

        bc.tool_call_start(
            "user1:dev1",
            "draft-tool",
            Some("toolu_abc"),
            "shell",
            r#"{"cmd":"ls /tmp"}"#,
        )
        .await
        .unwrap();
        bc.tool_call_result(
            "user1:dev1",
            "draft-tool",
            Some("toolu_abc"),
            "shell",
            true,
            "ok",
        )
        .await
        .unwrap();

        let mut saw_start = false;
        let mut saw_result = false;
        for _ in 0..10 {
            let frame = timeout(Duration::from_secs(2), wrx.next())
                .await
                .expect("tool frame timeout")
                .expect("ws closed")
                .expect("ws err");
            if let WsMessage::Text(t) = frame {
                if t.contains("\"type\":\"tool_call_start\"") {
                    saw_start = true;
                    assert!(t.contains("\"tool_name\":\"shell\""));
                    assert!(t.contains("\"draft_id\":\"draft-tool\""));
                }
                if t.contains("\"type\":\"tool_call_result\"") {
                    saw_result = true;
                    assert!(t.contains("\"success\":true"));
                }
                if saw_start && saw_result {
                    break;
                }
            }
        }
        assert!(
            saw_start && saw_result,
            "expected both tool_call_start and tool_call_result frames"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn hello_auth_required_when_token_set() {
        // J7: with auth enabled, frames other than Hello/HelloAuth/Ping
        // are dropped pre-auth. Sending a Cancel without HelloAuth must
        // not produce a `/stop` ChannelMessage.
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("zeroclaw.sock");
        let bc = Arc::new(BrickChannel::new(&sock, 2, dir.path()).with_auth_token("test-token"));
        let bc_clone = bc.clone();
        let (tx, mut rx) = mpsc::channel::<ChannelMessage>(8);
        let handle = tokio::spawn(async move {
            let _ = bc_clone.listen(tx).await;
        });
        for _ in 0..50 {
            if bc.health_check().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // The token file should have been written.
        let token_path = dir.path().join("brick-channel.token");
        let token_on_disk = std::fs::read_to_string(&token_path).expect("token file");
        assert_eq!(token_on_disk, "test-token");
        let mode = std::fs::metadata(&token_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "token file perms must be 0600");

        let stream = UnixStream::connect(&sock).await.expect("connect");
        let req = "ws://localhost/";
        let (ws, _resp) = tokio_tungstenite::client_async(req, stream)
            .await
            .expect("client handshake");
        let (mut wsx, _wrx) = ws.split();

        // Send Cancel without HelloAuth — should be dropped silently.
        let cancel = serde_json::json!({
            "type": "cancel",
            "sender_id": "u:d",
            "reply_target": "c",
            "thread_ts": null,
            "message_id": "m-cancel"
        });
        wsx.send(WsMessage::Text(cancel.to_string().into()))
            .await
            .unwrap();

        let result = timeout(Duration::from_millis(300), rx.recv()).await;
        assert!(
            result.is_err(),
            "pre-auth Cancel must not produce a ChannelMessage"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn hello_auth_unblocks_after_correct_token() {
        // J7: HelloAuth with the correct token flips authed=true and
        // subsequent frames are processed.
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("zeroclaw.sock");
        let bc = Arc::new(BrickChannel::new(&sock, 2, dir.path()).with_auth_token("good-token"));
        let bc_clone = bc.clone();
        let (tx, mut rx) = mpsc::channel::<ChannelMessage>(8);
        let handle = tokio::spawn(async move {
            let _ = bc_clone.listen(tx).await;
        });
        for _ in 0..50 {
            if bc.health_check().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let stream = UnixStream::connect(&sock).await.expect("connect");
        let req = "ws://localhost/";
        let (ws, _resp) = tokio_tungstenite::client_async(req, stream)
            .await
            .expect("client handshake");
        let (mut wsx, _wrx) = ws.split();

        let auth = serde_json::json!({"type":"hello_auth","token":"good-token"});
        wsx.send(WsMessage::Text(auth.to_string().into()))
            .await
            .unwrap();
        let cancel = serde_json::json!({
            "type": "cancel",
            "sender_id": "u:d",
            "reply_target": "c",
            "thread_ts": null,
            "message_id": "m-after-auth"
        });
        wsx.send(WsMessage::Text(cancel.to_string().into()))
            .await
            .unwrap();

        let cm = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("post-auth Cancel timed out")
            .expect("rx closed");
        assert_eq!(cm.content, "/stop");
        assert_eq!(cm.id, "m-after-auth");

        handle.abort();
    }

    #[tokio::test]
    async fn history_request_respects_limit() {
        use zeroclaw_api::provider::ChatMessage;

        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("zeroclaw.sock");

        {
            let store = SessionStore::new(dir.path()).expect("session store");
            let key = "brick_room1_alice:dev1";
            for i in 0..5 {
                store
                    .append(key, &ChatMessage::user(format!("m{i}")))
                    .unwrap();
            }
        }

        let bc = Arc::new(BrickChannel::new(&sock, 2, dir.path()));
        let bc_clone = bc.clone();
        let (tx, _rx) = mpsc::channel::<ChannelMessage>(8);
        let handle = tokio::spawn(async move {
            let _ = bc_clone.listen(tx).await;
        });

        for _ in 0..50 {
            if bc.health_check().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let stream = UnixStream::connect(&sock).await.expect("connect");
        let req = "ws://localhost/";
        let (ws, _resp) = tokio_tungstenite::client_async(req, stream)
            .await
            .expect("client handshake");
        let (mut wsx, mut wrx) = ws.split();

        let payload = serde_json::json!({
            "type": "history_request",
            "sender_id": "alice:dev1",
            "reply_target": "room1",
            "thread_ts": null,
            "limit": 2,
        });
        wsx.send(WsMessage::Text(payload.to_string().into()))
            .await
            .unwrap();

        let response_text = loop {
            let frame = timeout(Duration::from_secs(2), wrx.next())
                .await
                .expect("history response timeout")
                .expect("ws closed")
                .expect("ws error");
            if let WsMessage::Text(t) = frame {
                if t.contains("\"type\":\"history_response\"") {
                    break t;
                }
            }
        };

        let parsed: serde_json::Value =
            serde_json::from_str(&response_text).expect("response is JSON");
        let messages = parsed["messages"].as_array().expect("messages array");
        assert_eq!(messages.len(), 2, "limit=2 should drop oldest 3 of 5");
        // Limit keeps the most recent — m3 and m4.
        assert_eq!(messages[0]["content"], "m3");
        assert_eq!(messages[1]["content"], "m4");

        handle.abort();
    }

    #[test]
    fn session_key_isolates_by_sender_target_and_thread() {
        // Different (sender, target, thread) tuples must produce
        // distinct keys so a model set in one session can't bleed into
        // another. Two sessions that differ only by thread_ts (None vs.
        // Some(""), Some("a") vs. Some("b")) are also distinct.
        let a = session_key("u1:d1", "conv-A", None);
        let b = session_key("u1:d1", "conv-B", None);
        let c = session_key("u2:d1", "conv-A", None);
        let d = session_key("u1:d1", "conv-A", Some("t1"));
        let e = session_key("u1:d1", "conv-A", Some("t2"));
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_ne!(d, e);
    }

    #[tokio::test]
    async fn model_get_returns_none_until_model_set_then_returns_hint() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("zeroclaw.sock");
        let bc = Arc::new(BrickChannel::new(&sock, 2, dir.path()));
        let bc_clone = bc.clone();
        // Drain inbound — the synthetic `/model` ChannelMessage flows
        // here. Test only cares about outbound frames over the WS.
        let (tx, mut rx) = mpsc::channel::<ChannelMessage>(8);
        let handle = tokio::spawn(async move {
            let _ = bc_clone.listen(tx).await;
        });

        for _ in 0..50 {
            if bc.health_check().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let stream = UnixStream::connect(&sock).await.expect("connect");
        let req = "ws://localhost/";
        let (ws, _resp) = tokio_tungstenite::client_async(req, stream)
            .await
            .expect("client handshake");
        let (mut wsx, mut wrx) = ws.split();

        // 1. ModelGet on a fresh session returns model: null.
        let get1 = serde_json::json!({
            "type": "model_get",
            "sender_id": "user1:dev1",
            "reply_target": "conv-1",
            "thread_ts": null,
        });
        wsx.send(WsMessage::Text(get1.to_string().into()))
            .await
            .unwrap();
        let resp1 = loop {
            let frame = timeout(Duration::from_secs(2), wrx.next())
                .await
                .expect("model_get_ok #1 timeout")
                .expect("ws closed")
                .expect("ws error");
            if let WsMessage::Text(t) = frame {
                if t.contains("\"type\":\"model_get_ok\"") {
                    break t;
                }
            }
        };
        let parsed: serde_json::Value = serde_json::from_str(&resp1).unwrap();
        assert_eq!(parsed["sender_id"], "user1:dev1");
        assert_eq!(parsed["reply_target"], "conv-1");
        assert!(
            parsed["model"].is_null(),
            "fresh session must return null, got {parsed}"
        );

        // 2. ModelSet writes the cache and emits ModelSetOk.
        let set = serde_json::json!({
            "type": "model_set",
            "sender_id": "user1:dev1",
            "reply_target": "conv-1",
            "thread_ts": null,
            "model": "hint:sonnet",
        });
        wsx.send(WsMessage::Text(set.to_string().into()))
            .await
            .unwrap();
        // Drain the synthetic /model ChannelMessage so the inbound
        // channel doesn't fill up.
        let _ = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("synthetic /model timeout");
        // Drain ModelSetOk.
        let _set_ok = loop {
            let frame = timeout(Duration::from_secs(2), wrx.next())
                .await
                .expect("model_set_ok timeout")
                .expect("ws closed")
                .expect("ws error");
            if let WsMessage::Text(t) = frame {
                if t.contains("\"type\":\"model_set_ok\"") {
                    break t;
                }
            }
        };

        // 3. ModelGet on the same session returns the just-set hint.
        let get2 = serde_json::json!({
            "type": "model_get",
            "sender_id": "user1:dev1",
            "reply_target": "conv-1",
            "thread_ts": null,
        });
        wsx.send(WsMessage::Text(get2.to_string().into()))
            .await
            .unwrap();
        let resp2 = loop {
            let frame = timeout(Duration::from_secs(2), wrx.next())
                .await
                .expect("model_get_ok #2 timeout")
                .expect("ws closed")
                .expect("ws error");
            if let WsMessage::Text(t) = frame {
                if t.contains("\"type\":\"model_get_ok\"") {
                    break t;
                }
            }
        };
        let parsed2: serde_json::Value = serde_json::from_str(&resp2).unwrap();
        assert_eq!(parsed2["model"], "hint:sonnet");

        // 4. ModelGet for a different (sender, target) returns null —
        //    sessions don't bleed across the cache key.
        let get3 = serde_json::json!({
            "type": "model_get",
            "sender_id": "user1:dev1",
            "reply_target": "conv-OTHER",
            "thread_ts": null,
        });
        wsx.send(WsMessage::Text(get3.to_string().into()))
            .await
            .unwrap();
        let resp3 = loop {
            let frame = timeout(Duration::from_secs(2), wrx.next())
                .await
                .expect("model_get_ok #3 timeout")
                .expect("ws closed")
                .expect("ws error");
            if let WsMessage::Text(t) = frame {
                if t.contains("\"type\":\"model_get_ok\"") {
                    break t;
                }
            }
        };
        let parsed3: serde_json::Value = serde_json::from_str(&resp3).unwrap();
        assert!(
            parsed3["model"].is_null(),
            "isolated session must stay null, got {parsed3}"
        );

        handle.abort();
    }
}

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
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{debug, info, warn};
use uuid::Uuid;
use zeroclaw_api::channel::{
    Channel, ChannelApprovalRequest, ChannelApprovalResponse, ChannelMessage, SendMessage,
};
use zeroclaw_infra::session_store::SessionStore;

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
        before_ts: Option<u64>,
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
    ThinkingDelta {
        draft_id: String,
        text: String,
    },
    ToolProgress {
        draft_id: String,
        text: String,
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

    /// Snapshot of senders for a given recipient — the lookup key in
    /// `send()` is the `SendMessage::recipient` we previously echoed in
    /// `ChannelMessage::sender`.
    fn senders_for(&self, recipient: &str) -> Vec<mpsc::Sender<OutboundFrame>> {
        let Some(ids) = self.by_sender.get(recipient) else {
            // Broadcast: no specific subscriber — fan out to every
            // connection so the brick-os process at the other end always
            // sees its own draft updates even before it has issued a
            // `message` frame on this connection.
            return self
                .connections
                .values()
                .map(|e| e.tx.clone())
                .collect();
        };
        ids.iter()
            .filter_map(|id| self.connections.get(id))
            .map(|e| e.tx.clone())
            .collect()
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
    router: Arc<Mutex<Router>>,
    listening: Arc<Mutex<bool>>,
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
            router: Arc::new(Mutex::new(Router::default())),
            listening: Arc::new(Mutex::new(false)),
        }
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

            tokio::spawn(async move {
                if let Err(err) = handle_connection(
                    stream,
                    router,
                    inbound_tx,
                    daemon_version,
                    workspace_dir,
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

    async fn update_draft(
        &self,
        recipient: &str,
        message_id: &str,
        text: &str,
    ) -> Result<()> {
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

    async fn finalize_draft(
        &self,
        recipient: &str,
        message_id: &str,
        text: &str,
    ) -> Result<()> {
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

    async fn request_approval(
        &self,
        recipient: &str,
        request: &ChannelApprovalRequest,
    ) -> Result<Option<ChannelApprovalResponse>> {
        // The current Brick UX does not surface mid-turn approvals to the
        // mobile app — the device runs in `autonomy = "supervised"` and any
        // medium-risk tool would be auto-blocked at the policy layer. Emit
        // the prompt frame anyway so future apps can opt in; default to
        // `Deny` so the agent doesn't hang waiting for a response that
        // will never arrive.
        let request_id = Uuid::new_v4().to_string();
        self.dispatch(
            OutboundFrame::ApprovalRequest {
                sender_id: recipient.to_string(),
                request_id,
                tool_name: request.tool_name.clone(),
                arguments_summary: request.arguments_summary.clone(),
            },
            recipient,
        )
        .await;
        Ok(Some(ChannelApprovalResponse::Deny))
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

    // Pump outbound frames serialized as text WS messages.
    let writer_task = tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            let payload = match serde_json::to_string(&frame) {
                Ok(s) => s,
                Err(e) => {
                    warn!("brick: serialize outbound: {e}");
                    continue;
                }
            };
            if writer.send(WsMessage::Text(payload.into())).await.is_err() {
                break;
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
) -> Result<()> {
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

        match frame {
            InboundFrame::Hello { client, version: _ } => {
                debug!(client, "brick: hello from client");
                let r = router.lock().await;
                if let Some(entry) = r.connections.get(&conn_id) {
                    let _ = entry
                        .tx
                        .try_send(OutboundFrame::HelloOk {
                            daemon_version: daemon_version.to_string(),
                        });
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
            InboundFrame::ApprovalResponse { .. } => {
                // Approvals are intentionally a no-op in v1 — see the
                // doc comment on `request_approval`.
            }
            InboundFrame::HistoryRequest {
                sender_id,
                reply_target,
                thread_ts,
                limit,
                before_ts: _,
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
            "before_ts": null,
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
    async fn history_request_respects_limit() {
        use zeroclaw_api::provider::ChatMessage;

        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("zeroclaw.sock");

        {
            let store = SessionStore::new(dir.path()).expect("session store");
            let key = "brick_room1_alice:dev1";
            for i in 0..5 {
                store.append(key, &ChatMessage::user(format!("m{i}"))).unwrap();
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
            "before_ts": null,
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
}

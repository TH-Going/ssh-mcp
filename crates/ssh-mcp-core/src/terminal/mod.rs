use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use russh::{client, ChannelMsg, ChannelWriteHalf, Disconnect};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::db::AppDatabase;
use crate::error::{CoreError, CoreResult};
use crate::events::CoreEventSink;
use crate::ssh::{SshClientHandler, SshService};

const IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalSessionInfo {
    pub session_id: String,
    pub server_id: String,
    pub server_name: String,
}

struct LivePtySession {
    server_id: String,
    write_half: Arc<tokio::sync::Mutex<ChannelWriteHalf<client::Msg>>>,
    ssh_handle: Arc<tokio::sync::Mutex<client::Handle<SshClientHandler>>>,
    last_input_at: Arc<Mutex<Instant>>,
    cancel: CancellationToken,
}

pub struct TerminalService {
    db: Arc<AppDatabase>,
    ssh: Arc<SshService>,
    events: Arc<dyn CoreEventSink>,
    sessions: Mutex<HashMap<String, LivePtySession>>,
    shutdown: CancellationToken,
}

impl TerminalService {
    pub fn new(
        db: Arc<AppDatabase>,
        ssh: Arc<SshService>,
        events: Arc<dyn CoreEventSink>,
    ) -> Arc<Self> {
        let svc = Arc::new(Self {
            db,
            ssh,
            events,
            sessions: Mutex::new(HashMap::new()),
            shutdown: CancellationToken::new(),
        });

        let reaper = Arc::clone(&svc);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                tokio::select! {
                    _ = reaper.shutdown.cancelled() => break,
                    _ = interval.tick() => {
                        reaper.reap_idle_sessions().await;
                    }
                }
            }
        });

        svc
    }

    pub async fn open_session(
        self: &Arc<Self>,
        server_id: &str,
        cols: u32,
        rows: u32,
    ) -> CoreResult<TerminalSessionInfo> {
        let server = self
            .db
            .get_server(server_id)?
            .ok_or_else(|| CoreError::NotFound("服务器不存在".to_string()))?;

        let mut parts = self.ssh.open_pty(&server, cols, rows).await?;
        let session_id = Uuid::new_v4().to_string();
        let cancel = CancellationToken::new();
        let last_input_at = Arc::new(Mutex::new(Instant::now()));

        let write_half = Arc::new(tokio::sync::Mutex::new(parts.write_half));
        let ssh_handle = Arc::new(tokio::sync::Mutex::new(parts.handle));

        self.sessions.lock().insert(
            session_id.clone(),
            LivePtySession {
                server_id: server.id.clone(),
                write_half,
                ssh_handle: Arc::clone(&ssh_handle),
                last_input_at,
                cancel: cancel.clone(),
            },
        );

        let _ = self.db.record_audit(
            "terminal.opened",
            Some(&server.id),
            json!({ "sessionId": session_id, "serverName": server.name }),
        );

        let svc = Arc::clone(self);
        let sid = session_id.clone();
        let s_id = server.id.clone();
        tokio::spawn(async move {
            let mut utf8_tail: Vec<u8> = Vec::new();
            let close_reason: Option<String>;

            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        close_reason = Some("会话已关闭".to_string());
                        break;
                    }
                    msg = parts.read_half.wait() => {
                        match msg {
                            Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                                utf8_tail.extend_from_slice(&data);
                                let text = drain_valid_utf8(&mut utf8_tail);
                                if !text.is_empty() {
                                    svc.events.on_terminal_output(&sid, &text);
                                }
                            }
                            Some(ChannelMsg::Close) | None => {
                                close_reason = Some("远程终端已退出".to_string());
                                break;
                            }
                            _ => {}
                        }
                    }
                }
            }

            if !utf8_tail.is_empty() {
                let rem = String::from_utf8_lossy(&utf8_tail);
                svc.events.on_terminal_output(&sid, &rem);
            }

            svc.sessions.lock().remove(&sid);
            let _ = ssh_handle
                .lock()
                .await
                .disconnect(Disconnect::ByApplication, "", "en")
                .await;
            let _ = svc.db.record_audit(
                "terminal.closed",
                Some(&s_id),
                json!({ "sessionId": sid, "reason": close_reason }),
            );
            svc.events.on_terminal_closed(&sid, close_reason.as_deref());
        });

        Ok(TerminalSessionInfo {
            session_id,
            server_id: server.id,
            server_name: server.name,
        })
    }

    pub async fn send_input(&self, session_id: &str, data: &str) -> CoreResult<()> {
        let (writer, last_input) = {
            let map = self.sessions.lock();
            let sess = map
                .get(session_id)
                .ok_or_else(|| CoreError::NotFound("终端会话已断开".to_string()))?;
            (Arc::clone(&sess.write_half), Arc::clone(&sess.last_input_at))
        };

        *last_input.lock() = Instant::now();
        let bytes = data.as_bytes();
        writer
            .lock()
            .await
            .data(bytes)
            .await
            .map_err(|e| CoreError::Ssh(format!("写入终端失败: {e}")))?;
        Ok(())
    }

    pub async fn resize(&self, session_id: &str, cols: u32, rows: u32) -> CoreResult<()> {
        let writer = {
            let map = self.sessions.lock();
            let sess = map
                .get(session_id)
                .ok_or_else(|| CoreError::NotFound("终端会话已断开".to_string()))?;
            Arc::clone(&sess.write_half)
        };

        writer
            .lock()
            .await
            .window_change(cols.max(20), rows.max(5), 0, 0)
            .await
            .map_err(|e| CoreError::Ssh(format!("调整终端窗口尺寸失败: {e}")))?;
        Ok(())
    }

    pub async fn close_session(&self, session_id: &str) -> CoreResult<()> {
        let removed = self.sessions.lock().remove(session_id);
        if let Some(sess) = removed {
            sess.cancel.cancel();
            let _ = sess.write_half.lock().await.close().await;
            let _ = sess
                .ssh_handle
                .lock()
                .await
                .disconnect(Disconnect::ByApplication, "", "en")
                .await;
            let _ = self.db.record_audit(
                "terminal.closed",
                Some(&sess.server_id),
                json!({ "sessionId": session_id, "reason": "closed_by_user" }),
            );
        }
        Ok(())
    }

    pub async fn shutdown_all(&self) {
        self.shutdown.cancel();
        let ids: Vec<String> = self.sessions.lock().keys().cloned().collect();
        for id in ids {
            let _ = self.close_session(&id).await;
        }
    }

    async fn reap_idle_sessions(&self) {
        let now = Instant::now();
        let stale_ids: Vec<String> = self
            .sessions
            .lock()
            .iter()
            .filter_map(|(id, sess)| {
                if now.duration_since(*sess.last_input_at.lock()) >= IDLE_TIMEOUT {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();

        for id in stale_ids {
            let _ = self.close_session(&id).await;
        }
    }
}

fn drain_valid_utf8(buf: &mut Vec<u8>) -> String {
    match std::str::from_utf8(buf) {
        Ok(s) => {
            let out = s.to_string();
            buf.clear();
            out
        }
        Err(err) => {
            let up_to = err.valid_up_to();
            if err.error_len().is_none() {
                if up_to == 0 {
                    return String::new();
                }
                let out = String::from_utf8_lossy(&buf[..up_to]).into_owned();
                buf.drain(..up_to);
                out
            } else {
                let out = String::from_utf8_lossy(buf).into_owned();
                buf.clear();
                out
            }
        }
    }
}

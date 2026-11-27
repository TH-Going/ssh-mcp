pub mod migrations;

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use chrono::{Duration as ChronoDuration, Utc};
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde_json::json;
use uuid::Uuid;

use crate::error::{CoreError, CoreResult};
use crate::models::{
    AppSettings, Approval, ApprovalDecision, ApprovalDecisionRequest, ApprovalRiskLevel,
    ApprovalStatus, AuthKind, ConnectionStatus, ControlMode, CredentialReplaceRequest,
    DockerCleanupPolicy, DockerCleanupTarget, HostKeyConfirmRequest, HostKeyStatus, Job, JobStatus,
    JobTarget, SecretPayload, Server, ServerCreateRequest, ServerMetrics, ServerPatchRequest,
    SettingsUpdateRequest, SshAuthentication, TargetStatus, ToolOperation,
};
use crate::platform::autostart::is_autostart_enabled;
use crate::policy::ApprovalPolicyDecision;
use crate::security::{canonical_request_digest, SecretVault};

#[derive(Debug, Clone)]
pub struct RawSettingsRow {
    pub mcp_enabled: bool,
    pub mcp_port: u16,
    pub refresh_interval_seconds: u32,
    pub failure_alerts_enabled: bool,
    pub auto_update_enabled: bool,
    pub default_concurrency: usize,
    pub default_timeout_seconds: u32,
}

#[derive(Debug)]
pub struct BackupServerRecord {
    pub server: Server,
    pub secret: SecretPayload,
    pub trusted_fingerprint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct QueuedTargetItem {
    pub target_id: String,
    pub job_id: String,
    pub server_id: String,
    pub server_revision: i64,
    pub operation: ToolOperation,
}

#[derive(Debug, Clone, Default)]
pub struct TargetFinishExtra {
    pub structured_result: Option<serde_json::Value>,
    pub output_truncated: bool,
    pub executed_command: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OutputFileMeta {
    pub path: String,
    pub total_bytes: u64,
    pub expires_at: String,
    pub output_truncated: bool,
}

#[derive(Debug, Clone)]
pub struct ExpiredOutputEntry {
    pub target_id: String,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct StoredCleanupPlan {
    pub id: String,
    pub server_id: String,
    pub server_revision: i64,
    pub preview_job_id: String,
    pub preview_target_id: String,
    pub execution_job_id: Option<String>,
    pub policy: DockerCleanupPolicy,
    pub policy_summary: String,
    pub sudo: bool,
    pub inventory_json: String,
    pub targets: Vec<DockerCleanupTarget>,
    pub target_digest: String,
    pub status: String,
    pub created_at: String,
    pub expires_at: String,
}

pub struct AppDatabase {
    conn: Mutex<Connection>,
    vault: SecretVault,
}

impl AppDatabase {
    pub fn open(db_path: &Path, vault: SecretVault) -> CoreResult<Arc<Self>> {
        let conn = Connection::open(db_path)?;
        migrations::run_migrations(&conn)?;
        let db = Arc::new(Self {
            conn: Mutex::new(conn),
            vault,
        });
        db.recover_interrupted_jobs()?;
        Ok(db)
    }

    pub fn in_memory_for_test() -> CoreResult<Arc<Self>> {
        let conn = Connection::open_in_memory()?;
        migrations::run_migrations(&conn)?;
        Ok(Arc::new(Self {
            conn: Mutex::new(conn),
            vault: SecretVault::with_ephemeral_key(),
        }))
    }

    fn recover_interrupted_jobs(&self) -> CoreResult<()> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT DISTINCT job_id FROM job_targets WHERE status = 'running'")?;
        let job_ids: Vec<String> = stmt
            .query_map([], |r| r.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);

        if !job_ids.is_empty() {
            conn.execute(
                "UPDATE job_targets
                 SET status = 'failed', error = '核心服务重启，未自动重放远程操作', finished_at = ?1
                 WHERE status = 'running'",
                params![now],
            )?;
            for jid in job_ids {
                recompute_job_status(&conn, &jid, &now)?;
            }
        }
        Ok(())
    }

    pub fn get_raw_settings(&self) -> CoreResult<RawSettingsRow> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT mcp_enabled, mcp_port, refresh_interval_seconds, failure_alerts_enabled,
                    auto_update_enabled, default_concurrency, default_timeout_seconds
             FROM settings WHERE id = 1",
            [],
            |r| {
                Ok(RawSettingsRow {
                    mcp_enabled: r.get::<_, i64>(0)? != 0,
                    mcp_port: r.get::<_, u16>(1)?,
                    refresh_interval_seconds: r.get::<_, u32>(2)?,
                    failure_alerts_enabled: r.get::<_, i64>(3)? != 0,
                    auto_update_enabled: r.get::<_, i64>(4)? != 0,
                    default_concurrency: r.get::<_, usize>(5)?,
                    default_timeout_seconds: r.get::<_, u32>(6)?,
                })
            },
        )
        .map_err(Into::into)
    }

    pub fn get_settings(&self, mcp_running: bool, stdio_cmd: &str) -> CoreResult<AppSettings> {
        let raw = self.get_raw_settings()?;
        Ok(AppSettings {
            mcp_enabled: raw.mcp_enabled,
            mcp_running,
            mcp_port: raw.mcp_port,
            mcp_http_endpoint: format!("http://127.0.0.1:{}/mcp", raw.mcp_port),
            mcp_stdio_command: stdio_cmd.to_string(),
            refresh_interval_seconds: raw.refresh_interval_seconds,
            failure_alerts_enabled: raw.failure_alerts_enabled,
            autostart_enabled: is_autostart_enabled(),
            auto_update_enabled: raw.auto_update_enabled,
            default_concurrency: raw.default_concurrency,
            default_timeout_seconds: raw.default_timeout_seconds,
            approval_ttl_seconds: 900,
            output_retention_hours: 24,
            audit_retention_days: 90,
        })
    }

    pub fn update_raw_settings(&self, req: &SettingsUpdateRequest) -> CoreResult<RawSettingsRow> {
        let mut current = self.get_raw_settings()?;
        if let Some(v) = req.mcp_enabled {
            current.mcp_enabled = v;
        }
        if let Some(v) = req.refresh_interval_seconds {
            if !matches!(v, 0 | 3 | 5 | 10 | 30) {
                return Err(CoreError::InvalidInput(
                    "自动刷新频率仅支持 0、3、5、10、30 秒".to_string(),
                ));
            }
            current.refresh_interval_seconds = v;
        }
        if let Some(v) = req.failure_alerts_enabled {
            current.failure_alerts_enabled = v;
        }
        if let Some(v) = req.auto_update_enabled {
            current.auto_update_enabled = v;
        }
        if let Some(v) = req.default_concurrency {
            if !(1..=10).contains(&v) {
                return Err(CoreError::InvalidInput("默认并发数必须在 1..10 之间".to_string()));
            }
            current.default_concurrency = v;
        }
        if let Some(v) = req.default_timeout_seconds {
            if !(1..=1800).contains(&v) {
                return Err(CoreError::InvalidInput(
                    "默认超时秒数必须在 1..1800 之间".to_string(),
                ));
            }
            current.default_timeout_seconds = v;
        }

        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE settings SET
                mcp_enabled = ?1,
                refresh_interval_seconds = ?2,
                failure_alerts_enabled = ?3,
                auto_update_enabled = ?4,
                default_concurrency = ?5,
                default_timeout_seconds = ?6,
                updated_at = ?7
             WHERE id = 1",
            params![
                current.mcp_enabled as i64,
                current.refresh_interval_seconds,
                current.failure_alerts_enabled as i64,
                current.auto_update_enabled as i64,
                current.default_concurrency as i64,
                current.default_timeout_seconds,
                now
            ],
        )?;
        drop(conn);
        Ok(current)
    }

    pub fn list_servers(&self) -> CoreResult<Vec<Server>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(&format!("{SERVER_SELECT_SQL} ORDER BY s.created_at ASC"))?;
        let rows = stmt
            .query_map([], map_server_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn get_server(&self, server_id: &str) -> CoreResult<Option<Server>> {
        let conn = self.conn.lock();
        get_server_inner(&conn, server_id)
    }

    pub fn find_server_by_identity(
        &self,
        name: &str,
        host: &str,
        port: u16,
    ) -> CoreResult<Option<Server>> {
        let conn = self.conn.lock();
        conn.query_row(
            &format!("{SERVER_SELECT_SQL} WHERE s.name = ?1 OR (s.host = ?2 AND s.port = ?3) LIMIT 1"),
            params![name.trim(), host.trim(), port],
            map_server_row,
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn create_server(&self, req: ServerCreateRequest) -> CoreResult<Server> {
        let name = req.name.trim().to_string();
        let host = req.host.trim().to_string();
        let username = req.username.trim().to_string();
        let environment = if req.environment.trim().is_empty() {
            "生产".to_string()
        } else {
            req.environment.trim().to_string()
        };

        if name.is_empty() || name.len() > 100 {
            return Err(CoreError::InvalidInput("服务器名称长度需在 1..100 之间".to_string()));
        }
        if host.is_empty() || host.len() > 253 {
            return Err(CoreError::InvalidInput("主机地址无效".to_string()));
        }
        if req.port == 0 {
            return Err(CoreError::InvalidInput("SSH 端口必须在 1..65535 之间".to_string()));
        }
        if username.is_empty() || username.len() > 100 {
            return Err(CoreError::InvalidInput("SSH 用户名不能为空".to_string()));
        }
        validate_authentication(&req.authentication)?;

        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let auth_kind = req.authentication.kind();
        let has_passphrase = req.authentication.has_passphrase();
        let local_key_source = match &req.authentication {
            SshAuthentication::LocalKeyPath { path, .. } => Some(path.trim().to_string()),
            _ => None,
        };
        let sudo_password = req.sudo_password.filter(|s| !s.is_empty());
        let has_sudo = sudo_password.is_some();

        let secret = SecretPayload {
            authentication: req.authentication,
            sudo_password,
        };
        let encrypted = self.vault.encrypt_server_secret(&id, &secret)?;

        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO servers (
                id, name, host, port, username, environment, control_mode, auth_kind,
                local_key_source, has_passphrase, has_sudo_password, connection_status,
                revision, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'host_key_required', 1, ?12, ?12)",
            params![
                id,
                name,
                host,
                req.port,
                username,
                environment,
                req.control_mode.as_str(),
                auth_kind.as_str(),
                local_key_source,
                has_passphrase as i64,
                has_sudo as i64,
                now
            ],
        )?;
        tx.execute(
            "INSERT INTO server_secrets (server_id, encrypted_payload, updated_at) VALUES (?1, ?2, ?3)",
            params![id, encrypted, now],
        )?;
        tx.execute(
            "INSERT INTO host_keys (server_id, trusted_fingerprint, pending_fingerprint, observed_at, updated_at)
             VALUES (?1, NULL, NULL, NULL, ?2)",
            params![id, now],
        )?;
        insert_audit(&tx, "server.created", Some(&id), json!({ "name": name, "host": host, "port": req.port }))?;
        tx.commit()?;

        get_server_inner(&conn, &id)?
            .ok_or_else(|| CoreError::Internal("创建服务器后读取失败".to_string()))
    }

    pub fn patch_server(&self, server_id: &str, req: ServerPatchRequest) -> CoreResult<Server> {
        let mut conn = self.conn.lock();
        let current = get_server_inner(&conn, server_id)?
            .ok_or_else(|| CoreError::NotFound("服务器不存在".to_string()))?;
        if current.revision != req.expected_revision {
            return Err(CoreError::RevisionConflict);
        }

        let name = req.name.map(|s| s.trim().to_string()).unwrap_or(current.name.clone());
        let host = req.host.map(|s| s.trim().to_string()).unwrap_or(current.host.clone());
        let port = req.port.unwrap_or(current.port);
        let username = req
            .username
            .map(|s| s.trim().to_string())
            .unwrap_or(current.username.clone());
        let environment = req
            .environment
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or(current.environment.clone());
        let control_mode = req.control_mode.unwrap_or(current.control_mode);

        if name.is_empty() || host.is_empty() || username.is_empty() || port == 0 {
            return Err(CoreError::InvalidInput("服务器必填字段不能为空".to_string()));
        }

        let endpoint_changed = host != current.host || port != current.port;
        let now = Utc::now().to_rfc3339();
        let tx = conn.transaction()?;

        if endpoint_changed {
            tx.execute(
                "UPDATE servers SET
                    name = ?1, host = ?2, port = ?3, username = ?4, environment = ?5,
                    control_mode = ?6, connection_status = 'host_key_required',
                    last_checked_at = NULL, last_latency_ms = NULL, last_error = NULL,
                    cpu_percent = NULL, memory_percent = NULL, disk_percent = NULL, metrics_sampled_at = NULL,
                    revision = revision + 1, updated_at = ?7
                 WHERE id = ?8 AND revision = ?9",
                params![
                    name,
                    host,
                    port,
                    username,
                    environment,
                    control_mode.as_str(),
                    now,
                    server_id,
                    req.expected_revision
                ],
            )?;
            tx.execute(
                "UPDATE host_keys SET trusted_fingerprint = NULL, pending_fingerprint = NULL, observed_at = NULL, updated_at = ?1
                 WHERE server_id = ?2",
                params![now, server_id],
            )?;
        } else {
            tx.execute(
                "UPDATE servers SET
                    name = ?1, username = ?2, environment = ?3, control_mode = ?4,
                    revision = revision + 1, updated_at = ?5
                 WHERE id = ?6 AND revision = ?7",
                params![
                    name,
                    username,
                    environment,
                    control_mode.as_str(),
                    now,
                    server_id,
                    req.expected_revision
                ],
            )?;
        }

        insert_audit(
            &tx,
            "server.updated",
            Some(server_id),
            json!({ "endpointChanged": endpoint_changed, "controlMode": control_mode.as_str() }),
        )?;
        tx.commit()?;

        get_server_inner(&conn, server_id)?
            .ok_or_else(|| CoreError::Internal("更新服务器后读取失败".to_string()))
    }

    pub fn replace_credentials(
        &self,
        server_id: &str,
        req: CredentialReplaceRequest,
    ) -> CoreResult<Server> {
        validate_authentication(&req.authentication)?;
        let existing_secret = self.get_secret(server_id)?;
        let next_sudo = match req.sudo_password {
            Some(Some(s)) if !s.is_empty() => Some(s),
            Some(_) => None,
            None => existing_secret.sudo_password.clone(),
        };

        let auth_kind = req.authentication.kind();
        let has_passphrase = req.authentication.has_passphrase();
        let local_key_source = match &req.authentication {
            SshAuthentication::LocalKeyPath { path, .. } => Some(path.trim().to_string()),
            _ => None,
        };
        let has_sudo = next_sudo.is_some();

        let payload = SecretPayload {
            authentication: req.authentication,
            sudo_password: next_sudo,
        };
        let encrypted = self.vault.encrypt_server_secret(server_id, &payload)?;
        let now = Utc::now().to_rfc3339();

        let mut conn = self.conn.lock();
        let current = get_server_inner(&conn, server_id)?
            .ok_or_else(|| CoreError::NotFound("服务器不存在".to_string()))?;
        if current.revision != req.expected_revision {
            return Err(CoreError::RevisionConflict);
        }

        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE servers SET
                auth_kind = ?1, local_key_source = ?2, has_passphrase = ?3, has_sudo_password = ?4,
                revision = revision + 1, updated_at = ?5
             WHERE id = ?6 AND revision = ?7",
            params![
                auth_kind.as_str(),
                local_key_source,
                has_passphrase as i64,
                has_sudo as i64,
                now,
                server_id,
                req.expected_revision
            ],
        )?;
        tx.execute(
            "UPDATE server_secrets SET encrypted_payload = ?1, updated_at = ?2 WHERE server_id = ?3",
            params![encrypted, now, server_id],
        )?;
        insert_audit(
            &tx,
            "server.credentials_replaced",
            Some(server_id),
            json!({ "authKind": auth_kind.as_str() }),
        )?;
        tx.commit()?;

        get_server_inner(&conn, server_id)?
            .ok_or_else(|| CoreError::Internal("替换凭据后读取失败".to_string()))
    }

    pub fn delete_server(&self, server_id: &str) -> CoreResult<()> {
        let mut conn = self.conn.lock();
        let active_count: i64 = conn.query_row(
            "SELECT COUNT(1) FROM job_targets
             WHERE server_id = ?1 AND status IN ('queued', 'waiting_approval', 'running')",
            params![server_id],
            |r| r.get(0),
        )?;
        if active_count > 0 {
            return Err(CoreError::Conflict(
                "该服务器仍有进行中或等待审批的任务，请先取消任务后再删除".to_string(),
            ));
        }

        let tx = conn.transaction()?;
        let affected = tx.execute("DELETE FROM servers WHERE id = ?1", params![server_id])?;
        if affected == 0 {
            return Err(CoreError::NotFound("服务器不存在".to_string()));
        }
        insert_audit(&tx, "server.deleted", Some(server_id), json!({}))?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_secret(&self, server_id: &str) -> CoreResult<SecretPayload> {
        let blob: Vec<u8> = {
            let conn = self.conn.lock();
            conn.query_row(
                "SELECT encrypted_payload FROM server_secrets WHERE server_id = ?1",
                params![server_id],
                |r| r.get(0),
            )
            .optional()?
            .ok_or_else(|| CoreError::NotFound("服务器凭据不存在".to_string()))?
        };
        self.vault.decrypt_server_secret(server_id, &blob)
    }

    pub fn get_trusted_host_key(&self, server_id: &str) -> CoreResult<Option<String>> {
        let conn = self.conn.lock();
        let fp: Option<Option<String>> = conn
            .query_row(
                "SELECT trusted_fingerprint FROM host_keys WHERE server_id = ?1",
                params![server_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(fp.flatten())
    }

    pub fn set_trusted_host_key_direct(
        &self,
        server_id: &str,
        fingerprint: Option<&str>,
    ) -> CoreResult<()> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE host_keys SET trusted_fingerprint = ?1, pending_fingerprint = NULL, updated_at = ?2
             WHERE server_id = ?3",
            params![fingerprint, now, server_id],
        )?;
        if fingerprint.is_some() {
            conn.execute(
                "UPDATE servers SET connection_status = 'unknown', updated_at = ?1 WHERE id = ?2",
                params![now, server_id],
            )?;
        }
        Ok(())
    }

    pub fn record_host_key_observation(
        &self,
        server_id: &str,
        observed_fingerprint: &str,
    ) -> CoreResult<(Server, bool)> {
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock();
        let trusted: Option<String> = conn
            .query_row(
                "SELECT trusted_fingerprint FROM host_keys WHERE server_id = ?1",
                params![server_id],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();

        let is_changed = trusted.is_some();
        let next_status = if is_changed {
            ConnectionStatus::HostKeyChanged
        } else {
            ConnectionStatus::HostKeyRequired
        };
        let err_msg = if is_changed {
            "远程服务器主机密钥发生变更，已拦截连接以防范中间人风险"
        } else {
            "首次连接该服务器，请核对并确认主机密钥指纹"
        };

        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE host_keys SET pending_fingerprint = ?1, observed_at = ?2, updated_at = ?2
             WHERE server_id = ?3",
            params![observed_fingerprint, now, server_id],
        )?;
        tx.execute(
            "UPDATE servers SET connection_status = ?1, last_checked_at = ?2, last_error = ?3, updated_at = ?2
             WHERE id = ?4",
            params![next_status.as_str(), now, err_msg, server_id],
        )?;
        tx.commit()?;

        let server = get_server_inner(&conn, server_id)?
            .ok_or_else(|| CoreError::NotFound("服务器不存在".to_string()))?;
        Ok((server, is_changed))
    }

    pub fn confirm_host_key(&self, server_id: &str, req: HostKeyConfirmRequest) -> CoreResult<Server> {
        if !req.fingerprint.starts_with("SHA256:") {
            return Err(CoreError::InvalidInput("主机密钥指纹格式必须为 SHA256:...".to_string()));
        }
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock();
        let current = get_server_inner(&conn, server_id)?
            .ok_or_else(|| CoreError::NotFound("服务器不存在".to_string()))?;
        if current.revision != req.expected_revision {
            return Err(CoreError::RevisionConflict);
        }

        if let Some(pending) = &current.pending_host_key_fingerprint {
            if pending != &req.fingerprint {
                return Err(CoreError::Conflict(
                    "待确认指纹已变化，请重新检查连接后再确认".to_string(),
                ));
            }
        }

        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE host_keys SET trusted_fingerprint = ?1, pending_fingerprint = NULL, updated_at = ?2
             WHERE server_id = ?3",
            params![req.fingerprint, now, server_id],
        )?;
        tx.execute(
            "UPDATE servers SET connection_status = 'checking', last_error = NULL, revision = revision + 1, updated_at = ?1
             WHERE id = ?2",
            params![now, server_id],
        )?;
        insert_audit(
            &tx,
            "host_key.confirmed",
            Some(server_id),
            json!({ "fingerprint": req.fingerprint }),
        )?;
        tx.commit()?;

        get_server_inner(&conn, server_id)?
            .ok_or_else(|| CoreError::NotFound("服务器不存在".to_string()))
    }

    pub fn update_connection_probe(
        &self,
        server_id: &str,
        status: ConnectionStatus,
        latency_ms: Option<u32>,
        error: Option<&str>,
        metrics: Option<&ServerMetrics>,
    ) -> CoreResult<(Server, bool)> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock();
        let prev = get_server_inner(&conn, server_id)?
            .ok_or_else(|| CoreError::NotFound("服务器不存在".to_string()))?;

        let transitioned_offline =
            prev.connection_status == ConnectionStatus::Online && status == ConnectionStatus::Offline;

        if let Some(m) = metrics {
            conn.execute(
                "UPDATE servers SET
                    connection_status = ?1, last_checked_at = ?2, last_latency_ms = ?3, last_error = ?4,
                    cpu_percent = ?5, memory_percent = ?6, disk_percent = ?7, metrics_sampled_at = ?8,
                    updated_at = ?2
                 WHERE id = ?9",
                params![
                    status.as_str(),
                    now,
                    latency_ms,
                    error,
                    m.cpu_percent,
                    m.memory_percent,
                    m.disk_percent,
                    m.sampled_at,
                    server_id
                ],
            )?;
        } else if status == ConnectionStatus::Online {
            conn.execute(
                "UPDATE servers SET
                    connection_status = ?1, last_checked_at = ?2,
                    last_latency_ms = COALESCE(?3, last_latency_ms),
                    last_error = NULL, updated_at = ?2
                 WHERE id = ?4",
                params![status.as_str(), now, latency_ms, server_id],
            )?;
        } else {
            conn.execute(
                "UPDATE servers SET
                    connection_status = ?1, last_checked_at = ?2, last_latency_ms = NULL, last_error = ?3,
                    cpu_percent = NULL, memory_percent = NULL, disk_percent = NULL, metrics_sampled_at = NULL,
                    updated_at = ?2
                 WHERE id = ?4",
                params![status.as_str(), now, error, server_id],
            )?;
        }

        let updated = get_server_inner(&conn, server_id)?
            .ok_or_else(|| CoreError::NotFound("服务器不存在".to_string()))?;
        Ok((updated, transitioned_offline))
    }

    pub fn export_backup_records(&self) -> CoreResult<Vec<BackupServerRecord>> {
        let servers = self.list_servers()?;
        let mut out = Vec::with_capacity(servers.len());
        for server in servers {
            let secret = self.get_secret(&server.id)?;
            let trusted_fingerprint = self.get_trusted_host_key(&server.id)?;
            out.push(BackupServerRecord {
                server,
                secret,
                trusted_fingerprint,
            });
        }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_job<F>(
        &self,
        server_ids: &[String],
        requester: &str,
        reason: Option<&str>,
        logical_op: &ToolOperation,
        exec_op: &ToolOperation,
        content_digest: Option<&str>,
        eval_policy: F,
    ) -> CoreResult<(Job, Vec<Approval>)>
    where
        F: Fn(&Server, &ToolOperation) -> ApprovalPolicyDecision,
    {
        if server_ids.is_empty() || server_ids.len() > 50 {
            return Err(CoreError::InvalidInput(
                "单次任务目标服务器数量需在 1..50 台之间".to_string(),
            ));
        }
        let unique: HashSet<&String> = server_ids.iter().collect();
        if unique.len() != server_ids.len() {
            return Err(CoreError::InvalidInput("目标服务器 ID 不能重复".to_string()));
        }

        let mut conn = self.conn.lock();
        let mut servers = Vec::with_capacity(server_ids.len());
        for sid in server_ids {
            let s = get_server_inner(&conn, sid)?
                .ok_or_else(|| CoreError::NotFound(format!("未找到服务器: {sid}")))?;
            servers.push(s);
        }

        let job_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let now_str = now.to_rfc3339();
        let expires_str = (now + ChronoDuration::seconds(900)).to_rfc3339();
        let op_json = serde_json::to_string(logical_op)?;
        let exec_json = serde_json::to_string(exec_op)?;
        let effective_reason = reason
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or_else(|| logical_op.caller_reason().map(str::trim).filter(|s| !s.is_empty()));

        let mut any_waiting = false;
        let mut created_approval_ids = Vec::new();

        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO jobs (
                id, tool, requester, reason, operation_json, execution_json, status, created_at, revision
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'queued', ?7, 1)",
            params![
                job_id,
                logical_op.tool_name(),
                requester,
                effective_reason,
                op_json,
                exec_json,
                now_str
            ],
        )?;

        for server in &servers {
            let target_id = Uuid::new_v4().to_string();
            let decision = eval_policy(server, logical_op);
            let target_status = if decision.requires_approval {
                any_waiting = true;
                TargetStatus::WaitingApproval
            } else {
                TargetStatus::Queued
            };

            tx.execute(
                "INSERT INTO job_targets (
                    id, job_id, server_id, server_name, server_revision, status, output_bytes, output_truncated
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 0)",
                params![
                    target_id,
                    job_id,
                    server.id,
                    server.name,
                    server.revision,
                    target_status.as_str()
                ],
            )?;

            if decision.requires_approval {
                let approval_id = Uuid::new_v4().to_string();
                let req_digest = canonical_request_digest(&json!({
                    "operation": logical_op,
                    "serverId": server.id,
                    "serverRevision": server.revision,
                    "contentDigest": content_digest,
                }));
                let risk_str = match decision.risk_level {
                    ApprovalRiskLevel::Low | ApprovalRiskLevel::Medium => "medium",
                    ApprovalRiskLevel::High => "high",
                };

                tx.execute(
                    "INSERT INTO approvals (
                        id, job_id, target_id, server_id, server_name, requester, caller_reason,
                        operation_json, content_digest, request_digest, risk, approval_reason,
                        matched_policy, policy_summary, sudo, status, created_at, expires_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, 'pending', ?16, ?17)",
                    params![
                        approval_id,
                        job_id,
                        target_id,
                        server.id,
                        server.name,
                        requester,
                        effective_reason,
                        op_json,
                        content_digest,
                        req_digest,
                        risk_str,
                        decision.approval_reason,
                        decision.matched_policy,
                        decision.policy_summary,
                        logical_op.uses_sudo() as i64,
                        now_str,
                        expires_str
                    ],
                )?;
                created_approval_ids.push(approval_id);
            }
        }

        if any_waiting {
            tx.execute(
                "UPDATE jobs SET status = 'waiting_approval' WHERE id = ?1",
                params![job_id],
            )?;
        }

        insert_audit(
            &tx,
            "job.created",
            Some(&job_id),
            json!({
                "tool": logical_op.tool_name(),
                "requester": requester,
                "serverCount": servers.len(),
                "waitingApprovals": created_approval_ids.len()
            }),
        )?;
        tx.commit()?;

        let job = get_job_inner(&conn, &job_id)?
            .ok_or_else(|| CoreError::Internal("创建任务后读取失败".to_string()))?;
        let mut approvals = Vec::with_capacity(created_approval_ids.len());
        for aid in created_approval_ids {
            if let Some(a) = get_approval_inner(&conn, &aid)? {
                approvals.push(a);
            }
        }
        Ok((job, approvals))
    }

    pub fn list_jobs(&self, limit: usize) -> CoreResult<Vec<Job>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id FROM jobs ORDER BY created_at DESC, rowid DESC LIMIT ?1",
        )?;
        let ids: Vec<String> = stmt
            .query_map(params![limit.clamp(1, 200) as i64], |r| r.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);

        let mut jobs = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(j) = get_job_inner(&conn, &id)? {
                jobs.push(j);
            }
        }
        Ok(jobs)
    }

    pub fn get_job(&self, job_id: &str) -> CoreResult<Option<Job>> {
        let conn = self.conn.lock();
        get_job_inner(&conn, job_id)
    }

    pub fn get_queued_targets(&self) -> CoreResult<Vec<QueuedTargetItem>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT t.id, t.job_id, t.server_id, t.server_revision, j.execution_json
             FROM job_targets t
             JOIN jobs j ON j.id = t.job_id
             WHERE t.status = 'queued'
             ORDER BY j.created_at ASC, t.rowid ASC",
        )?;
        let rows = stmt
            .query_map([], |r| {
                let exec_json: String = r.get(4)?;
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    exec_json,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let mut out = Vec::with_capacity(rows.len());
        for (target_id, job_id, server_id, server_revision, exec_json) in rows {
            let operation: ToolOperation = serde_json::from_str(&exec_json)?;
            out.push(QueuedTargetItem {
                target_id,
                job_id,
                server_id,
                server_revision,
                operation,
            });
        }
        Ok(out)
    }

    pub fn mark_target_running(&self, target_id: &str, output_path: &str) -> CoreResult<bool> {
        let now = Utc::now().to_rfc3339();
        let expires = (Utc::now() + ChronoDuration::hours(24)).to_rfc3339();
        let mut conn = self.conn.lock();
        let job_id: Option<String> = conn
            .query_row(
                "SELECT job_id FROM job_targets WHERE id = ?1 AND status = 'queued'",
                params![target_id],
                |r| r.get(0),
            )
            .optional()?;
        let Some(job_id) = job_id else {
            return Ok(false);
        };

        let tx = conn.transaction()?;
        let changed = tx.execute(
            "UPDATE job_targets SET
                status = 'running', started_at = ?1, output_path = ?2, output_expires_at = ?3
             WHERE id = ?4 AND status = 'queued'",
            params![now, output_path, expires, target_id],
        )?;
        if changed == 0 {
            return Ok(false);
        }
        tx.execute(
            "UPDATE approvals SET status = 'used' WHERE target_id = ?1 AND status = 'approved'",
            params![target_id],
        )?;
        tx.execute(
            "UPDATE jobs SET
                status = 'running',
                started_at = COALESCE(started_at, ?1),
                revision = revision + 1
             WHERE id = ?2",
            params![now, job_id],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn finish_target(
        &self,
        target_id: &str,
        status: TargetStatus,
        exit_code: Option<i32>,
        error: Option<&str>,
        output_bytes: u64,
        extra: TargetFinishExtra,
    ) -> CoreResult<(String, JobStatus, bool)> {
        let now = Utc::now().to_rfc3339();
        let result_json = extra
            .structured_result
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;

        let mut conn = self.conn.lock();
        let job_id: String = conn.query_row(
            "SELECT job_id FROM job_targets WHERE id = ?1",
            params![target_id],
            |r| r.get(0),
        )?;
        let prev_job_status: String = conn.query_row(
            "SELECT status FROM jobs WHERE id = ?1",
            params![job_id],
            |r| r.get(0),
        )?;

        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE job_targets SET
                status = ?1, exit_code = ?2, error = ?3, output_bytes = ?4,
                output_truncated = ?5, executed_command = ?6, result_json = ?7,
                finished_at = ?8
             WHERE id = ?9",
            params![
                status.as_str(),
                exit_code,
                error,
                output_bytes as i64,
                extra.output_truncated as i64,
                extra.executed_command,
                result_json,
                now,
                target_id
            ],
        )?;

        let next_job_status = recompute_job_status(&tx, &job_id, &now)?;
        insert_audit(
            &tx,
            "job.target_finished",
            Some(target_id),
            json!({ "jobId": job_id, "status": status.as_str(), "exitCode": exit_code }),
        )?;
        tx.commit()?;

        let newly_failed = !matches!(prev_job_status.as_str(), "failed" | "partial_failure")
            && matches!(next_job_status, JobStatus::Failed | JobStatus::PartialFailure);

        Ok((job_id, next_job_status, newly_failed))
    }

    pub fn cancel_job(&self, job_id: &str) -> CoreResult<Job> {
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock();
        let exists: Option<i64> = conn
            .query_row("SELECT 1 FROM jobs WHERE id = ?1", params![job_id], |r| r.get(0))
            .optional()?;
        if exists.is_none() {
            return Err(CoreError::NotFound("任务不存在".to_string()));
        }

        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE approvals SET status = 'rejected', decided_at = ?1, decision_reason = '任务已取消'
             WHERE job_id = ?2 AND status = 'pending'",
            params![now, job_id],
        )?;
        tx.execute(
            "UPDATE job_targets SET status = 'cancelled', error = '已取消', finished_at = ?1
             WHERE job_id = ?2 AND status IN ('queued', 'waiting_approval', 'running')",
            params![now, job_id],
        )?;
        recompute_job_status(&tx, job_id, &now)?;
        tx.commit()?;

        get_job_inner(&conn, job_id)?
            .ok_or_else(|| CoreError::NotFound("任务不存在".to_string()))
    }

    pub fn delete_job(&self, job_id: &str) -> CoreResult<Vec<String>> {
        let mut conn = self.conn.lock();
        let status_str: String = conn
            .query_row("SELECT status FROM jobs WHERE id = ?1", params![job_id], |r| {
                r.get(0)
            })
            .optional()?
            .ok_or_else(|| CoreError::NotFound("任务不存在".to_string()))?;

        if JobStatus::from_db(&status_str).is_active() {
            return Err(CoreError::Conflict(
                "运行中或等待审批的任务不可直接删除，请先取消任务".to_string(),
            ));
        }

        let paths = collect_job_files(&conn, job_id)?;
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM jobs WHERE id = ?1", params![job_id])?;
        insert_audit(&tx, "job.deleted", Some(job_id), json!({}))?;
        tx.commit()?;
        Ok(paths)
    }

    pub fn clear_finished_jobs(&self) -> CoreResult<(usize, Vec<String>)> {
        let mut conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id FROM jobs WHERE status NOT IN ('queued', 'waiting_approval', 'running')",
        )?;
        let job_ids: Vec<String> = stmt
            .query_map([], |r| r.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);

        if job_ids.is_empty() {
            return Ok((0, Vec::new()));
        }

        let mut paths = Vec::new();
        for jid in &job_ids {
            paths.extend(collect_job_files(&conn, jid)?);
        }

        let tx = conn.transaction()?;
        let deleted = tx.execute(
            "DELETE FROM jobs WHERE status NOT IN ('queued', 'waiting_approval', 'running')",
            [],
        )?;
        insert_audit(&tx, "job.cleared_finished", None, json!({ "count": deleted }))?;
        tx.commit()?;
        Ok((deleted, paths))
    }

    pub fn get_output_meta(&self, job_id: &str, target_id: &str) -> CoreResult<OutputFileMeta> {
        let conn = self.conn.lock();
        let row: Option<(Option<String>, i64, Option<String>, i64)> = conn
            .query_row(
                "SELECT output_path, output_bytes, output_expires_at, output_truncated
                 FROM job_targets WHERE id = ?1 AND job_id = ?2",
                params![target_id, job_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;

        let Some((path, total_bytes, expires_at, truncated)) = row else {
            return Err(CoreError::NotFound("未找到任务目标".to_string()));
        };
        let Some(path) = path else {
            return Err(CoreError::NotFound("该任务尚无输出或输出已过期清理".to_string()));
        };

        Ok(OutputFileMeta {
            path,
            total_bytes: total_bytes.max(0) as u64,
            expires_at: expires_at.unwrap_or_else(|| Utc::now().to_rfc3339()),
            output_truncated: truncated != 0,
        })
    }

    pub fn list_pending_approvals(&self) -> CoreResult<Vec<Approval>> {
        self.expire_overdue_approvals_now()?;
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id FROM approvals WHERE status = 'pending' ORDER BY created_at DESC",
        )?;
        let ids: Vec<String> = stmt
            .query_map([], |r| r.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);

        let mut list = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(a) = get_approval_inner(&conn, &id)? {
                list.push(a);
            }
        }
        Ok(list)
    }

    pub fn get_approval(&self, approval_id: &str) -> CoreResult<Option<Approval>> {
        self.expire_overdue_approvals_now()?;
        let conn = self.conn.lock();
        get_approval_inner(&conn, approval_id)
    }

    pub fn decide_approval(
        &self,
        approval_id: &str,
        req: &ApprovalDecisionRequest,
    ) -> CoreResult<(Approval, String)> {
        self.expire_overdue_approvals_now()?;
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock();
        let current = get_approval_inner(&conn, approval_id)?
            .ok_or_else(|| CoreError::NotFound("审批单不存在".to_string()))?;

        if current.status != ApprovalStatus::Pending {
            return Err(CoreError::Conflict(format!(
                "该审批单当前状态为 {}，无法重复处理",
                current.status.as_str()
            )));
        }
        if current.request_digest != req.expected_request_digest {
            return Err(CoreError::Conflict(
                "审批请求摘要不匹配，操作请求可能已变化".to_string(),
            ));
        }

        let tx = conn.transaction()?;
        match req.decision {
            ApprovalDecision::Approve => {
                tx.execute(
                    "UPDATE approvals SET status = 'approved', decided_at = ?1, decision_reason = ?2
                     WHERE id = ?3 AND status = 'pending'",
                    params![now, req.reason, approval_id],
                )?;
                tx.execute(
                    "UPDATE job_targets SET status = 'queued' WHERE id = ?1 AND status = 'waiting_approval'",
                    params![current.target_id],
                )?;
            }
            ApprovalDecision::Reject => {
                tx.execute(
                    "UPDATE approvals SET status = 'rejected', decided_at = ?1, decision_reason = ?2
                     WHERE id = ?3 AND status = 'pending'",
                    params![now, req.reason, approval_id],
                )?;
                tx.execute(
                    "UPDATE job_targets SET status = 'cancelled', error = '审批被拒绝', finished_at = ?1
                     WHERE id = ?2 AND status = 'waiting_approval'",
                    params![now, current.target_id],
                )?;
            }
        }

        recompute_job_status(&tx, &current.job_id, &now)?;
        insert_audit(
            &tx,
            if req.decision == ApprovalDecision::Approve {
                "approval.approve"
            } else {
                "approval.reject"
            },
            Some(approval_id),
            json!({ "jobId": current.job_id, "serverId": current.server_id }),
        )?;
        tx.commit()?;

        let updated = get_approval_inner(&conn, approval_id)?
            .ok_or_else(|| CoreError::Internal("更新审批后读取失败".to_string()))?;
        Ok((updated, current.job_id))
    }

    fn expire_overdue_approvals_now(&self) -> CoreResult<Vec<String>> {
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, job_id, target_id FROM approvals WHERE status = 'pending' AND expires_at <= ?1",
        )?;
        let rows: Vec<(String, String, String)> = stmt
            .query_map(params![now], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);

        if rows.is_empty() {
            return Ok(Vec::new());
        }

        let mut touched_jobs = HashSet::new();
        let tx = conn.transaction()?;
        for (aid, jid, tid) in rows {
            tx.execute(
                "UPDATE approvals SET status = 'expired', decided_at = ?1 WHERE id = ?2 AND status = 'pending'",
                params![now, aid],
            )?;
            tx.execute(
                "UPDATE job_targets SET status = 'cancelled', error = '审批已过期', finished_at = ?1
                 WHERE id = ?2 AND status = 'waiting_approval'",
                params![now, tid],
            )?;
            touched_jobs.insert(jid);
        }
        for jid in &touched_jobs {
            recompute_job_status(&tx, jid, &now)?;
        }
        tx.commit()?;
        Ok(touched_jobs.into_iter().collect())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn save_cleanup_plan(
        &self,
        server_id: &str,
        server_revision: i64,
        preview_job_id: &str,
        preview_target_id: &str,
        policy: &DockerCleanupPolicy,
        policy_summary: &str,
        sudo: bool,
        inventory_json: &str,
        targets: &[DockerCleanupTarget],
        target_digest: &str,
    ) -> CoreResult<StoredCleanupPlan> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let created_at = now.to_rfc3339();
        let expires_at = (now + ChronoDuration::seconds(900)).to_rfc3339();
        let policy_json = serde_json::to_string(policy)?;
        let targets_json = serde_json::to_string(targets)?;

        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO docker_cleanup_plans (
                id, server_id, server_revision, preview_job_id, preview_target_id,
                policy_json, policy_summary, sudo, inventory_json, targets_json,
                target_digest, status, created_at, expires_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'ready', ?12, ?13, ?12)",
            params![
                id,
                server_id,
                server_revision,
                preview_job_id,
                preview_target_id,
                policy_json,
                policy_summary,
                sudo as i64,
                inventory_json,
                targets_json,
                target_digest,
                created_at,
                expires_at
            ],
        )?;

        Ok(StoredCleanupPlan {
            id,
            server_id: server_id.to_string(),
            server_revision,
            preview_job_id: preview_job_id.to_string(),
            preview_target_id: preview_target_id.to_string(),
            execution_job_id: None,
            policy: policy.clone(),
            policy_summary: policy_summary.to_string(),
            sudo,
            inventory_json: inventory_json.to_string(),
            targets: targets.to_vec(),
            target_digest: target_digest.to_string(),
            status: "ready".to_string(),
            created_at,
            expires_at,
        })
    }

    pub fn get_cleanup_plan(&self, plan_id: &str) -> CoreResult<Option<StoredCleanupPlan>> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE docker_cleanup_plans SET status = 'expired', updated_at = ?1
             WHERE id = ?2 AND status = 'ready' AND expires_at <= ?1",
            params![now, plan_id],
        )?;

        let row = conn
            .query_row(
                "SELECT id, server_id, server_revision, preview_job_id, preview_target_id,
                        execution_job_id, policy_json, policy_summary, sudo, inventory_json,
                        targets_json, target_digest, status, created_at, expires_at
                 FROM docker_cleanup_plans WHERE id = ?1",
                params![plan_id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, Option<String>>(5)?,
                        r.get::<_, String>(6)?,
                        r.get::<_, String>(7)?,
                        r.get::<_, i64>(8)? != 0,
                        r.get::<_, String>(9)?,
                        r.get::<_, String>(10)?,
                        r.get::<_, String>(11)?,
                        r.get::<_, String>(12)?,
                        r.get::<_, String>(13)?,
                        r.get::<_, String>(14)?,
                    ))
                },
            )
            .optional()?;

        let Some((
            id,
            server_id,
            server_revision,
            preview_job_id,
            preview_target_id,
            execution_job_id,
            policy_json,
            policy_summary,
            sudo,
            inventory_json,
            targets_json,
            target_digest,
            status,
            created_at,
            expires_at,
        )) = row
        else {
            return Ok(None);
        };

        Ok(Some(StoredCleanupPlan {
            id,
            server_id,
            server_revision,
            preview_job_id,
            preview_target_id,
            execution_job_id,
            policy: serde_json::from_str(&policy_json)?,
            policy_summary,
            sudo,
            inventory_json,
            targets: serde_json::from_str(&targets_json)?,
            target_digest,
            status,
            created_at,
            expires_at,
        }))
    }

    pub fn claim_cleanup_plan(&self, plan_id: &str, execution_job_id: &str) -> CoreResult<()> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock();
        let changed = conn.execute(
            "UPDATE docker_cleanup_plans SET status = 'claimed', execution_job_id = ?1, updated_at = ?2
             WHERE id = ?3 AND status = 'ready' AND expires_at > ?2",
            params![execution_job_id, now, plan_id],
        )?;
        if changed == 0 {
            return Err(CoreError::Conflict(
                "CLEANUP_PLAN_ALREADY_USED: 清理计划已被消费或已过期".to_string(),
            ));
        }
        Ok(())
    }

    pub fn finish_cleanup_plan(&self, plan_id: &str, status: &str) -> CoreResult<()> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE docker_cleanup_plans SET status = ?1, updated_at = ?2 WHERE id = ?3",
            params![status, now, plan_id],
        )?;
        Ok(())
    }

    pub fn run_maintenance(&self) -> CoreResult<(Vec<String>, Vec<ExpiredOutputEntry>)> {
        let expired_jobs = self.expire_overdue_approvals_now()?;
        let now = Utc::now();
        let now_str = now.to_rfc3339();
        let audit_cutoff = (now - ChronoDuration::days(90)).to_rfc3339();

        let conn = self.conn.lock();
        conn.execute(
            "UPDATE docker_cleanup_plans SET status = 'expired', updated_at = ?1
             WHERE status = 'ready' AND expires_at <= ?1",
            params![now_str],
        )?;
        conn.execute(
            "DELETE FROM audit_events WHERE created_at <= ?1",
            params![audit_cutoff],
        )?;

        let mut stmt = conn.prepare(
            "SELECT id, output_path FROM job_targets
             WHERE output_path IS NOT NULL AND output_expires_at IS NOT NULL AND output_expires_at <= ?1",
        )?;
        let expired_outputs = stmt
            .query_map(params![now_str], |r| {
                Ok(ExpiredOutputEntry {
                    target_id: r.get(0)?,
                    path: r.get(1)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok((expired_jobs, expired_outputs))
    }

    pub fn clear_expired_output(&self, target_id: &str) -> CoreResult<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE job_targets SET output_path = NULL WHERE id = ?1",
            params![target_id],
        )?;
        Ok(())
    }

    pub fn record_audit(
        &self,
        event_type: &str,
        entity_id: Option<&str>,
        detail: serde_json::Value,
    ) -> CoreResult<()> {
        let conn = self.conn.lock();
        insert_audit(&conn, event_type, entity_id, detail)
    }
}

const SERVER_SELECT_SQL: &str = "
    SELECT
        s.id, s.name, s.host, s.port, s.username, s.environment,
        s.control_mode, s.auth_kind, s.local_key_source, s.has_passphrase, s.has_sudo_password,
        s.connection_status, s.last_checked_at, s.last_latency_ms, s.last_error,
        s.cpu_percent, s.memory_percent, s.disk_percent, s.metrics_sampled_at,
        s.revision, s.created_at, s.updated_at,
        hk.trusted_fingerprint, hk.pending_fingerprint
    FROM servers s
    LEFT JOIN host_keys hk ON hk.server_id = s.id
";

fn map_server_row(r: &Row<'_>) -> rusqlite::Result<Server> {
    let trusted_fp: Option<String> = r.get(22)?;
    let pending_fp: Option<String> = r.get(23)?;
    let host_key_status = match (&trusted_fp, &pending_fp) {
        (Some(_), Some(_)) => HostKeyStatus::Changed,
        (Some(_), None) => HostKeyStatus::Trusted,
        _ => HostKeyStatus::Unknown,
    };

    let cpu: Option<f64> = r.get(15)?;
    let mem: Option<f64> = r.get(16)?;
    let disk: Option<f64> = r.get(17)?;
    let sampled_at: Option<String> = r.get(18)?;
    let metrics = match (cpu, mem, disk, sampled_at) {
        (Some(cpu_percent), Some(memory_percent), Some(disk_percent), Some(sampled_at)) => {
            Some(ServerMetrics {
                cpu_percent,
                memory_percent,
                disk_percent,
                sampled_at,
            })
        }
        _ => None,
    };

    Ok(Server {
        id: r.get(0)?,
        name: r.get(1)?,
        host: r.get(2)?,
        port: r.get::<_, u16>(3)?,
        username: r.get(4)?,
        environment: r.get(5)?,
        control_mode: ControlMode::from_db(&r.get::<_, String>(6)?),
        auth_kind: AuthKind::from_db(&r.get::<_, String>(7)?),
        local_key_source: r.get(8)?,
        has_passphrase: r.get::<_, i64>(9)? != 0,
        has_sudo_password: r.get::<_, i64>(10)? != 0,
        connection_status: ConnectionStatus::from_db(&r.get::<_, String>(11)?),
        host_key_status,
        host_key_fingerprint: trusted_fp,
        pending_host_key_fingerprint: pending_fp,
        last_checked_at: r.get(12)?,
        last_latency_ms: r.get(13)?,
        last_error: r.get(14)?,
        metrics,
        revision: r.get(19)?,
        created_at: r.get(20)?,
        updated_at: r.get(21)?,
    })
}

fn get_server_inner(conn: &Connection, server_id: &str) -> CoreResult<Option<Server>> {
    conn.query_row(
        &format!("{SERVER_SELECT_SQL} WHERE s.id = ?1"),
        params![server_id],
        map_server_row,
    )
    .optional()
    .map_err(Into::into)
}

fn get_job_inner(conn: &Connection, job_id: &str) -> CoreResult<Option<Job>> {
    let row = conn
        .query_row(
            "SELECT id, tool, requester, reason, operation_json, status,
                    created_at, started_at, finished_at, revision
             FROM jobs WHERE id = ?1",
            params![job_id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, Option<String>>(7)?,
                    r.get::<_, Option<String>>(8)?,
                    r.get::<_, i64>(9)?,
                ))
            },
        )
        .optional()?;

    let Some((
        id,
        tool,
        requester,
        reason,
        operation_json,
        status_str,
        created_at,
        started_at,
        finished_at,
        revision,
    )) = row
    else {
        return Ok(None);
    };

    let operation: ToolOperation = serde_json::from_str(&operation_json)?;
    let tool_label = operation.display_label().to_string();

    let mut stmt = conn.prepare(
        "SELECT t.id, t.server_id, t.server_name, t.status, t.exit_code, t.error,
                t.started_at, t.finished_at, t.output_bytes, t.output_truncated,
                t.executed_command, t.result_json,
                a.id, a.approval_reason, a.matched_policy, a.risk
         FROM job_targets t
         LEFT JOIN approvals a ON a.target_id = t.id
         WHERE t.job_id = ?1
         ORDER BY t.rowid ASC",
    )?;
    let raw_targets = stmt
        .query_map(params![job_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<i32>>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, Option<String>>(7)?,
                r.get::<_, i64>(8)?,
                r.get::<_, i64>(9)? != 0,
                r.get::<_, Option<String>>(10)?,
                r.get::<_, Option<String>>(11)?,
                r.get::<_, Option<String>>(12)?,
                r.get::<_, Option<String>>(13)?,
                r.get::<_, Option<String>>(14)?,
                r.get::<_, Option<String>>(15)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut targets = Vec::with_capacity(raw_targets.len());
    for (
        tid,
        server_id,
        server_name,
        t_status,
        exit_code,
        error,
        t_started,
        t_finished,
        output_bytes,
        output_truncated,
        executed_command,
        result_json,
        approval_id,
        approval_reason,
        matched_policy,
        risk_str,
    ) in raw_targets
    {
        let structured_result = result_json
            .as_deref()
            .map(serde_json::from_str)
            .transpose()?;
        targets.push(JobTarget {
            id: tid,
            server_id,
            server_name,
            status: TargetStatus::from_db(&t_status),
            exit_code,
            error,
            started_at: t_started,
            finished_at: t_finished,
            output_bytes: output_bytes.max(0) as u64,
            output_truncated,
            executed_command,
            structured_result,
            approval_id,
            approval_reason,
            matched_policy,
            risk_level: risk_str.as_deref().map(ApprovalRiskLevel::from_db),
        });
    }

    Ok(Some(Job {
        id,
        tool,
        tool_label,
        requester,
        reason,
        operation,
        status: JobStatus::from_db(&status_str),
        targets,
        created_at,
        started_at,
        finished_at,
        revision,
    }))
}

fn get_approval_inner(conn: &Connection, approval_id: &str) -> CoreResult<Option<Approval>> {
    let row = conn
        .query_row(
            "SELECT id, job_id, target_id, server_id, server_name, requester, caller_reason,
                    operation_json, content_digest, request_digest, risk, approval_reason,
                    matched_policy, policy_summary, sudo, status, created_at, expires_at, decided_at
             FROM approvals WHERE id = ?1",
            params![approval_id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, Option<String>>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, Option<String>>(8)?,
                    r.get::<_, String>(9)?,
                    r.get::<_, String>(10)?,
                    r.get::<_, String>(11)?,
                    r.get::<_, String>(12)?,
                    r.get::<_, Option<String>>(13)?,
                    r.get::<_, i64>(14)? != 0,
                    r.get::<_, String>(15)?,
                    r.get::<_, String>(16)?,
                    r.get::<_, String>(17)?,
                    r.get::<_, Option<String>>(18)?,
                ))
            },
        )
        .optional()?;

    let Some((
        id,
        job_id,
        target_id,
        server_id,
        server_name,
        requester,
        caller_reason,
        operation_json,
        content_digest,
        request_digest,
        risk_str,
        approval_reason,
        matched_policy,
        policy_summary,
        sudo,
        status_str,
        created_at,
        expires_at,
        decided_at,
    )) = row
    else {
        return Ok(None);
    };

    let operation: ToolOperation = serde_json::from_str(&operation_json)?;
    let risk = ApprovalRiskLevel::from_db(&risk_str);

    Ok(Some(Approval {
        id,
        job_id,
        target_id,
        server_id,
        server_name,
        tool_label: operation.display_label().to_string(),
        command_preview: operation.command_preview(),
        requester,
        caller_reason,
        operation,
        content_digest,
        request_digest,
        risk,
        risk_level: risk,
        approval_reason,
        matched_policy,
        policy_summary,
        sudo,
        status: ApprovalStatus::from_db(&status_str),
        created_at,
        expires_at,
        decided_at,
    }))
}

fn recompute_job_status(conn: &Connection, job_id: &str, now: &str) -> CoreResult<JobStatus> {
    let mut stmt = conn.prepare("SELECT status FROM job_targets WHERE job_id = ?1")?;
    let statuses: Vec<TargetStatus> = stmt
        .query_map(params![job_id], |r| {
            Ok(TargetStatus::from_db(&r.get::<_, String>(0)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(stmt);

    let any_running = statuses.contains(&TargetStatus::Running);
    let any_waiting = statuses.contains(&TargetStatus::WaitingApproval);
    let any_queued = statuses.contains(&TargetStatus::Queued);

    let next_status = if any_running {
        JobStatus::Running
    } else if any_waiting {
        JobStatus::WaitingApproval
    } else if any_queued {
        JobStatus::Queued
    } else {
        let succeeded = statuses
            .iter()
            .filter(|&&s| s == TargetStatus::Succeeded)
            .count();
        let cancelled = statuses
            .iter()
            .filter(|&&s| s == TargetStatus::Cancelled)
            .count();
        if succeeded == statuses.len() {
            JobStatus::Succeeded
        } else if cancelled == statuses.len() {
            JobStatus::Cancelled
        } else if succeeded > 0 {
            JobStatus::PartialFailure
        } else {
            JobStatus::Failed
        }
    };

    let finished_at = if next_status.is_active() {
        None
    } else {
        Some(now)
    };

    conn.execute(
        "UPDATE jobs SET status = ?1, finished_at = ?2, revision = revision + 1 WHERE id = ?3",
        params![next_status.as_str(), finished_at, job_id],
    )?;

    Ok(next_status)
}

fn collect_job_files(conn: &Connection, job_id: &str) -> CoreResult<Vec<String>> {
    let mut paths = Vec::new();
    let mut stmt = conn.prepare(
        "SELECT output_path FROM job_targets WHERE job_id = ?1 AND output_path IS NOT NULL",
    )?;
    let rows: Vec<String> = stmt
        .query_map(params![job_id], |r| r.get(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(stmt);
    paths.extend(rows);

    if let Some(exec_json) = conn
        .query_row(
            "SELECT execution_json FROM jobs WHERE id = ?1",
            params![job_id],
            |r| r.get::<_, String>(0),
        )
        .optional()?
    {
        if let Ok(ToolOperation::FileUpload { local_path, .. }) =
            serde_json::from_str::<ToolOperation>(&exec_json)
        {
            if local_path.ends_with(".upload") {
                paths.push(local_path);
            }
        }
    }
    Ok(paths)
}

fn validate_authentication(auth: &SshAuthentication) -> CoreResult<()> {
    match auth {
        SshAuthentication::Password { password } => {
            if password.is_empty() || password.len() > 4096 {
                return Err(CoreError::InvalidInput("SSH 密码不能为空".to_string()));
            }
        }
        SshAuthentication::ManagedKey { private_key, .. } => {
            if private_key.trim().is_empty() || private_key.len() > 1024 * 1024 {
                return Err(CoreError::InvalidInput("托管私钥内容无效".to_string()));
            }
        }
        SshAuthentication::LocalKeyPath { path, .. } => {
            if path.len() > 32767 {
                return Err(CoreError::InvalidInput("本机密钥路径过长".to_string()));
            }
        }
    }
    Ok(())
}

fn insert_audit(
    conn: &Connection,
    event_type: &str,
    entity_id: Option<&str>,
    detail: serde_json::Value,
) -> CoreResult<()> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO audit_events (id, event_type, entity_id, detail_json, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![id, event_type, entity_id, detail.to_string(), now],
    )?;
    Ok(())
}

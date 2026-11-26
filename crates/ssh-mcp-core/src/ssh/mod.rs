use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use chrono::Utc;
use parking_lot::Mutex;
use russh::keys::agent::client::AgentClient;
use russh::keys::{decode_secret_key, load_secret_key, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{client, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Disconnect, Sig};
use russh_sftp::client::SftpSession;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::db::AppDatabase;
use crate::docker::{
    build_delete_command, build_docker_command, is_docker_operation, parse_docker_result,
    quote_posix,
};
use crate::error::{CoreError, CoreResult};
use crate::events::CoreEventSink;
use crate::models::{
    ConnectionStatus, DirectProbeResult, DockerCleanupTarget, Server, ServerMetrics,
    SshAuthentication, ToolOperation,
};
use crate::security::{redact_json_value, redact_text};

const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const METRICS_SCRIPT: &str = r#"read _ u1 n1 s1 i1 w1 q1 sq1 st1 _ < /proc/stat
sleep 0.15
read _ u2 n2 s2 i2 w2 q2 sq2 st2 _ < /proc/stat
printf 'CPU1=%s %s %s %s %s %s %s %s\n' "$u1" "$n1" "$s1" "$i1" "$w1" "$q1" "$sq1" "$st1"
printf 'CPU2=%s %s %s %s %s %s %s %s\n' "$u2" "$n2" "$s2" "$i2" "$w2" "$q2" "$sq2" "$st2"
awk '/^MemTotal:/{t=$2} /^MemAvailable:/{a=$2} /^MemFree:/{f=$2} /^Buffers:/{b=$2} /^Cached:/{c=$2} END{if(a>0) printf "MEM=%d %d\n", t-a, t; else printf "MEM=%d %d\n", t-f-b-c, t}' /proc/meminfo
df -P -k / | tail -n 1 | awk '{printf "DISK=%s %s\n", $3, $2}'"#;

#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub structured_result: Option<serde_json::Value>,
    pub output_truncated: bool,
    pub executed_command: Option<String>,
}

pub struct SshClientHandler {
    trusted_fingerprint: Option<String>,
    observed_fingerprint: Arc<Mutex<Option<String>>>,
}

impl client::Handler for SshClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let fp = compute_sha256_fingerprint(server_public_key);
        *self.observed_fingerprint.lock() = Some(fp.clone());
        Ok(self.trusted_fingerprint.as_deref() == Some(fp.as_str()))
    }
}

pub struct PtySessionParts {
    pub read_half: ChannelReadHalf,
    pub write_half: ChannelWriteHalf<client::Msg>,
    pub handle: client::Handle<SshClientHandler>,
}

struct ConnectedSession {
    handle: client::Handle<SshClientHandler>,
    secrets: Vec<String>,
    sudo_password: Option<String>,
    latency_ms: u32,
}

pub struct SshService {
    db: Arc<AppDatabase>,
    events: Arc<dyn CoreEventSink>,
}

impl SshService {
    pub fn new(db: Arc<AppDatabase>, events: Arc<dyn CoreEventSink>) -> Arc<Self> {
        Arc::new(Self { db, events })
    }

    /// Directly probes a server's SSH connection (and optionally collects CPU/Memory/Disk metrics)
    /// without creating a row in `jobs`.
    pub async fn probe_server(
        &self,
        server: &Server,
        collect_metrics: bool,
    ) -> CoreResult<DirectProbeResult> {
        let cancel = CancellationToken::new();
        let conn = self.connect(server, &cancel).await?;
        let latency_ms = conn.latency_ms;

        let mut metrics = None;
        if collect_metrics {
            if let Ok(raw) = self
                .exec_raw(&conn.handle, METRICS_SCRIPT, false, None, 15, &cancel)
                .await
            {
                if raw.exit_code == Some(0) {
                    metrics = parse_metrics_output(&raw.stdout);
                }
            }
        }

        let _ = conn
            .handle
            .disconnect(Disconnect::ByApplication, "", "en")
            .await;

        let (updated, _) = self.db.update_connection_probe(
            &server.id,
            ConnectionStatus::Online,
            Some(latency_ms),
            None,
            metrics.as_ref(),
        )?;
        self.events.on_state_changed();

        Ok(DirectProbeResult {
            server: updated,
            latency_ms: Some(latency_ms),
        })
    }

    pub async fn execute_operation(
        &self,
        server: &Server,
        operation: &ToolOperation,
        default_timeout_secs: u32,
        cancel: CancellationToken,
    ) -> CoreResult<ExecutionResult> {
        let mut conn = self.connect(server, &cancel).await?;
        let latency_ms = conn.latency_ms;

        let result = match operation {
            ToolOperation::ServerCheck => {
                let mut metrics = None;
                if let Ok(raw) = self
                    .exec_raw(&conn.handle, METRICS_SCRIPT, false, None, 15, &cancel)
                    .await
                {
                    if raw.exit_code == Some(0) {
                        metrics = parse_metrics_output(&raw.stdout);
                    }
                }
                let _ = self.db.update_connection_probe(
                    &server.id,
                    ConnectionStatus::Online,
                    Some(latency_ms),
                    None,
                    metrics.as_ref(),
                );
                Ok(ExecutionResult {
                    exit_code: Some(0),
                    stdout: format!("SSH 连接成功 · {latency_ms}ms\n"),
                    stderr: String::new(),
                    structured_result: None,
                    output_truncated: false,
                    executed_command: None,
                })
            }
            ToolOperation::FileUpload {
                local_path,
                remote_path,
                overwrite,
                ..
            } => {
                let logical = format!("sftp upload {local_path} -> {remote_path}");
                self.sftp_upload(&conn.handle, local_path, remote_path, *overwrite, &cancel)
                    .await?;
                let _ = self.db.update_connection_probe(
                    &server.id,
                    ConnectionStatus::Online,
                    Some(latency_ms),
                    None,
                    None,
                );
                Ok(ExecutionResult {
                    exit_code: Some(0),
                    stdout: format!("已上传到 {remote_path}\n"),
                    stderr: String::new(),
                    structured_result: None,
                    output_truncated: false,
                    executed_command: Some(redact_text(&logical, &conn.secrets)),
                })
            }
            ToolOperation::FileDownload {
                remote_path,
                local_path,
                overwrite,
                ..
            } => {
                let logical = format!("sftp download {remote_path} -> {local_path}");
                self.sftp_download(&conn.handle, remote_path, local_path, *overwrite, &cancel)
                    .await?;
                let _ = self.db.update_connection_probe(
                    &server.id,
                    ConnectionStatus::Online,
                    Some(latency_ms),
                    None,
                    None,
                );
                Ok(ExecutionResult {
                    exit_code: Some(0),
                    stdout: format!("已下载到 {local_path}\n"),
                    stderr: String::new(),
                    structured_result: None,
                    output_truncated: false,
                    executed_command: Some(redact_text(&logical, &conn.secrets)),
                })
            }
            other => {
                let cmd = build_remote_command(other)?;
                let timeout = other
                    .timeout_seconds()
                    .unwrap_or(default_timeout_secs)
                    .clamp(1, 1800);
                let raw = self
                    .exec_raw(
                        &conn.handle,
                        &cmd,
                        other.uses_sudo(),
                        conn.sudo_password.as_deref(),
                        timeout,
                        &cancel,
                    )
                    .await?;
                let _ = self.db.update_connection_probe(
                    &server.id,
                    ConnectionStatus::Online,
                    Some(latency_ms),
                    None,
                    None,
                );

                let stdout = redact_text(&raw.stdout, &conn.secrets);
                let stderr = redact_text(&raw.stderr, &conn.secrets);
                let structured = if raw.exit_code == Some(0) && is_docker_operation(other) {
                    parse_docker_result(other, &stdout)
                        .ok()
                        .map(|v| redact_json_value(&v, &conn.secrets))
                } else {
                    None
                };

                Ok(ExecutionResult {
                    exit_code: raw.exit_code,
                    stdout,
                    stderr,
                    structured_result: structured,
                    output_truncated: false,
                    executed_command: Some(redact_text(&cmd, &conn.secrets)),
                })
            }
        };

        let _ = conn
            .handle
            .disconnect(Disconnect::ByApplication, "", "en")
            .await;
        for s in &mut conn.secrets {
            zeroize::Zeroize::zeroize(s);
        }
        result
    }

    pub async fn execute_cleanup_delete(
        &self,
        server: &Server,
        target: &DockerCleanupTarget,
        sudo: bool,
        timeout_secs: u32,
        cancel: CancellationToken,
    ) -> CoreResult<ExecutionResult> {
        let cmd = build_delete_command(target)?;
        let mut conn = self.connect(server, &cancel).await?;
        let raw_res = self
            .exec_raw(
                &conn.handle,
                &cmd,
                sudo,
                conn.sudo_password.as_deref(),
                timeout_secs.clamp(1, 1800),
                &cancel,
            )
            .await;
        let _ = conn
            .handle
            .disconnect(Disconnect::ByApplication, "", "en")
            .await;

        let raw = raw_res?;
        let stdout = redact_text(&raw.stdout, &conn.secrets);
        let stderr = redact_text(&raw.stderr, &conn.secrets);
        let exec_cmd = redact_text(&cmd, &conn.secrets);
        for s in &mut conn.secrets {
            zeroize::Zeroize::zeroize(s);
        }

        Ok(ExecutionResult {
            exit_code: raw.exit_code,
            stdout,
            stderr,
            structured_result: None,
            output_truncated: false,
            executed_command: Some(exec_cmd),
        })
    }

    pub async fn open_pty(
        &self,
        server: &Server,
        cols: u32,
        rows: u32,
    ) -> CoreResult<PtySessionParts> {
        let cancel = CancellationToken::new();
        let mut conn = self.connect(server, &cancel).await?;
        for s in &mut conn.secrets {
            zeroize::Zeroize::zeroize(s);
        }

        let channel = tokio::time::timeout(
            Duration::from_secs(15),
            conn.handle.channel_open_session(),
        )
        .await
        .map_err(|_| CoreError::Timeout)?
        .map_err(|e| CoreError::Ssh(format!("无法打开 SSH 终端通道: {e}")))?;

        channel
            .request_pty(true, "xterm-256color", cols.max(20), rows.max(5), 0, 0, &[])
            .await
            .map_err(|e| CoreError::Ssh(format!("请求远程 PTY 失败: {e}")))?;

        channel
            .request_shell(true)
            .await
            .map_err(|e| CoreError::Ssh(format!("启动远程交互式 Shell 失败: {e}")))?;

        let (read_half, write_half) = channel.split();
        Ok(PtySessionParts {
            read_half,
            write_half,
            handle: conn.handle,
        })
    }

    async fn connect(
        &self,
        server: &Server,
        cancel: &CancellationToken,
    ) -> CoreResult<ConnectedSession> {
        if cancel.is_cancelled() {
            return Err(CoreError::Cancelled);
        }

        let secret = self.db.get_secret(&server.id)?;
        let trusted_fp = self.db.get_trusted_host_key(&server.id)?;
        let observed_fp = Arc::new(Mutex::new(None));

        let mut secrets = Vec::new();
        if let SshAuthentication::Password { password } = &secret.authentication {
            secrets.push(password.clone());
        } else if let SshAuthentication::ManagedKey {
            passphrase: Some(p),
            ..
        }
        | SshAuthentication::LocalKeyPath {
            passphrase: Some(p),
            ..
        } = &secret.authentication
        {
            if !p.is_empty() {
                secrets.push(p.clone());
            }
        }
        if let Some(sudo_pw) = &secret.sudo_password {
            if !sudo_pw.is_empty() {
                secrets.push(sudo_pw.clone());
            }
        }

        let mut cfg = client::Config::default();
        cfg.inactivity_timeout = Some(Duration::from_secs(60));
        cfg.keepalive_interval = Some(Duration::from_secs(15));
        cfg.keepalive_max = 3;
        cfg.nodelay = true;
        let cfg = Arc::new(cfg);

        let handler = SshClientHandler {
            trusted_fingerprint: trusted_fp.clone(),
            observed_fingerprint: Arc::clone(&observed_fp),
        };

        let start = Instant::now();
        let addr = (server.host.as_str(), server.port);
        let connect_fut = client::connect(cfg, addr, handler);

        let handle_res = tokio::select! {
            _ = cancel.cancelled() => return Err(CoreError::Cancelled),
            res = tokio::time::timeout(Duration::from_secs(15), connect_fut) => {
                match res {
                    Ok(inner) => inner,
                    Err(_) => {
                        self.record_offline_and_maybe_alert(server, "SSH 连接超时，请检查网络或端口");
                        return Err(CoreError::Ssh("SSH 连接超时，请检查网络或端口".to_string()));
                    }
                }
            }
        };

        let mut handle = match handle_res {
            Ok(h) => h,
            Err(err) => {
                let maybe_obs = observed_fp.lock().clone();
                if let Some(obs) = maybe_obs {
                    if trusted_fp.as_deref() != Some(obs.as_str()) {
                        let (_, is_changed) =
                            self.db.record_host_key_observation(&server.id, &obs)?;
                        self.events.on_state_changed();
                        return if is_changed {
                            Err(CoreError::HostKeyChanged { fingerprint: obs })
                        } else {
                            Err(CoreError::HostKeyRequired { fingerprint: obs })
                        };
                    }
                }
                let redacted = redact_text(&format!("SSH 握手失败: {err}"), &secrets);
                self.record_offline_and_maybe_alert(server, &redacted);
                return Err(CoreError::Ssh(redacted));
            }
        };

        let auth_ok = match &secret.authentication {
            SshAuthentication::Password { password } => handle
                .authenticate_password(&server.username, password)
                .await
                .map(|r| r.success())
                .map_err(|e| format!("密码认证错误: {e}")),
            SshAuthentication::ManagedKey {
                private_key,
                passphrase,
            } => {
                let key = decode_secret_key(
                    private_key,
                    passphrase.as_deref().filter(|s| !s.is_empty()),
                )
                .map_err(|e| CoreError::Ssh(format!("解析托管私钥失败: {e}")))?;
                let rsa_hash = handle
                    .best_supported_rsa_hash()
                    .await
                    .ok()
                    .flatten()
                    .flatten();
                let key_with_alg = PrivateKeyWithHashAlg::new(Arc::new(key), rsa_hash);
                handle
                    .authenticate_publickey(&server.username, key_with_alg)
                    .await
                    .map(|r| r.success())
                    .map_err(|e| format!("公钥认证错误: {e}"))
            }
            SshAuthentication::LocalKeyPath { path, passphrase } => {
                let trimmed = path.trim();
                if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("ssh-agent") {
                    authenticate_via_windows_agent(&mut handle, &server.username).await
                } else {
                    let key = load_secret_key(
                        trimmed,
                        passphrase.as_deref().filter(|s| !s.is_empty()),
                    )
                    .map_err(|e| {
                        CoreError::Ssh(format!("读取本机密钥 ({trimmed}) 失败: {e}"))
                    })?;
                    let rsa_hash = handle
                        .best_supported_rsa_hash()
                        .await
                        .ok()
                        .flatten()
                        .flatten();
                    let key_with_alg = PrivateKeyWithHashAlg::new(Arc::new(key), rsa_hash);
                    handle
                        .authenticate_publickey(&server.username, key_with_alg)
                        .await
                        .map(|r| r.success())
                        .map_err(|e| format!("本机密钥认证错误: {e}"))
                }
            }
        };

        match auth_ok {
            Ok(true) => {
                let latency_ms = start.elapsed().as_millis().min(u32::MAX as u128) as u32;
                Ok(ConnectedSession {
                    handle,
                    secrets,
                    sudo_password: secret.sudo_password.clone(),
                    latency_ms,
                })
            }
            Ok(false) => {
                let msg = "SSH 身份认证被服务器拒绝，请检查用户名或密钥/密码";
                self.record_offline_and_maybe_alert(server, msg);
                Err(CoreError::Ssh(msg.to_string()))
            }
            Err(e) => {
                let redacted = redact_text(&e, &secrets);
                self.record_offline_and_maybe_alert(server, &redacted);
                Err(CoreError::Ssh(redacted))
            }
        }
    }

    fn record_offline_and_maybe_alert(&self, server: &Server, err_msg: &str) {
        if let Ok((updated, transitioned_offline)) = self.db.update_connection_probe(
            &server.id,
            ConnectionStatus::Offline,
            None,
            Some(err_msg),
            None,
        ) {
            self.events.on_state_changed();
            if transitioned_offline {
                let alerts_on = self
                    .db
                    .get_raw_settings()
                    .map(|s| s.failure_alerts_enabled)
                    .unwrap_or(true);
                if alerts_on {
                    self.events.on_failure_alert(
                        &format!("服务器离线告警 · {}", updated.name),
                        &format!("{}:{} 连接中断：{}", updated.host, updated.port, err_msg),
                        Some(&updated.id),
                        None,
                    );
                }
            }
        }
    }

    async fn exec_raw(
        &self,
        handle: &client::Handle<SshClientHandler>,
        command: &str,
        sudo: bool,
        sudo_password: Option<&str>,
        timeout_secs: u32,
        cancel: &CancellationToken,
    ) -> CoreResult<RawExecOutput> {
        let remote_cmd = if sudo {
            if sudo_password.is_some_and(|s| !s.is_empty()) {
                format!("sudo -S -p '' -- sh -c {}", quote_posix(command))
            } else {
                format!("sudo -n -- sh -c {}", quote_posix(command))
            }
        } else {
            command.to_string()
        };

        let mut channel = handle
            .channel_open_session()
            .await
            .map_err(|e| CoreError::Ssh(format!("打开执行通道失败: {e}")))?;

        channel
            .exec(true, remote_cmd.into_bytes())
            .await
            .map_err(|e| CoreError::Ssh(format!("发送远程命令失败: {e}")))?;

        if sudo {
            if let Some(pw) = sudo_password.filter(|s| !s.is_empty()) {
                let mut line = pw.as_bytes().to_vec();
                line.push(b'\n');
                let _ = channel.data(&line[..]).await;
                zeroize::Zeroize::zeroize(&mut line);
            }
        }
        let _ = channel.eof().await;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code: Option<i32> = None;
        let deadline = tokio::time::sleep(Duration::from_secs(timeout_secs as u64));
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    let _ = channel.signal(Sig::TERM).await;
                    let _ = channel.close().await;
                    return Err(CoreError::Cancelled);
                }
                _ = &mut deadline => {
                    let _ = channel.signal(Sig::TERM).await;
                    let _ = channel.close().await;
                    return Err(CoreError::Timeout);
                }
                msg = channel.wait() => {
                    match msg {
                        Some(ChannelMsg::Data { data }) => {
                            if stdout.len() + stderr.len() + data.len() > MAX_OUTPUT_BYTES {
                                let _ = channel.signal(Sig::TERM).await;
                                return Err(CoreError::Ssh("远程输出超过 16 MiB 安全上限".to_string()));
                            }
                            stdout.extend_from_slice(&data);
                        }
                        Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                            if stdout.len() + stderr.len() + data.len() > MAX_OUTPUT_BYTES {
                                let _ = channel.signal(Sig::TERM).await;
                                return Err(CoreError::Ssh("远程输出超过 16 MiB 安全上限".to_string()));
                            }
                            stderr.extend_from_slice(&data);
                        }
                        Some(ChannelMsg::ExitStatus { exit_status }) => {
                            exit_code = Some(exit_status as i32);
                        }
                        Some(ChannelMsg::Close) | None => break,
                        _ => {}
                    }
                }
            }
        }

        Ok(RawExecOutput {
            exit_code,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    }

    async fn sftp_upload(
        &self,
        handle: &client::Handle<SshClientHandler>,
        local_path: &str,
        remote_path: &str,
        overwrite: bool,
        cancel: &CancellationToken,
    ) -> CoreResult<()> {
        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| CoreError::Ssh(format!("打开 SFTP 通道失败: {e}")))?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| CoreError::Ssh(format!("启动 SFTP 子系统失败: {e}")))?;

        let sftp = SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| CoreError::Ssh(format!("SFTP 握手失败: {e}")))?;

        let exists = sftp
            .try_exists(remote_path)
            .await
            .map_err(|e| CoreError::Ssh(format!("检查远程文件失败: {e}")))?;
        if exists && !overwrite {
            let _ = sftp.close().await;
            return Err(CoreError::Conflict(
                "远程文件已存在，必须明确开启 overwrite 允许覆盖".to_string(),
            ));
        }

        let remote_norm = remote_path.replace('\\', "/");
        let (parent, base) = match remote_norm.rfind('/') {
            Some(0) => ("/", &remote_norm[1..]),
            Some(idx) => (&remote_norm[..idx], &remote_norm[idx + 1..]),
            None => (".", remote_norm.as_str()),
        };
        let temp_remote = format!("{parent}/.{base}.ssc-{}.tmp", Uuid::new_v4());

        let mut src = tokio::fs::File::open(local_path)
            .await
            .map_err(|e| CoreError::Io(e))?;
        let mut dst = sftp
            .create(&temp_remote)
            .await
            .map_err(|e| CoreError::Ssh(format!("无法创建远程临时文件 ({temp_remote}): {e}")))?;

        let mut buf = vec![0u8; 64 * 1024];
        let copy_res: CoreResult<()> = async {
            loop {
                if cancel.is_cancelled() {
                    return Err(CoreError::Cancelled);
                }
                let n = src.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                dst.write_all(&buf[..n])
                    .await
                    .map_err(|e| CoreError::Ssh(format!("SFTP 写入中断: {e}")))?;
            }
            dst.shutdown()
                .await
                .map_err(|e| CoreError::Ssh(format!("SFTP 刷盘失败: {e}")))?;
            Ok(())
        }
        .await;

        drop(dst);
        if let Err(err) = copy_res {
            let _ = sftp.remove_file(&temp_remote).await;
            let _ = sftp.close().await;
            return Err(err);
        }

        if sftp.posix_rename(&temp_remote, remote_path).await.is_err() {
            if overwrite && exists {
                let _ = sftp.remove_file(remote_path).await;
            }
            if let Err(e) = sftp.rename(&temp_remote, remote_path).await {
                let _ = sftp.remove_file(&temp_remote).await;
                let _ = sftp.close().await;
                return Err(CoreError::Ssh(format!("SFTP 原子重命名失败: {e}")));
            }
        }

        let _ = sftp.close().await;
        Ok(())
    }

    async fn sftp_download(
        &self,
        handle: &client::Handle<SshClientHandler>,
        remote_path: &str,
        local_path: &str,
        overwrite: bool,
        cancel: &CancellationToken,
    ) -> CoreResult<()> {
        let dst_path = Path::new(local_path);
        if !overwrite && dst_path.exists() {
            return Err(CoreError::Conflict(
                "本机目标文件已存在，必须明确开启 overwrite 允许覆盖".to_string(),
            ));
        }
        if let Some(parent) = dst_path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await?;
            }
        }

        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| CoreError::Ssh(format!("打开 SFTP 通道失败: {e}")))?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| CoreError::Ssh(format!("启动 SFTP 子系统失败: {e}")))?;

        let sftp = SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| CoreError::Ssh(format!("SFTP 握手失败: {e}")))?;

        let mut src = sftp
            .open(remote_path)
            .await
            .map_err(|e| CoreError::Ssh(format!("打开远程文件 ({remote_path}) 失败: {e}")))?;

        let file_name = dst_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("download");
        let temp_local = dst_path.with_file_name(format!(".{file_name}.ssc-{}.tmp", Uuid::new_v4()));

        let mut dst = tokio::fs::File::create(&temp_local).await?;
        let mut buf = vec![0u8; 64 * 1024];

        let dl_res: CoreResult<()> = async {
            loop {
                if cancel.is_cancelled() {
                    return Err(CoreError::Cancelled);
                }
                let n = src
                    .read(&mut buf)
                    .await
                    .map_err(|e| CoreError::Ssh(format!("SFTP 读取失败: {e}")))?;
                if n == 0 {
                    break;
                }
                dst.write_all(&buf[..n]).await?;
            }
            dst.flush().await?;
            Ok(())
        }
        .await;

        drop(dst);
        drop(src);
        let _ = sftp.close().await;

        if let Err(err) = dl_res {
            let _ = tokio::fs::remove_file(&temp_local).await;
            return Err(err);
        }

        if overwrite && dst_path.exists() {
            let _ = tokio::fs::remove_file(dst_path).await;
        }
        tokio::fs::rename(&temp_local, dst_path).await?;
        Ok(())
    }
}

struct RawExecOutput {
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
}

async fn authenticate_via_windows_agent(
    handle: &mut client::Handle<SshClientHandler>,
    username: &str,
) -> Result<bool, String> {
    #[cfg(windows)]
    {
        let mut agent = AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent")
            .await
            .map_err(|e| {
                format!(
                    "无法连接 Windows OpenSSH Authentication Agent (\\\\.\\pipe\\openssh-ssh-agent): {e}"
                )
            })?;

        let identities = agent
            .request_identities()
            .await
            .map_err(|e| format!("读取 Windows OpenSSH Agent 密钥列表失败: {e}"))?;

        if identities.is_empty() {
            return Err("Windows OpenSSH Agent 中没有已加载的密钥，请先运行 ssh-add".to_string());
        }

        let rsa_hash = handle
            .best_supported_rsa_hash()
            .await
            .ok()
            .flatten()
            .flatten();

        for ident in identities {
            let pubkey = ident.public_key().into_owned();
            let hash_alg = if pubkey.algorithm().is_rsa() {
                rsa_hash
            } else {
                None
            };
            if let Ok(res) = handle
                .authenticate_publickey_with(username, pubkey, hash_alg, &mut agent)
                .await
            {
                if res.success() {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    #[cfg(not(windows))]
    {
        let _ = (handle, username);
        Err("仅支持 Windows 10/11 OpenSSH Agent".to_string())
    }
}

pub fn compute_sha256_fingerprint(key: &PublicKeyOrCertificate) -> String {
    let pubkey = key.public_key();
    if let Ok(bytes) = pubkey.to_bytes() {
        let digest = Sha256::digest(&bytes);
        format!("SHA256:{}", STANDARD_NO_PAD.encode(digest))
    } else {
        pubkey.fingerprint(russh::keys::HashAlg::Sha256).to_string()
    }
}

fn build_remote_command(op: &ToolOperation) -> CoreResult<String> {
    if is_docker_operation(op) {
        return build_docker_command(op);
    }
    match op {
        ToolOperation::SystemSummary { .. } => Ok(
            "printf 'HOSTNAME='; hostname; printf 'UPTIME='; uptime -p; printf 'LOAD='; cat /proc/loadavg; printf 'MEMORY='; free -b; printf 'DISK='; df -B1 -x tmpfs -x devtmpfs".to_string(),
        ),
        ToolOperation::ProcessesList { limit, .. } => Ok(format!(
            "ps -eo pid,user,pcpu,pmem,etime,comm,args --sort=-pcpu | head -n {}",
            limit + 1
        )),
        ToolOperation::ServicesList { state, limit, .. } => Ok(format!(
            "systemctl list-units --type=service --state={} --no-pager --no-legend --plain | head -n {}",
            state.as_str(),
            limit
        )),
        ToolOperation::ServiceStatus { service, .. } => Ok(format!(
            "systemctl status --no-pager --full {}",
            quote_posix(service)
        )),
        ToolOperation::ServiceControl {
            service, action, ..
        } => Ok(format!("systemctl {} {}", action.as_str(), quote_posix(service))),
        ToolOperation::LogsQuery {
            unit,
            lines,
            since,
            query,
            ..
        } => {
            let mut parts = vec![
                "journalctl".to_string(),
                "--no-pager".to_string(),
                "--output=short-iso".to_string(),
                "-n".to_string(),
                lines.to_string(),
            ];
            if let Some(u) = unit.as_deref().filter(|s| !s.is_empty()) {
                parts.push("-u".to_string());
                parts.push(quote_posix(u));
            }
            if let Some(s) = since.as_deref().filter(|s| !s.is_empty()) {
                parts.push("--since".to_string());
                parts.push(quote_posix(s));
            }
            if let Some(q) = query.as_deref().filter(|s| !s.is_empty()) {
                parts.push("--grep".to_string());
                parts.push(quote_posix(q));
            }
            Ok(parts.join(" "))
        }
        ToolOperation::ShellExecute { command, .. } => Ok(command.clone()),
        _ => Err(CoreError::InvalidInput("不支持的远程命令类型".to_string())),
    }
}

pub fn parse_metrics_output(stdout: &str) -> Option<ServerMetrics> {
    let mut cpu1: Option<Vec<u64>> = None;
    let mut cpu2: Option<Vec<u64>> = None;
    let mut mem_pct: Option<f64> = None;
    let mut disk_pct: Option<f64> = None;

    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("CPU1=") {
            cpu1 = Some(
                rest.split_whitespace()
                    .filter_map(|s| s.parse::<u64>().ok())
                    .collect(),
            );
        } else if let Some(rest) = trimmed.strip_prefix("CPU2=") {
            cpu2 = Some(
                rest.split_whitespace()
                    .filter_map(|s| s.parse::<u64>().ok())
                    .collect(),
            );
        } else if let Some(rest) = trimmed.strip_prefix("MEM=") {
            let nums: Vec<f64> = rest
                .split_whitespace()
                .filter_map(|s| s.parse::<f64>().ok())
                .collect();
            if nums.len() == 2 && nums[1] > 0.0 {
                mem_pct = Some(((nums[0] / nums[1]) * 100.0).clamp(0.0, 100.0));
            }
        } else if let Some(rest) = trimmed.strip_prefix("DISK=") {
            let nums: Vec<f64> = rest
                .split_whitespace()
                .filter_map(|s| s.parse::<f64>().ok())
                .collect();
            if nums.len() == 2 && nums[1] > 0.0 {
                disk_pct = Some(((nums[0] / nums[1]) * 100.0).clamp(0.0, 100.0));
            }
        }
    }

    let cpu_pct = match (cpu1, cpu2) {
        (Some(v1), Some(v2)) if v1.len() >= 5 && v2.len() >= 5 => {
            let total1: u64 = v1.iter().sum();
            let total2: u64 = v2.iter().sum();
            let idle1 = v1[3] + v1[4];
            let idle2 = v2[3] + v2[4];
            let total_delta = total2.saturating_sub(total1);
            let idle_delta = idle2.saturating_sub(idle1);
            if total_delta > 0 {
                (((total_delta.saturating_sub(idle_delta)) as f64 / total_delta as f64) * 100.0)
                    .clamp(0.0, 100.0)
            } else {
                0.0
            }
        }
        _ => return None,
    };

    Some(ServerMetrics {
        cpu_percent: (cpu_pct * 10.0).round() / 10.0,
        memory_percent: (mem_pct? * 10.0).round() / 10.0,
        disk_percent: (disk_pct? * 10.0).round() / 10.0,
        sampled_at: Utc::now().to_rfc3339(),
    })
}

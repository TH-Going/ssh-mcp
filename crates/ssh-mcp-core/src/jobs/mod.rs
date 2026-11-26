use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::DateTime;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::db::{AppDatabase, QueuedTargetItem, TargetFinishExtra};
use crate::docker::{
    make_cleanup_execution_result, make_cleanup_preview_result,
    make_incomplete_cleanup_execution_result, select_cleanup_targets, DockerInventory,
};
use crate::error::{CoreError, CoreResult};
use crate::events::CoreEventSink;
use crate::models::{
    Approval, ApprovalDecision, ApprovalDecisionRequest, DockerCleanupFailedItem,
    DockerResourceType, Job, JobCreateRequest, JobOutput, JobOutputSummary, JobStatus,
    JobWaitRequest, JobWaitResult, TargetStatus, ToolOperation, WaitUntilMode, WakeReason,
};
use crate::policy::{evaluate_approval_policy, ApprovalPolicyContext};
use crate::security::sha256_file_prefixed;
use crate::ssh::{ExecutionResult, SshService};

pub struct JobService {
    db: Arc<AppDatabase>,
    ssh: Arc<SshService>,
    events: Arc<dyn CoreEventSink>,
    output_dir: PathBuf,
    staging_dir: PathBuf,
    active_targets: Mutex<HashMap<String, CancellationToken>>,
    scheduled_targets: Mutex<HashSet<String>>,
    in_flight: AtomicUsize,
    scheduler_notify: Notify,
    job_waiters: Mutex<HashMap<String, Arc<Notify>>>,
    shutdown: CancellationToken,
}

impl JobService {
    pub fn new(
        db: Arc<AppDatabase>,
        ssh: Arc<SshService>,
        events: Arc<dyn CoreEventSink>,
        output_dir: PathBuf,
    ) -> CoreResult<Arc<Self>> {
        let staging_dir = output_dir.join("staging");
        std::fs::create_dir_all(&output_dir)?;
        std::fs::create_dir_all(&staging_dir)?;

        let svc = Arc::new(Self {
            db,
            ssh,
            events,
            output_dir,
            staging_dir,
            active_targets: Mutex::new(HashMap::new()),
            scheduled_targets: Mutex::new(HashSet::new()),
            in_flight: AtomicUsize::new(0),
            scheduler_notify: Notify::new(),
            job_waiters: Mutex::new(HashMap::new()),
            shutdown: CancellationToken::new(),
        });

        svc.start_background_workers();
        svc.wake();
        Ok(svc)
    }

    fn start_background_workers(self: &Arc<Self>) {
        let disp = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = disp.shutdown.cancelled() => break,
                    _ = disp.scheduler_notify.notified() => {
                        disp.dispatch_available().await;
                    }
                }
            }
        });

        let maint = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                tokio::select! {
                    _ = maint.shutdown.cancelled() => break,
                    _ = interval.tick() => {
                        maint.maintain_once().await;
                    }
                }
            }
        });
    }

    pub fn shutdown(&self) {
        self.shutdown.cancel();
        let tokens: Vec<CancellationToken> = self.active_targets.lock().values().cloned().collect();
        for t in tokens {
            t.cancel();
        }
        let waiters: Vec<Arc<Notify>> = self.job_waiters.lock().values().cloned().collect();
        for w in waiters {
            w.notify_waiters();
        }
    }

    pub fn wake(&self) {
        self.scheduler_notify.notify_one();
    }

    pub fn notify_job(&self, job_id: &str) {
        if let Some(notify) = self.job_waiters.lock().get(job_id).cloned() {
            notify.notify_waiters();
        }
    }

    pub async fn create(&self, input: JobCreateRequest) -> CoreResult<Job> {
        validate_operation(&input.operation)?;

        let mut exec_op = input.operation.clone();
        let mut content_digest: Option<String> = None;
        let mut snapshot_path: Option<PathBuf> = None;

        let cleanup_plan = match &input.operation {
            ToolOperation::DockerCleanupExecute {
                cleanup_plan_id, ..
            } => {
                let plan = self
                    .db
                    .get_cleanup_plan(cleanup_plan_id)?
                    .ok_or_else(|| CoreError::NotFound("CLEANUP_PLAN_NOT_FOUND: 清理计划不存在".to_string()))?;
                if plan.status == "expired" {
                    return Err(CoreError::Conflict(
                        "CLEANUP_PLAN_EXPIRED: 清理计划已超过 15 分钟有效期，请重新预览".to_string(),
                    ));
                }
                if plan.status != "ready" {
                    return Err(CoreError::Conflict(
                        "CLEANUP_PLAN_ALREADY_USED: 清理计划已被使用".to_string(),
                    ));
                }
                if input.server_ids.len() != 1 || input.server_ids[0] != plan.server_id {
                    return Err(CoreError::InvalidInput(
                        "CLEANUP_PLAN_SERVER_MISMATCH: 目标服务器与预览计划不一致".to_string(),
                    ));
                }
                content_digest = Some(plan.target_digest.clone());
                Some(plan)
            }
            _ => None,
        };

        if let ToolOperation::FileUpload {
            local_path,
            remote_path,
            overwrite,
            timeout_seconds,
            reason,
        } = &input.operation
        {
            let snap = self.staging_dir.join(format!("{}.upload", Uuid::new_v4()));
            tokio::fs::copy(local_path, &snap).await.map_err(|e| {
                CoreError::InvalidInput(format!("无法读取待上传本机文件 ({local_path}): {e}"))
            })?;
            let snap_clone = snap.clone();
            let digest = tokio::task::spawn_blocking(move || sha256_file_prefixed(&snap_clone))
                .await
                .map_err(|e| CoreError::Internal(format!("计算文件摘要失败: {e}")))??;
            content_digest = Some(digest);
            exec_op = ToolOperation::FileUpload {
                local_path: snap.to_string_lossy().to_string(),
                remote_path: remote_path.clone(),
                overwrite: *overwrite,
                timeout_seconds: *timeout_seconds,
                reason: reason.clone(),
            };
            snapshot_path = Some(snap);
        }

        let settings = self.db.get_raw_settings()?;
        let requester = input
            .requester
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("本机管理员");

        let create_res = self.db.create_job(
            &input.server_ids,
            requester,
            input.reason.as_deref(),
            &input.operation,
            &exec_op,
            content_digest.as_deref(),
            |server, op| {
                evaluate_approval_policy(
                    server,
                    op,
                    &ApprovalPolicyContext {
                        allow_read_only_shell_without_approval: settings
                            .allow_read_only_shell_without_approval,
                        cleanup_includes_volumes: cleanup_plan
                            .as_ref()
                            .is_some_and(|p| p.policy.resource_types.contains(&DockerResourceType::Volumes)),
                        policy_summary: cleanup_plan.as_ref().map(|p| p.policy_summary.clone()),
                    },
                )
            },
        );

        let (job, approvals) = match create_res {
            Ok(pair) => pair,
            Err(err) => {
                if let Some(snap) = snapshot_path {
                    let _ = tokio::fs::remove_file(snap).await;
                }
                return Err(err);
            }
        };

        if let Some(plan) = cleanup_plan {
            if let Err(err) = self.db.claim_cleanup_plan(&plan.id, &job.id) {
                let _ = self.db.cancel_job(&job.id);
                return Err(err);
            }
        }

        for approval in &approvals {
            self.events.on_approval_created(approval);
        }
        self.events.on_state_changed();
        self.notify_job(&job.id);
        self.wake();
        Ok(job)
    }

    pub async fn create_cleanup_execution(
        &self,
        cleanup_plan_id: String,
        timeout_seconds: Option<u32>,
        requester: Option<String>,
        reason: Option<String>,
    ) -> CoreResult<Job> {
        let plan = self
            .db
            .get_cleanup_plan(&cleanup_plan_id)?
            .ok_or_else(|| CoreError::NotFound("CLEANUP_PLAN_NOT_FOUND: 清理计划不存在".to_string()))?;

        self.create(JobCreateRequest {
            server_ids: vec![plan.server_id],
            operation: ToolOperation::DockerCleanupExecute {
                cleanup_plan_id,
                timeout_seconds,
                reason: reason.clone(),
            },
            requester,
            reason,
        })
        .await
    }

    pub fn decide_approval(
        &self,
        approval_id: &str,
        req: &ApprovalDecisionRequest,
    ) -> CoreResult<Approval> {
        let (approval, job_id) = self.db.decide_approval(approval_id, req)?;
        self.events.on_state_changed();
        self.notify_job(&job_id);
        if req.decision == ApprovalDecision::Approve {
            self.wake();
        }
        Ok(approval)
    }

    pub fn cancel(&self, job_id: &str) -> CoreResult<Job> {
        let job = self.db.cancel_job(job_id)?;
        {
            let map = self.active_targets.lock();
            for target in &job.targets {
                if let Some(tok) = map.get(&target.id) {
                    tok.cancel();
                }
            }
        }
        self.events.on_state_changed();
        self.notify_job(job_id);
        Ok(job)
    }

    pub async fn delete(&self, job_id: &str) -> CoreResult<()> {
        let paths = self.db.delete_job(job_id)?;
        for p in paths {
            let _ = tokio::fs::remove_file(p).await;
        }
        self.events.on_state_changed();
        Ok(())
    }

    pub async fn clear_finished(&self) -> CoreResult<usize> {
        let (count, paths) = self.db.clear_finished_jobs()?;
        for p in paths {
            let _ = tokio::fs::remove_file(p).await;
        }
        self.events.on_state_changed();
        Ok(count)
    }

    pub async fn wait(&self, req: JobWaitRequest) -> CoreResult<JobWaitResult> {
        let wait_ms = req.wait_ms.min(300_000);
        let initial = self
            .db
            .get_job(&req.job_id)?
            .ok_or_else(|| CoreError::NotFound("任务不存在".to_string()))?;

        if let Some(after) = req.after_revision {
            if after > initial.revision {
                return Err(CoreError::InvalidInput("afterRevision 超出当前任务版本".to_string()));
            }
        }

        let baseline = req.after_revision.unwrap_or(initial.revision);
        if let Some(reason) = evaluate_wake_reason(&initial, req.until, req.after_revision) {
            return Ok(build_wait_result(initial, baseline, reason, false));
        }

        if wait_ms == 0 {
            let changed = initial.revision > baseline;
            return Ok(JobWaitResult {
                job_id: initial.id.clone(),
                revision: initial.revision,
                changed,
                timed_out: true,
                wake_reason: WakeReason::Timeout,
                job: if changed { Some(initial) } else { None },
            });
        }

        let deadline = Instant::now() + Duration::from_millis(wait_ms);
        loop {
            let notify = {
                let mut map = self.job_waiters.lock();
                map.entry(req.job_id.clone())
                    .or_insert_with(|| Arc::new(Notify::new()))
                    .clone()
            };
            let notified = notify.notified();

            // Re-check after registering waiter to prevent missed wakeup race.
            let current = self
                .db
                .get_job(&req.job_id)?
                .ok_or_else(|| CoreError::NotFound("任务不存在".to_string()))?;
            if let Some(reason) = evaluate_wake_reason(&current, req.until, Some(baseline)) {
                return Ok(build_wait_result(current, baseline, reason, false));
            }

            let now = Instant::now();
            if now >= deadline || self.shutdown.is_cancelled() {
                let changed = current.revision > baseline;
                return Ok(JobWaitResult {
                    job_id: current.id.clone(),
                    revision: current.revision,
                    changed,
                    timed_out: true,
                    wake_reason: WakeReason::Timeout,
                    job: if changed { Some(current) } else { None },
                });
            }

            let remaining = deadline - now;
            if tokio::time::timeout(remaining, notified).await.is_err() {
                let latest = self
                    .db
                    .get_job(&req.job_id)?
                    .ok_or_else(|| CoreError::NotFound("任务不存在".to_string()))?;
                if let Some(reason) = evaluate_wake_reason(&latest, req.until, Some(baseline)) {
                    return Ok(build_wait_result(latest, baseline, reason, false));
                }
                let changed = latest.revision > baseline;
                return Ok(JobWaitResult {
                    job_id: latest.id.clone(),
                    revision: latest.revision,
                    changed,
                    timed_out: true,
                    wake_reason: WakeReason::Timeout,
                    job: if changed { Some(latest) } else { None },
                });
            }
        }
    }

    pub fn read_output(
        &self,
        job_id: &str,
        target_id: &str,
        offset: u64,
        limit_bytes: usize,
        cursor: Option<&str>,
    ) -> CoreResult<JobOutput> {
        let limit_bytes = limit_bytes.clamp(4, 65536);
        let cursor_state = cursor
            .filter(|s| !s.is_empty())
            .map(|c| decode_cursor(c, job_id, target_id))
            .transpose()?;
        if cursor_state.is_some() && offset != 0 {
            return Err(CoreError::InvalidInput(
                "同时传入 cursor 时 offset 必须为 0".to_string(),
            ));
        }
        let resolved_offset = cursor_state.as_ref().map(|c| c.offset).unwrap_or(offset);
        let meta = self.db.get_output_meta(job_id, target_id)?;
        if let Some(cs) = &cursor_state {
            if cs.total_bytes != meta.total_bytes {
                return Err(CoreError::InvalidInput("输出游标已失效".to_string()));
            }
        }

        if resolved_offset >= meta.total_bytes {
            let empty_summary = JobOutputSummary {
                returned_bytes: 0,
                line_count: 0,
                has_stdout: false,
                has_stderr: false,
                has_error: false,
            };
            return Ok(JobOutput {
                target_id: target_id.to_string(),
                content: String::new(),
                offset: resolved_offset,
                next_offset: None,
                total_bytes: meta.total_bytes,
                expires_at: meta.expires_at,
                cursor: encode_cursor(job_id, target_id, meta.total_bytes, resolved_offset),
                next_cursor: None,
                truncated: meta.output_truncated,
                summary: empty_summary.clone(),
                page_summary: empty_summary,
            });
        }

        let to_read = (meta.total_bytes - resolved_offset).min(limit_bytes as u64) as usize;
        let mut file = std::fs::File::open(&meta.path).map_err(|_| {
            CoreError::NotFound("输出日志文件已被清理或不存在".to_string())
        })?;
        file.seek(SeekFrom::Start(resolved_offset))?;
        let mut raw = vec![0u8; to_read];
        let n = file.read(&mut raw)?;
        raw.truncate(n);

        let at_eof = resolved_offset + (n as u64) >= meta.total_bytes;
        let (content, consumed_bytes) = decode_utf8_page(&raw, at_eof);
        let next_offset = if resolved_offset + (consumed_bytes as u64) < meta.total_bytes {
            Some(resolved_offset + consumed_bytes as u64)
        } else {
            None
        };

        let summary = JobOutputSummary {
            returned_bytes: consumed_bytes,
            line_count: if content.is_empty() {
                0
            } else {
                content.lines().count()
            },
            has_stdout: content.contains("[stdout]"),
            has_stderr: content.contains("[stderr]"),
            has_error: content.contains("[error]"),
        };

        Ok(JobOutput {
            target_id: target_id.to_string(),
            content,
            offset: resolved_offset,
            next_offset,
            total_bytes: meta.total_bytes,
            expires_at: meta.expires_at,
            cursor: encode_cursor(job_id, target_id, meta.total_bytes, resolved_offset),
            next_cursor: next_offset
                .map(|next| encode_cursor(job_id, target_id, meta.total_bytes, next)),
            truncated: meta.output_truncated,
            summary: summary.clone(),
            page_summary: summary,
        })
    }

    pub fn read_full_output(&self, job_id: &str, target_id: &str) -> CoreResult<String> {
        let meta = self.db.get_output_meta(job_id, target_id)?;
        std::fs::read_to_string(&meta.path)
            .map_err(|_| CoreError::NotFound("输出日志文件不存在或已过期".to_string()))
    }

    async fn dispatch_available(self: &Arc<Self>) {
        let max_conc = self
            .db
            .get_raw_settings()
            .map(|s| s.default_concurrency.clamp(1, 10))
            .unwrap_or(3);

        let queued = match self.db.get_queued_targets() {
            Ok(q) => q,
            Err(_) => return,
        };

        for item in queued {
            if self.in_flight.load(Ordering::SeqCst) >= max_conc {
                break;
            }
            {
                let mut sched = self.scheduled_targets.lock();
                if sched.contains(&item.target_id) {
                    continue;
                }
                sched.insert(item.target_id.clone());
            }

            self.in_flight.fetch_add(1, Ordering::SeqCst);
            let svc = Arc::clone(self);
            tokio::spawn(async move {
                svc.run_target(item.clone()).await;
                svc.scheduled_targets.lock().remove(&item.target_id);
                svc.in_flight.fetch_sub(1, Ordering::SeqCst);
                svc.wake();
            });
        }
    }

    async fn run_target(&self, item: QueuedTargetItem) {
        let server = match self.db.get_server(&item.server_id) {
            Ok(Some(s)) => s,
            _ => {
                let _ = self.db.finish_target(
                    &item.target_id,
                    TargetStatus::Failed,
                    None,
                    Some("服务器不存在"),
                    0,
                    TargetFinishExtra::default(),
                );
                self.finish_unavailable_cleanup(&item.operation, "failed");
                self.notify_job(&item.job_id);
                self.events.on_state_changed();
                return;
            }
        };

        if server.revision != item.server_revision {
            let _ = self.db.finish_target(
                &item.target_id,
                TargetStatus::Failed,
                None,
                Some("服务器配置在审批后发生变化，请重新发起任务"),
                0,
                TargetFinishExtra::default(),
            );
            self.finish_unavailable_cleanup(&item.operation, "stale");
            self.notify_job(&item.job_id);
            self.events.on_state_changed();
            return;
        }

        let output_path = self.output_dir.join(format!("{}.log", item.target_id));
        let output_path_str = output_path.to_string_lossy().to_string();
        match self.db.mark_target_running(&item.target_id, &output_path_str) {
            Ok(true) => {}
            _ => return,
        }
        self.notify_job(&item.job_id);
        self.events.on_state_changed();

        let cancel = CancellationToken::new();
        self.active_targets
            .lock()
            .insert(item.target_id.clone(), cancel.clone());

        let default_timeout = self
            .db
            .get_raw_settings()
            .map(|s| s.default_timeout_seconds)
            .unwrap_or(300);

        let exec_res = match &item.operation {
            ToolOperation::DockerCleanupExecute {
                cleanup_plan_id,
                timeout_seconds,
                ..
            } => {
                self.run_cleanup_execution(
                    &item,
                    &server,
                    cleanup_plan_id,
                    timeout_seconds.unwrap_or(default_timeout),
                    cancel.clone(),
                )
                .await
            }
            other => {
                self.ssh
                    .execute_operation(&server, other, default_timeout, cancel.clone())
                    .await
            }
        };

        self.active_targets.lock().remove(&item.target_id);

        match exec_res {
            Ok(mut res) => {
                let mut sections = Vec::new();
                if !res.stdout.is_empty() {
                    sections.push(format!("[stdout]\n{}", res.stdout));
                }
                if !res.stderr.is_empty() {
                    sections.push(format!("[stderr]\n{}", res.stderr));
                }
                let log_content = sections.join("\n");
                let _ = tokio::fs::write(&output_path, log_content.as_bytes()).await;
                let bytes = log_content.len() as u64;

                if res.exit_code == Some(0) {
                    if let ToolOperation::DockerCleanupPreview { policy, sudo, .. } = &item.operation
                    {
                        if let Some(val) = res.structured_result.take() {
                            if let Ok(inventory) = serde_json::from_value::<DockerInventory>(val) {
                                let now = chrono::Utc::now();
                                if let Ok(sel) = select_cleanup_targets(&inventory, policy, now) {
                                    let inv_json =
                                        serde_json::to_string(&inventory).unwrap_or_default();
                                    if let Ok(plan) = self.db.save_cleanup_plan(
                                        &server.id,
                                        item.server_revision,
                                        &item.job_id,
                                        &item.target_id,
                                        &sel.policy,
                                        &sel.policy_summary,
                                        *sudo,
                                        &inv_json,
                                        &sel.targets,
                                        &sel.target_digest,
                                    ) {
                                        let preview = make_cleanup_preview_result(
                                            &plan.id,
                                            &plan.server_id,
                                            &plan.created_at,
                                            &plan.expires_at,
                                            sel,
                                        );
                                        res.structured_result = serde_json::to_value(preview).ok();
                                    }
                                }
                            }
                        }
                    }
                }

                let (status, err_msg) = if cancel.is_cancelled() {
                    (TargetStatus::Cancelled, Some("已取消".to_string()))
                } else if res.exit_code == Some(0) {
                    (TargetStatus::Succeeded, None)
                } else {
                    let msg = match res.exit_code {
                        Some(code) => format!("远程命令退出码 {code}"),
                        None => "远程命令异常终止".to_string(),
                    };
                    (TargetStatus::Failed, Some(msg))
                };

                if let Ok((_, job_status, newly_failed)) = self.db.finish_target(
                    &item.target_id,
                    status,
                    res.exit_code,
                    err_msg.as_deref(),
                    bytes,
                    TargetFinishExtra {
                        structured_result: res.structured_result,
                        output_truncated: res.output_truncated,
                        executed_command: res.executed_command,
                    },
                ) {
                    if newly_failed {
                        self.maybe_alert_job_failure(&item.job_id, &server.name, job_status);
                    }
                }
            }
            Err(err) => {
                let msg = err.to_string();
                if let ToolOperation::DockerCleanupExecute {
                    cleanup_plan_id, ..
                } = &item.operation
                {
                    let status = if msg.contains("CLEANUP_PLAN_STALE") {
                        "stale"
                    } else {
                        "failed"
                    };
                    let _ = self.db.finish_cleanup_plan(cleanup_plan_id, status);
                }

                let log_content = format!("[error]\n{msg}");
                let _ = tokio::fs::write(&output_path, log_content.as_bytes()).await;
                let status = if cancel.is_cancelled() || matches!(err, CoreError::Cancelled) {
                    TargetStatus::Cancelled
                } else {
                    TargetStatus::Failed
                };
                if let Ok((_, job_status, newly_failed)) = self.db.finish_target(
                    &item.target_id,
                    status,
                    None,
                    Some(&msg),
                    log_content.len() as u64,
                    TargetFinishExtra {
                        structured_result: None,
                        output_truncated: false,
                        executed_command: Some(item.operation.command_preview()),
                    },
                ) {
                    if newly_failed {
                        self.maybe_alert_job_failure(&item.job_id, &server.name, job_status);
                    }
                }
            }
        }

        if let ToolOperation::FileUpload { local_path, .. } = &item.operation {
            if local_path.ends_with(".upload") {
                let _ = tokio::fs::remove_file(local_path).await;
            }
        }

        self.notify_job(&item.job_id);
        self.events.on_state_changed();
    }

    async fn run_cleanup_execution(
        &self,
        item: &QueuedTargetItem,
        server: &crate::models::Server,
        cleanup_plan_id: &str,
        timeout_secs: u32,
        cancel: CancellationToken,
    ) -> CoreResult<ExecutionResult> {
        let plan = self
            .db
            .get_cleanup_plan(cleanup_plan_id)?
            .ok_or_else(|| CoreError::Conflict("CLEANUP_PLAN_NOT_FOUND".to_string()))?;

        if plan.status != "claimed" || plan.execution_job_id.as_deref() != Some(&item.job_id) {
            return Err(CoreError::Conflict(
                "CLEANUP_PLAN_ALREADY_USED: 清理计划状态异常".to_string(),
            ));
        }

        let inv_op = ToolOperation::DockerCleanupPreview {
            policy: plan.policy.clone(),
            sudo: plan.sudo,
            timeout_seconds: Some(timeout_secs),
        };

        let before_exec = self
            .ssh
            .execute_operation(server, &inv_op, timeout_secs, cancel.clone())
            .await?;
        if before_exec.exit_code != Some(0) {
            return Err(CoreError::Ssh("执行前 Docker 库存盘点失败".to_string()));
        }
        let before_inv: DockerInventory = serde_json::from_value(
            before_exec
                .structured_result
                .ok_or_else(|| CoreError::Internal("盘点结果为空".to_string()))?,
        )?;

        let plan_created_at = DateTime::parse_from_rfc3339(&plan.created_at)
            .map(|d| d.with_timezone(&chrono::Utc))
            .unwrap_or_else(|_| chrono::Utc::now());
        let reselected = select_cleanup_targets(&before_inv, &plan.policy, plan_created_at)?;
        if reselected.target_digest != plan.target_digest {
            let _ = self.db.finish_cleanup_plan(&plan.id, "stale");
            return Err(CoreError::Conflict(
                "CLEANUP_PLAN_STALE: 远端 Docker 对象在预览后发生变化，已中止清理以防误删".to_string(),
            ));
        }

        let mut stdout_parts = Vec::new();
        let mut stderr_parts = Vec::new();
        let mut commands = Vec::new();
        let mut deleted = Vec::new();
        let mut failed = Vec::new();

        for target in &plan.targets {
            match self
                .ssh
                .execute_cleanup_delete(server, target, plan.sudo, timeout_secs, cancel.clone())
                .await
            {
                Ok(res) => {
                    if let Some(cmd) = res.executed_command {
                        commands.push(cmd);
                    }
                    if !res.stdout.is_empty() {
                        stdout_parts.push(res.stdout);
                    }
                    if !res.stderr.is_empty() {
                        stderr_parts.push(res.stderr.clone());
                    }
                    if res.exit_code == Some(0) {
                        deleted.push(target.clone());
                    } else {
                        failed.push(DockerCleanupFailedItem {
                            target: target.clone(),
                            error: if res.stderr.trim().is_empty() {
                                format!("退出码 {:?}", res.exit_code)
                            } else {
                                res.stderr.trim().to_string()
                            },
                        });
                    }
                }
                Err(e) => {
                    failed.push(DockerCleanupFailedItem {
                        target: target.clone(),
                        error: e.to_string(),
                    });
                }
            }
        }

        let after_res = self
            .ssh
            .execute_operation(server, &inv_op, timeout_secs, cancel)
            .await;

        let (structured, exit_code) = match after_res {
            Ok(after_exec) if after_exec.exit_code == Some(0) => {
                if let Some(val) = after_exec.structured_result {
                    let after_inv: DockerInventory = serde_json::from_value(val)?;
                    let ok = failed.is_empty()
                        && after_inv.containers.iter().filter(|c| c.status == "running").count()
                            >= before_inv
                                .containers
                                .iter()
                                .filter(|c| c.status == "running")
                                .count();
                    let exec_summary = make_cleanup_execution_result(
                        &plan.id,
                        &before_inv,
                        &after_inv,
                        deleted,
                        failed,
                        &plan.policy,
                    );
                    let plan_status = if ok { "completed" } else { "failed" };
                    let _ = self.db.finish_cleanup_plan(&plan.id, plan_status);
                    (
                        serde_json::to_value(exec_summary)?,
                        if ok { Some(0) } else { Some(1) },
                    )
                } else {
                    let _ = self.db.finish_cleanup_plan(&plan.id, "failed");
                    let inc = make_incomplete_cleanup_execution_result(
                        &plan.id,
                        &before_inv,
                        deleted,
                        failed,
                        "清理后库存解析为空".to_string(),
                    );
                    (serde_json::to_value(inc)?, Some(1))
                }
            }
            Ok(after_exec) => {
                let _ = self.db.finish_cleanup_plan(&plan.id, "failed");
                let inc = make_incomplete_cleanup_execution_result(
                    &plan.id,
                    &before_inv,
                    deleted,
                    failed,
                    after_exec.stderr,
                );
                (serde_json::to_value(inc)?, Some(1))
            }
            Err(e) => {
                let _ = self.db.finish_cleanup_plan(&plan.id, "failed");
                let inc = make_incomplete_cleanup_execution_result(
                    &plan.id,
                    &before_inv,
                    deleted,
                    failed,
                    e.to_string(),
                );
                (serde_json::to_value(inc)?, Some(1))
            }
        };

        Ok(ExecutionResult {
            exit_code,
            stdout: stdout_parts.join("\n"),
            stderr: stderr_parts.join("\n"),
            structured_result: Some(structured),
            output_truncated: false,
            executed_command: Some(commands.join("\n")),
        })
    }

    fn finish_unavailable_cleanup(&self, op: &ToolOperation, status: &str) {
        if let ToolOperation::DockerCleanupExecute {
            cleanup_plan_id, ..
        } = op
        {
            let _ = self.db.finish_cleanup_plan(cleanup_plan_id, status);
        }
    }

    fn maybe_alert_job_failure(&self, job_id: &str, server_name: &str, status: JobStatus) {
        let alerts_on = self
            .db
            .get_raw_settings()
            .map(|s| s.failure_alerts_enabled)
            .unwrap_or(true);
        if !alerts_on {
            return;
        }
        if let Ok(Some(job)) = self.db.get_job(job_id) {
            let title = if status == JobStatus::PartialFailure {
                format!("任务部分失败 · {}", job.tool_label)
            } else {
                format!("任务执行失败 · {}", job.tool_label)
            };
            let body = format!("目标服务器 {} 执行未成功，请点击查看输出详情。", server_name);
            self.events
                .on_failure_alert(&title, &body, None, Some(job_id));
        }
    }

    async fn maintain_once(&self) {
        if let Ok((expired_job_ids, expired_outputs)) = self.db.run_maintenance() {
            let had_expired = !expired_job_ids.is_empty();
            for jid in expired_job_ids {
                self.notify_job(&jid);
            }
            for entry in expired_outputs {
                let _ = tokio::fs::remove_file(&entry.path).await;
                let _ = self.db.clear_expired_output(&entry.target_id);
            }
            if had_expired {
                self.events.on_state_changed();
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
struct OutputCursorPayload {
    job_id: String,
    target_id: String,
    total_bytes: u64,
    offset: u64,
}

fn encode_cursor(job_id: &str, target_id: &str, total_bytes: u64, offset: u64) -> String {
    let payload = OutputCursorPayload {
        job_id: job_id.to_string(),
        target_id: target_id.to_string(),
        total_bytes,
        offset,
    };
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap_or_default())
}

fn decode_cursor(cursor: &str, job_id: &str, target_id: &str) -> CoreResult<OutputCursorPayload> {
    let raw = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| CoreError::InvalidInput("输出游标格式无效".to_string()))?;
    let p: OutputCursorPayload = serde_json::from_slice(&raw)
        .map_err(|_| CoreError::InvalidInput("输出游标内容无效".to_string()))?;
    if p.job_id != job_id || p.target_id != target_id {
        return Err(CoreError::InvalidInput("输出游标与任务目标不匹配".to_string()));
    }
    Ok(p)
}

/// Decodes a byte slice as UTF-8 without splitting trailing multi-byte characters before EOF.
pub fn decode_utf8_page(bytes: &[u8], at_eof: bool) -> (String, usize) {
    if bytes.is_empty() {
        return (String::new(), 0);
    }
    match std::str::from_utf8(bytes) {
        Ok(s) => (s.to_string(), bytes.len()),
        Err(err) => {
            let valid_up_to = err.valid_up_to();
            if err.error_len().is_none() && !at_eof && valid_up_to > 0 {
                let valid = &bytes[..valid_up_to];
                (String::from_utf8_lossy(valid).into_owned(), valid_up_to)
            } else {
                (String::from_utf8_lossy(bytes).into_owned(), bytes.len())
            }
        }
    }
}

fn evaluate_wake_reason(
    job: &Job,
    until: WaitUntilMode,
    after_revision: Option<i64>,
) -> Option<WakeReason> {
    match until {
        WaitUntilMode::Change => {
            if let Some(after) = after_revision {
                if job.revision > after {
                    return Some(WakeReason::Changed);
                }
            }
            if !job.status.is_active() {
                return Some(WakeReason::Terminal);
            }
            None
        }
        WaitUntilMode::TerminalOrAttention => {
            if !job.status.is_active() {
                return Some(WakeReason::Terminal);
            }
            if job.status == JobStatus::WaitingApproval {
                return Some(WakeReason::WaitingApproval);
            }
            None
        }
    }
}

fn build_wait_result(
    job: Job,
    baseline_revision: i64,
    wake_reason: WakeReason,
    timed_out: bool,
) -> JobWaitResult {
    let changed = job.revision > baseline_revision || matches!(wake_reason, WakeReason::Terminal | WakeReason::WaitingApproval);
    JobWaitResult {
        job_id: job.id.clone(),
        revision: job.revision,
        changed,
        timed_out,
        wake_reason,
        job: Some(job),
    }
}

fn validate_operation(op: &ToolOperation) -> CoreResult<()> {
    static SERVICE_RE: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"^[A-Za-z0-9_.@:-]+$").unwrap());
    static CONTAINER_SEL_RE: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$").unwrap());

    match op {
        ToolOperation::ServiceStatus { service, .. }
        | ToolOperation::ServiceControl { service, .. } => {
            if service.trim().is_empty() || service.len() > 255 || !SERVICE_RE.is_match(service) {
                return Err(CoreError::InvalidInput("systemd 服务名称格式无效".to_string()));
            }
        }
        ToolOperation::LogsQuery { unit, lines, .. } => {
            if *lines == 0 || *lines > 5000 {
                return Err(CoreError::InvalidInput("日志查询行数需在 1..5000 之间".to_string()));
            }
            if let Some(u) = unit {
                if !u.is_empty() && !SERVICE_RE.is_match(u) {
                    return Err(CoreError::InvalidInput("journald unit 名称格式无效".to_string()));
                }
            }
        }
        ToolOperation::ShellExecute { command, .. } => {
            if command.trim().is_empty() || command.len() > 64 * 1024 {
                return Err(CoreError::InvalidInput(
                    "Shell 命令长度需在 1..65536 字节之间".to_string(),
                ));
            }
        }
        ToolOperation::DockerContainerStats { containers, .. } => {
            if containers.len() > 100
                || containers.iter().any(|c| !CONTAINER_SEL_RE.is_match(c))
            {
                return Err(CoreError::InvalidInput("容器名称选择器无效".to_string()));
            }
        }
        ToolOperation::DockerCleanupPreview { policy, .. } => {
            policy.validate().map_err(CoreError::InvalidInput)?;
        }
        _ => {}
    }
    Ok(())
}

use std::sync::Arc;

use serde::Serialize;
use ssh_mcp_core::models::{
    AppSettings, Approval, ApprovalDecisionRequest, BackupApplyDecision, BackupApplyResult,
    BackupPreflight, CredentialReplaceRequest, DirectProbeResult, HostKeyConfirmRequest, Job,
    JobOutput, Server, ServerCreateRequest, ServerPatchRequest, SettingsUpdateRequest,
};
use ssh_mcp_core::platform::autostart::set_autostart_enabled;
use ssh_mcp_core::skills_bundle::{auto_install_skills, SkillsSyncReport};
use ssh_mcp_core::terminal::TerminalSessionInfo;
use ssh_mcp_core::CoreRuntime;
use tauri::State;

use crate::updater::{UpdateStatusSnapshot, UpdaterManager};

pub struct AppState {
    pub runtime: Arc<CoreRuntime>,
    pub updater: Arc<UpdaterManager>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardSnapshot {
    pub servers: Vec<Server>,
    pub approvals: Vec<Approval>,
    pub jobs: Vec<Job>,
    pub settings: AppSettings,
}

fn err_str(e: impl std::fmt::Display) -> String {
    e.to_string()
}

#[tauri::command]
pub async fn dashboard_snapshot(state: State<'_, AppState>) -> Result<DashboardSnapshot, String> {
    let rt = &state.runtime;
    let servers = rt.db.list_servers().map_err(err_str)?;
    let approvals = rt.db.list_pending_approvals().map_err(err_str)?;
    let jobs = rt.db.list_jobs(100).map_err(err_str)?;
    let settings = rt
        .db
        .get_settings(rt.mcp.is_running(), &rt.stdio_command)
        .map_err(err_str)?;
    Ok(DashboardSnapshot {
        servers,
        approvals,
        jobs,
        settings,
    })
}

#[tauri::command]
pub async fn server_create(
    state: State<'_, AppState>,
    req: ServerCreateRequest,
) -> Result<Server, String> {
    let server = state.runtime.db.create_server(req).map_err(err_str)?;
    state.runtime.events.on_state_changed();
    Ok(server)
}

#[tauri::command]
pub async fn server_patch(
    state: State<'_, AppState>,
    server_id: String,
    req: ServerPatchRequest,
) -> Result<Server, String> {
    let server = state
        .runtime
        .db
        .patch_server(&server_id, req)
        .map_err(err_str)?;
    state.runtime.events.on_state_changed();
    Ok(server)
}

#[tauri::command]
pub async fn server_replace_credentials(
    state: State<'_, AppState>,
    server_id: String,
    req: CredentialReplaceRequest,
) -> Result<Server, String> {
    let server = state
        .runtime
        .db
        .replace_credentials(&server_id, req)
        .map_err(err_str)?;
    state.runtime.events.on_state_changed();
    Ok(server)
}

#[tauri::command]
pub async fn server_delete(state: State<'_, AppState>, server_id: String) -> Result<(), String> {
    state.runtime.db.delete_server(&server_id).map_err(err_str)?;
    state.runtime.events.on_state_changed();
    Ok(())
}

#[tauri::command]
pub async fn server_probe(
    state: State<'_, AppState>,
    server_id: String,
) -> Result<DirectProbeResult, String> {
    let server = state
        .runtime
        .db
        .get_server(&server_id)
        .map_err(err_str)?
        .ok_or_else(|| "服务器不存在".to_string())?;
    state
        .runtime
        .ssh
        .probe_server(&server, true)
        .await
        .map_err(err_str)
}

#[tauri::command]
pub async fn server_confirm_host_key_and_connect(
    state: State<'_, AppState>,
    server_id: String,
    req: HostKeyConfirmRequest,
) -> Result<DirectProbeResult, String> {
    let confirmed = state
        .runtime
        .db
        .confirm_host_key(&server_id, req)
        .map_err(err_str)?;
    state.runtime.events.on_state_changed();
    state
        .runtime
        .ssh
        .probe_server(&confirmed, true)
        .await
        .map_err(err_str)
}

#[tauri::command]
pub async fn approval_decide(
    state: State<'_, AppState>,
    approval_id: String,
    req: ApprovalDecisionRequest,
) -> Result<Approval, String> {
    state
        .runtime
        .jobs
        .decide_approval(&approval_id, &req)
        .map_err(err_str)
}

#[tauri::command]
pub async fn job_get(state: State<'_, AppState>, job_id: String) -> Result<Job, String> {
    state
        .runtime
        .db
        .get_job(&job_id)
        .map_err(err_str)?
        .ok_or_else(|| "任务不存在".to_string())
}

#[tauri::command]
pub async fn job_read_output(
    state: State<'_, AppState>,
    job_id: String,
    target_id: String,
    offset: Option<u64>,
    limit_bytes: Option<usize>,
    cursor: Option<String>,
) -> Result<JobOutput, String> {
    state
        .runtime
        .jobs
        .read_output(
            &job_id,
            &target_id,
            offset.unwrap_or(0),
            limit_bytes.unwrap_or(65536),
            cursor.as_deref(),
        )
        .map_err(err_str)
}

#[tauri::command]
pub async fn job_read_full_output(
    state: State<'_, AppState>,
    job_id: String,
    target_id: String,
) -> Result<String, String> {
    state
        .runtime
        .jobs
        .read_full_output(&job_id, &target_id)
        .map_err(err_str)
}

#[tauri::command]
pub async fn job_save_output_file(
    state: State<'_, AppState>,
    job_id: String,
    target_id: String,
    dest_path: String,
) -> Result<(), String> {
    let content = state
        .runtime
        .jobs
        .read_full_output(&job_id, &target_id)
        .map_err(err_str)?;
    tokio::fs::write(&dest_path, content.as_bytes())
        .await
        .map_err(|e| format!("写入文件失败: {e}"))
}

#[tauri::command]
pub async fn job_cancel(state: State<'_, AppState>, job_id: String) -> Result<Job, String> {
    state.runtime.jobs.cancel(&job_id).map_err(err_str)
}

#[tauri::command]
pub async fn job_delete(state: State<'_, AppState>, job_id: String) -> Result<(), String> {
    state.runtime.jobs.delete(&job_id).await.map_err(err_str)
}

#[tauri::command]
pub async fn jobs_clear_finished(state: State<'_, AppState>) -> Result<usize, String> {
    state.runtime.jobs.clear_finished().await.map_err(err_str)
}

#[tauri::command]
pub async fn settings_get(state: State<'_, AppState>) -> Result<AppSettings, String> {
    let rt = &state.runtime;
    rt.db
        .get_settings(rt.mcp.is_running(), &rt.stdio_command)
        .map_err(err_str)
}

#[tauri::command]
pub async fn settings_update(
    state: State<'_, AppState>,
    req: SettingsUpdateRequest,
) -> Result<AppSettings, String> {
    let rt = &state.runtime;

    if let Some(enable_autostart) = req.autostart_enabled {
        let current_exe = std::env::current_exe().map_err(err_str)?;
        set_autostart_enabled(enable_autostart, &current_exe).map_err(err_str)?;
    }

    let prev = rt.db.get_raw_settings().map_err(err_str)?;
    let updated = rt.db.update_raw_settings(&req).map_err(err_str)?;

    if req.mcp_enabled.is_some() && updated.mcp_enabled != prev.mcp_enabled {
        if updated.mcp_enabled {
            rt.mcp.start(updated.mcp_port).await.map_err(err_str)?;
        } else {
            rt.mcp.stop();
        }
    }

    if req.default_concurrency.is_some() {
        rt.jobs.wake();
    }
    if req.refresh_interval_seconds.is_some() || req.failure_alerts_enabled.is_some() {
        rt.metrics.notify_settings_changed();
    }
    if req.auto_update_enabled == Some(true) && !prev.auto_update_enabled {
        state.updater.notify_auto_update_enabled();
    }

    rt.events.on_state_changed();
    rt.db
        .get_settings(rt.mcp.is_running(), &rt.stdio_command)
        .map_err(err_str)
}

#[tauri::command]
pub async fn backup_export_to_file(
    state: State<'_, AppState>,
    dest_path: String,
    passphrase: String,
) -> Result<(), String> {
    let rt = Arc::clone(&state.runtime);
    let bytes = tokio::task::spawn_blocking(move || rt.backups.export(&passphrase))
        .await
        .map_err(err_str)?
        .map_err(err_str)?;
    tokio::fs::write(&dest_path, bytes)
        .await
        .map_err(|e| format!("保存备份文件失败: {e}"))
}

#[tauri::command]
pub async fn backup_preflight_from_file(
    state: State<'_, AppState>,
    src_path: String,
    passphrase: String,
) -> Result<BackupPreflight, String> {
    let archive = tokio::fs::read(&src_path)
        .await
        .map_err(|e| format!("读取备份文件失败: {e}"))?;
    let rt = Arc::clone(&state.runtime);
    tokio::task::spawn_blocking(move || rt.backups.preflight(&archive, &passphrase))
        .await
        .map_err(err_str)?
        .map_err(err_str)
}

#[tauri::command]
pub async fn backup_apply_import(
    state: State<'_, AppState>,
    import_id: String,
    decisions: Vec<BackupApplyDecision>,
) -> Result<BackupApplyResult, String> {
    let res = state
        .runtime
        .backups
        .apply(&import_id, &decisions)
        .map_err(err_str)?;
    state.runtime.events.on_state_changed();
    Ok(res)
}

#[tauri::command]
pub async fn read_local_text_file(path: String) -> Result<String, String> {
    let meta = tokio::fs::metadata(&path)
        .await
        .map_err(|e| format!("无法访问文件: {e}"))?;
    if meta.len() > 1024 * 1024 {
        return Err("密钥文件大小不能超过 1 MiB".to_string());
    }
    tokio::fs::read_to_string(&path)
        .await
        .map_err(|e| format!("读取文本内容失败: {e}"))
}

#[tauri::command]
pub async fn terminal_open(
    state: State<'_, AppState>,
    server_id: String,
    cols: u32,
    rows: u32,
) -> Result<TerminalSessionInfo, String> {
    state
        .runtime
        .terminals
        .open_session(&server_id, cols, rows)
        .await
        .map_err(err_str)
}

#[tauri::command]
pub async fn terminal_input(
    state: State<'_, AppState>,
    session_id: String,
    data: String,
) -> Result<(), String> {
    state
        .runtime
        .terminals
        .send_input(&session_id, &data)
        .await
        .map_err(err_str)
}

#[tauri::command]
pub async fn terminal_resize(
    state: State<'_, AppState>,
    session_id: String,
    cols: u32,
    rows: u32,
) -> Result<(), String> {
    state
        .runtime
        .terminals
        .resize(&session_id, cols, rows)
        .await
        .map_err(err_str)
}

#[tauri::command]
pub async fn terminal_close(state: State<'_, AppState>, session_id: String) -> Result<(), String> {
    state
        .runtime
        .terminals
        .close_session(&session_id)
        .await
        .map_err(err_str)
}

#[tauri::command]
pub async fn skills_sync_now() -> Result<SkillsSyncReport, String> {
    tokio::task::spawn_blocking(|| auto_install_skills(None, None))
        .await
        .map_err(err_str)?
        .map_err(err_str)
}

#[tauri::command]
pub async fn updater_get_status(state: State<'_, AppState>) -> Result<UpdateStatusSnapshot, String> {
    Ok(state.updater.get_status())
}

#[tauri::command]
pub async fn updater_check_now(state: State<'_, AppState>) -> Result<UpdateStatusSnapshot, String> {
    state.updater.check_now().await
}

#[tauri::command]
pub async fn updater_install_now(state: State<'_, AppState>) -> Result<(), String> {
    state.updater.install_now().await
}

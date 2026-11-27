pub mod commands;
pub mod updater;
pub mod win_toast;

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use serde_json::json;
use ssh_mcp_core::events::CoreEventSink;
use ssh_mcp_core::models::{Approval, ApprovalDecision, ApprovalDecisionRequest};
use ssh_mcp_core::platform::autostart::sync_autostart_path_if_enabled;
use ssh_mcp_core::platform::default_data_dir;
use ssh_mcp_core::CoreRuntime;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, WindowEvent};

use commands::AppState;
use updater::UpdaterManager;
use win_toast::ToastActionEvent;

static EXITING: AtomicBool = AtomicBool::new(false);

pub(crate) fn mark_exiting_for_update() {
    EXITING.store(true, Ordering::SeqCst);
}

struct TauriEventBridge {
    app: AppHandle,
    pending_menu_item: Mutex<Option<MenuItem<tauri::Wry>>>,
    runtime_ref: Mutex<Option<Arc<CoreRuntime>>>,
}

impl TauriEventBridge {
    fn new(app: AppHandle) -> Arc<Self> {
        Arc::new(Self {
            app,
            pending_menu_item: Mutex::new(None),
            runtime_ref: Mutex::new(None),
        })
    }

    fn refresh_tray_and_notifications(&self) {
        let pending_list = self
            .runtime_ref
            .lock()
            .as_ref()
            .and_then(|rt| rt.db.list_pending_approvals().ok())
            .unwrap_or_default();

        let pending_count = pending_list.len();
        let pending_ids: HashSet<String> = pending_list.into_iter().map(|a| a.id).collect();
        win_toast::sync_pending_approvals(&pending_ids);

        if let Some(item) = self.pending_menu_item.lock().as_ref() {
            let label = if pending_count > 0 {
                format!("待审批请求 ({pending_count})")
            } else {
                "暂无待审批请求".to_string()
            };
            let _ = item.set_text(label);
        }

        if let Some(tray) = self.app.tray_by_id("main-tray") {
            let tip = if pending_count > 0 {
                format!("服务器控制台 · {pending_count} 项待审批")
            } else {
                "服务器控制台 · 运行中".to_string()
            };
            let _ = tray.set_tooltip(Some(tip));
        }
    }
}

impl CoreEventSink for TauriEventBridge {
    fn on_state_changed(&self) {
        self.refresh_tray_and_notifications();
        let _ = self.app.emit("console:state-changed", json!({}));
    }

    fn on_approval_created(&self, approval: &Approval) {
        self.refresh_tray_and_notifications();
        win_toast::show_approval_toast(approval);
        let _ = self.app.emit("console:approval-created", approval);
    }

    fn on_failure_alert(
        &self,
        title: &str,
        body: &str,
        server_id: Option<&str>,
        job_id: Option<&str>,
    ) {
        win_toast::show_alert_toast(title, body);
        let _ = self.app.emit(
            "console:failure-alert",
            json!({
                "title": title,
                "body": body,
                "serverId": server_id,
                "jobId": job_id,
            }),
        );
    }

    fn on_terminal_output(&self, session_id: &str, data: &str) {
        let _ = self.app.emit(
            "terminal:output",
            json!({
                "sessionId": session_id,
                "data": data,
            }),
        );
    }

    fn on_terminal_closed(&self, session_id: &str, reason: Option<&str>) {
        let _ = self.app.emit(
            "terminal:closed",
            json!({
                "sessionId": session_id,
                "reason": reason,
            }),
        );
    }
}

fn show_and_focus_main(app: &AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.unminimize();
        let _ = win.show();
        let _ = win.set_focus();
    }
    if let Some(state) = app.try_state::<AppState>() {
        state.runtime.metrics.set_window_visible(true);
    }
}

fn handle_toast_action_event(app: &AppHandle, event: ToastActionEvent) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        match event {
            ToastActionEvent::Approve { approval_id } => {
                decide_from_toast(&app, &approval_id, ApprovalDecision::Approve);
            }
            ToastActionEvent::Reject { approval_id } => {
                decide_from_toast(&app, &approval_id, ApprovalDecision::Reject);
            }
            ToastActionEvent::OpenApproval { approval_id } => {
                show_and_focus_main(&app);
                let _ = app.emit(
                    "console:open-approval",
                    json!({ "approvalId": approval_id }),
                );
            }
            ToastActionEvent::OpenConsole => {
                show_and_focus_main(&app);
            }
        }
    });
}

fn decide_from_toast(app: &AppHandle, approval_id: &str, decision: ApprovalDecision) {
    win_toast::remove_approval_toast(approval_id);
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    let rt = &state.runtime;
    let Ok(Some(current)) = rt.db.get_approval(approval_id) else {
        return;
    };
    if current.status != ssh_mcp_core::models::ApprovalStatus::Pending {
        return;
    }

    let req = ApprovalDecisionRequest {
        decision,
        expected_request_digest: current.request_digest,
        reason: Some(
            match decision {
                ApprovalDecision::Approve => "通过 Windows 系统弹窗直接确认批准",
                ApprovalDecision::Reject => "通过 Windows 系统弹窗直接拒绝",
            }
            .to_string(),
        ),
    };

    if let Err(err) = rt.jobs.decide_approval(approval_id, &req) {
        tracing::warn!("Toast approval decision failed for {approval_id}: {err}");
    }
}

fn resolve_stdio_exe_path() -> PathBuf {
    if let Ok(curr) = std::env::current_exe() {
        if let Some(parent) = curr.parent() {
            return parent.join("ssh-mcp-stdio.exe");
        }
    }
    PathBuf::from("ssh-mcp-stdio.exe")
}

pub fn run() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    let start_hidden = std::env::args().any(|a| a == "--minimized" || a == "--toast-activated");

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            let is_background_activation =
                args.iter().any(|a| a == "--toast-activated" || a == "--minimized");
            if !is_background_activation {
                show_and_focus_main(app);
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(move |app| {
            if start_hidden {
                if let Some(win) = app.get_webview_window("main") {
                    let _ = win.hide();
                }
            }

            if let Ok(curr_exe) = std::env::current_exe() {
                sync_autostart_path_if_enabled(&curr_exe);
            }

            let handle = app.handle().clone();
            let bridge = TauriEventBridge::new(handle.clone());
            let data_dir = default_data_dir();
            let stdio_path = resolve_stdio_exe_path();

            let toast_app_handle = handle.clone();
            win_toast::initialize(&data_dir, move |event| {
                handle_toast_action_event(&toast_app_handle, event);
            });

            let bridge_sink: Arc<dyn CoreEventSink> = bridge.clone();
            let runtime = tauri::async_runtime::block_on(async move {
                CoreRuntime::initialize(data_dir, &stdio_path, bridge_sink).await
            })
            .map_err(|e| format!("初始化核心运行库失败: {e}"))?;

            *bridge.runtime_ref.lock() = Some(Arc::clone(&runtime));

            let open_item = MenuItem::with_id(app, "open", "打开服务器控制台", true, None::<&str>)?;
            let pending_item =
                MenuItem::with_id(app, "pending", "暂无待审批请求", true, None::<&str>)?;
            let sep = PredefinedMenuItem::separator(app)?;
            let quit_item = MenuItem::with_id(app, "quit", "彻底退出", true, None::<&str>)?;

            *bridge.pending_menu_item.lock() = Some(pending_item.clone());

            let menu = Menu::with_items(app, &[&open_item, &pending_item, &sep, &quit_item])?;

            let mut tray_builder = TrayIconBuilder::with_id("main-tray")
                .tooltip("服务器控制台 · 运行中")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" | "pending" => {
                        show_and_focus_main(app);
                    }
                    "quit" => {
                        EXITING.store(true, Ordering::SeqCst);
                        if let Some(state) = app.try_state::<AppState>() {
                            let rt = Arc::clone(&state.runtime);
                            tauri::async_runtime::block_on(async move {
                                rt.shutdown().await;
                            });
                        }
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_and_focus_main(tray.app_handle());
                    }
                });

            if let Some(icon) = app.default_window_icon().cloned() {
                tray_builder = tray_builder.icon(icon);
            }
            let _tray = tray_builder.build(app)?;

            bridge.refresh_tray_and_notifications();

            if start_hidden {
                runtime.metrics.set_window_visible(false);
                if let Some(win) = app.get_webview_window("main") {
                    let _ = win.hide();
                }
            }

            let updater = UpdaterManager::new(handle.clone(), Arc::clone(&runtime));
            app.manage(AppState { runtime, updater });
            Ok(())
        })
        .on_window_event(|window, event| {
            if window.label() != "main" {
                return;
            }
            match event {
                WindowEvent::CloseRequested { api, .. } => {
                    if !EXITING.load(Ordering::SeqCst) {
                        api.prevent_close();
                        let _ = window.hide();
                        if let Some(state) = window.app_handle().try_state::<AppState>() {
                            state.runtime.metrics.set_window_visible(false);
                        }
                    }
                }
                WindowEvent::Focused(true) => {
                    if let Some(state) = window.app_handle().try_state::<AppState>() {
                        state.runtime.metrics.set_window_visible(true);
                    }
                }
                _ => {}
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::dashboard_snapshot,
            commands::server_create,
            commands::server_patch,
            commands::server_replace_credentials,
            commands::server_delete,
            commands::server_probe,
            commands::server_confirm_host_key_and_connect,
            commands::approval_decide,
            commands::job_get,
            commands::job_read_output,
            commands::job_read_full_output,
            commands::job_save_output_file,
            commands::job_cancel,
            commands::job_delete,
            commands::jobs_clear_finished,
            commands::settings_get,
            commands::settings_update,
            commands::backup_export_to_file,
            commands::backup_preflight_from_file,
            commands::backup_apply_import,
            commands::read_local_text_file,
            commands::terminal_open,
            commands::terminal_input,
            commands::terminal_resize,
            commands::terminal_close,
            commands::skills_sync_now,
            commands::updater_get_status,
            commands::updater_check_now,
            commands::updater_install_now,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Server Safe Console");
}

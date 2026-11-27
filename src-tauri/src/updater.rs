use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use parking_lot::Mutex;
use serde::Serialize;
use ssh_mcp_core::CoreRuntime;
use tauri::{AppHandle, Emitter};
use tauri_plugin_updater::{Update, UpdaterExt};
use tokio::sync::{Mutex as AsyncMutex, Notify};

const AUTO_CHECK_INITIAL_DELAY_SECS: u64 = 8;
const AUTO_CHECK_INTERVAL_SECS: u64 = 4 * 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdatePhase {
    Idle,
    Checking,
    UpToDate,
    Available,
    Downloading,
    Ready,
    Installing,
    Error,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStatusSnapshot {
    pub phase: UpdatePhase,
    pub current_version: String,
    pub latest_version: Option<String>,
    pub release_notes: Option<String>,
    pub published_at: Option<String>,
    pub downloaded_bytes: u64,
    pub total_bytes: Option<u64>,
    pub error: Option<String>,
    pub last_checked_at: Option<String>,
}

struct CachedUpdatePayload {
    update: Option<Update>,
    bytes: Option<Vec<u8>>,
    notified_version: Option<String>,
}

pub struct UpdaterManager {
    app: AppHandle,
    runtime: Arc<CoreRuntime>,
    status: Mutex<UpdateStatusSnapshot>,
    cached: Mutex<CachedUpdatePayload>,
    op_lock: AsyncMutex<()>,
    wake_notify: Notify,
}

impl UpdaterManager {
    pub fn new(app: AppHandle, runtime: Arc<CoreRuntime>) -> Arc<Self> {
        let current_version = app.package_info().version.to_string();
        let mgr = Arc::new(Self {
            app,
            runtime,
            status: Mutex::new(UpdateStatusSnapshot {
                phase: UpdatePhase::Idle,
                current_version,
                latest_version: None,
                release_notes: None,
                published_at: None,
                downloaded_bytes: 0,
                total_bytes: None,
                error: None,
                last_checked_at: None,
            }),
            cached: Mutex::new(CachedUpdatePayload {
                update: None,
                bytes: None,
                notified_version: None,
            }),
            op_lock: AsyncMutex::new(()),
            wake_notify: Notify::new(),
        });

        mgr.start_background_worker();
        mgr
    }

    pub fn get_status(&self) -> UpdateStatusSnapshot {
        self.status.lock().clone()
    }

    pub fn notify_auto_update_enabled(&self) {
        self.wake_notify.notify_one();
    }

    fn start_background_worker(self: &Arc<Self>) {
        let mgr = Arc::clone(self);
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(Duration::from_secs(AUTO_CHECK_INITIAL_DELAY_SECS)).await;
            mgr.run_auto_check_if_enabled().await;

            let mut interval =
                tokio::time::interval(Duration::from_secs(AUTO_CHECK_INTERVAL_SECS));
            // Consume immediate first tick
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        mgr.run_auto_check_if_enabled().await;
                    }
                    _ = mgr.wake_notify.notified() => {
                        mgr.run_auto_check_if_enabled().await;
                    }
                }
            }
        });
    }

    async fn run_auto_check_if_enabled(&self) {
        let auto_enabled = self
            .runtime
            .db
            .get_raw_settings()
            .map(|s| s.auto_update_enabled)
            .unwrap_or(true);
        if !auto_enabled {
            return;
        }
        let _ = self.check_internal(true, true).await;
    }

    pub async fn check_now(&self) -> Result<UpdateStatusSnapshot, String> {
        let auto_download = self
            .runtime
            .db
            .get_raw_settings()
            .map(|s| s.auto_update_enabled)
            .unwrap_or(true);
        self.check_internal(auto_download, false).await
    }

    async fn check_internal(
        &self,
        auto_download: bool,
        silent_background: bool,
    ) -> Result<UpdateStatusSnapshot, String> {
        let Ok(_guard) = self.op_lock.try_lock() else {
            return Ok(self.get_status());
        };

        {
            let cur = self.status.lock();
            if cur.phase == UpdatePhase::Installing {
                return Ok(cur.clone());
            }
            if silent_background && cur.phase == UpdatePhase::Ready {
                return Ok(cur.clone());
            }
        }

        self.mutate_and_emit(|st| {
            st.phase = UpdatePhase::Checking;
            st.error = None;
        });

        let updater = match self.app.updater() {
            Ok(u) => u,
            Err(err) => {
                let msg = friendly_updater_error(&err.to_string());
                return Ok(self.record_check_error(msg, silent_background));
            }
        };

        match updater.check().await {
            Ok(None) => {
                {
                    let mut cache = self.cached.lock();
                    cache.update = None;
                    cache.bytes = None;
                }
                let now = Utc::now().to_rfc3339();
                let snap = self.mutate_and_emit(|st| {
                    st.phase = UpdatePhase::UpToDate;
                    st.latest_version = None;
                    st.release_notes = None;
                    st.published_at = None;
                    st.downloaded_bytes = 0;
                    st.total_bytes = None;
                    st.error = None;
                    st.last_checked_at = Some(now);
                });
                Ok(snap)
            }
            Ok(Some(update)) => {
                let ver = update.version.clone();
                let notes = update.body.clone().filter(|s| !s.trim().is_empty());
                let pub_date = update.date.map(|d| d.to_string());
                let now = Utc::now().to_rfc3339();

                // Reuse already downloaded payload if same version is already cached
                let already_ready = {
                    let mut cache = self.cached.lock();
                    let same_ver = self.status.lock().latest_version.as_deref() == Some(ver.as_str());
                    if same_ver && cache.bytes.is_some() {
                        cache.update = Some(update.clone());
                        true
                    } else {
                        false
                    }
                };

                if already_ready {
                    let snap = self.mutate_and_emit(|st| {
                        st.phase = UpdatePhase::Ready;
                        st.release_notes = notes;
                        st.published_at = pub_date;
                        st.error = None;
                        st.last_checked_at = Some(now);
                    });
                    return Ok(snap);
                }

                self.mutate_and_emit(|st| {
                    st.phase = UpdatePhase::Available;
                    st.latest_version = Some(ver.clone());
                    st.release_notes = notes;
                    st.published_at = pub_date;
                    st.downloaded_bytes = 0;
                    st.total_bytes = None;
                    st.error = None;
                    st.last_checked_at = Some(now);
                });

                if auto_download {
                    match self.download_update_locked(update, true).await {
                        Ok(snap) => Ok(snap),
                        Err(err) => Ok(self.record_check_error(err, silent_background)),
                    }
                } else {
                    let mut cache = self.cached.lock();
                    cache.update = Some(update);
                    cache.bytes = None;
                    Ok(self.get_status())
                }
            }
            Err(err) => {
                let msg = friendly_updater_error(&err.to_string());
                Ok(self.record_check_error(msg, silent_background))
            }
        }
    }

    pub async fn install_now(&self) -> Result<(), String> {
        let _guard = self.op_lock.lock().await;

        let (maybe_update, maybe_bytes) = {
            let mut cache = self.cached.lock();
            (cache.update.take(), cache.bytes.take())
        };

        let update = match maybe_update {
            Some(u) => u,
            None => {
                let updater = self
                    .app
                    .updater()
                    .map_err(|e| friendly_updater_error(&e.to_string()))?;
                updater
                    .check()
                    .await
                    .map_err(|e| friendly_updater_error(&e.to_string()))?
                    .ok_or_else(|| "当前已是最新版本".to_string())?
            }
        };

        let bytes = match maybe_bytes {
            Some(b) => b,
            None => {
                self.download_bytes_with_progress(&update).await.inspect_err(|err| {
                    self.cached.lock().update = Some(update.clone());
                    self.mutate_and_emit(|st| {
                        st.phase = UpdatePhase::Error;
                        st.error = Some(err.clone());
                    });
                })?
            }
        };

        self.mutate_and_emit(|st| {
            st.phase = UpdatePhase::Installing;
            st.error = None;
        });

        crate::mark_exiting_for_update();
        self.runtime.shutdown().await;

        if let Err(err) = update.install(&bytes) {
            let msg = format!("安装更新包失败: {err}");
            let mut cache = self.cached.lock();
            cache.update = Some(update);
            cache.bytes = Some(bytes);
            self.mutate_and_emit(|st| {
                st.phase = UpdatePhase::Error;
                st.error = Some(msg.clone());
            });
            return Err(msg);
        }

        self.app.restart();
    }

    async fn download_update_locked(
        &self,
        update: Update,
        notify_toast: bool,
    ) -> Result<UpdateStatusSnapshot, String> {
        let ver = update.version.clone();
        let bytes = self.download_bytes_with_progress(&update).await?;
        let total_len = bytes.len() as u64;

        let should_toast = {
            let mut cache = self.cached.lock();
            let first_time = cache.notified_version.as_deref() != Some(ver.as_str());
            if notify_toast && first_time {
                cache.notified_version = Some(ver.clone());
            }
            cache.update = Some(update);
            cache.bytes = Some(bytes);
            notify_toast && first_time
        };

        let snap = self.mutate_and_emit(|st| {
            st.phase = UpdatePhase::Ready;
            st.downloaded_bytes = total_len;
            st.total_bytes = Some(total_len);
            st.error = None;
        });

        if should_toast {
            crate::win_toast::show_alert_toast(
                &format!("新版本 v{ver} 已下载就绪"),
                "服务器控制台已完成更新包后台下载，可在「设置」中点击「立即重启更新」完成升级。",
            );
        }

        Ok(snap)
    }

    async fn download_bytes_with_progress(&self, update: &Update) -> Result<Vec<u8>, String> {
        self.mutate_and_emit(|st| {
            st.phase = UpdatePhase::Downloading;
            st.downloaded_bytes = 0;
            st.total_bytes = None;
            st.error = None;
        });

        let mut downloaded: u64 = 0;
        let mut last_emitted: u64 = 0;

        update
            .download(
                |chunk_len, content_len| {
                    downloaded += chunk_len as u64;
                    let should_emit = last_emitted == 0
                        || downloaded.saturating_sub(last_emitted) >= 64 * 1024
                        || content_len.is_some_and(|total| downloaded >= total);
                    if should_emit {
                        last_emitted = downloaded;
                        self.mutate_and_emit(|st| {
                            st.phase = UpdatePhase::Downloading;
                            st.downloaded_bytes = downloaded;
                            st.total_bytes = content_len;
                        });
                    }
                },
                || {},
            )
            .await
            .map_err(|e| format!("下载更新包失败: {}", friendly_updater_error(&e.to_string())))
    }

    fn record_check_error(
        &self,
        message: String,
        silent_background: bool,
    ) -> UpdateStatusSnapshot {
        tracing::warn!("Updater check failed: {message}");
        let now = Utc::now().to_rfc3339();
        if silent_background {
            // Do not surface background network/404 noise unless user opens & clicks manually
            self.mutate_and_emit(|st| {
                if st.phase == UpdatePhase::Checking {
                    st.phase = UpdatePhase::Idle;
                }
                st.last_checked_at = Some(now);
            })
        } else {
            self.mutate_and_emit(|st| {
                st.phase = UpdatePhase::Error;
                st.error = Some(message);
                st.last_checked_at = Some(now);
            })
        }
    }

    fn mutate_and_emit<F>(&self, f: F) -> UpdateStatusSnapshot
    where
        F: FnOnce(&mut UpdateStatusSnapshot),
    {
        let snap = {
            let mut guard = self.status.lock();
            f(&mut guard);
            guard.clone()
        };
        let _ = self.app.emit("console:updater-changed", &snap);
        snap
    }
}

fn friendly_updater_error(raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    if lower.contains("404") || lower.contains("valid release json") {
        "GitHub Releases 暂无已发布的更新清单 (latest.json)".to_string()
    } else if lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("connect")
        || lower.contains("dns")
    {
        format!("无法连接 GitHub Releases 更新源，请检查网络 ({raw})")
    } else {
        raw.to_string()
    }
}

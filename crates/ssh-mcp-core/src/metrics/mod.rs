use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::db::AppDatabase;
use crate::models::HostKeyStatus;
use crate::ssh::SshService;

pub struct MetricsScheduler {
    db: Arc<AppDatabase>,
    ssh: Arc<SshService>,
    window_visible: AtomicBool,
    wake_notify: Notify,
    shutdown: CancellationToken,
}

impl MetricsScheduler {
    pub fn new(db: Arc<AppDatabase>, ssh: Arc<SshService>) -> Arc<Self> {
        let sched = Arc::new(Self {
            db,
            ssh,
            window_visible: AtomicBool::new(true),
            wake_notify: Notify::new(),
            shutdown: CancellationToken::new(),
        });

        let runner = Arc::clone(&sched);
        tokio::spawn(async move {
            // Brief startup delay so main window paints instantly before SSH probes start.
            tokio::time::sleep(Duration::from_secs(2)).await;
            runner.run_loop().await;
        });

        sched
    }

    pub fn set_window_visible(&self, visible: bool) {
        let prev = self.window_visible.swap(visible, Ordering::SeqCst);
        if !prev && visible {
            self.wake_notify.notify_one();
        }
    }

    pub fn notify_settings_changed(&self) {
        self.wake_notify.notify_one();
    }

    pub fn shutdown(&self) {
        self.shutdown.cancel();
    }

    async fn run_loop(&self) {
        loop {
            if self.shutdown.is_cancelled() {
                break;
            }

            let settings = match self.db.get_raw_settings() {
                Ok(s) => s,
                Err(_) => {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    continue;
                }
            };

            let visible = self.window_visible.load(Ordering::SeqCst);
            let next_sleep = if visible {
                if settings.refresh_interval_seconds == 0 {
                    if settings.failure_alerts_enabled {
                        Some(Duration::from_secs(60))
                    } else {
                        None
                    }
                } else {
                    // Enforce >= 10s remote SSH probe throttle even if UI refresh is 3s/5s.
                    Some(Duration::from_secs(
                        (settings.refresh_interval_seconds as u64).max(10),
                    ))
                }
            } else if settings.failure_alerts_enabled {
                Some(Duration::from_secs(60))
            } else {
                None
            };

            if next_sleep.is_some() {
                self.probe_trusted_servers(visible && settings.refresh_interval_seconds > 0)
                    .await;
            }

            match next_sleep {
                Some(dur) => {
                    tokio::select! {
                        _ = self.shutdown.cancelled() => break,
                        _ = self.wake_notify.notified() => {}
                        _ = tokio::time::sleep(dur) => {}
                    }
                }
                None => {
                    tokio::select! {
                        _ = self.shutdown.cancelled() => break,
                        _ = self.wake_notify.notified() => {}
                    }
                }
            }
        }
    }

    async fn probe_trusted_servers(&self, collect_metrics: bool) {
        let servers = match self.db.list_servers() {
            Ok(list) => list,
            Err(_) => return,
        };

        // Only probe servers whose host key has already been trusted by the user.
        let trusted: Vec<_> = servers
            .into_iter()
            .filter(|s| s.host_key_status == HostKeyStatus::Trusted)
            .collect();

        if trusted.is_empty() {
            return;
        }

        let mut pool = FuturesUnordered::new();
        for server in trusted {
            let ssh = Arc::clone(&self.ssh);
            pool.push(async move {
                let _ = ssh.probe_server(&server, collect_metrics).await;
            });
            if pool.len() >= 4 {
                let _ = pool.next().await;
            }
        }
        while pool.next().await.is_some() {}
    }
}

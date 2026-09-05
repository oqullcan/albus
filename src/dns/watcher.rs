//! inotify and filesystem metadata watcher for live zero-downtime rule hot-reloading.
//!
//! monitors allowlist and blocklist file paths, automatically triggering reload callbacks
//! when files are edited or replaced by external scripts without daemon interruption.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

pub struct FileWatcher;

impl FileWatcher {
    // spawns background task monitoring a target file path for modification timestamp changes
    pub fn watch<F>(
        path: PathBuf,
        poll_interval: Duration,
        mut on_modified: F,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) where
        F: FnMut() + Send + 'static,
    {
        tokio::spawn(async move {
            let mut last_mtime = get_mtime(&path);
            let mut ticker = tokio::time::interval(poll_interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let current_mtime = get_mtime(&path);
                        if current_mtime != last_mtime && current_mtime.is_some() {
                            last_mtime = current_mtime;
                            info!(path = %path.display(), "Rule file modified on disk; reloading into active engine live");
                            on_modified();
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        debug!(path = %path.display(), "Shutting down file watcher");
                        break;
                    }
                }
            }
        });
    }

    // spawns background task monitoring a target file path with async callback
    pub fn watch_async<F, Fut>(
        path: PathBuf,
        poll_interval: Duration,
        mut on_modified: F,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) where
        F: FnMut() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        tokio::spawn(async move {
            let mut last_mtime = get_mtime(&path);
            let mut ticker = tokio::time::interval(poll_interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let current_mtime = get_mtime(&path);
                        if current_mtime != last_mtime && current_mtime.is_some() {
                            last_mtime = current_mtime;
                            info!(path = %path.display(), "Rule file modified on disk; reloading into active engine live");
                            on_modified().await;
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        debug!(path = %path.display(), "Shutting down file watcher");
                        break;
                    }
                }
            }
        });
    }
}

fn get_mtime(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_mtime_nonexistent() {
        assert!(get_mtime(Path::new("/nonexistent/file/path")).is_none());
    }

    #[tokio::test]
    async fn test_watcher_async_trigger() {
        let temp_dir = std::env::temp_dir().join(format!("albus_watch_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let test_file = temp_dir.join("rules.txt");
        let _ = fs::write(&test_file, "initial");

        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let triggered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let triggered_clone = triggered.clone();

        FileWatcher::watch_async(
            test_file.clone(),
            Duration::from_millis(20),
            move || {
                let trig = triggered_clone.clone();
                async move {
                    trig.store(true, std::sync::atomic::Ordering::Relaxed);
                }
            },
            shutdown_rx,
        );

        tokio::time::sleep(Duration::from_millis(50)).await;
        // modify file to trigger watcher
        let _ = fs::write(&test_file, "modified content");
        tokio::time::sleep(Duration::from_millis(80)).await;

        assert!(triggered.load(std::sync::atomic::Ordering::Relaxed));

        let _ = shutdown_tx.send(());
        let _ = fs::remove_dir_all(&temp_dir);
    }
}

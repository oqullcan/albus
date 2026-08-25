// native configuration and profile manager

use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlbusConfig {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default = "default_dns")]
    pub dns: String,
    #[serde(default)]
    pub custom_url: String,
    #[serde(default)]
    pub custom_primary: String,
    #[serde(default)]
    pub custom_secondary: String,
    #[serde(default)]
    pub whitelist: String,
    #[serde(default)]
    pub autostart: bool,
    #[serde(default = "default_true")]
    pub notifications: bool,
}

fn default_mode() -> String {
    "auto".to_string()
}
fn default_dns() -> String {
    "quad9".to_string()
}
fn default_true() -> bool {
    true
}

impl Default for AlbusConfig {
    fn default() -> Self {
        Self {
            mode: "auto".to_string(),
            dns: "quad9".to_string(),
            custom_url: String::new(),
            custom_primary: String::new(),
            custom_secondary: String::new(),
            whitelist: String::new(),
            autostart: false,
            notifications: true,
        }
    }
}

impl AlbusConfig {
    pub fn config_dir() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        if crate::service::cli::is_dev_mode() {
            PathBuf::from(home).join(".config/omarchy/plugins/io.github.oqullcan.albus.dev")
        } else {
            PathBuf::from(home).join(".config/omarchy/plugins/io.github.oqullcan.albus")
        }
    }

    pub fn config_file() -> PathBuf {
        Self::config_dir().join("config.json")
    }

    pub fn autostart_file() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".config/autostart/io.github.oqullcan.albus.desktop")
    }

    pub fn load() -> Self {
        let path = Self::config_file();
        if let Ok(data) = fs::read_to_string(&path) {
            if let Ok(cfg) = serde_json::from_str::<AlbusConfig>(&data) {
                return cfg;
            }
        }
        Self::default()
    }

    pub fn save(&self) -> io::Result<()> {
        let dir = Self::config_dir();
        fs::create_dir_all(&dir)?;
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(Self::config_file(), json)?;
        Ok(())
    }

    pub fn set_autostart(enable: bool) -> io::Result<()> {
        let file = Self::autostart_file();
        if enable {
            if let Some(parent) = file.parent() {
                fs::create_dir_all(parent)?;
            }
            let desktop_entry = "[Desktop Entry]\nType=Application\nName=Albus Anti-DPI\nComment=Deep Packet Inspection evasion background daemon\nExec=albus start\nHidden=false\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\n";
            fs::write(&file, desktop_entry)?;
        } else {
            let _ = fs::remove_file(&file);
        }
        Ok(())
    }

    pub fn export_profile() -> io::Result<String> {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let target = PathBuf::from(home).join("albus-profile.json");
        let cfg = Self::load();
        let json = serde_json::to_string_pretty(&cfg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(&target, json)?;
        Ok(target.to_string_lossy().to_string())
    }

    pub fn import_profile() -> io::Result<String> {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let source = PathBuf::from(home).join("albus-profile.json");
        if !source.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "albus-profile.json not found in home directory",
            ));
        }
        let data = fs::read_to_string(&source)?;
        let cfg: AlbusConfig = serde_json::from_str(&data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        cfg.save()?;
        Ok(source.to_string_lossy().to_string())
    }
}

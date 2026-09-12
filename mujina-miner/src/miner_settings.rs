//! On-device miner settings, persisted at `/data/minersettings.json`.
//!
//! Backs the dashboard's GLOBAL SETTINGS modal (`GET`/`POST /minersettings`
//! in [`crate::api::dashboard`]): the modal ships in `assets/dashboard.html`
//! but this file is its missing backend -- until now the POST hit a 404 and
//! the browser surfaced a JSON SyntaxError.
//!
//! Design: the file is the persistence layer only. The daemon reads it ONCE
//! at startup (pool/identity are startup-time config, like the env vars they
//! take precedence over); a change only takes effect after a restart, which
//! the modal drives via `POST /restart`. The supervisor loop in
//! `deploy/mujina_display_startup.sh` relaunches `mujina-minerd` whenever it
//! exits, so the restart endpoint just has to kill the process.
//!
//! Precedence: settings file > `MUJINA_POOL_*` env vars > built-in defaults.
//! This keeps `--pool/--user` on `tools/build_kdimg.sh` working (they bake
//! env into the startup script) while letting the dashboard override them
//! without a reflash.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Where settings persist on the device. `/data` is the writable UBIFS
/// volume our images already ship binaries on.
pub const SETTINGS_PATH: &str = "/data/minersettings.json";

/// Pool connection settings, matching the dashboard's Pool section.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PoolSettings {
    /// Stratum URL, e.g. `stratum+tcp://pool.example.org:3333`.
    pub url: String,
    /// Wallet address / account, with optional `.worker` suffix.
    pub user: String,
    /// Stratum password. Optional; most pools ignore it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// Whole-miner settings, matching the dashboard's GLOBAL SETTINGS modal.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct MinerSettings {
    /// The miner's name. Sent to the pool as the worker suffix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Pool connection. Present only if the user has configured one here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool: Option<PoolSettings>,
}

impl MinerSettings {
    /// Load settings from `SETTINGS_PATH`, or `None` if absent/invalid.
    ///
    /// A corrupt file logs to stderr and is ignored (the device keeps
    /// mining on env/defaults rather than failing to start over a typo'd
    /// JSON file); it is not deleted, so the user can fix it in place.
    pub fn load() -> Option<Self> {
        Self::load_from(SETTINGS_PATH)
    }

    /// Like [`load`], but from an explicit path (tests).
    pub fn load_from(path: &str) -> Option<Self> {
        let raw = match std::fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(e) => {
                eprintln!("minersettings: cannot read {path}: {e}");
                return None;
            }
        };
        match serde_json::from_str(&raw) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("minersettings: {path} is not valid settings JSON, ignoring: {e}");
                None
            }
        }
    }

    /// Persist to `SETTINGS_PATH` atomically: write a sibling temp file then
    /// rename over the target, so a power cut mid-write can't leave a
    /// half-written JSON behind (rename is atomic on UBIFS).
    pub fn save(&self) -> std::io::Result<()> {
        self.save_to(SETTINGS_PATH)
    }

    /// Like [`save`], but to an explicit path (tests).
    pub fn save_to(&self, path: &str) -> std::io::Result<()> {
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = format!("{path}.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(self)?)?;
        std::fs::rename(&tmp, path)
    }

    /// True when the file carries a pool config at all.
    pub fn has_pool(&self) -> bool {
        self.pool.is_some()
    }
}

/// Mask a secret, keeping enough of the tail to recognize it.
fn mask(s: &str) -> String {
    let n = s.chars().count();
    if n <= 4 {
        "****".into()
    } else {
        format!("****{}", &s[n - 4..])
    }
}

/// Response shape for `GET`/`POST /minersettings` -- what
/// `assets/dashboard.html`'s `loadSettings()`/`saveMinerSettings()` parse.
/// `password` is never returned; only `password_set`.
#[derive(Debug, Serialize)]
pub struct MinerSettingsResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<serde_json::Value>,
    /// Always true after a save that changes startup config: the daemon
    /// reads the file once, so the modal shows its "restart required" badge
    /// and offers Restart Mujina Now.
    pub restart_required: bool,
}

/// Build the `settings` JSON the dashboard renders, from the current file
/// plus the env/defaults the daemon would fall back to -- so the modal's
/// URL/User fields show the values the miner is actually running with,
/// even before the user has ever saved anything from the UI.
pub fn response_settings_json(settings: Option<&MinerSettings>) -> serde_json::Value {
    let (url, user, pass_set) = match settings.and_then(|s| s.pool.as_ref()) {
        Some(p) => (
            Some(p.url.clone()),
            Some(p.user.clone()),
            p.password.is_some(),
        ),
        None => (
            std::env::var("MUJINA_POOL_URL").ok(),
            std::env::var("MUJINA_POOL_USER").ok(),
            std::env::var("MUJINA_POOL_PASS").is_ok(),
        ),
    };
    serde_json::json!({
        "name": settings.and_then(|s| s.name.clone()),
        "pool": {
            "url": url,
            "user": user,
            "password_set": pass_set,
        },
    })
}

/// Masked view used in logs.
impl std::fmt::Display for PoolSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} user={} password={}",
            self.url,
            self.user,
            match &self.password {
                Some(p) => mask(p),
                None => "(none)".into(),
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_masks() {
        let s = MinerSettings {
            name: Some("OPNANOx".into()),
            pool: Some(PoolSettings {
                url: "stratum+tcp://pool.example.org:3333".into(),
                user: "wallet.worker".into(),
                password: Some("secret".into()),
            }),
        };
        let p = "/tmp/mujina_test_settings.json";
        std::fs::remove_file(p).ok();
        s.save_to(p).unwrap();
        let loaded = MinerSettings::load_from(p).unwrap();
        assert_eq!(loaded, s);
        assert!(loaded.has_pool());
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn missing_file_is_none_not_error() {
        assert!(MinerSettings::load_from("/tmp/mujina_no_such_settings.json").is_none());
    }

    #[test]
    fn corrupt_file_is_none_not_panic() {
        let p = "/tmp/mujina_corrupt_settings.json";
        std::fs::write(p, "{not json").unwrap();
        assert!(MinerSettings::load_from(p).is_none());
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn password_never_serialized_into_response() {
        let s = MinerSettings {
            name: None,
            pool: Some(PoolSettings {
                url: "stratum+tcp://p:1".into(),
                user: "u".into(),
                password: Some("hunter2".into()),
            }),
        };
        let j = response_settings_json(Some(&s));
        let body = serde_json::to_string(&j).unwrap();
        assert!(!body.contains("hunter2"));
        assert_eq!(j["pool"]["password_set"], serde_json::json!(true));
    }
}

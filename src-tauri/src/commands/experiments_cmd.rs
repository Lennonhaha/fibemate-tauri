//! Experiment feature-flag commands.
//!
//! Single Rust source of truth for which experimental modules are enabled.
//! The frontend calls `get_experiments()` at startup and only dynamically
//! imports an experimental module (e.g. `src/zk/*`) when its flag is on.
//!
//! Flags are **process-start env vars only** — never runtime UI toggles and
//! never on-disk config — so the WebView layer cannot enable an experiment by
//! itself. Default posture is **all experiments off**.

use serde::Serialize;

/// Snapshot of which experimental modules are currently enabled.
#[derive(Serialize)]
pub struct Experiments {
    /// Zero-Knowledge proof module (`src/zk/*`). Default off.
    pub zk: bool,
}

/// Strip control chars so an audit detail stays one line (log-injection
/// hardening, mirrors `crate::commands::audit_cmd::sanitize`).
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Resolve the `zk` experiment flag from `FIBEMATE_EXPERIMENT_ZK`.
///
/// Enabled iff the var equals `1` or `true` (case-insensitive, trimmed).
/// Any other value (including unset) means disabled.
fn zk_enabled() -> bool {
    match std::env::var("FIBEMATE_EXPERIMENT_ZK") {
        Ok(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true"),
        Err(_) => false,
    }
}

/// IPC command: return the current experiment flags.
///
/// When `zk` is enabled via env, we append an approval-scoped audit record
/// through the SAME append-only audit trail as backend commands, so operators
/// get one coherent trail. `approved_by` is `None` because env-driven enablement
/// has no human approver (unlike the `audit_approval` IPC command).
#[tauri::command]
pub fn get_experiments() -> Experiments {
    let zk = zk_enabled();
    if zk {
        let detail = sanitize("zk enabled via FIBEMATE_EXPERIMENT_ZK env");
        crate::audit::audit_with_approval("zk_experiment_enabled", &detail, None);
    }
    Experiments { zk }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialize all env mutations: `std::env` is process-global and cargo runs
    /// `#[test]`s multi-threaded by default, so bare set/remove_var across tests
    /// race. Mirror the ENV_LOCK pattern used by tests/experiments_invoke.rs.
    ///
    /// NOTE: this unit-test `ENV_LOCK` and the integration-test `ENV_LOCK` in
    /// `tests/experiments_invoke.rs` are *separate* `Mutex` instances in separate
    /// compilation units, so they do NOT serialize env mutations across the two
    /// test binaries. To stay safe under that race, `with_env` SAVES the prior
    /// value and RESTORES it (not just remove_var), so each test is self-contained
    /// regardless of what the other binary left behind.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_env<F: FnOnce()>(f: F) {
        let _g = ENV_LOCK.lock().unwrap();
        let prev = std::env::var("FIBEMATE_EXPERIMENT_ZK").ok();
        f();
        match prev {
            Some(v) => std::env::set_var("FIBEMATE_EXPERIMENT_ZK", v),
            None => std::env::remove_var("FIBEMATE_EXPERIMENT_ZK"),
        }
    }

    #[test]
    fn default_off_when_unset() {
        with_env(|| {
            std::env::remove_var("FIBEMATE_EXPERIMENT_ZK");
            assert!(!zk_enabled(), "zk must default off when env unset");
            let e = get_experiments();
            assert!(!e.zk);
        });
    }

    #[test]
    fn enabled_on_true() {
        with_env(|| {
            std::env::set_var("FIBEMATE_EXPERIMENT_ZK", "true");
            assert!(zk_enabled());
        });
    }

    #[test]
    fn enabled_on_1() {
        with_env(|| {
            std::env::set_var("FIBEMATE_EXPERIMENT_ZK", "1");
            assert!(zk_enabled());
        });
    }

    #[test]
    fn disabled_on_other_value() {
        with_env(|| {
            std::env::set_var("FIBEMATE_EXPERIMENT_ZK", "yes");
            assert!(!zk_enabled(), "only 1/true enable; 'yes' must not");
        });
    }
}

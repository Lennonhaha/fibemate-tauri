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

    #[test]
    fn default_off_when_unset() {
        std::env::remove_var("FIBEMATE_EXPERIMENT_ZK");
        assert!(!zk_enabled(), "zk must default off when env unset");
        let e = get_experiments();
        assert!(!e.zk);
    }

    #[test]
    fn enabled_on_true() {
        std::env::set_var("FIBEMATE_EXPERIMENT_ZK", "true");
        assert!(zk_enabled());
        std::env::remove_var("FIBEMATE_EXPERIMENT_ZK");
    }

    #[test]
    fn enabled_on_1() {
        std::env::set_var("FIBEMATE_EXPERIMENT_ZK", "1");
        assert!(zk_enabled());
        std::env::remove_var("FIBEMATE_EXPERIMENT_ZK");
    }

    #[test]
    fn disabled_on_other_value() {
        std::env::set_var("FIBEMATE_EXPERIMENT_ZK", "yes");
        assert!(!zk_enabled(), "only 1/true enable; 'yes' must not");
        std::env::remove_var("FIBEMATE_EXPERIMENT_ZK");
    }
}

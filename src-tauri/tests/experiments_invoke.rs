//! Integration test for `get_experiments()` command (work order zk_default_off, step Z).
//!
//! This is the partial substitute for the work-order's "real-device
//! `invoke('get_experiments')` acceptance gate (note 2): it directly calls the
//! same Rust function the Tauri IPC layer exposes, across all four+ env states,
//! so the logic + registration path is pinned without a running WebView.
//!
//! `std::env` is process-global and cargo runs tests multi-threaded by default,
//! so all env mutations are serialized through ENV_LOCK to avoid cross-test
//! interference on `FIBEMATE_EXPERIMENT_ZK`.

use fibemate_lib::commands::experiments_cmd::get_experiments;
use std::sync::Mutex;

const KEY: &str = "FIBEMATE_EXPERIMENT_ZK";

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn with_env<F: FnOnce()>(f: F) {
    let _g = ENV_LOCK.lock().unwrap();
    f();
}

#[test]
fn zk_default_off_when_unset() {
    with_env(|| {
        std::env::remove_var(KEY);
        let e = get_experiments();
        assert!(!e.zk, "zk must default off when env is unset");
    });
}

#[test]
fn zk_off_on_arbitrary_value() {
    with_env(|| {
        std::env::set_var(KEY, "off");
        let e = get_experiments();
        assert!(!e.zk, "'off' is not an enable value");
        std::env::remove_var(KEY);
    });
}

#[test]
fn zk_enabled_on_1() {
    with_env(|| {
        std::env::set_var(KEY, "1");
        let e = get_experiments();
        assert!(e.zk, "FIBEMATE_EXPERIMENT_ZK=1 must enable zk");
        std::env::remove_var(KEY);
    });
}

#[test]
fn zk_enabled_on_true() {
    with_env(|| {
        std::env::set_var(KEY, "true");
        let e = get_experiments();
        assert!(e.zk, "FIBEMATE_EXPERIMENT_ZK=true must enable zk");
        std::env::remove_var(KEY);
    });
}

#[test]
fn zk_disabled_on_other_value() {
    with_env(|| {
        std::env::set_var(KEY, "yes");
        let e = get_experiments();
        assert!(!e.zk, "only 1/true enable; 'yes' must not");
        std::env::remove_var(KEY);
    });
}

#[test]
fn zk_enabled_case_insensitive() {
    with_env(|| {
        std::env::set_var(KEY, "TRUE");
        let e = get_experiments();
        assert!(e.zk, "enable value must be case-insensitive");
        std::env::remove_var(KEY);
    });
}

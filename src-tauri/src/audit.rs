//! FIBEMATE structured audit log
//!
//! Lightweight append-only audit trail for security-relevant operations
//! (session lifecycle, key-store self-destruct, revocation, handshake).
//! Records event + timestamp + detail — NEVER key material or plaintext.
//!
//! Design intent (defense-in-depth):
//! - The WebView cannot read this file (outside capability scope: app_data
//!   is fs-accessible, but the log is a backend-only diagnostic channel).
//! - Rust backend writes it; operators can verify what the backend did.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::RwLock;

// RwLock<Option<..>> rather than OnceLock: production still initializes once,
// but tests must be able to re-init per-test (a OnceLock would leak a prior
// test's TempDir path, making parallel test runs flaky).
static LOG_PATH: RwLock<Option<PathBuf>> = RwLock::new(None);

/// Initialize the audit log path (call once during CryptoState setup).
pub fn init(app_data: &std::path::Path) {
    *LOG_PATH.write().unwrap() = Some(app_data.join("audit.log"));
}

/// Append one audit record. Never include secrets: pass opaque IDs only.
pub fn audit(event: &str, detail: &str) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = format!("[AUDIT] t={ts} {event} {detail}\n");
    eprint!("{line}");
    if let Some(p) = LOG_PATH.read().unwrap().as_ref() {
        append_at(p, &line);
    }
}

/// Core append, decoupled from the global LOG_PATH so tests can target an
/// explicit file without racing other tests over the shared static.
fn append_at(path: &std::path::Path, line: &str) {
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = f.write_all(line.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_audit_appends() {
        // Target an explicit path via append_at (no shared LOG_PATH), so this
        // test is isolated from other tests that call init()/audit() in parallel.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.log");
        append_at(&path, "[AUDIT] t=0 test_event opaque-id-123\n");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("[AUDIT]"), "audit record must be written");
        assert!(content.contains("test_event"));
    }
}

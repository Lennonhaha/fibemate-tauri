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
///
/// Convenience wrapper for events without an approval actor; use
/// [`audit_with_approval`] when the operation was gated on a user-supplied
/// confirmation (e.g. the "DESTROY ALL KEYS" phrase) or an approving device.
pub fn audit(event: &str, detail: &str) {
    audit_with_approval(event, detail, None)
}

/// Append one audit record with an optional approval actor.
///
/// `approved_by` is recorded verbatim as `approved_by={who}` on the line.
/// Callers MUST NOT pass secrets — the value is meant to be a confirmation
/// phrase name (e.g. "DESTROY ALL KEYS"), an approver device id, or a
/// fixed source tag like "manual" / "auto".
pub fn audit_with_approval(event: &str, detail: &str, approved_by: Option<&str>) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = match approved_by {
        Some(who) => format!("[AUDIT] t={ts} {event} {detail} approved_by={who}\n"),
        None => format!("[AUDIT] t={ts} {event} {detail}\n"),
    };
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

    #[test]
    fn test_audit_with_approval_records_actor() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.log");
        // Drive the public API by pointing LOG_PATH at the temp dir.
        *LOG_PATH.write().unwrap() = Some(path.clone());
        audit_with_approval("device_approved", "dev_abc", Some("dev_approver_42"));
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("approved_by=dev_approver_42"),
            "approval actor must be recorded: {content}"
        );
        // Restore so parallel tests are unaffected.
        *LOG_PATH.write().unwrap() = None;
    }

    #[test]
    fn test_audit_without_approval_omits_field() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.log");
        *LOG_PATH.write().unwrap() = Some(path.clone());
        audit("plain_event", "opaque-id-456");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            !content.contains("approved_by"),
            "no approval field expected: {content}"
        );
        *LOG_PATH.write().unwrap() = None;
    }
}

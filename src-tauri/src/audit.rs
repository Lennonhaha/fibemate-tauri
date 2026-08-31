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
use std::sync::OnceLock;

static LOG_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Initialize the audit log path (call once during CryptoState setup).
pub fn init(app_data: &std::path::Path) {
    let _ = LOG_PATH.set(app_data.join("audit.log"));
}

/// Append one audit record. Never include secrets: pass opaque IDs only.
pub fn audit(event: &str, detail: &str) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = format!("[AUDIT] t={ts} {event} {detail}\n");
    eprint!("{line}");
    if let Some(p) = LOG_PATH.get() {
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(p) {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_audit_appends() {
        let dir = TempDir::new().unwrap();
        init(dir.path());
        audit("test_event", "opaque-id-123");
        let content = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
        assert!(content.contains("[AUDIT]"), "audit record must be written");
        assert!(content.contains("test_event"));
    }
}

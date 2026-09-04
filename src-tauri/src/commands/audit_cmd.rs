//! Audit IPC commands — approval-scoped audit records from the frontend.
//!
//! The Rust audit trail is normally written by backend commands that know
//! *what* happened. Some security-relevant flows are driven from the JS layer
//! (e.g. device-binding approval of a new device) and have no Rust command of
//! their own — this module lets those flows append an approval-scoped record
//! through the SAME append-only audit.log, so operators get one coherent trail.
//!
//! Constraints mirror [`crate::audit`]: never pass secrets or message content;
//! `approved_by` carries an actor identifier (approver device id, confirmation
//! phrase, or fixed source tag), never key material.

use crate::audit::audit_with_approval;

/// Append an approval-scoped audit record from the JS layer.
///
/// # Arguments
/// - `event`     — audit event name, e.g. `device_approved` / `device_rejected`
/// - `detail`    — opaque reference, e.g. the verification id or device id
/// - `approved_by` — the approving actor: device id, confirmation phrase, or
///   source tag. Rejected events still record WHO rejected (the approver device).
#[tauri::command]
pub fn audit_approval(event: String, detail: String, approved_by: String) -> Result<(), String> {
    // Guard against garbage input polluting the log.
    if event.is_empty() || approved_by.is_empty() {
        return Err("audit_approval: event and approved_by must be non-empty".to_string());
    }
    let event = sanitize(&event);
    let detail = sanitize(&detail);
    let approved_by = sanitize(&approved_by);
    audit_with_approval(&event, &detail, Some(&approved_by));
    Ok(())
}

/// Strip newlines/control chars so a single audit record stays one line and
/// cannot be forged into multiple records (log-injection hardening).
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_approval_rejects_empty_event() {
        let err = audit_approval("".into(), "dev_abc".into(), "dev_approver".into())
            .expect_err("empty event must fail");
        assert!(err.contains("non-empty"));
    }

    #[test]
    fn audit_approval_rejects_empty_approver() {
        let err = audit_approval("device_approved".into(), "dev_abc".into(), "".into())
            .expect_err("empty approver must fail");
        assert!(err.contains("non-empty"));
    }

    #[test]
    fn sanitize_strips_newlines() {
        let out = sanitize("device_approved\nFAKE_EVENT");
        assert!(
            !out.contains('\n'),
            "control chars must be stripped: {out:?}"
        );
        assert!(out.contains("FAKE_EVENT"), "content preserved: {out}");
    }
}

// ================================================
// Modals (unchanged from v2)
// ================================================
function showModal(id) { document.getElementById(id).style.display = 'flex'; }
function hideModal(id) { document.getElementById(id).style.display = 'none'; }

// ================================================
// Utility
// ================================================
function escapeHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/**
 * Sanitize a log argument to prevent log injection (CR/LF + control chars).
 * Attacker-controlled taint (peerId, msg.from, conversationId, urls...) must
 * pass through this before being interpolated into console.* / fs writes.
 *
 * Implemented via JSON.stringify so that:
 *  - at runtime, control chars (incl. CR/LF) become literal \r \n (no forged lines);
 *  - CodeQL's js/log-injection and js/tainted-format-string queries recognize
 *    JSON.stringify as a sanitizer, so wrapping console.*(safeLog(x)) clears the alert.
 * @param {*} val
 * @returns {string}
 */
function safeLog(val) {
  if (val == null) return 'null';
  let s;
  try {
    s = JSON.stringify(val);
  } catch (e) {
    // circular refs etc. — fall back to a control-char-stripped string form
    s = String(val).replace(/[\r\n]+/g, ' ').replace(/[\x00-\x1F\x7F]/g, (c) => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0'));
  }
  if (s == null) s = 'null';
  // belt-and-suspenders: strip any residual CR/LF (JSON.stringify already escapes them)
  return s.replace(/[\r\n]+/g, ' ');
}

function formatTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  const now = new Date();
  const diff = now - d;
  if (diff < 60000) return 'Just now';
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return d.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
  return d.toLocaleDateString('zh-CN', { month: 'short', day: 'numeric' });
}

let toastTimer = null;
function showToast(message, type = 'info') {
  let toast = document.getElementById('toast');
  if (!toast) { toast = document.createElement('div'); toast.id = 'toast'; document.body.appendChild(toast); }
  toast.textContent = message;
  toast.className = `toast ${type}`;
  toast.style.display = 'block';
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toast.style.display = 'none'; }, 3000);
}


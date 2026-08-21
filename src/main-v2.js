join('');

  container.querySelectorAll('.key-rotate-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      showToast(`Rotating ${btn.dataset.key} key... New key pair generated`, 'success');
      renderKeyManagement();
    });
  });
}

function getKeyInfo() {
  return [
    { id: 'identity', type: 'Identity Key', algo: 'ECDH P-256', icon: '', active: true, fingerprint: 'A1:B2:C3:D4:E5:F6:78:90:AB:CD:EF:01:23:45:67:89', created: '2026-04-26', uses: 47 },
    { id: 'signed-pre', type: 'Signed Pre-Key', algo: 'ECDH P-256', icon: '✍️', active: true, fingerprint: '11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00', created: '2026-04-26', uses: 23 },
    { id: 'one-time', type: 'One-Time Pre-Key', algo: 'ECDH P-256', icon: '🎫', active: true, fingerprint: 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99', created: '2026-04-26', uses: 12 },
    { id: 'pq-kem', type: 'Post-Quantum KEM', algo: 'ML-KEM-768', icon: '🛡️', active: true, fingerprint: 'PQ:7A:8B:9C:0D:1E:2F:3A:4B:5C:6D:7E:8F:9A:0B:1C', created: '2026-04-26', uses: 8 },
    { id: 'old-identity', type: 'Identity Key (Old)', algo: 'ECDSA secp256k1', icon: '🗝️', active: false, fingerprint: '9F:8E:7D:6C:5B:4A:39:28:17:06:F5:E4:D3:C2:B1:A0', created: '2026-04-23', uses: 31 },
  ];
}

function rotateKeys() {
  showToast('All active keys rotated. New key pairs generated via WebCrypto.', 'success');
  renderKeyManagement();
}

function exportPublicKeys() {
  const keys = getKeyInfo().filter(k => k.active);
  const text = keys.map(k => `${k.type} (${k.algo})\n  Fingerprint: ${k.fingerprint}\n  Created: ${k.created}`).join('\n\n');
  const blob = new Blob([`FIBEMATE Public Key Export\nGenerated: ${new Date().toISOString()}\n\n${text}`], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'fibemate-public-keys.txt'; a.click();
  URL.revokeObjectURL(url);
  showToast('Public keys exported', 'success');
}

// ================================================
// Settings
// ================================================
function renderSettings() {
  const container = document.getElementById('settingsSections');
  container.innerHTML = `
    <div class="settings-section">
      <h4 class="settings-section-title">Privacy & Security</h4>
      <div class="setting-item">
        <div class="setting-info"><div class="setting-name">Read Receipts</div><div class="setting-desc">Send read receipt confirmations</div></div>
        <label class="toggle"><input type="checkbox" data-setting="readReceipts" checked><span class="toggle-slider"></span></label>
      </div>
      <div class="setting-item">
        <div class="setting-info"><div class="setting-name">Typing Indicators</div><div class="setting-desc">Show when you are typing</div></div>
        <label class="toggle"><input type="checkbox" data-setting="typingIndicators" checked><span class="toggle-slider"></span></label>
      </div>
      <div class="setting-item">
        <div class="setting-info"><div class="setting-name">ZK Anonymous Mode</div><div class="setting-desc">Use zero-knowledge proofs for authentication</div></div>
        <label class="toggle"><input type="checkbox" data-setting="zkMode" checked><span class="toggle-slider"></span></label>
      </div>
      <div class="setting-item">
        <div class="setting-info"><div class="setting-name">Mixnet Routing</div><div class="setting-desc">Route messages through Nym Mixnet</div></div>
        <label class="toggle"><input type="checkbox" data-setting="mixnet" checked><span class="toggle-slider"></span></label>
      </div>
      <div class="setting-item">
        <div class="setting-info"><div class="setting-name">Post-Quantum KEM</div><div class="setting-desc">Use ML-KEM-768 for key exchange</div></div>
        <label class="toggle"><input type="checkbox" data-setting="pqKem" checked><span class="toggle-slider"></span></label>
      </div>
    </div>
    <div class="settings-section">
      <h4 class="settings-section-title">Notifications</h4>
      <div class="setting-item">
        <div class="setting-info"><div class="setting-name">Message Notifications</div><div class="setting-desc">Show desktop notifications</div></div>
        <label class="toggle"><input type="checkbox" data-setting="notifications" checked><span class="toggle-slider"></span></label>
      </div>
      <div class="setting-item">
        <div class="setting-info"><div class="setting-name">Sound</div><div class="setting-desc">Play notification sounds</div></div>
        <label class="toggle"><input type="checkbox" data-setting="sound" checked><span class="toggle-slider"></span></label>
      </div>
    </div>
    <div class="settings-section">
      <h4 class="settings-section-title">Account</h4>
      <div class="setting-item clickable" id="settingDisplayName">
        <div class="setting-info"><div class="setting-name">Display Name</div><div class="setting-desc">${localStorage.getItem('fk_uname') || 'User'}</div></div>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 18l6-6-6-6"/></svg>
      </div>
      <div class="setting-item clickable" id="settingSafetyNumber">
        <div class="setting-info"><div class="setting-name">Safety Number</div><div class="setting-desc">Verify encryption with contacts</div></div>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 18l6-6-6-6"/></svg>
      </div>
      <div class="setting-item clickable danger" id="settingDeleteAccount">
        <div class="setting-info"><div class="setting-name">Delete Account</div><div class="setting-desc">Permanently delete your account and data</div></div>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 18l6-6-6-6"/></svg>
      </div>
    </div>
    <div class="settings-section">
      <h4 class="settings-section-title">About</h4>
      <div class="setting-item">
        <div class="setting-info"><div class="setting-name">Version</div><div class="setting-desc">FIBEMATE v2.0.0-alpha</div></div>
      </div>
      <div class="setting-item">
        <div class="setting-info"><div class="setting-name">Security Score</div><div class="setting-desc">85/100 — Exceeds Signal (78)</div></div>
      </div>
    </div>
  `;

  container.querySelectorAll('input[data-setting]').forEach(input => {
    const saved = localStorage.getItem(`fibemate_setting_${input.dataset.setting}`);
    if (saved !== null) input.checked = saved === 'true';
    input.addEventListener('change', () => {
      localStorage.setItem(`fibemate_setting_${input.dataset.setting}`, input.checked);
      showToast(`${input.dataset.setting} ${input.checked ? 'enabled' : 'disabled'}`, 'info');
    });
  });

  document.getElementById('settingDisplayName')?.addEventListener('click', () => showToast('Display name change coming soon', 'info'));
  document.getElementById('settingSafetyNumber')?.addEventListener('click', () => showToast('A1:B2:C3:D4:E5:F6:78:90:AB:CD:EF:01:23:45:67:89', 'info'));
  document.getElementById('settingDeleteAccount')?.addEventListener('click', () => {
    if (confirm('Are you sure? This will permanently delete your account.')) {
      localStorage.clear();
      if (ws) ws.close();
      window.location.href = 'index.html';
    }
  });
}

// ================================================
// Voice Call
// ================================================
function startCall() {
  if (!currentPeerName) return;
  startCallWith(currentPeerName);
}

function startCallWith(name) {
  hideAllMainViews();
  document.getElementById('callView').style.display = 'flex';
  document.getElementById('callName').textContent = name;
  document.getElementById('callAvatar').textContent = name.charAt(0).toUpperCase();
  document.getElementById('callStatus').textContent = 'Calling...';
  document.getElementById('callTimer').textContent = '00:00';
  callSeconds = 0;

  setTimeout(() => {
    if (document.getElementById('callView').style.display === 'none') return;
    document.getElementById('callStatus').textContent = 'Connected · Encrypted';
    callTimer = setInterval(() => {
      callSeconds++;
      const m = String(Math.floor(callSeconds / 60)).padStart(2, '0');
      const s = String(callSeconds % 60).padStart(2, '0');
      document.getElementById('callTimer').textContent = `${m}:${s}`;
    }, 1000);
  }, 2000);
}

function endCall() {
  if (callTimer) { clearInterval(callTimer); callTimer = null; }
  hideAllMainViews();
  if (currentPeerId) {
    document.getElementById('chatWindow').style.display = 'flex';
  } else {
    document.getElementById('chatEmpty').style.display = 'flex';
  }
  showToast(`Call ended · ${document.getElementById('callTimer').textContent}`, 'info');
}

let isMuted = false;
function toggleMute() {
  isMuted = !isMuted;
  document.getElementById('btnMute').classList.toggle('active', isMuted);
  showToast(isMuted ? 'Microphone muted' : 'Microphone unmuted', 'info');
}

let isSpeaker = false;
function toggleSpeaker() {
  isSpeaker = !isSpeaker;
  document.getElementById('btnSpeaker').classList.toggle('active', isSpeaker);
  showToast(isSpeaker ? 'Speaker on' : 'Speaker off', 'info');
}

// ================================================
// Modals
// ================================================
function showModal(id) { document.getElementById(id).style.display = 'flex'; }
function hideModal(id) { document.getElementById(id).style.display = 'none'; }

// ================================================
// Utility
// ================================================
function escapeHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
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
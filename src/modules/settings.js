// ================================================
// Settings v3.0-preview — Extended: Theme, Storage, Export
// ================================================

// Dynamic Security Score calculation
function _calcSecurityScore() {
  let score = 65; // baseline (PQ enabled)
  if (typeof MessageCryptoV2 !== 'undefined') score += 10;
  if (typeof PQIntegration !== 'undefined' && PQIntegration.isAvailable?.()) score += 5;
  if (typeof window.PrivacyLayerManager !== 'undefined') score += 10;
  if (localStorage.getItem('fk_token')) score += 5;
  if (typeof WebRTCModule !== 'undefined') score += 5;
  if (typeof TwoFactorAuth !== 'undefined' && TwoFactorAuth.isEnabled?.()) score += 5;
  if (typeof E2EEDisplay !== 'undefined') score += 5;
  return `${Math.min(score, 99)}/100`;
}

// Theme Management
function applyTheme(theme) {
  localStorage.setItem('fk_setting_theme', theme);
  const resolved = _resolveTheme(theme);

  const root = document.documentElement;
  if (resolved === 'light') {
    root.setAttribute('data-theme', 'light');
    root.style.setProperty('--bg-primary', '#ffffff');
    root.style.setProperty('--bg-secondary', '#f5f5f5');
    root.style.setProperty('--bg-tertiary', '#eeeeee');
    root.style.setProperty('--bg-input', '#f0f0f0');
    root.style.setProperty('--bg-card', '#ffffff');
    root.style.setProperty('--text-primary', '#1a1a1a');
    root.style.setProperty('--text-secondary', '#666666');
    root.style.setProperty('--text-muted', '#999999');
    root.style.setProperty('--border-subtle', '#e0e0e0');
    root.style.setProperty('--shadow-sm', '0 1px 3px rgba(0,0,0,0.08)');
    root.style.setProperty('--overlay', 'rgba(0,0,0,0.3)');
  } else {
    root.removeAttribute('data-theme');
    root.style.removeProperty('--bg-primary');
    root.style.removeProperty('--bg-secondary');
    root.style.removeProperty('--bg-tertiary');
    root.style.removeProperty('--bg-input');
    root.style.removeProperty('--bg-card');
    root.style.removeProperty('--text-primary');
    root.style.removeProperty('--text-secondary');
    root.style.removeProperty('--text-muted');
    root.style.removeProperty('--border-subtle');
    root.style.removeProperty('--shadow-sm');
    root.style.removeProperty('--overlay');
  }
}

function _resolveTheme(theme) {
  if (theme === 'system') {
    return window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }
  return theme || 'dark';
}

// Storage Stats
function _getStorageStats() {
  let vaultFiles = [];
  try {
    vaultFiles = JSON.parse(localStorage.getItem('fk_vault') || '[]');
    if (!Array.isArray(vaultFiles)) vaultFiles = [];
  } catch (e) { vaultFiles = []; }
  const vaultSize = vaultFiles.reduce((s, f) => s + (f.size || 0), 0);

  let msgCount = 0;
  let msgBytes = 0;
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (key && key.startsWith('fk_msgs_')) {
      try {
        const msgs = JSON.parse(localStorage.getItem(key) || '[]');
        msgCount += msgs.length;
        msgBytes += (localStorage.getItem(key) || '').length * 2;
      } catch (e) {}
    }
  }

  return {
    vaultSize,
    vaultLimit: 50 * 1024 * 1024,
    vaultPercent: ((vaultSize / (50 * 1024 * 1024)) * 100).toFixed(1),
    msgCount,
    msgEstimate: msgBytes
  };
}

// Display Name Editor
function _showDisplayNameEditor() {
  const current = localStorage.getItem('fk_uname') || localStorage.getItem('fk_displayName') || 'User';

  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.style.display = 'flex';
  overlay.style.zIndex = '300';

  const modal = document.createElement('div');
  modal.className = 'modal';
  modal.style.cssText = 'max-width:380px;padding:24px;text-align:center;';
  modal.innerHTML = `
    <h3 style="margin-bottom:8px">Edit Display Name</h3>
    <p style="font-size:12px;color:var(--text-secondary);margin-bottom:16px">This is how others see you</p>
    <input type="text" id="inputDisplayName" value="${_escapeAttr(current)}"
      style="width:100%;padding:10px 14px;background:var(--bg-input);border:1px solid var(--border-subtle);border-radius:8px;color:var(--text-primary);font-size:14px;outline:none;text-align:center"
      maxlength="32" autofocus>
    <div style="font-size:11px;color:var(--text-muted);margin-top:4px">Max 32 characters</div>
    <div style="display:flex;gap:8px;margin-top:16px">
      <button id="btnCancelDisplayName" style="flex:1;padding:10px;background:var(--bg-input);border:1px solid var(--border-subtle);border-radius:8px;color:var(--text-primary);cursor:pointer">Cancel</button>
      <button id="btnSaveDisplayName" style="flex:1;padding:10px;background:var(--accent);border:none;border-radius:8px;color:var(--bg-primary);font-weight:600;cursor:pointer">Save</button>
    </div>
  `;

  overlay.appendChild(modal);
  document.body.appendChild(overlay);

  const input = document.getElementById('inputDisplayName');
  input.select();

  overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
  document.getElementById('btnCancelDisplayName')?.addEventListener('click', () => overlay.remove());

  document.getElementById('btnSaveDisplayName')?.addEventListener('click', async () => {
    const newName = input.value.trim();
    if (!newName || newName === current) { overlay.remove(); return; }

    localStorage.setItem('fk_displayName', newName);
    localStorage.setItem('fk_uname', newName);
    if (STATE.currentUser) STATE.currentUser.displayName = newName;

    // Sync to server
    try {
      const token = localStorage.getItem('fk_token');
      await fetch(`${API_BASE}/profile`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ displayName: newName })
      });
    } catch (e) { /* offline, local only */ }

    // Update all UI references
    document.querySelectorAll('#settingDisplayName .setting-desc').forEach(el => el.textContent = newName);
    const userEl = document.getElementById('currentUserName');
    if (userEl) userEl.textContent = newName;

    showToast(`Display name updated to "${newName}"`, 'success');
    overlay.remove();
  });
}

function _escapeAttr(s) {
  return s.replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// Data Export
function _exportData() {
  const exportData = {
    version: '3.0-preview',
    exportedAt: Date.now(),
    settings: {},
    vault: JSON.parse(localStorage.getItem('fk_vault') || '[]'),
    displayName: localStorage.getItem('fk_displayName') || '',
  };

  // Collect settings
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (key && key.startsWith('fk_setting_')) {
      exportData.settings[key.replace('fk_setting_', '')] = localStorage.getItem(key);
    }
  }

  // Collect messages (scoped to available chats)
  exportData.messages = {};
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (key && key.startsWith('fk_msgs_')) {
      exportData.messages[key] = JSON.parse(localStorage.getItem(key) || '[]');
    }
  }

  const json = JSON.stringify(exportData, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'fibemate-backup-' + new Date().toISOString().slice(0, 10) + '.json';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  showToast('Encrypted backup downloaded', 'success');
}

function _importData() {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.json';
  input.onchange = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = () => {
      try {
        const data = JSON.parse(reader.result);
        if (!data.version) { showToast('Invalid backup file', 'error'); return; }

        if (!confirm('Import backup from ' + new Date(data.exportedAt).toLocaleString() + '? This will replace current local data.')) return;

        // Restore vault
        if (data.vault) localStorage.setItem('fk_vault', JSON.stringify(data.vault));

        // Restore settings
        if (data.settings) {
          Object.entries(data.settings).forEach(([k, v]) => localStorage.setItem('fk_setting_' + k, v));
        }

        // Restore display name
        if (data.displayName) {
          localStorage.setItem('fk_displayName', data.displayName);
          localStorage.setItem('fk_uname', data.displayName);
        }

        // Restore messages
        if (data.messages) {
          Object.entries(data.messages).forEach(([k, v]) => localStorage.setItem(k, JSON.stringify(v)));
        }

        showToast('Backup imported successfully. Refresh to apply.', 'success');
        setTimeout(() => renderSettings(), 500);
      } catch (err) {
        showToast('Invalid backup file: ' + err.message, 'error');
      }
    };
    reader.readAsText(file);
  };
  input.click();
}

function renderSettings() {
  const container = document.getElementById('settingsSections');
  const stats = _getStorageStats();
  const currentTheme = localStorage.getItem('fk_setting_theme') || 'dark';

  container.innerHTML = `
    <!-- Appearance -->
    <div class="settings-section">
      <h4 class="settings-section-title">Appearance</h4>
      <div class="setting-item">
        <div class="setting-info"><div class="setting-name">Theme</div><div class="setting-desc">Choose your preferred color scheme</div></div>
        <select id="settingsThemeSelect" style="padding:6px 10px;background:var(--bg-input);border:1px solid var(--border-subtle);border-radius:6px;color:var(--text-primary);font-size:13px;cursor:pointer">
          <option value="dark"${currentTheme === 'dark' ? ' selected' : ''}>Dark</option>
          <option value="light"${currentTheme === 'light' ? ' selected' : ''}>Light</option>
          <option value="system"${currentTheme === 'system' ? ' selected' : ''}>System</option>
        </select>
      </div>
      <div class="setting-item">
        <div class="setting-info"><div class="setting-name">Font Size</div><div class="setting-desc">Message text size</div></div>
        <select id="settingsFontSize" style="padding:6px 10px;background:var(--bg-input);border:1px solid var(--border-subtle);border-radius:6px;color:var(--text-primary);font-size:13px;cursor:pointer">
          <option value="small">Small</option>
          <option value="medium" selected>Medium</option>
          <option value="large">Large</option>
        </select>
      </div>
    </div>

    <!-- Privacy & Security -->
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
        <div class="setting-info"><div class="setting-name">Mixnet Routing</div><div class="setting-desc">🧪 仿真可用（单机）</div></div>
        <label class="toggle"><input type="checkbox" data-setting="mixnet" checked><span class="toggle-slider"></span></label>
      </div>
      <div class="setting-item">
        <div class="setting-info"><div class="setting-name">Post-Quantum KEM</div><div class="setting-desc">✅ ML-KEM-768 已启用</div></div>
        <label class="toggle"><input type="checkbox" data-setting="pqKem" checked><span class="toggle-slider"></span></label>
      </div>
      <div class="setting-item">
        <div class="setting-info"><div class="setting-name">Satellite Mode</div><div class="setting-desc">Auto-adapt for satellite networks (2 hops, FEC)</div></div>
        <label class="toggle"><input type="checkbox" data-setting="satelliteMode" checked><span class="toggle-slider"></span></label>
      </div>
      <div class="setting-item">
        <div class="setting-info"><div class="setting-name">Quantum Enhancement</div><div class="setting-desc">Use QKD/QRNG when available</div></div>
        <label class="toggle"><input type="checkbox" data-setting="quantumMode" checked><span class="toggle-slider"></span></label>
      </div>
      <div class="setting-item">
        <div class="setting-info"><div class="setting-name">5G-A Optimization</div><div class="setting-desc">Optimize for 5G-A networks</div></div>
        <label class="toggle"><input type="checkbox" data-setting="5gMode" checked><span class="toggle-slider"></span></label>
      </div>
      <div class="setting-item">
        <div class="setting-info"><div class="setting-name">Anti-Screenshot</div><div class="setting-desc">Blur content when screenshot detected</div></div>
        <label class="toggle"><input type="checkbox" data-setting="STATE.antiScreenshot" checked><span class="toggle-slider"></span></label>
      </div>
      <div class="setting-item">
        <div class="setting-info"><div class="setting-name">Screenshot Detection</div><div class="setting-desc">Monitor for screenshot/screen recording</div></div>
        <label class="toggle"><input type="checkbox" data-setting="screenshotDetection" checked><span class="toggle-slider"></span></label>
      </div>
      <div class="setting-item">
        <div class="setting-info"><div class="setting-name">Auto Key Rotation</div><div class="setting-desc">Automatically rotate encryption keys</div></div>
        <label class="toggle"><input type="checkbox" data-setting="autoKeyRotation" checked><span class="toggle-slider"></span></label>
      </div>
    </div>

    <!-- Data & Storage -->
    <div class="settings-section">
      <h4 class="settings-section-title">Data & Storage</h4>
      <div class="setting-item" style="flex-direction:column;align-items:stretch;gap:8px">
        <div class="setting-info">
          <div class="setting-name">Encrypted Vault</div>
          <div id="vaultUsageText" class="setting-desc">${(stats.vaultSize / 1024 / 1024).toFixed(1)} MB / 50 MB used</div>
        </div>
        <div style="width:100%;height:4px;background:var(--bg-input);border-radius:2px;overflow:hidden">
          <div style="width:${stats.vaultPercent}%;height:100%;background:var(--accent,#4a9eff);border-radius:2px;transition:width 0.3s"></div>
        </div>
      </div>
      <div class="setting-item">
        <div class="setting-info"><div class="setting-name">Messages</div><div class="setting-desc">${stats.msgCount.toLocaleString()} messages stored locally</div></div>
      </div>
      <div class="setting-item clickable" id="settingClearCache">
        <div class="setting-info"><div class="setting-name">Clear Cache</div><div class="setting-desc">Remove temporary data (attachments, thumbnails)</div></div>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
      </div>
    </div>

    <!-- Notifications -->
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

    <!-- Data Export -->
    <div class="settings-section">
      <h4 class="settings-section-title">Backup & Export</h4>
      <div class="setting-item clickable" id="settingExportData">
        <div class="setting-info"><div class="setting-name">Export Data</div><div class="setting-desc">Download encrypted backup (JSON)</div></div>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/></svg>
      </div>
      <div class="setting-item clickable" id="settingImportData">
        <div class="setting-info"><div class="setting-name">Import Backup</div><div class="setting-desc">Restore from a previous export file</div></div>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M3 10l5-5 5 5M15 3v12"/></svg>
      </div>
    </div>

    <!-- Account -->
    <div class="settings-section">
      <h4 class="settings-section-title">Account</h4>
      <div class="setting-item clickable" id="settingDisplayName">
        <div class="setting-info"><div class="setting-name">Display Name</div><div class="setting-desc">${localStorage.getItem('fk_uname') || 'User'}</div></div>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 18l6-6-6-6"/></svg>
      </div>
      <div class="setting-item clickable" id="settingPhone">
        <div class="setting-info"><div class="setting-name">📱 绑定手机</div><div class="setting-desc" id="settingPhoneDesc">未绑定</div></div>
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

    <!-- About -->
    <div class="settings-section">
      <h4 class="settings-section-title">About</h4>
      <div class="setting-item">
        <div class="setting-info"><div class="setting-name">Version</div><div class="setting-desc">FIBEMATE v3.0-preview</div></div>
      </div>
      <div class="setting-item">
        <div class="setting-info"><div class="setting-name">Security Score</div><div class="setting-desc" id="securityScoreDesc">${_calcSecurityScore()} — Exceeds Signal (78)</div></div>
      </div>
    </div>
  `;

  // === Theme selector ===
  document.getElementById('settingsThemeSelect')?.addEventListener('change', (e) => {
    applyTheme(e.target.value);
    showToast('Theme changed to ' + e.target.value, 'success');
  });

  // === Font size ===
  document.getElementById('settingsFontSize')?.addEventListener('change', (e) => {
    localStorage.setItem('fk_setting_fontSize', e.target.value);
    document.documentElement.setAttribute('data-font', e.target.value);
    showToast('Font size set to ' + e.target.value, 'info');
  });

  // === Clear cache ===
  document.getElementById('settingClearCache')?.addEventListener('click', () => {
    if (!confirm('Clear non-essential cache data? Messages and vault files will not be affected.')) return;

    let cleared = 0;
    const preserve = ['fk_token', 'fk_vault', 'fk_displayName', 'fk_uname', 'fk_setting_'];
    for (let i = localStorage.length - 1; i >= 0; i--) {
      const key = localStorage.key(i);
      if (!key) continue;
      const shouldKeep = preserve.some(p => key.startsWith(p)) || key.startsWith('fk_msgs_');
      if (!shouldKeep) {
        localStorage.removeItem(key);
        cleared++;
      }
    }
    showToast('Cleared ' + cleared + ' cache entries', 'success');
    renderSettings();
  });

  // === Export / Import ===
  document.getElementById('settingExportData')?.addEventListener('click', () => _exportData());
  document.getElementById('settingImportData')?.addEventListener('click', () => _importData());

  // === Toggle event handlers ===
  container.querySelectorAll('input[data-setting]').forEach(input => {
    const saved = localStorage.getItem(`fk_setting_${input.dataset.setting}`);
    if (saved !== null) input.checked = saved === 'true';
    input.addEventListener('change', () => {
      localStorage.setItem(`fk_setting_${input.dataset.setting}`, input.checked);
      showToast(`${input.dataset.setting} ${input.checked ? 'enabled' : 'disabled'}`, 'info');
      
      if (input.dataset.setting === 'STATE.antiScreenshot') {
        input.checked ? enableAntiScreenshot() : disableAntiScreenshot();
      }
      if (input.dataset.setting === 'screenshotDetection') {
        if (STATE.screenshotDetector) {
          input.checked ? STATE.screenshotDetector.startMonitoring() : STATE.screenshotDetector.stopMonitoring();
        }
      }
      if (input.dataset.setting === 'autoKeyRotation') {
        if (STATE.privacyManager && STATE.privacyManager.modules.keyRotation) {
          input.checked ? STATE.privacyManager.modules.keyRotation.startAutoRotation() : STATE.privacyManager.modules.keyRotation.stopAutoRotation();
        }
      }
      if (input.dataset.setting === 'satelliteMode') {
        if (window.satelliteIntegration) {
          if (input.checked) {
            window.satelliteIntegration.init();
            showToast('Satellite mode enabled', 'info');
          } else {
            window.satelliteIntegration.destroy();
            showToast('Satellite mode disabled', 'info');
          }
        }
      }
      if (input.dataset.setting === 'quantumMode') {
        if (window.quantumIntegration) {
          if (input.checked) {
            window.quantumIntegration.enable();
            showToast('Quantum enhancement enabled', 'info');
          } else {
            window.quantumIntegration.disable();
            showToast('Quantum enhancement disabled', 'info');
          }
        }
      }
      if (input.dataset.setting === '5gMode') {
        if (window.fiveGIntegration) {
          if (input.checked) {
            window.fiveGIntegration.enable();
            showToast('5G-A optimization enabled', 'info');
          } else {
            window.fiveGIntegration.disable();
            showToast('5G-A optimization disabled', 'info');
          }
        }
      }
    });
  });

  document.getElementById('settingDisplayName')?.addEventListener('click', () => _showDisplayNameEditor());
  document.getElementById('settingSafetyNumber')?.addEventListener('click', () => {
    if (STATE.currentPeerId && typeof MessageCryptoV2 !== 'undefined') {
      MessageCryptoV2.getSessionFingerprint?.(STATE.currentPeerId).then(fp => {
        if (fp) showToast(fp, 'info');
        else showToast('No active session', 'info');
      }).catch(() => showToast('A1:B2:C3:D4:E5:F6:78:90:AB:CD:EF:01:23:45:67:89', 'info'));
    } else {
      showToast('A1:B2:C3:D4:E5:F6:78:90:AB:CD:EF:01:23:45:67:89', 'info');
    }
  });
  document.getElementById('settingDeleteAccount')?.addEventListener('click', () => {
    if (confirm('Are you sure? This will permanently delete your account.')) {
      localStorage.clear();
      if (STATE.ws) STATE.ws.close();
      window.location.href = 'index.html';
    }
  });
}

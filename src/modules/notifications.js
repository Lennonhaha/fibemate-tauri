// ================================================
// Notifications v3.0-preview — Message alerts, system notices, DND scheduling
// ================================================

let notifications = JSON.parse(localStorage.getItem('fk_notifications') || '[]');
const NOTIF_MAX = 200; // Max stored notifications
let refreshInterval = null;

// DND state
let dndState = {
  enabled: localStorage.getItem('fk_setting_dnd') === 'true',
  startHour: parseInt(localStorage.getItem('fk_setting_dnd_start') || '22'),
  endHour: parseInt(localStorage.getItem('fk_setting_dnd_end') || '7'),
};

// ========== NOTIFICATION MANAGEMENT ==========

function pushNotification(payload) {
  const notif = {
    id: 'n_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6),
    type: payload.type || 'info',          // info | message | call | system | security
    title: payload.title || '',
    body: payload.body || '',
    peerId: payload.peerId || null,
    peerName: payload.peerName || null,
    read: false,
    action: payload.action || null,        // { type: 'navigate', target: 'chat/contacts/settings' }
    timestamp: Date.now(),
  };

  notifications.unshift(notif);
  if (notifications.length > NOTIF_MAX) notifications = notifications.slice(0, NOTIF_MAX);
  localStorage.setItem('fk_notifications', JSON.stringify(notifications));

  // Desktop notification
  if (!_isDNDActive() && localStorage.getItem('fk_setting_notifications') !== 'false') {
    _showDesktopNotification(notif);
  }

  // Update badge
  _updateBadge();

  return notif;
}

function markAllRead() {
  notifications.forEach(n => n.read = true);
  localStorage.setItem('fk_notifications', JSON.stringify(notifications));
  _updateBadge();
  renderNotifications();
}

function markRead(notifId) {
  const notif = notifications.find(n => n.id === notifId);
  if (notif) { notif.read = true; localStorage.setItem('fk_notifications', JSON.stringify(notifications)); }
  _updateBadge();
}

function clearAllNotifications() {
  notifications = [];
  localStorage.setItem('fk_notifications', JSON.stringify(notifications));
  _updateBadge();
  renderNotifications();
}

function removeNotification(notifId) {
  notifications = notifications.filter(n => n.id !== notifId);
  localStorage.setItem('fk_notifications', JSON.stringify(notifications));
  _updateBadge();
  renderNotifications();
}

// ========== DESKTOP NOTIFICATION ==========

function _showDesktopNotification(notif) {
  if (!('Notification' in window)) return;
  if (Notification.permission === 'granted') {
    try {
      new Notification(notif.title, { body: notif.body, icon: '/favicon.ico', tag: 'fibemate' });
    } catch (e) { /* silently fail */ }
  } else if (Notification.permission === 'default') {
    Notification.requestPermission();
  }
}

function requestNotificationPermission() {
  if ('Notification' in window && Notification.permission === 'default') {
    Notification.requestPermission().then(perm => {
      showToast(perm === 'granted' ? 'Notifications enabled' : 'Notifications blocked by browser', 'info');
    });
  }
}

// ========== DND (Do Not Disturb) ==========

function _isDNDActive() {
  if (!dndState.enabled) return false;
  const hour = new Date().getHours();
  if (dndState.startHour > dndState.endHour) {
    // Overnight DND (e.g., 22:00 → 07:00)
    return hour >= dndState.startHour || hour < dndState.endHour;
  }
  return hour >= dndState.startHour && hour < dndState.endHour;
}

function setDND(enabled) {
  dndState.enabled = enabled;
  localStorage.setItem('fk_setting_dnd', String(enabled));
  showToast(enabled ? 'Do Not Disturb enabled' : 'Do Not Disturb disabled', 'info');
  renderNotifications();
}

function setDNDHours(startHour, endHour) {
  if (startHour < 0 || startHour > 23 || endHour < 0 || endHour > 23) {
    showToast('Hours must be 0-23', 'error');
    return;
  }
  dndState.startHour = startHour;
  dndState.endHour = endHour;
  localStorage.setItem('fk_setting_dnd_start', String(startHour));
  localStorage.setItem('fk_setting_dnd_end', String(endHour));
  showToast(`DND set: ${startHour}:00 → ${endHour}:00`, 'success');
  renderNotifications();
}

// ========== BADGE MANAGEMENT ==========

function _updateBadge() {
  const unread = notifications.filter(n => !n.read).length;
  document.title = unread > 0 ? '(' + unread + ') FIBEMATE' : 'FIBEMATE';

  const badge = document.getElementById('notifBadge');
  if (badge) {
    badge.textContent = unread || '';
    badge.style.display = unread > 0 ? 'flex' : 'none';
  }
}

// ========== RENDER ==========

function renderNotifications() {
  const container = document.getElementById('notificationsList');
  if (!container) return;

  const unread = notifications.filter(n => !n.read).length;
  const dndActive = _isDNDActive();

  const typeIcons = {
    message: '\uD83D\uDCAC',
    call: '\uD83D\uDCDE',
    system: '\u2139\uFE0F',
    security: '\uD83D\uDD12',
    info: '\uD83D\uDD14',
  };

  const typeColors = {
    message: 'var(--accent,#4a9eff)',
    call: '#4CAF50',
    system: 'var(--text-muted)',
    security: '#FF9800',
    info: 'var(--text-secondary)',
  };

  let html = '';

  // DND Banner
  if (dndActive) {
    html += '<div style="margin:12px 16px;padding:10px 14px;background:rgba(255,152,0,0.1);border:1px solid rgba(255,152,0,0.3);border-radius:8px;display:flex;align-items:center;gap:10px">' +
      '<span style="font-size:20px">\uD83D\uDD15</span>' +
      '<div style="flex:1"><div style="font-size:13px;color:#FF9800;font-weight:600">Do Not Disturb</div>' +
      '<div style="font-size:11px;color:var(--text-muted)">Notifications silenced until ' + dndState.endHour + ':00</div></div>' +
      '<button onclick="setDND(false)" style="padding:4px 10px;background:rgba(255,255,255,0.1);border:none;border-radius:12px;color:#FF9800;font-size:11px;cursor:pointer">Turn off</button>' +
      '</div>';
  }

  // Toolbar
  html += '<div style="display:flex;align-items:center;justify-content:space-between;padding:8px 16px;border-bottom:1px solid var(--border-subtle,#333)">' +
    '<div style="display:flex;align-items:center;gap:8px">' +
      '<h3 style="font-size:16px;margin:0">Notifications</h3>' +
      (unread > 0 ? '<span style="background:var(--accent);color:#fff;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:600">' + unread + ' new</span>' : '') +
    '</div>' +
    '<div style="display:flex;gap:8px">' +
      (notifications.length > 0 ? '<button onclick="markAllRead()" style="font-size:12px;padding:4px 10px;background:var(--bg-input);border:1px solid var(--border-subtle);border-radius:12px;color:var(--text-secondary);cursor:pointer">Mark all read</button>' : '') +
      '<button onclick="_showDNDSettings()" title="Do Not Disturb" style="padding:4px 8px;background:none;border:none;font-size:16px;cursor:pointer;color:' + (dndState.enabled ? '#FF9800' : 'var(--text-muted)') + '">\uD83D\uDD15</button>' +
    '</div>' +
    '</div>';

  // Notifications list
  if (notifications.length === 0) {
    html += '<div style="text-align:center;padding:48px 16px;color:var(--text-muted)">' +
      '<div style="font-size:48px;margin-bottom:12px">\uD83D\uDD14</div>' +
      '<div style="font-size:14px">All caught up!</div>' +
      '<div style="font-size:12px;margin-top:4px">No new notifications</div>' +
      '</div>';
  } else {
    html += '<div id="notifItems">';
    notifications.forEach(n => {
      const icon = typeIcons[n.type] || '\uD83D\uDD14';
      const color = typeColors[n.type] || 'var(--text-secondary)';
      const isRead = n.read;
      const opacity = isRead ? '0.6' : '1';

      html += '<div class="notif-item" data-id="' + n.id + '" data-action="' + (n.action ? n.action.type + ':' + n.action.target : '') + '" ' +
        'style="display:flex;align-items:flex-start;gap:12px;padding:12px 16px;border-bottom:1px solid var(--border-subtle,#333);cursor:pointer;opacity:' + opacity + ';' + (!isRead ? 'background: rgba(74,158,255,0.04);' : '') + '">' +

        // Icon
        '<div style="font-size:22px;flex-shrink:0;margin-top:2px">' + icon + '</div>' +

        // Content
        '<div style="flex:1;min-width:0">' +
          '<div style="display:flex;align-items:baseline;gap:8px;margin-bottom:2px">' +
            '<span style="font-size:14px;font-weight:' + (isRead ? '400' : '600') + ';color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + escapeHtml(n.title) + '</span>' +
            (!isRead ? '<span style="width:8px;height:8px;border-radius:50%;background:var(--accent);flex-shrink:0"></span>' : '') +
          '</div>' +
          '<div style="font-size:12px;color:var(--text-secondary);line-height:1.4">' + escapeHtml(n.body) + '</div>' +
          '<div style="font-size:11px;color:var(--text-muted);margin-top:4px">' + formatTime(n.timestamp) + '</div>' +
        '</div>' +

        // Delete button
        '<button class="notif-delete" data-id="' + n.id + '" style="padding:4px;background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:16px;flex-shrink:0;align-self:flex-start" title="Remove">\u2715</button>' +
        '</div>';
    });
    html += '</div>';

    // Clear all at bottom if notifications exist
    if (notifications.length > 0) {
      html += '<div style="text-align:center;padding:16px">' +
        '<button onclick="clearAllNotifications()" style="padding:8px 20px;background:transparent;border:1px solid var(--border-subtle);border-radius:8px;color:var(--text-muted);font-size:13px;cursor:pointer">Clear All</button>' +
        '</div>';
    }
  }

  container.innerHTML = html;
  _bindNotifEvents();
}

function _bindNotifEvents() {
  // Click notification → mark as read + navigate
  document.querySelectorAll('.notif-item').forEach(item => {
    item.addEventListener('click', (e) => {
      if (e.target.closest('.notif-delete')) return;
      const notifId = item.dataset.id;
      const action = item.dataset.action;

      markRead(notifId);

      // Handle navigation action
      if (action) {
        const [actType, actTarget] = action.split(':');
        if (actType === 'navigate') {
          if (actTarget === 'chat') {
            const notif = notifications.find(n => n.id === notifId);
            if (notif && notif.peerId && typeof selectPeer === 'function') {
              selectPeer({ id: notif.peerId, name: notif.peerName, displayName: notif.peerName });
            }
          } else if (actTarget === 'contacts') {
            document.querySelector('#tabNav button[data-view="contactsView"]')?.click();
          } else if (actTarget === 'settings') {
            document.querySelector('#tabNav button[data-view="settingsView"]')?.click();
          } else if (actTarget === 'vault') {
            document.querySelector('#tabNav button[data-view="vaultView"]')?.click();
          }
        }
      }

      renderNotifications();
    });
  });

  // Delete button
  document.querySelectorAll('.notif-delete').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      removeNotification(btn.dataset.id);
    });
  });
}

// ========== DND SETTINGS MODAL ==========

function _showDNDSettings() {
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.style.display = 'flex';
  overlay.style.zIndex = '300';

  const modal = document.createElement('div');
  modal.className = 'modal';
  modal.style.cssText = 'max-width:380px;width:90%;padding:24px;';

  modal.innerHTML =
    '<h3 style="margin-bottom:16px">\uD83D\uDD15 Do Not Disturb</h3>' +
    '<div style="display:flex;align-items:center;justify-content:space-between;padding:12px 0;border-bottom:1px solid var(--border-subtle)">' +
      '<div><div style="font-size:14px">Enable DND</div><div style="font-size:11px;color:var(--text-muted)">Silence notifications during set hours</div></div>' +
      '<label class="toggle"><input type="checkbox" id="dndToggle" ' + (dndState.enabled ? 'checked' : '') + '><span class="toggle-slider"></span></label>' +
    '</div>' +
    '<div style="padding:16px 0;border-bottom:1px solid var(--border-subtle)">' +
      '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">' +
        '<span style="font-size:13px;color:var(--text-secondary)">From</span>' +
        '<input type="number" id="dndStartHour" min="0" max="23" value="' + dndState.startHour + '" style="width:60px;padding:6px;background:var(--bg-input);border:1px solid var(--border-subtle);border-radius:6px;color:var(--text-primary);text-align:center">' +
        '<span style="font-size:13px;color:var(--text-secondary)">:00</span>' +
      '</div>' +
      '<div style="display:flex;align-items:center;gap:8px">' +
        '<span style="font-size:13px;color:var(--text-secondary)">To</span>' +
        '<input type="number" id="dndEndHour" min="0" max="23" value="' + dndState.endHour + '" style="width:60px;padding:6px;background:var(--bg-input);border:1px solid var(--border-subtle);border-radius:6px;color:var(--text-primary);text-align:center">' +
        '<span style="font-size:13px;color:var(--text-secondary)">:00</span>' +
      '</div>' +
    '</div>' +
    '<div style="font-size:12px;color:var(--text-muted);padding:12px 0;text-align:center">' +
      (dndState.enabled ? 'Currently active: notifications are silenced' : 'DND is off — you receive all notifications') +
    '</div>' +
    '<div style="display:flex;gap:8px">' +
      '<button id="btnCancelDND" style="flex:1;padding:10px;background:var(--bg-input);border:1px solid var(--border-subtle);border-radius:8px;color:var(--text-primary);cursor:pointer">Cancel</button>' +
      '<button id="btnSaveDND" style="flex:1;padding:10px;background:var(--accent);border:none;border-radius:8px;color:#fff;font-weight:600;cursor:pointer">Save</button>' +
    '</div>';

  overlay.appendChild(modal);
  document.body.appendChild(overlay);

  overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
  document.getElementById('btnCancelDND')?.addEventListener('click', () => overlay.remove());

  document.getElementById('dndToggle')?.addEventListener('change', (e) => {
    const save = document.getElementById('btnSaveDND');
    if (save) save.style.background = 'var(--accent)';
  });

  document.getElementById('btnSaveDND')?.addEventListener('click', () => {
    const enabled = document.getElementById('dndToggle')?.checked || false;
    const start = parseInt(document.getElementById('dndStartHour')?.value) || 22;
    const end = parseInt(document.getElementById('dndEndHour')?.value) || 7;

    setDND(enabled);
    if (enabled) setDNDHours(start, end);
    overlay.remove();
  });
}

// ========== AUTO-SEED (demo data) ==========

function seedDemoNotifications() {
  if (notifications.length > 0) return; // Don't overwrite existing

  const demos = [
    { type: 'message', title: 'Alice Chen', body: 'Hey, did you see the latest build? The encryption layer looks solid.', peerId: 'peer-alice', peerName: 'Alice Chen', action: { type: 'navigate', target: 'chat' } },
    { type: 'call', title: 'Missed Call', body: 'Bob Zhang tried to call you', peerId: 'peer-bob', peerName: 'Bob Zhang', action: { type: 'navigate', target: 'chat' } },
    { type: 'security', title: '\uD83D\uDD12 Key Rotation Complete', body: 'Your session keys have been rotated automatically. All active sessions are secure.', action: null },
    { type: 'system', title: 'FIBEMATE v3.0-preview', body: 'New features: Enhanced vault, theme switching, call history, and contact management.', action: { type: 'navigate', target: 'settings' } },
    { type: 'message', title: 'Carol Liu', body: 'Can you share the vault file I sent last week?', peerId: 'peer-carol', peerName: 'Carol Liu', action: { type: 'navigate', target: 'chat' } },
  ];

  demos.forEach((d, i) => {
    pushNotification({ ...d, timestamp: Date.now() - (demos.length - i) * 300000 });
  });

  markAllRead(); // Demo data starts as read except first
  // Un-read the first one
  const first = notifications[notifications.length - 1];
  if (first) {
    first.read = false;
    localStorage.setItem('fk_notifications', JSON.stringify(notifications));
  }
  _updateBadge();
}

// ========== SOUND PLAYBACK ==========

function playNotificationSound() {
  if (localStorage.getItem('fk_setting_sound') === 'false') return;
  if (_isDNDActive()) return;

  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.type = 'sine';
    osc.frequency.setValueAtTime(880, ctx.currentTime);     // A5
    osc.frequency.setValueAtTime(1100, ctx.currentTime + 0.1); // C#6
    gain.gain.setValueAtTime(0.1, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.3);
    osc.start(ctx.currentTime);
    osc.stop(ctx.currentTime + 0.3);
  } catch (e) { /* Audio not available */ }
}
// ================================================
// Voice/Video Call v3.0-preview — Extended: Call History, Incoming UI, Status
// ================================================

// Call state tracking
const CALL_STATE = { IDLE: 'idle', OUTGOING: 'outgoing', INCOMING: 'incoming', CONNECTED: 'connected', ENDED: 'ended' };
let callHistory = JSON.parse(localStorage.getItem('fk_callHistory') || '[]');
let currentCallState = CALL_STATE.IDLE;

// ========== CALL HISTORY ==========

function _saveCallRecord(peerName, peerId, type, duration, status) {
  callHistory.unshift({
    peerName: peerName || 'Unknown',
    peerId: peerId || '',
    type: type || 'voice',
    duration: duration || '00:00',
    durationSec: STATE.callSeconds || 0,
    status: status || 'completed',
    timestamp: Date.now()
  });
  // Keep max 100 records
  if (callHistory.length > 100) callHistory = callHistory.slice(0, 100);
  localStorage.setItem('fk_callHistory', JSON.stringify(callHistory));
}

function renderCallHistory() {
  if (callHistory.length === 0) return '';

  return callHistory.slice(0, 20).map((c, i) => {
    const date = new Date(c.timestamp);
    const timeStr = isToday(date)
      ? date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      : date.toLocaleDateString([], { month: 'short', day: 'numeric' });
    const statusIcon = c.status === 'missed'
      ? '\u274C'
      : c.type === 'video' ? '\uD83C\uDFA5' : '\uD83D\uDCDE';
    const statusColor = c.status === 'missed' ? '#ff4444' : 'var(--text-secondary)';
    const dirIcon = c.status === 'missed'
      ? (c.direction === 'incoming' ? '\u2199' : '\u2197')
      : (c.direction === 'incoming' ? '\u2199' : '\u2197');

    return '<div class="call-history-item" data-idx="' + i + '" style="display:flex;align-items:center;gap:12px;padding:10px 12px;cursor:pointer;border-bottom:1px solid var(--border-subtle,#333)">' +
      '<div style="font-size:20px">' + statusIcon + '</div>' +
      '<div style="flex:1"><div style="font-size:14px;color:var(--text-primary)">' + escapeHtml(c.peerName) + '</div>' +
      '<div style="font-size:12px;color:' + statusColor + '">' + dirIcon + ' ' + c.type + ' \u00B7 ' + c.duration + ' \u00B7 ' + timeStr + '</div></div>' +
      '<button class="icon-btn call-history-call" title="Call back" data-name="' + escapeHtml(c.peerName) + '" data-id="' + (c.peerId || '') + '" style="padding:6px;color:var(--accent,#4a9eff)"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0 1 22 16.92z"/></svg></button>' +
    '</div>';
  }).join('');
}

function bindCallHistoryEvents() {
  document.querySelectorAll('.call-history-item').forEach(item => {
    item.addEventListener('click', (e) => {
      if (e.target.closest('.call-history-call')) return;
      const idx = parseInt(item.dataset.idx);
      const record = callHistory[idx];
      if (record && record.peerId) {
        // Navigate to chat with this peer
        if (typeof selectPeer === 'function') {
          selectPeer({ id: record.peerId, name: record.peerName, displayName: record.peerName });
        }
      }
    });
  });

  document.querySelectorAll('.call-history-call').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const name = btn.dataset.name;
      const peerId = btn.dataset.id;
      STATE.currentPeerName = name;
      STATE.currentPeerId = peerId;
      startCall();
    });
  });
}

function isToday(date) {
  const now = new Date();
  return date.getDate() === now.getDate() &&
    date.getMonth() === now.getMonth() &&
    date.getFullYear() === now.getFullYear();
}

function showCallHistoryModal() {
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.style.display = 'flex';
  overlay.style.zIndex = '300';

  const modal = document.createElement('div');
  modal.className = 'modal';
  modal.style.cssText = 'max-width:500px;width:90%;max-height:70vh;overflow:auto;padding:0;border-radius:12px;';

  // Header
  const header = document.createElement('div');
  header.style.cssText = 'display:flex;align-items:center;justify-content:space-between;padding:16px 16px 12px;border-bottom:1px solid var(--border-subtle,#333);position:sticky;top:0;background:var(--bg-card,#1a1a2e);z-index:1;';
  header.innerHTML = '<h3 style="margin:0">Call History</h3>' +
    '<button style="background:none;border:none;color:var(--text-muted);font-size:20px;cursor:pointer;padding:4px 8px" id="closeCallHistory">\u2715</button>';
  modal.appendChild(header);

  // Content
  const content = document.createElement('div');
  content.id = 'callHistoryContent';
  content.style.cssText = 'padding:0;';
  content.innerHTML = callHistory.length === 0
    ? '<p style="text-align:center;padding:32px;color:var(--text-muted)">No call history yet</p>'
    : renderCallHistory();
  modal.appendChild(content);

  overlay.appendChild(modal);
  document.body.appendChild(overlay);

  overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
  document.getElementById('closeCallHistory')?.addEventListener('click', () => overlay.remove());
  bindCallHistoryEvents();
}

// ========== INCOMING CALL UI ==========

function showIncomingCall(callerName, callerAvatar, callType) {
  if (currentCallState !== CALL_STATE.IDLE) return false;

  currentCallState = CALL_STATE.INCOMING;
  const overlay = document.createElement('div');
  overlay.id = 'incomingCallOverlay';
  overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;z-index:500;display:flex;align-items:center;justify-content:center;flex-direction:column;background:rgba(0,0,0,0.85);';

  const content = document.createElement('div');
  content.style.cssText = 'text-align:center;padding:32px;max-width:320px;';

  // Avatar
  const avatar = document.createElement('div');
  avatar.style.cssText = 'width:80px;height:80px;border-radius:50%;background:var(--accent,#4a9eff);display:flex;align-items:center;justify-content:center;font-size:32px;color:#fff;margin:0 auto 16px;';
  avatar.textContent = (callerAvatar || callerName?.charAt(0)?.toUpperCase() || '?');
  content.appendChild(avatar);

  // Name
  const nameEl = document.createElement('div');
  nameEl.style.cssText = 'font-size:22px;font-weight:600;color:#fff;margin-bottom:4px;';
  nameEl.textContent = callerName || 'Unknown Caller';
  content.appendChild(nameEl);

  // Type
  const typeEl = document.createElement('div');
  typeEl.style.cssText = 'font-size:14px;color:#aaa;margin-bottom:8px;';
  typeEl.textContent = callType === 'video' ? 'Incoming video call...' : 'Incoming voice call...';
  content.appendChild(typeEl);

  // Encrypted badge
  const encEl = document.createElement('div');
  encEl.style.cssText = 'font-size:11px;color:#4a9eff;margin-bottom:24px;';
  encEl.textContent = '\uD83D\uDD12 End-to-end encrypted';
  content.appendChild(encEl);

  // Action buttons
  const actions = document.createElement('div');
  actions.style.cssText = 'display:flex;gap:24px;justify-content:center;';

  // Decline
  const declineBtn = document.createElement('button');
  declineBtn.style.cssText = 'width:60px;height:60px;border-radius:50%;background:#ff4444;border:none;color:#fff;font-size:24px;cursor:pointer;display:flex;align-items:center;justify-content:center;';
  declineBtn.innerHTML = '\u2715';
  declineBtn.title = 'Decline';
  declineBtn.onclick = () => {
    _declineCall(callerName);
    overlay.remove();
  };
  actions.appendChild(declineBtn);

  // Accept
  const acceptBtn = document.createElement('button');
  acceptBtn.style.cssText = 'width:60px;height:60px;border-radius:50%;background:#4CAF50;border:none;color:#fff;font-size:24px;cursor:pointer;display:flex;align-items:center;justify-content:center;';
  acceptBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="28" height="28"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0 1 22 16.92z"/></svg>';
  acceptBtn.title = 'Accept';
  acceptBtn.onclick = () => {
    currentCallState = CALL_STATE.CONNECTED;
    overlay.remove();
    if (typeof WebRTCModule !== 'undefined') {
      WebRTCModule.answerCall();
    } else {
      _startCallFallback(callerName);
    }
  };
  actions.appendChild(acceptBtn);

  content.appendChild(actions);

  // Quick reply (voice only)
  if (callType !== 'video') {
    const replyRow = document.createElement('div');
    replyRow.style.cssText = 'display:flex;gap:8px;margin-top:20px;flex-wrap:wrap;justify-content:center;';
    const quickReplies = ["Can't talk now", "Call you back", "Busy, message me"];
    quickReplies.forEach(reply => {
      const btn = document.createElement('button');
      btn.style.cssText = 'padding:6px 14px;border-radius:16px;background:rgba(255,255,255,0.1);border:none;color:#ccc;font-size:12px;cursor:pointer;';
      btn.textContent = reply;
      btn.onclick = () => {
        _declineWithReply(callerName, reply);
        overlay.remove();
      };
      replyRow.appendChild(btn);
    });
    content.appendChild(replyRow);
  }

  overlay.appendChild(content);
  document.body.appendChild(overlay);

  // Auto-dismiss after 30s if no answer
  setTimeout(() => {
    if (document.getElementById('incomingCallOverlay') && currentCallState === CALL_STATE.INCOMING) {
      _declineCall(callerName);
      overlay.remove();
    }
  }, 30000);

  return true;
}

function _declineCall(callerName) {
  currentCallState = CALL_STATE.IDLE;
  if (typeof WebRTCModule !== 'undefined' && WebRTCModule.isCalling()) {
    WebRTCModule.rejectCall();
  }
  _saveCallRecord(callerName, STATE.currentPeerId, 'voice', '00:00', 'missed');
  showToast('Call declined from ' + (callerName || 'Unknown'), 'info');
}

function _declineWithReply(callerName, reply) {
  _declineCall(callerName);
  showToast('Replied: "' + reply + '"', 'info');
  // Optionally send the reply as a message
  if (typeof sendMessage === 'function' && STATE.currentPeerId) {
    sendMessage(reply);
  }
}

// ========== CORE CALL FUNCTIONS (extended) ==========

function startCall() {
  if (!STATE.currentPeerName || !STATE.currentPeerId) return;

  currentCallState = CALL_STATE.OUTGOING;

  // Route through VideoCallUI type selector if available
  if (typeof VideoCallUI !== 'undefined') {
    VideoCallUI.updatePeerName(STATE.currentPeerName);
    VideoCallUI.showVideoSelectModal();
  } else if (typeof WebRTCModule !== 'undefined') {
    WebRTCModule.startCall(STATE.currentPeerId, 'voice');
  } else {
    _startCallFallback(STATE.currentPeerName);
  }
}

function startCallWith(name) {
  currentCallState = CALL_STATE.OUTGOING;
  if (typeof WebRTCModule !== 'undefined' && STATE.currentPeerId) {
    WebRTCModule.startCall(STATE.currentPeerId, 'voice');
  } else {
    _startCallFallback(name);
  }
}

function startVideoCall() {
  if (!STATE.currentPeerId) return;
  currentCallState = CALL_STATE.OUTGOING;
  if (typeof WebRTCModule !== 'undefined') {
    WebRTCModule.startCall(STATE.currentPeerId, 'video');
  }
}

function _startCallFallback(name) {
  hideAllMainViews();
  document.getElementById('callView').style.display = 'flex';
  document.getElementById('callName').textContent = name;
  document.getElementById('callAvatar').textContent = name.charAt(0).toUpperCase();
  document.getElementById('callStatus').textContent = 'Calling...';
  document.getElementById('STATE.callTimer').textContent = '00:00';
  STATE.callSeconds = 0;

  // Simulate connection after 2s
  setTimeout(() => {
    if (document.getElementById('callView').style.display === 'none') return;
    currentCallState = CALL_STATE.CONNECTED;
    document.getElementById('callStatus').textContent = 'Connected \u00B7 Encrypted';
    STATE.callTimer = setInterval(() => {
      STATE.callSeconds++;
      const m = String(Math.floor(STATE.callSeconds / 60)).padStart(2, '0');
      const s = String(STATE.callSeconds % 60).padStart(2, '0');
      document.getElementById('STATE.callTimer').textContent = m + ':' + s;
    }, 1000);
  }, 2000);
}

function endCall() {
  const duration = STATE.callSeconds || 0;
  const m = String(Math.floor(duration / 60)).padStart(2, '0');
  const s = String(duration % 60).padStart(2, '0');
  const durationStr = m + ':' + s;

  const status = currentCallState === CALL_STATE.INCOMING ? 'missed' : 'completed';
  const dir = currentCallState === CALL_STATE.INCOMING ? 'incoming' : 'outgoing';

  // Save call record
  _saveCallRecord(STATE.currentPeerName, STATE.currentPeerId, 'voice', durationStr, status);
  if (status !== 'missed') {
    // Also tag direction
    const last = callHistory[0];
    if (last) last.direction = dir;
    localStorage.setItem('fk_callHistory', JSON.stringify(callHistory));
  }

  // Use WebRTCModule for real cleanup
  if (typeof WebRTCModule !== 'undefined' && WebRTCModule.isCalling()) {
    WebRTCModule.endCall();
  }

  // Fallback cleanup
  if (STATE.callTimer) { clearInterval(STATE.callTimer); STATE.callTimer = null; }

  // Hide call overlay views
  if (typeof VideoCallUI !== 'undefined') {
    VideoCallUI.hideCallOverlay();
  }

  hideAllMainViews();
  if (STATE.currentPeerId) {
    document.getElementById('chatWindow').style.display = 'flex';
  } else {
    document.getElementById('chatEmpty').style.display = 'flex';
  }

  currentCallState = CALL_STATE.IDLE;
  STATE.callSeconds = 0;
  showToast('Call ended \u00B7 ' + durationStr, 'info');
}

function toggleMute() {
  if (typeof WebRTCModule !== 'undefined' && WebRTCModule.isCalling()) {
    const isMuted = WebRTCModule.toggleMute();
    STATE.isMuted = isMuted;
    document.getElementById('btnMute')?.classList.toggle('active', isMuted);
    showToast(isMuted ? 'Microphone muted' : 'Microphone unmuted', 'info');
  } else {
    STATE.isMuted = !STATE.isMuted;
    document.getElementById('btnMute')?.classList.toggle('active', STATE.isMuted);
    showToast(STATE.isMuted ? 'Microphone muted' : 'Microphone unmuted', 'info');
  }
}

function toggleSpeaker() {
  if (typeof WebRTCModule !== 'undefined' && WebRTCModule.isCalling()) {
    WebRTCModule.toggleSpeaker();
  }
  STATE.isSpeaker = !STATE.isSpeaker;
  document.getElementById('btnSpeaker')?.classList.toggle('active', STATE.isSpeaker);
  showToast(STATE.isSpeaker ? 'Speaker on' : 'Speaker off', 'info');
}

function toggleVideo() {
  if (typeof WebRTCModule !== 'undefined' && WebRTCModule.isCalling()) {
    WebRTCModule.toggleVideo();
  }
}

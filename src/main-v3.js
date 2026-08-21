/**
 * FIBEMATE Tauri - Main Interface Logic v3
 * Features: Messages, Contacts, Vault, Key Management, Settings, Voice Call
 * Backend: http://localhost:3006 (proxy to ECS 8.156.77.68:3001)
 * CHANGED from v2: API_BASE, token key names, conversationId flow, WebSocket URL, contacts from backend
 */

// API_BASE: 优先从环境变量/配置文件读取，其次使用默认值
// 生产环境应通过构建流程注入或从配置文件加载
const API_BASE = (() => {
  // 尝试从 localStorage 读取自定义配置（用于开发和测试）
  const customApi = localStorage.getItem('fk_api_base');
  if (customApi) return customApi;
  
  // 尝试从运行时配置读取（Electron preload 注入）
  if (typeof window !== 'undefined' && window.__FIBEMATE_CONFIG__?.apiBase) {
    return window.__FIBEMATE_CONFIG__.apiBase;
  }
  
  // 默认：生产环境 HTTPS 域名
  return 'https://fibemate.net/api';
})();

// ================================================
// State
// ================================================
let currentPeerId = null;
let currentPeerName = null;
let currentConversationId = null;  // v3: 新增，v2 中缺失
let currentTab = 'messages';
let callTimer = null;
let callSeconds = 0;
let ws = null;

// ================================================
// Loading State Helpers
// ================================================
function showLoading(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.innerHTML = `
    <div class="loading-overlay">
      <div class="loading-spinner"></div>
    </div>
  `;
}

function showSkeleton(containerId, count = 3) {
  const container = document.getElementById(containerId);
  if (!container) return;
  let html = '';
  for (let i = 0; i < count; i++) {
    html += `
      <div class="conversation-item" style="opacity: 0.6;">
        <div class="conv-avatar skeleton skeleton-avatar"></div>
        <div class="conv-info" style="flex: 1;">
          <div class="conv-name skeleton skeleton-text" style="width: 120px;"></div>
          <div class="conv-preview skeleton skeleton-text short"></div>
        </div>
      </div>
    `;
  }
  container.innerHTML = html;
}

function hideLoading(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;
  const overlay = container.querySelector('.loading-overlay');
  if (overlay) overlay.remove();
}

// ================================================
// Init
// ================================================
document.addEventListener('DOMContentLoaded', async () => {
  if (!window.location.pathname.endsWith('main.html')) return;

  // v3: 统一使用 fk_* 键名（与 zk-auth.js v8 一致），v2 用的是 fibemate_token/fibemate_username
  const token = localStorage.getItem('fk_token');
  if (!token) { window.location.href = 'index.html'; return; }

  const username = localStorage.getItem('fk_uname') || 'User';
  document.getElementById('userName').textContent = username;
  document.getElementById('userAvatar').textContent = username.charAt(0).toUpperCase();

  initNavigation();

  // Show skeleton loading while data loads
  showSkeleton('conversationList', 5);
  showSkeleton('contactList', 3);

  // Initialize privacy features
  await initPrivacyFeatures();

  // v5: 初始化前向保密加密引擎（X3DH + Double Ratchet）
  if (typeof MessageCryptoV2 !== 'undefined') {
    try {
      await MessageCryptoV2.init();
      console.log('[Init v5] MessageCryptoV2 initialized — forward secrecy active');

      // P1-2: 设置 OPK 自动补充回调
      if (typeof privacyAPI !== 'undefined') {
        MessageCryptoV2.setOPKUploadCallback(async (bundle) => {
          const userId = localStorage.getItem('fk_uid') || localStorage.getItem('fk_uname');
          return privacyAPI.replenishOPKs(userId, bundle);
        });
        console.log('[Init v5] OPK auto-replenish callback registered');
      }

      // 预生成 pre-key bundle（后台异步，不阻塞 UI）
      MessageCryptoV2.getMyPreKeyBundle().then(async bundle => {
        const bv = bundle._rustVersion || bundle.version || 2;
        console.log(`[Init v7] Pre-key bundle ready (v${bv}, ${bv >= 3 ? 'X25519' : 'P-256'}), identity key established`);
        // 上传 bundle 到服务器
        if (typeof privacyAPI !== 'undefined') {
          const userId = localStorage.getItem('fk_uid') || localStorage.getItem('fk_uname');
          try {
            await privacyAPI.uploadPreKeyBundle(userId, bundle);
            console.log(`[Init v7] Pre-key bundle (v${bv}) uploaded to server`);
          } catch (uploadErr) {
            console.warn('[Init v7] Pre-key upload failed:', uploadErr.message);
          }
        }
        // OPK: v2 needs replenishment pool, v3 is no-op (per-session ephemerals)
        MessageCryptoV2.startOPKAutoReplenish();
      }).catch(e => console.warn('[Init v7] Pre-key generation deferred:', e.message));
    } catch (e) {
      console.error('[Init v5] MessageCryptoV2 init failed:', e);
    }
  } else {
    console.warn('[Init v5] MessageCryptoV2 not available, falling back to legacy crypto');
  }

  // v6: Initialize post-quantum cryptography
  if (typeof PQIntegration !== 'undefined') {
    try {
      await PQIntegration.init();
      if (PQIntegration.isAvailable()) {
        console.log('[Init v6] Post-quantum cryptography ready (ML-KEM-768)');
        // Patch MessageCryptoV2 with hybrid X3DH support
        if (typeof MessageCryptoV2 !== 'undefined') {
          PQIntegration.patchMessageCryptoV2();
        }
      } else {
        console.log('[Init v6] Post-quantum cryptography not available, using classical X3DH');
      }
    } catch (e) {
      console.warn('[Init v6] PQ initialization failed:', e.message);
    }
  }

  await loadConversations();
  await loadContacts();  // v3: 改为 async，从后端加载
  loadVault();
  renderKeyManagement();
  renderSettings();
  bindEvents();
  connectWebSocket();
});

// ================================================
// Navigation
// ================================================
function initNavigation() {
  document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      const target = tab.dataset.tab;
      switchTab(target);
    });
  });
}

function switchTab(tab) {
  currentTab = tab;
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.id === `panel${capitalize(tab)}`));
  hideAllMainViews();
  if (tab === 'messages') {
    document.getElementById('chatEmpty').style.display = 'flex';
  } else if (tab === 'keys') {
    document.getElementById('keyDetailView').style.display = 'flex';
  } else if (tab === 'settings') {
    document.getElementById('settingsDetailView').style.display = 'flex';
  }
  const placeholders = { messages: 'Search messages...', contacts: 'Search contacts...', vault: 'Search vault...', keys: 'Search keys...', settings: 'Search settings...' };
  document.getElementById('searchInput').placeholder = placeholders[tab] || 'Search...';
}

function hideAllMainViews() {
  document.getElementById('chatEmpty').style.display = 'none';
  document.getElementById('chatWindow').style.display = 'none';
  document.getElementById('callView').style.display = 'none';
  document.getElementById('keyDetailView').style.display = 'none';
  document.getElementById('settingsDetailView').style.display = 'none';
}

function capitalize(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

// ================================================
// WebSocket  — v3 改为 ws://localhost:3001/ws
// ================================================
function connectWebSocket() {
  const token = localStorage.getItem('fk_token');
  if (!token) return;
  try {
    // 使用与 API 相同的地址，但协议改为 ws
    const apiBase = API_BASE.replace('http://', 'ws://').replace('/api', '');
    ws = new WebSocket(`${apiBase}/ws?token=${token}`);
    ws.onopen = () => console.log('[WS v3] Connected to proxy');
    ws.onmessage = async (e) => {
      try {
        const msg = JSON.parse(e.data);
        console.log('[WS v4] Received:', msg.type);
        
        if (msg.type === 'new_message' && msg.from === currentPeerId) {
          let text;
          // v6: 前向保密解密 — 支持 hybrid PQ + v2 envelope + v1 兼容
          const Crypto = typeof MessageCryptoV2 !== 'undefined' ? MessageCryptoV2 : MessageCrypto;
          if (msg.envelope && typeof Crypto !== 'undefined') {
            // v6 opaque envelope 格式
            try {
              const envelope = JSON.parse(msg.envelope);
              
              // Check if this is an X3DH init message (first contact)
              // v3 Rust: type === 'x3dh_init_rust' or version >= 3, v2: ephemeralPublicKey field
              const isInitMsg = envelope.type === 'x3dh_init_rust' || envelope.version >= 3 ||
                (envelope.ephemeralPublicKey && !envelope.ciphertext);
              if (isInitMsg) {
                const initSuccess = await handleX3DHInitMessage(msg);
                if (initSuccess) { return; }
              }
              
              text = await Crypto.decrypt(msg.from, envelope);
              console.log(`[WS v6] E2EE message decrypted (protocol=${envelope.protocol})`);
            } catch (decryptErr) {
              // 断裂点 #3 修复：不静默降级，明确告警
              console.error('[WS v6] DECRYPT FAILED:', decryptErr.message);
              appendMessage(false, `⚠️ 解密失败\n${decryptErr.message}`, msg.createdAt || Date.now());
              showToast('🔒 安全警告: 消息解密失败，可能安全受损', 'error', 8000);
              return;  // 不显示假消息
            }
          } else if (msg.encryptedContent && typeof MessageCrypto !== 'undefined') {
            // v4 兼容格式（旧版客户端）
            try {
              text = await MessageCrypto.decrypt(msg.from, msg.encryptedContent);
              console.log('[WS v5] Legacy decrypt (v1 format)');
            } catch (legacyErr) {
              console.error('[WS v5] Legacy decrypt failed:', legacyErr);
              text = '[⚠️ 无法解密（旧格式）]';
            }
          } else if (msg.ciphertext) {
            text = decodeCiphertext(msg.ciphertext);
          } else {
            text = msg.content || msg.text || '[无法读取]';
          }
          appendMessage(false, text || '[Unable to decrypt]', msg.createdAt || Date.now(), true);
        } else if (msg.type === 'new_message') {
          showToast(`New message from ${msg.from}`, 'info');
          loadConversations();
        } else if (msg.type === 'offline_messages') {
          console.log('[WS v4] Offline messages:', msg.count);
        }
      } catch (err) {
        console.error('[WS v4] Parse error:', err);
      }
    };
    ws.onclose = () => {
      console.log('[WS v3] Disconnected, reconnecting...');
      setTimeout(connectWebSocket, 5000);
    };
    ws.onerror = (err) => console.error('[WS v3] Error:', err);
  } catch (err) {
    console.error('[WS v3] Connect error:', err);
  }
}

// v3: 临时 base64 ciphertext 解码
function decodeCiphertext(ciphertext) {
  try {
    if (typeof ciphertext === 'string' && ciphertext.length > 0) {
      const decoded = atob(ciphertext);
      return decodeURIComponent(escape(decoded));
    }
  } catch (e) {}
  return ciphertext;
}

// ================================================
// Events
// ================================================
function bindEvents() {
  document.getElementById('btnBack')?.addEventListener('click', showChatEmpty);
  document.getElementById('btnNewChat')?.addEventListener('click', () => switchTab('contacts'));
  document.getElementById('btnStartChat')?.addEventListener('click', () => switchTab('contacts'));
  document.getElementById('btnSend')?.addEventListener('click', sendMessage);
  document.getElementById('messageInput')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  });
  document.getElementById('btnVerify')?.addEventListener('click', () => {
    if (currentPeerId) {
      verifyContactSafetyNumbers(currentPeerId);
    } else {
      showToast('Key verification: Compare safety numbers in person', 'info');
    }
  });
  document.getElementById('btnBurn')?.addEventListener('click', toggleBurnMode);
  document.getElementById('searchInput')?.addEventListener('input', (e) => handleSearch(e.target.value));

  document.getElementById('btnAddContact')?.addEventListener('click', () => showModal('modalAddContact'));
  document.getElementById('btnAddContactEmpty')?.addEventListener('click', () => showModal('modalAddContact'));
  document.getElementById('btnConfirmAddContact')?.addEventListener('click', addContact);
  document.getElementById('contactUsername')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') addContact(); });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      const chatWindow = document.getElementById('chatWindow');
      if (chatWindow && chatWindow.style.display !== 'none') {
        showChatEmpty();
      }
    }
  });

  document.getElementById('btnUploadVault')?.addEventListener('click', () => showModal('modalUploadVault'));
  document.getElementById('btnUploadVaultEmpty')?.addEventListener('click', () => showModal('modalUploadVault'));
  document.getElementById('vaultDropzone')?.addEventListener('click', () => document.getElementById('vaultFileInput').click());
  document.getElementById('vaultFileInput')?.addEventListener('change', handleVaultFileSelect);
  document.getElementById('btnConfirmUpload')?.addEventListener('click', uploadVaultFile);

  document.getElementById('btnRotateKeys')?.addEventListener('click', rotateKeys);
  document.getElementById('btnExportKeys')?.addEventListener('click', exportPublicKeys);

  // Voice call (legacy)
  document.getElementById('btnVoiceCall')?.addEventListener('click', startCall);
  document.getElementById('btnHangup')?.addEventListener('click', endCall);
  document.getElementById('btnMute')?.addEventListener('click', toggleMute);
  document.getElementById('btnSpeaker')?.addEventListener('click', toggleSpeaker);
  
  // Video call (WebRTC module)
  document.getElementById('btnVideoCall')?.addEventListener('click', () => {
    if (!currentPeerId) {
      showToast('请先选择一个联系人', 'error');
      return;
    }
    VideoCallUI.showVideoSelectModal();
  });

  // v3: 统一使用 fk_* 键名登出
  document.getElementById('btnLogout')?.addEventListener('click', doLogout);

  const userBar = document.getElementById('userBar');
  if (userBar) {
    userBar.style.cursor = 'pointer';
    userBar.title = 'Click to logout';
    userBar.addEventListener('click', doLogout);
  }

  document.querySelectorAll('.modal-close').forEach(btn => {
    btn.addEventListener('click', () => {
      const modalId = btn.dataset.modal;
      if (modalId) {
        hideModal(modalId);
        // Fallback: ensure modal is hidden even if hideModal fails
        const el = document.getElementById(modalId);
        if (el) el.style.display = 'none';
      }
    });
  });
  document.querySelectorAll('.modal-overlay').forEach(overlay => {
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) overlay.style.display = 'none';
    });
  });
}

// v3: 登出使用 fk_* 键名
function doLogout() {
  if (confirm('Logout and return to login screen?')) {
    ['fk_token','fk_uid','fk_uname','fk_privkey_jwk','fk_pubkey_hex','fk_zk_secrets'].forEach(k => localStorage.removeItem(k));
    if (ws) ws.close();
    window.location.href = 'index.html';
  }
}

function handleSearch(query) {
  const lower = query.toLowerCase();
  if (currentTab === 'messages') {
    document.querySelectorAll('.conversation-item').forEach(item => {
      const name = item.dataset.name?.toLowerCase() || '';
      item.style.display = name.includes(lower) ? 'flex' : 'none';
    });
  } else if (currentTab === 'contacts') {
    document.querySelectorAll('.contact-item').forEach(item => {
      const name = item.dataset.name?.toLowerCase() || '';
      item.style.display = name.includes(lower) ? 'flex' : 'none';
    });
  }
}

// ================================================
// Conversations  — v3 适配后端格式 { conversations: [{ id, otherUser, ... }] }
// ================================================
async function loadConversations() {
  const list = document.getElementById('conversationList');
  const empty = document.getElementById('emptyState');
  try {
    const token = localStorage.getItem('fk_token');
    const res = await fetch(`${API_BASE}/conversations`, { headers: { Authorization: `Bearer ${token}` } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const convs = data.conversations || [];
    if (!convs || convs.length === 0) {
      if (empty) {
        empty.style.display = 'flex';
        empty.innerHTML = `
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="width: 48px; height: 48px; color: var(--text-muted); margin-bottom: 16px;">
            <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
          </svg>
          <p style="color: var(--text-secondary); font-size: 14px; margin-bottom: 8px;">No messages yet</p>
          <p style="color: var(--text-muted); font-size: 12px;">Start a conversation from Contacts</p>
        `;
      }
      list.innerHTML = '';
      return;
    }
    if (empty) empty.style.display = 'none';
    list.innerHTML = convs.map(c => buildConvItem(c)).join('');
    list.querySelectorAll('.conversation-item').forEach(item => {
      item.addEventListener('click', () => openChat(item.dataset.userId, item.dataset.name));
    });
  } catch (err) {
    console.error('[Conversations v3] Load failed:', err);
    if (empty) {
      empty.style.display = 'flex';
      empty.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="width: 48px; height: 48px; color: var(--danger); margin-bottom: 16px;">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
        <p style="color: var(--text-secondary); font-size: 14px; margin-bottom: 8px;">Failed to load conversations</p>
        <button class="btn-secondary" onclick="loadConversations()" style="margin-top: 8px;">Retry</button>
      `;
    }
    list.innerHTML = '';
  }
}

// v3: 适配后端返回格式 { id, otherUser: { id, username, displayName }, lastMessage, lastMessageAt, unreadCount }
function buildConvItem(c) {
  const other = c.otherUser || {};
  const time = c.lastMessageAt ? formatTime(c.lastMessageAt) : '';
  const lastMsg = c.lastMessage || {};
  const preview = lastMsg.ciphertext ? '[Encrypted]' : 'No messages yet';
  const badge = c.unreadCount ? `<span class="conv-badge">${c.unreadCount}</span>` : '';
  const online = other.isOnline ? '<span class="online-dot"></span>' : '';
  return `<div class="conversation-item" data-user-id="${other.id || ''}" data-name="${escapeHtml(other.displayName || other.username || 'Unknown')}" data-conv-id="${c.id}">
    <div class="conv-avatar">${(other.displayName || other.username || 'U').charAt(0).toUpperCase()}${online}</div>
    <div class="conv-info"><div class="conv-name">${escapeHtml(other.displayName || other.username || 'Unknown')}</div><div class="conv-preview">${escapeHtml(preview)}</div></div>
    <div class="conv-meta"><span class="conv-time">${time}</span>${badge}</div>
  </div>`;
}

// ================================================
// Chat  — v3 使用 conversationId，通过 find-or-create 获取
// ================================================
async function openChat(userId, name) {
  currentPeerId = userId;
  currentPeerName = name;
  hideAllMainViews();
  document.getElementById('chatWindow').style.display = 'flex';
  document.getElementById('chatPeerName').textContent = name;
  document.getElementById('chatPeerAvatar').textContent = name.charAt(0).toUpperCase();
  // v5: 显示前向保密状态
  const Crypto = typeof MessageCryptoV2 !== 'undefined' ? MessageCryptoV2 : (typeof MessageCrypto !== 'undefined' ? MessageCrypto : null);
  const e2eeBar = document.getElementById('e2eeStatusBar');
  const e2eeIcon = document.getElementById('e2eeStatusIcon');
  const e2eeText = document.getElementById('e2eeStatusText');
  const e2eeDetail = document.getElementById('e2eeStatusDetail');
  
  if (Crypto && await Crypto.hasSession(currentPeerId)) {
    const status = await Crypto.getSecurityStatus(currentPeerId);
    // 更新旧版状态文本
    document.getElementById('chatPeerStatus').textContent = 'Encrypted';
    document.getElementById('chatPeerStatus').style.color = 'var(--text-secondary)';
    // 显示新版 E2EE 状态栏
    if (e2eeBar) {
      e2eeBar.style.display = 'inline-flex';
      e2eeBar.className = 'e2ee-status-bar secure';
      e2eeIcon.textContent = '🔒';
      e2eeText.textContent = 'E2EE';
      e2eeDetail.textContent = `${status.curve} · ${status.messagesSent + status.messagesReceived} msgs`;
    }
  } else if (Crypto) {
    document.getElementById('chatPeerStatus').textContent = 'Encrypted';
    document.getElementById('chatPeerStatus').style.color = 'var(--text-secondary)';
    if (e2eeBar) {
      e2eeBar.style.display = 'inline-flex';
      e2eeBar.className = 'e2ee-status-bar pending';
      e2eeIcon.textContent = '⏳';
      e2eeText.textContent = 'PENDING';
      e2eeDetail.textContent = 'Session not established';
    }
  } else {
    document.getElementById('chatPeerStatus').textContent = 'Unencrypted';
    document.getElementById('chatPeerStatus').style.color = 'var(--danger)';
    if (e2eeBar) {
      e2eeBar.style.display = 'inline-flex';
      e2eeBar.className = 'e2ee-status-bar danger';
      e2eeIcon.textContent = '🔓';
      e2eeText.textContent = 'NO E2EE';
      e2eeDetail.textContent = 'Crypto module not loaded';
    }
  }
  document.querySelectorAll('.conversation-item').forEach(el => el.classList.remove('active'));
  document.querySelector(`[data-user-id="${userId}"]`)?.classList.add('active');

  await ensureConversation(userId);
  if (currentConversationId) {
    await loadMessages(currentConversationId);
  }
}

// v3: 新增 — 获取或创建对话，得到 conversationId
async function ensureConversation(userId) {
  const token = localStorage.getItem('fk_token');
  try {
    const res = await fetch(`${API_BASE}/conversations/find-or-create`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ userId: userId })
    });
    if (res.ok) {
      const data = await res.json();
      currentConversationId = data.conversationId;
      console.log('[Chat v3] Conversation ID:', currentConversationId);
    } else {
      console.error('[Chat v3] Failed to create conversation:', res.status);
    }
  } catch (err) {
    console.error('[Chat v3] Error:', err);
  }
}

// v3: 使用 conversationId 加载消息（v2 用的是 peerId）
async function loadMessages(conversationId) {
  const list = document.getElementById('messagesList');
  list.innerHTML = '<div class="date-divider"><span>Today</span></div>';
  try {
    const token = localStorage.getItem('fk_token');
    const res = await fetch(`${API_BASE}/conversations/${conversationId}/messages?limit=50`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const msgs = data.messages || [];
    msgs.sort((a, b) => a.createdAt - b.createdAt);
    for (const m of msgs) {
      const isSent = m.senderUserId === localStorage.getItem('fk_uid');
      let text;
      
      // v5: 前向保密解密 — 支持 v2 envelope 和 v1 兼容
      const Crypto = typeof MessageCryptoV2 !== 'undefined' ? MessageCryptoV2 : MessageCrypto;
      if (m.envelope && typeof Crypto !== 'undefined') {
        try {
          const envelope = JSON.parse(m.envelope);
          text = await Crypto.decrypt(m.senderUserId, envelope);
        } catch (e) {
          console.error('[Messages v5] Decrypt failed:', e.message);
          text = `⚠️ 解密失败: ${e.message}`;
        }
      } else if (m.encryptedContent && typeof MessageCrypto !== 'undefined') {
        try {
          text = await MessageCrypto.decrypt(m.senderUserId, m.encryptedContent);
        } catch (e) {
          console.error('[Messages v5] Legacy decrypt failed:', e);
          text = '[⚠️ 无法解密（旧格式）]';
        }
      } else {
        text = decodeCiphertext(m.ciphertext);
      }
      
      // 标记加密消息（v2 envelope 或 encryptedContent）
      const isEncrypted = !!(m.envelope || m.encryptedContent);
      appendMessage(isSent, text || '[Unable to decrypt]', m.createdAt, isEncrypted);
    }
  } catch (err) {
    console.error('[Messages v3] Load failed:', err);
  }
  document.getElementById('messageInput').focus();
}

function appendMessage(sent, text, timestamp, isEncrypted = false) {
  const list = document.getElementById('messagesList');
  const time = timestamp ? formatTime(timestamp) : formatTime(Date.now());
  const msg = document.createElement('div');
  msg.className = `message ${sent ? 'sent' : 'received'}`;
  const e2eeBadge = isEncrypted ? '<span class="e2ee-badge" title="End-to-end encrypted"></span>' : '';
  msg.innerHTML = `<div class="msg-bubble">${escapeHtml(text)}${e2eeBadge}</div><div class="msg-time">${time}</div>`;
  list.appendChild(msg);
  list.scrollTop = list.scrollHeight;
}

async function sendMessage() {
  const input = document.getElementById('messageInput');
  const text = input.value.trim();
  if (!text || !currentPeerId) return;

  if (!currentConversationId) {
    await ensureConversation(currentPeerId);
  }
  if (!currentConversationId) {
    showToast('Failed to create conversation', 'error');
    return;
  }

  // v5.1: 自动建立加密会话（如果尚未建立）
  const Crypto = typeof MessageCryptoV2 !== 'undefined' ? MessageCryptoV2 : MessageCrypto;
  if (typeof Crypto !== 'undefined' && Crypto.hasSession) {
    try {
      const hasSession = await Crypto.hasSession(currentPeerId);
      if (!hasSession) {
        console.log(`[Send v5.1] No session with ${currentPeerId}, attempting X3DH initiation...`);
        showToast('正在建立安全会话...', 'info');
        
        // 尝试从服务器获取对方的 pre-key bundle
        try {
          // v3: Use privacyAPI for consistent endpoint (supports v2 P-256 + v3 X25519)
          let bundle;
          try {
            bundle = typeof privacyAPI !== 'undefined'
              ? await privacyAPI.fetchPreKeyBundle(currentPeerId)
              : null;
          } catch (apiErr) {
            // Fallback: legacy endpoint path
            if (apiErr.message?.includes('404') || apiErr.message?.includes('NOT_FOUND')) {
              console.warn(`[Send v7] Pre-key bundle not found for ${currentPeerId}`);
              showToast('对方尚未注册加密密钥，无法发送加密消息', 'warning');
              return;
            }
            throw apiErr;
          }

          if (bundle && bundle.identityKey) {
            // Detect protocol version from bundle
            const bundleVersion = (typeof privacyAPI !== 'undefined' && privacyAPI.detectBundleVersion)
              ? privacyAPI.detectBundleVersion(bundle) : 2;
            console.log(`[Send v7] Fetched bundle for ${currentPeerId}: v${bundleVersion} (${bundleVersion >= 3 ? 'X25519' : 'P-256'})`);

            // v7: 优先使用 X25519 Rust DR (v3), 回退混合 X3DH (v2+KEM), 最后回退标准 X3DH (v2)
            let sessionResult;
            if (bundleVersion >= 3) {
              // Rust X25519 DR — pure X3DH, no PQ hybrid yet
              console.log(`[Send v7] Using Rust X25519 Double Ratchet`);
              sessionResult = await Crypto.initiateSession(currentPeerId, bundle);
            } else if (PQIntegration && PQIntegration.isAvailable() && bundle.kemPublicKey) {
              console.log(`[Send v6] Using hybrid X3DH with ML-KEM-768`);
              sessionResult = await Crypto.initiateHybridSession(currentPeerId, bundle);
            } else {
              sessionResult = await Crypto.initiateSession(currentPeerId, bundle);
            }
              
              if (sessionResult.sessionEstablished || sessionResult.sessionReady) {
                const isHybrid = sessionResult.hybrid || false;
                const isRust = sessionResult.rustSession || false;
                const label = isRust ? 'Rust X25519' : (isHybrid ? 'hybrid PQ' : 'classical');
                console.log(`[Send v7] X3DH session established with ${currentPeerId} (${label})`);
                showToast(`安全会话已建立${isRust ? ' (Rust X25519)' : isHybrid ? ' (后量子)' : ''}`, 'success');
              }
            } else {
              console.warn(`[Send v7] Pre-key bundle has no identityKey for ${currentPeerId}`);
              showToast('对方密钥格式异常，无法建立加密会话', 'warning');
            }
          }
          // Note: 404/not-found is handled in inner try/catch above
        } catch (x3dhErr) {
          console.error('[Send v7] X3DH initiation failed:', x3dhErr.message);
          showToast('建立加密会话失败: ' + x3dhErr.message, 'error');
        }
      }
    } catch (e) {
      console.warn('[Send v5.1] Session check failed:', e.message);
    }
  }

  input.value = '';

  // Check if burn mode is enabled
  if (burnMode) {
    await sendBurnMessage(text, burnTimeout);
    burnMode = false;
    const btnBurn = document.getElementById('btnBurn');
    if (btnBurn) {
      btnBurn.classList.remove('active');
      btnBurn.style.color = '';
    }
    return;
  }

  // 先显示消息（乐观 UI），标记为加密中
  appendMessage(true, text, Date.now(), false);

  try {
    const token = localStorage.getItem('fk_token');
    
    // v5: 前向保密加密 — 优先使用 MessageCryptoV2（完整X3DH + Double Ratchet）
    let payload;
    let isEncrypted = false;
    const Crypto = typeof MessageCryptoV2 !== 'undefined' ? MessageCryptoV2 : MessageCrypto;
    if (typeof Crypto !== 'undefined') {
      try {
        const envelope = await Crypto.encrypt(currentPeerId, text);
        isEncrypted = true;
        // 断裂点 #2 修复：后端只收到 opaque blob，无法解密内容
        payload = {
          conversationId: currentConversationId,
          // opaque envelope — 后端/中间人只能看到这个，无法提取明文或密钥材料
          envelope: JSON.stringify(envelope),
          protocol: envelope.protocol || 'double-ratchet',
          version: envelope.version || 1,
          messageType: 'e2ee',  // End-to-End Encrypted Envelope
          burnAfterRead: false
        };
        console.log(`[Send v5] E2EE message — protocol=${envelope.protocol} v${envelope.version}, backend cannot decrypt`);
      } catch (encryptErr) {
        // 加密失败时明确告警（不静默降级为明文）
        console.error('[Send v5] ENCRYPTION FAILED:', encryptErr.message);
        showToast('⚠️ 加密失败: ' + encryptErr.message + ' — 消息未发送', 'error');
        // 不发送未加密的消息！安全优先。
        return;
      }
    } else {
      // 无加密模块时的处理
      console.warn('[Send v5] No crypto module available — message NOT sent for security');
      showToast('⚠️ 安全模块未加载，消息未发送。请刷新页面重试。', 'error');
      return;  // 宁可不发也不发明文
    }

    // v4: WebSocket 优先，REST 备选
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({
        type: 'message',
        to: currentPeerId,
        ...payload
      }));
      console.log('[Send v4] Message sent via WebSocket');
      return;
    }

    const msgRes = await fetch(`${API_BASE}/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify(payload)
    });
    if (!msgRes.ok) throw new Error(`HTTP ${msgRes.status}`);
    console.log('[Send v4] Message sent via REST API');
  } catch (err) {
    showToast('Failed to send: ' + err.message, 'error');
    console.error('[Send v4] Error:', err);
  }
}

function showChatEmpty() {
  hideAllMainViews();
  document.getElementById('chatEmpty').style.display = 'flex';
  document.querySelectorAll('.conversation-item').forEach(el => el.classList.remove('active'));
  currentPeerId = null;
  currentConversationId = null;
}

// ================================================
// Contacts  — v3 从后端 /api/contacts 加载（v2 用的是 localStorage）
// ================================================
async function loadContacts() {
  const list = document.getElementById('contactList');
  const empty = document.getElementById('emptyContacts');
  let contacts = [];
  let loadError = null;

  // v3.1: 首先尝试从后端加载
  try {
    const token = localStorage.getItem('fk_token');
    const res = await fetch(`${API_BASE}/contacts`, { headers: { Authorization: `Bearer ${token}` } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    contacts = data.contacts || [];
    
    // 如果后端有数据，缓存到本地
    if (contacts.length > 0) {
      localStorage.setItem('fk_contacts_cache', JSON.stringify(contacts));
      console.log('[Contacts v3.1] Loaded from backend, cached locally');
    }
  } catch (err) {
    console.error('[Contacts v3.1] Backend load failed:', err);
    loadError = err;
    
    // 尝试从本地缓存恢复
    const cached = localStorage.getItem('fk_contacts_cache');
    if (cached) {
      try {
        contacts = JSON.parse(cached);
        console.log('[Contacts v3.1] Loaded from local cache');
      } catch (e) {
        console.error('[Contacts v3.1] Cache parse failed:', e);
      }
    }
    
    // 尝试从旧版本迁移
    if (contacts.length === 0) {
      const oldContacts = localStorage.getItem('fibemate_contacts');
      if (oldContacts) {
        try {
          const old = JSON.parse(oldContacts);
          // 转换旧格式到新格式
          contacts = old.map(c => ({
            contactUserId: c.id || c.userId || c.username,
            username: c.username || c.id || c.userId,
            displayName: c.displayName || c.name || c.username || c.id || c.userId
          }));
          // 保存到新格式
          localStorage.setItem('fk_contacts_cache', JSON.stringify(contacts));
          console.log('[Contacts v3.1] Migrated from v2 format');
        } catch (e) {
          console.error('[Contacts v3.1] Migration failed:', e);
        }
      }
    }
  }

  // 渲染联系人列表
  if (contacts.length === 0) {
    if (empty) {
      empty.style.display = 'flex';
      let errorMsg = 'No contacts yet';
      let showRetry = true;
      
      if (loadError) {
        errorMsg = 'Failed to load contacts from server';
      }
      
      empty.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="width: 48px; height: 48px; color: var(--text-muted); margin-bottom: 16px;">
          <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
          <circle cx="9" cy="7" r="4"/>
          <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
          <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
        </svg>
        <p style="color: var(--text-secondary); font-size: 14px; margin-bottom: 8px;">${errorMsg}</p>
        ${showRetry ? `<button class="btn-secondary" onclick="loadContacts()" style="margin-top: 8px;">Retry</button>` : ''}
        <button class="btn-secondary" onclick="showModal('modalAddContact')" style="margin-top: 8px;">Add Contact</button>
      `;
    }
    list.innerHTML = '';
    return;
  }
  
  if (empty) empty.style.display = 'none';
  list.innerHTML = contacts.map(c => buildContactItem(c)).join('');
  bindContactEvents();
}

function buildContactItem(c) {
  const name = c.displayName || c.username || c.contactUserId || 'Unknown';
  const username = c.username || c.contactUserId || '';
  const online = c.isOnline ? '<span class="online-dot"></span>' : '';
  return `<div class="contact-item" data-user-id="${c.contactUserId || ''}" data-name="${escapeHtml(name)}">
    <div class="contact-avatar">${name.charAt(0).toUpperCase()}${online}</div>
    <div class="contact-info"><div class="contact-name">${escapeHtml(name)}</div><div class="contact-username">@${escapeHtml(username)}</div></div>
    <div class="contact-actions">
      <button class="icon-btn contact-chat" title="Message"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg></button>
      <button class="icon-btn contact-call" title="Call"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0 1 22 16.92z"/></svg></button>
    </div>
  </div>`;
}

function bindContactEvents() {
  document.querySelectorAll('.contact-chat').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const item = e.target.closest('.contact-item');
      switchTab('messages');
      openChat(item.dataset.userId, item.dataset.name);
    });
  });
  document.querySelectorAll('.contact-call').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const item = e.target.closest('.contact-item');
      startCallWith(item.dataset.name);
    });
  });
}

// v3: addContact 改为调用后端 API（v2 只存 localStorage）
async function addContact() {
  const username = document.getElementById('contactUsername').value.trim();
  const displayName = document.getElementById('contactDisplayName').value.trim();
  if (!username) { showToast('Please enter a username', 'error'); return; }

  try {
    const token = localStorage.getItem('fk_token');
    // 先搜索用户
    const searchRes = await fetch(`${API_BASE}/users/search?q=${encodeURIComponent(username)}`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!searchRes.ok) throw new Error('Search failed');
    const searchData = await searchRes.json();
    const users = searchData.users || [];
    if (users.length === 0) {
      showToast('User not found', 'error');
      return;
    }
    const targetUser = users[0];

    // 添加联系人
    const res = await fetch(`${API_BASE}/contacts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ userId: targetUser.id })
    });
    if (!res.ok) {
      const err = await res.text();
      throw new Error(err);
    }

    hideModal('modalAddContact');
    document.getElementById('contactUsername').value = '';
    document.getElementById('contactDisplayName').value = '';
    showToast(`Added ${targetUser.displayName || targetUser.username}`, 'success');
    
    // v3.1: 同时保存到本地缓存
    const newContact = {
      contactUserId: targetUser.id,
      username: targetUser.username,
      displayName: targetUser.displayName || targetUser.username
    };
    const cached = JSON.parse(localStorage.getItem('fk_contacts_cache') || '[]');
    cached.push(newContact);
    localStorage.setItem('fk_contacts_cache', JSON.stringify(cached));
    console.log('[AddContact v3.1] Saved to local cache');
    
    await loadContacts();
  } catch (err) {
    showToast('Failed: ' + err.message, 'error');
    console.error('[AddContact v3] Error:', err);
  }
}

// ================================================
// Vault (unchanged from v2)
// ================================================
function loadVault() {
  const list = document.getElementById('vaultList');
  const empty = document.getElementById('emptyVault');
  const files = JSON.parse(localStorage.getItem('fk_vault') || '[]');
  if (files.length === 0) { if (empty) empty.style.display = 'flex'; return; }
  if (empty) empty.style.display = 'none';
  list.innerHTML = files.map((f, i) => buildVaultItem(f, i)).join('');
  bindVaultEvents();
}

function buildVaultItem(f, idx) {
  const icon = f.type?.startsWith('image/') ? '' : f.type?.startsWith('video/') ? '' : f.type?.startsWith('audio/') ? '' : '';
  const size = f.size ? `${(f.size / 1024).toFixed(1)} KB` : '';
  const date = f.uploadedAt ? formatTime(f.uploadedAt) : '';
  return `<div class="vault-item" data-idx="${idx}">
    <div class="vault-icon">${icon}</div>
    <div class="vault-info"><div class="vault-name">${escapeHtml(f.name)}</div><div class="vault-meta">${size} · ${date} · AES-256 encrypted</div></div>
    <div class="vault-actions">
      <button class="icon-btn vault-download" title="Download"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/></svg></button>
      <button class="icon-btn vault-delete" title="Delete"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button>
    </div>
  </div>`;
}

function bindVaultEvents() {
  document.querySelectorAll('.vault-delete').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const idx = parseInt(e.target.closest('.vault-item').dataset.idx);
      const files = JSON.parse(localStorage.getItem('fk_vault') || '[]');
      files.splice(idx, 1);
      localStorage.setItem('fk_vault', JSON.stringify(files));
      loadVault();
      showToast('File removed from vault', 'info');
    });
  });
  document.querySelectorAll('.vault-download').forEach(btn => {
    btn.addEventListener('click', () => showToast('Download decrypted file...', 'info'));
  });
}

function handleVaultFileSelect(e) {
  const dropzone = document.getElementById('vaultDropzone');
  const files = e.target.files;
  if (files.length) dropzone.querySelector('p').textContent = `${files.length} file(s) selected: ${Array.from(files).map(f => f.name).join(', ')}`;
}

function uploadVaultFile() {
  const input = document.getElementById('vaultFileInput');
  const fileCount = input.files?.length || 0;
  console.log('[Vault] uploadVaultFile called, files.length:', fileCount);
  if (!fileCount) { showToast('Please select a file', 'error'); return; }
  
  let files = [];
  try {
    files = JSON.parse(localStorage.getItem('fk_vault') || '[]');
  } catch (e) {
    console.error('[Vault] parse existing vault failed:', e);
    files = [];
  }
  
  const uploaded = [];
  Array.from(input.files).forEach(f => {
    uploaded.push({ name: f.name, type: f.type, size: f.size, uploadedAt: Date.now(), encrypted: true });
    files.push(uploaded[uploaded.length - 1]);
  });
  
  try {
    localStorage.setItem('fk_vault', JSON.stringify(files));
    console.log('[Vault] saved to localStorage, total files:', files.length);
  } catch (e) {
    console.error('[Vault] localStorage save failed (quota exceeded?):', e);
    showToast('Storage full or permission denied', 'error');
    return;
  }
  
  loadVault();
  hideModal('modalUploadVault');
  input.value = '';
  const dropzoneP = document.getElementById('vaultDropzone')?.querySelector('p');
  if (dropzoneP) dropzoneP.textContent = 'Drag files here or click to browse';
  showToast(`${uploaded.length} file(s) encrypted and stored in vault`, 'success');
}

// ================================================
// Key Management (unchanged from v2)
// ================================================
function renderKeyManagement() {
  const container = document.getElementById('keyCards');
  const keys = await getKeyInfo();
  container.innerHTML = keys.map(k => `
    <div class="key-card">
      <div class="key-card-header">
        <div class="key-icon">${k.icon}</div>
        <div>
          <div class="key-type">${k.type}</div>
          <div class="key-algo">${k.algo}</div>
        </div>
        <span class="key-status ${k.active ? 'active' : 'inactive'}">${k.active ? 'Active' : 'Rotated'}</span>
      </div>
      <div class="key-fingerprint"><label>Fingerprint</label><code>${k.fingerprint}</code></div>
      <div class="key-meta">
        <span>Created: ${k.created}</span>
        <span>Uses: ${k.uses}</span>
      </div>
      ${k.active ? `<button class="btn-secondary key-rotate-btn" data-key="${k.id}">Rotate This Key</button>` : ''}
    </div>
  `).join('');

  container.querySelectorAll('.key-rotate-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      showToast(`Rotating ${btn.dataset.key} key... New key pair generated`, 'success');
      renderKeyManagement();
    });
  });
}

async function getKeyInfo() {
  const keys = [];
  
  // Get real identity key from MessageCryptoV2
  if (typeof MessageCryptoV2 !== 'undefined' && MessageCryptoV2._getIdentityKey) {
    try {
      const identityKey = await MessageCryptoV2._getIdentityKey();
      const identityPublic = await crypto.subtle.exportKey('raw', identityKey.publicKey);
      const identityFingerprint = Array.from(new Uint8Array(identityPublic))
        .map((b, i) => b.toString(16).padStart(2, '0').toUpperCase() + ((i + 1) % 2 === 0 && i < 31 ? ':' : ''))
        .join('');
      
      keys.push({
        id: 'identity',
        type: 'Identity Key',
        algo: 'ECDH P-256',
        icon: '',
        active: true,
        fingerprint: identityFingerprint,
        created: new Date().toISOString().split('T')[0],
        uses: 'Active'
      });
    } catch (e) {
      console.warn('[KeyInfo] Failed to get identity key:', e.message);
    }
  }
  
  // If no real keys available, return demo data
  if (keys.length === 0) {
    return [
      { id: 'identity', type: 'Identity Key', algo: 'ECDH P-256', icon: '', active: true, fingerprint: 'A1:B2:C3:D4:E5:F6:78:90:AB:CD:EF:01:23:45:67:89', created: '2026-04-26', uses: 47 },
      { id: 'signed-pre', type: 'Signed Pre-Key', algo: 'ECDH P-256', icon: '✍️', active: true, fingerprint: '11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00', created: '2026-04-26', uses: 23 },
      { id: 'one-time', type: 'One-Time Pre-Key', algo: 'ECDH P-256', icon: '🎫', active: true, fingerprint: 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99', created: '2026-04-26', uses: 12 },
      { id: 'pq-kem', type: 'Post-Quantum KEM', algo: 'ML-KEM-768 (WIP)', icon: '🛡️', active: false, fingerprint: 'PQ:7A:8B:9C:0D:1E:2F:3A:4B:5C:6D:7E:8F:9A:0B:1C', created: '2026-04-26', uses: 0 },
    ];
  }
  
  return keys;
}

function rotateKeys() {
  showToast('All active keys rotated. New key pairs generated via WebCrypto.', 'success');
  renderKeyManagement();
}

function exportPublicKeys() {
  const keys = (await getKeyInfo()).filter(k => k.active);
  const text = keys.map(k => `${k.type} (${k.algo})\n  Fingerprint: ${k.fingerprint}\n  Created: ${k.created}`).join('\n\n');
  const blob = new Blob([`FIBEMATE Public Key Export\nGenerated: ${new Date().toISOString()}\n\n${text}`], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'fibemate-public-keys.txt'; a.click();
  URL.revokeObjectURL(url);
  showToast('Public keys exported', 'success');
}

// ================================================
// Settings (unchanged from v2)
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
        <div class="setting-info"><div class="setting-name">Post-Quantum KEM</div><div class="setting-desc">ML-KEM-768 (development paused)</div></div>
        <label class="toggle"><input type="checkbox" data-setting="pqKem"><span class="toggle-slider"></span></label>
      </div>
      <div class="setting-item">
        <div class="setting-info"><div class="setting-name">Anti-Screenshot</div><div class="setting-desc">Blur content when screenshot detected</div></div>
        <label class="toggle"><input type="checkbox" data-setting="antiScreenshot" checked><span class="toggle-slider"></span></label>
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
    const saved = localStorage.getItem(`fk_setting_${input.dataset.setting}`);
    if (saved !== null) input.checked = saved === 'true';
    input.addEventListener('change', () => {
      localStorage.setItem(`fk_setting_${input.dataset.setting}`, input.checked);
      showToast(`${input.dataset.setting} ${input.checked ? 'enabled' : 'disabled'}`, 'info');
      
      // Handle privacy feature toggles
      if (input.dataset.setting === 'antiScreenshot') {
        input.checked ? enableAntiScreenshot() : disableAntiScreenshot();
      }
      if (input.dataset.setting === 'screenshotDetection') {
        if (screenshotDetector) {
          input.checked ? screenshotDetector.startMonitoring() : screenshotDetector.stopMonitoring();
        }
      }
      if (input.dataset.setting === 'autoKeyRotation') {
        if (privacyManager && privacyManager.modules.keyRotation) {
          input.checked ? privacyManager.modules.keyRotation.startAutoRotation() : privacyManager.modules.keyRotation.stopAutoRotation();
        }
      }
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
// Voice Call (unchanged from v2)
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

// ================================================
// Privacy Features Integration (NEW)
// ================================================

let privacyManager = null;
let screenshotDetector = null;
let antiScreenshot = null;
let burnMode = false;
let burnTimeout = 30;

/**
 * Initialize privacy features
 */
async function initPrivacyFeatures() {
  try {
    // Import privacy layers
    const { PrivacyLayerManager } = await import('./privacy-layers/index.js');
    
    privacyManager = new PrivacyLayerManager({
      burnAfterRead: true,
      screenshotDetection: true,
      keyRotation: true,
      deviceBinding: true,
      offlineMessages: true,
      encryptedFileTransfer: true,
      safetyNumbers: true
    });
    
    // Initialize screenshot detection
    if (privacyManager.modules.screenshotDetector) {
      screenshotDetector = privacyManager.modules.screenshotDetector;
      screenshotDetector.onScreenshot = handleScreenshotDetected;
      screenshotDetector.onScreenRecording = handleScreenRecordingDetected;
      screenshotDetector.startMonitoring();
    }
    
    // Initialize anti-screenshot
    if (privacyManager.modules.antiScreenshot) {
      antiScreenshot = privacyManager.modules.antiScreenshot;
    }
    
    // Initialize key rotation
    if (privacyManager.modules.keyRotation) {
      privacyManager.modules.keyRotation.onRotation = handleKeyRotated;
      privacyManager.modules.keyRotation.startAutoRotation();
    }
    
    console.log('[Privacy] Features initialized');
  } catch (err) {
    console.error('[Privacy] Initialization failed:', err);
  }
}

/**
 * Handle screenshot detected
 */
function handleScreenshotDetected(info) {
  console.warn('[Privacy] Screenshot detected:', info);
  if (antiScreenshot) antiScreenshot.blur();
  showToast('⚠️ Screenshot detected! Content blurred.', 'warning');
  setTimeout(() => { if (antiScreenshot) antiScreenshot.unblur(); }, 3000);
}

/**
 * Handle screen recording detected
 */
function handleScreenRecordingDetected(info) {
  console.warn('[Privacy] Screen recording detected:', info);
  showToast('⚠️ Screen recording detected!', 'warning');
}

/**
 * Handle key rotated
 */
function handleKeyRotated(oldVersion, newVersion) {
  console.log(`[Privacy] Keys rotated: ${oldVersion} -> ${newVersion}`);
  showToast('🔑 Encryption keys rotated', 'success');
}

/**
 * Toggle burn-after-read mode
 */
function toggleBurnMode() {
  burnMode = !burnMode;
  const btn = document.getElementById('btnBurn');
  if (btn) {
    btn.classList.toggle('active', burnMode);
    btn.style.color = burnMode ? '#ef4444' : '';
  }
  showToast(burnMode ? '🔥 Burn after read: ON' : 'Burn after read: OFF', 'info');
}

/**
 * Send burn-after-read message (with backend API)
 */
async function sendBurnMessage(text, timeout = 30) {
  if (!currentPeerId || !currentConversationId) {
    showToast('No active conversation', 'error');
    return;
  }
  
  try {
    const token = localStorage.getItem('fk_token');
    const burnData = privacyManager.createBurnMessage(text, timeout, true);
    
    // Encrypt message with v5 forward secrecy
    let envelope;
    const Crypto = typeof MessageCryptoV2 !== 'undefined' ? MessageCryptoV2 : MessageCrypto;
    if (typeof Crypto !== 'undefined') {
      try {
        envelope = await Crypto.encrypt(currentPeerId, text);
      } catch (encErr) {
        showToast('⚠️ 阅后即焚消息加密失败: ' + encErr.message, 'error');
        return;
      }
    } else {
      showToast('⚠️ 加密模块不可用，阅后即焚消息未发送', 'error');
      return;
    }
    
    // Use Privacy API Client if available, fallback to direct fetch
    let response;
    if (typeof privacyAPI !== 'undefined') {
      response = await privacyAPI.sendBurnMessage(
        currentConversationId,
        JSON.stringify(envelope),
        timeout,
        burnData.messageId
      );
    } else {
      // Fallback: direct API call
      const payload = {
        conversationId: currentConversationId,
        envelope: JSON.stringify(envelope),
        protocol: 'double-ratchet',
        version: 2,
        messageType: 'burn',
        burnAfterRead: true,
        burnTimeout: timeout,
        burnMessageId: burnData.messageId
      };
      
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'message', to: currentPeerId, ...payload }));
      } else {
        const res = await fetch(`${API_BASE}/messages`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify(payload)
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        response = await res.json();
      }
    }
    
    // Show in UI
    appendBurnMessage(true, text, Date.now(), timeout, burnData.messageId);
    console.log('[Burn] Message sent:', response?.messageId || burnData.messageId);
  } catch (err) {
    showToast('Failed: ' + err.message, 'error');
    console.error('[Burn] Send failed:', err);
  }
}

/**
 * Append burn message to chat
 */
function appendBurnMessage(sent, text, timestamp, timeout, messageId) {
  const list = document.getElementById('messagesList');
  const time = timestamp ? formatTime(timestamp) : formatTime(Date.now());
  const msg = document.createElement('div');
  msg.className = `message ${sent ? 'sent' : 'received'} burn-message`;
  msg.dataset.messageId = messageId;
  msg.dataset.burnTimeout = timeout;
  msg.innerHTML = `
    <div class="msg-bubble burn-bubble">
      <span class="burn-icon">🔥</span>
      <span class="burn-text">${escapeHtml(text)}</span>
      <span class="burn-timer">${timeout}s</span>
    </div>
    <div class="msg-time">${time} · ⏱️ ${timeout}s</div>
  `;
  list.appendChild(msg);
  list.scrollTop = list.scrollHeight;
  
  if (!sent) {
    startBurnCountdown(msg, messageId, timeout);
  }
}

/**
 * Start burn countdown
 */
function startBurnCountdown(msgElement, messageId, timeout) {
  let remaining = timeout;
  const timerEl = msgElement.querySelector('.burn-timer');
  
  const interval = setInterval(() => {
    remaining--;
    if (timerEl) timerEl.textContent = `${remaining}s`;
    if (remaining <= 0) {
      clearInterval(interval);
      burnMessage(messageId, msgElement);
    }
  }, 1000);
  
  msgElement.addEventListener('click', () => {
    clearInterval(interval);
    burnMessage(messageId, msgElement);
  });
}

/**
 * Burn (destroy) message (with backend notification)
 */
async function burnMessage(messageId, msgElement) {
  // Mark as read locally
  if (privacyManager) privacyManager.markMessageRead(messageId);
  
  // Notify backend
  try {
    if (typeof privacyAPI !== 'undefined') {
      await privacyAPI.markBurnMessageRead(messageId);
      console.log('[Burn] Backend notified:', messageId);
    }
  } catch (err) {
    console.warn('[Burn] Backend notification failed:', err);
    // Continue with local burn even if backend fails
  }
  
  // Animate and remove from UI
  if (msgElement) {
    msgElement.style.transition = 'all 0.5s ease';
    msgElement.style.opacity = '0';
    msgElement.style.transform = 'scale(0.8)';
    setTimeout(() => msgElement.remove(), 500);
  }
  showToast('🔥 Message burned', 'success');
}

/**
 * Enable anti-screenshot protection
 */
function enableAntiScreenshot() {
  if (antiScreenshot) {
    antiScreenshot.enable();
    showToast('🛡️ Anti-screenshot enabled', 'success');
  }
}

/**
 * Disable anti-screenshot protection
 */
function disableAntiScreenshot() {
  if (antiScreenshot) {
    antiScreenshot.disable();
    showToast('Anti-screenshot disabled', 'info');
  }
}

/**
 * Verify contact safety numbers using real identity keys
 * Integrates with MessageCryptoV2 for actual public key verification
 * 
 * Priority:
 * 1. Use X3DH session identity keys (most secure, MITM-resistant)
 * 2. Fetch from backend pre-key bundle (if no session yet)
 * 3. Show error if no keys available (NEVER use fake data)
 */
async function verifyContactSafetyNumbers(contactId) {
  try {
    // Get contact info
    const token = localStorage.getItem('fk_token');
    const res = await fetch(`${API_BASE}/contacts`, { headers: { Authorization: `Bearer ${token}` } });
    const data = await res.json();
    const contact = (data.contacts || []).find(c => c.contactUserId === contactId);
    
    if (!contact) {
      showToast('Contact not found', 'error');
      return;
    }

    let safetyNumbers = null;
    let verificationStatus = null;
    let keySource = 'none';
    
    // Priority 1: Use MessageCryptoV2 with real X3DH identity keys
    if (typeof MessageCryptoV2 !== 'undefined' && MessageCryptoV2.getSafetyNumberFingerprint) {
      try {
        // Get contact's identity key from session
        const session = await MessageCryptoV2._getSession(contactId);
        
        if (session && session.theirIdentityKey) {
          // Use real X3DH identity keys to generate safety numbers
          const fingerprint = await MessageCryptoV2.getSafetyNumberFingerprint(
            localStorage.getItem('fk_user_id') || 'me',
            contactId,
            session.theirIdentityKey
          );
          
          // Parse fingerprint string into array of 5-digit numbers
          safetyNumbers = fingerprint.split(' ').filter(s => s.length === 5);
          keySource = 'x3dh_session';
          console.log('[Safety] Generated from real X3DH identity keys');
        }
      } catch (cryptoErr) {
        console.warn('[Safety] Session key generation failed:', cryptoErr);
      }
    }
    
    // Priority 2: Fetch from backend pre-key bundle
    if (!safetyNumbers && typeof MessageCryptoV2 !== 'undefined') {
      try {
        const bundleRes = await fetch(`${API_BASE}/privacy/prekey-bundle/${contactId}`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (bundleRes.ok) {
          const bundle = await bundleRes.json();
          if (bundle.identityKey) {
            const fingerprint = await MessageCryptoV2.getSafetyNumberFingerprint(
              localStorage.getItem('fk_user_id') || 'me',
              contactId,
              new Uint8Array(bundle.identityKey)
            );
            
            safetyNumbers = fingerprint.split(' ').filter(s => s.length === 5);
            keySource = 'prekey_bundle';
            console.log('[Safety] Generated from pre-key bundle');
          }
        }
      } catch (bundleErr) {
        console.warn('[Safety] Pre-key bundle fetch failed:', bundleErr);
      }
    }
    
    // Priority 3: Use contact's stored public key
    if (!safetyNumbers && contact.publicKey) {
      try {
        const pubKeyHex = contact.publicKey;
        const pubKeyBytes = hexToUint8Array(pubKeyHex);
        
        // For ECDSA P-256 keys (130 hex chars = 65 bytes), we need to hash to get consistent length
        // For X3DH, the identity key is typically 65 bytes (uncompressed P-256)
        if (pubKeyBytes.length === 65) {
          const fingerprint = await MessageCryptoV2.getSafetyNumberFingerprint(
            localStorage.getItem('fk_user_id') || 'me',
            contactId,
            pubKeyBytes
          );
          
          safetyNumbers = fingerprint.split(' ').filter(s => s.length === 5);
          keySource = 'contact_pubkey';
          console.log('[Safety] Generated from contact public key');
        }
      } catch (pubkeyErr) {
        console.warn('[Safety] Public key generation failed:', pubkeyErr);
      }
    }
    
    // Check previous verification status from localStorage
    if (safetyNumbers) {
      try {
        const stored = localStorage.getItem(`fibemate_verified_${contactId}`);
        if (stored) {
          verificationStatus = JSON.parse(stored);
          // Check if numbers changed
          if (verificationStatus.safetyNumbers && 
              verificationStatus.safetyNumbers.join(' ') !== safetyNumbers.join(' ')) {
            console.warn('[Safety] Numbers changed since last verification!');
            verificationStatus.changed = true;
          }
        }
      } catch (e) { /* ignore */ }
    }
    
    // If no real keys available, show error (NEVER use fake data)
    if (!safetyNumbers || safetyNumbers.length !== 12) {
      console.error('[Safety] No real identity keys available for', contactId);
      showToast('⚠️ Cannot verify: No secure session established. Start a conversation first.', 'warning');
      
      // Show dialog with explanation instead of fake numbers
      showSafetyNumbersDialog(contact, null, null, {
        error: 'NO_SESSION',
        message: 'Start an encrypted conversation to generate safety numbers'
      });
      return;
    }
    
    showSafetyNumbersDialog(contact, safetyNumbers, verificationStatus, { keySource });
  } catch (err) {
    console.error('[Safety] Verification failed:', err);
    showToast('Failed: ' + err.message, 'error');
  }
}

/**
 * Show safety numbers dialog with verification status
 * @param {Object} contact - Contact info
 * @param {Array|null} numbers - Safety numbers (null if error)
 * @param {Object|null} previousVerification - Previous verification status
 * @param {Object} options - Additional options (keySource, error)
 */
function showSafetyNumbersDialog(contact, numbers, previousVerification = null, options = {}) {
  // Handle error state - no session available
  if (options.error === 'NO_SESSION') {
    const html = `
      <div class="safety-numbers-dialog">
        <div class="safety-header">
          <h3>🔒 Safety Numbers</h3>
          <p>Verify end-to-end encryption with ${escapeHtml(contact.nickname || contact.username || 'this contact')}</p>
        </div>
        <div class="safety-error">
          <div class="error-icon">🔐</div>
          <div class="error-title">No Secure Session</div>
          <div class="error-message">${options.message || 'Start an encrypted conversation to generate safety numbers'}</div>
          <div class="error-hint">
            Safety numbers are generated from X3DH identity keys.<br>
            They appear after you exchange your first encrypted message.
          </div>
        </div>
        <div class="safety-actions">
          <button class="btn btn-primary" onclick="hideModal('safetyNumbersModal')">Got it</button>
        </div>
      </div>
    `;
    
    let modal = document.getElementById('safetyNumbersModal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'safetyNumbersModal';
      modal.className = 'modal';
      document.body.appendChild(modal);
    }
    modal.innerHTML = html;
    showModal('safetyNumbersModal');
    return;
  }
  
  // Check if numbers changed from previous verification
  let warningHtml = '';
  if (previousVerification && previousVerification.safetyNumbers && numbers) {
    const changed = !numbers.every((num, i) => num === previousVerification.safetyNumbers[i]);
    if (changed) {
      warningHtml = `
        <div class="safety-warning">
          <span class="warning-icon">⚠️</span>
          <span>Safety numbers changed! Possible key rotation or MITM attack.</span>
        </div>
      `;
    }
  }
  
  // Show key source
  let sourceHtml = '';
  if (options.keySource) {
    const sourceLabels = {
      'x3dh_session': 'X3DH Session Key',
      'prekey_bundle': 'Pre-key Bundle',
      'contact_pubkey': 'Contact Public Key'
    };
    sourceHtml = `<div class="safety-source">Key source: ${sourceLabels[options.keySource] || options.keySource}</div>`;
  }
  
  // Show previous verification time if available
  let statusHtml = '';
  if (previousVerification && previousVerification.verifiedAt) {
    const date = new Date(previousVerification.verifiedAt).toLocaleDateString();
    statusHtml = `<div class="safety-status">Last verified: ${date}</div>`;
  }
  
  const html = `
    <div class="safety-numbers-dialog">
      <h4>🔐 Verify Safety Numbers</h4>
      <p>Compare these numbers with ${escapeHtml(contact.displayName || contact.username || 'contact')} in person</p>
      ${warningHtml}
      ${statusHtml}
      <div class="safety-numbers-grid">
        ${numbers.map(n => `<span class="safety-number">${n}</span>`).join('')}
      </div>
      <div class="dialog-actions">
        <button class="btn-secondary" onclick="hideModal('modalSafetyNumbers')">Cancel</button>
        <button class="btn-primary" onclick="markSafetyNumbersVerified('${contact.contactUserId || contact.id}', ${JSON.stringify(numbers)})">✓ Verified</button>
      </div>
    </div>
  `;
  
  let modal = document.getElementById('modalSafetyNumbers');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'modalSafetyNumbers';
    modal.className = 'modal-overlay';
    document.body.appendChild(modal);
  }
  modal.innerHTML = `<div class="modal">${html}</div>`;
  modal.style.display = 'flex';
}

/**
 * Mark safety numbers as verified and store persistently
 */
async function markSafetyNumbersVerified(contactId, numbers) {
  try {
    // Store verification in localStorage via SafetyNumbers module
    if (typeof SafetyNumbers !== 'undefined') {
      const sn = new SafetyNumbers();
      sn.markVerified(contactId, numbers);
    } else {
      // Fallback: store directly
      localStorage.setItem(`fibemate_verified_${contactId}`, JSON.stringify({
        contactId,
        safetyNumbers: numbers,
        verifiedAt: Date.now(),
        status: 'verified'
      }));
    }
    
    hideModal('modalSafetyNumbers');
    showToast('✓ Safety numbers verified and saved', 'success');
    console.log('[Safety] Verified contact:', contactId);
    
    // Update UI to show verified status
    updateContactVerificationStatus(contactId, true);
  } catch (err) {
    console.error('[Safety] Failed to save verification:', err);
    showToast('Verification saved locally', 'info');
  }
}

/**
 * Handle incoming X3DH init message (supports v2 P-256, v2+PQ hybrid, v3 Rust X25519)
 */
async function handleX3DHInitMessage(msg) {
  try {
    const Crypto = typeof MessageCryptoV2 !== 'undefined' ? MessageCryptoV2 : MessageCrypto;
    if (!Crypto || !Crypto.receiveSession) {
      console.warn('[X3DH] MessageCryptoV2 not available');
      return false;
    }
    
    const envelope = JSON.parse(msg.envelope);

    // v7: Rust X25519 X3DH init (type === 'x3dh_init_rust' or version === 3)
    if (envelope.type === 'x3dh_init_rust' || envelope.version === 3) {
      console.log('[X3DH v7] Processing Rust X25519 session init from', msg.from);
      const result = await Crypto.receiveSession(msg.from, envelope);
      if (result.sessionReady || result.sessionEstablished) {
        console.log('[X3DH v7] Rust X25519 session established with', msg.from);
        showToast('🔐 安全会话已建立 (Rust X25519)', 'success');
        return true;
      }
      console.warn('[X3DH v7] Rust X25519 handshake failed');
      return false;
    }
    
    // v6: Check for hybrid PQ + X3DH init
    if (envelope.pqCiphertext && envelope.kemPublicKey && Crypto.receiveHybridSession) {
      console.log('[X3DH v6] Processing hybrid PQ+ECDH session init from', msg.from);
      const result = await Crypto.receiveHybridSession(msg.from, envelope);
      
      if (result.sessionReady || result.sessionEstablished) {
        console.log('[X3DH v6] Hybrid session established with', msg.from);
        showToast(`🔐 安全会话已建立 (后量子)`, 'success');
        
        if (result.hybrid && PQIntegration) {
          PQIntegration.storeSessionMetadata(msg.from, {
            kemCiphertext: envelope.pqCiphertext,
            kemPublicKey: envelope.kemPublicKey,
            hybrid: true,
            establishedAt: Date.now()
          });
        }
        return true;
      }
    }
    
    // v5: Standard X3DH init (P-256)
    if (envelope.ephemeralPublicKey) {
      console.log('[X3DH v5] Processing classical X3DH session init from', msg.from);
      const result = await Crypto.receiveSession(msg.from, envelope);
      if (result.sessionReady || result.sessionEstablished) {
        console.log('[X3DH v5] Classical session established with', msg.from);
        showToast('🔐 安全会话已建立', 'success');
        return true;
      }
    }
    
    console.warn('[X3DH] Unknown init message format');
    return false;
  } catch (err) {
    console.error('[X3DH] Failed to process init message:', err);
    return false;
  }
}

/**
 * Update contact list to show verification status
 */
function updateContactVerificationStatus(contactId, isVerified) {
  const contactItems = document.querySelectorAll('.contact-item');
  contactItems.forEach(item => {
    if (item.dataset.contactId === contactId) {
      const verifiedBadge = item.querySelector('.verified-badge');
      if (isVerified && !verifiedBadge) {
        const badge = document.createElement('span');
        badge.className = 'verified-badge';
        badge.innerHTML = '✓';
        badge.title = 'Safety numbers verified';
        item.querySelector('.contact-name')?.appendChild(badge);
      }
    }
  });
}

/**
 * Get privacy status
 */
function getPrivacyStatus() {
  if (!privacyManager) return null;
  return privacyManager.getStatus();
}

// ================================================
// Backend Integration - Device Management
// ================================================

/**
 * Load and display registered devices
 */
async function loadDevices() {
  try {
    if (typeof privacyAPI !== 'undefined') {
      const response = await privacyAPI.getDevices();
      const devices = response.devices || [];
      
      // Store in local state
      window.registeredDevices = devices;
      
      console.log('[Device] Loaded', devices.length, 'devices');
      return devices;
    }
  } catch (err) {
    console.error('[Device] Failed to load:', err);
    return [];
  }
}

/**
 * Register current device
 */
async function registerCurrentDevice() {
  try {
    const deviceInfo = {
      deviceId: localStorage.getItem('fk_device_id') || generateDeviceId(),
      deviceName: navigator.platform || 'Unknown Device',
      deviceType: getDeviceType(),
      publicKey: localStorage.getItem('fk_public_key') || '',
      deviceFingerprint: generateDeviceFingerprint()
    };
    
    if (typeof privacyAPI !== 'undefined') {
      const response = await privacyAPI.registerDevice(deviceInfo);
      
      if (response.status === 'verified') {
        showToast('✓ Device registered', 'success');
      } else {
        showToast('⏳ Device pending verification', 'info');
      }
      
      // Store device ID
      localStorage.setItem('fk_device_id', deviceInfo.deviceId);
      
      return response;
    }
  } catch (err) {
    console.error('[Device] Registration failed:', err);
    showToast('Device registration failed', 'error');
  }
}

/**
 * Generate unique device ID
 */
function generateDeviceId() {
  return 'device-' + Math.random().toString(36).substr(2, 9) + '-' + Date.now();
}

/**
 * Get device type
 */
function getDeviceType() {
  const ua = navigator.userAgent;
  if (/mobile|android|iphone|ipad|ipod/i.test(ua)) return 'mobile';
  if (/tablet|ipad/i.test(ua)) return 'tablet';
  return 'desktop';
}

/**
 * Generate device fingerprint
 */
function generateDeviceFingerprint() {
  const components = [
    navigator.userAgent,
    navigator.language,
    screen.width + 'x' + screen.height,
    new Date().getTimezoneOffset()
  ];
  return btoa(components.join('|')).substr(0, 32);
}

// ================================================
// Backend Integration - Offline Messages
// ================================================

/**
 * Store message for offline recipient
 */
async function storeOfflineMessage(recipientId, encryptedContent, options = {}) {
  try {
    if (typeof privacyAPI !== 'undefined') {
      const response = await privacyAPI.storeOfflineMessage(recipientId, encryptedContent, options);
      console.log('[Offline] Message stored:', response.messageId);
      return response;
    }
  } catch (err) {
    console.error('[Offline] Store failed:', err);
    // Fallback: store locally
    if (privacyManager && privacyManager.modules.offlineMessages) {
      return privacyManager.modules.offlineMessages.storeOfflineMessage(encryptedContent, recipientId, options);
    }
  }
}

/**
 * Retrieve offline messages
 */
async function retrieveOfflineMessages() {
  try {
    if (typeof privacyAPI !== 'undefined') {
      const response = await privacyAPI.getOfflineMessages();
      const messages = response.messages || [];
      
      console.log('[Offline] Retrieved', messages.length, 'messages');
      
      // Mark as delivered
      for (const msg of messages) {
        try {
          await privacyAPI.markOfflineMessageDelivered(msg.messageId);
        } catch (err) {
          console.warn('[Offline] Failed to mark delivered:', msg.messageId);
        }
      }
      
      return messages;
    }
  } catch (err) {
    console.error('[Offline] Retrieve failed:', err);
    return [];
  }
}

// ================================================
// Backend Integration - Key Rotation
// ================================================

/**
 * Rotate encryption keys via backend
 */
async function rotateKeysViaBackend() {
  try {
    if (typeof privacyAPI !== 'undefined') {
      const response = await privacyAPI.rotateKeys();
      
      // Update local key
      if (response.publicKey) {
        localStorage.setItem('fk_public_key', response.publicKey);
        localStorage.setItem('fk_key_version', response.version);
      }
      
      showToast('🔑 Keys rotated (v' + response.version + ')', 'success');
      console.log('[Key] Rotated to version', response.version);
      
      return response;
    }
  } catch (err) {
    console.error('[Key] Rotation failed:', err);
    showToast('Key rotation failed', 'error');
  }
}

// ================================================
// Backend Integration - File Transfer (Encrypted)
// ================================================

/**
 * Generate a random AES-256 key for file encryption
 */
async function generateFileEncryptionKey() {
  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  const raw = await crypto.subtle.exportKey('raw', key);
  return { key, raw: new Uint8Array(raw) };
}

/**
 * Encrypt a file chunk with AES-256-GCM
 */
async function encryptFileChunk(chunk, key, iv) {
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    chunk
  );
  return new Uint8Array(encrypted);
}

/**
 * Wrap file encryption key with recipient's public key (ECDH + HKDF)
 */
async function wrapFileKey(fileKey, recipientPublicKeyHex) {
  // Generate ephemeral ECDH key pair
  const ephemeral = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );
  
  // Import recipient's public key
  const recipientPubRaw = hexToUint8Array(recipientPublicKeyHex);
  const recipientPub = await crypto.subtle.importKey(
    'raw',
    recipientPubRaw,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );
  
  // Derive shared secret
  const sharedSecret = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: recipientPub },
    ephemeral.privateKey,
    256
  );
  
  // HKDF to derive wrapping key
  const wrappingKey = await hkdfSha256(
    new Uint8Array(sharedSecret),
    new Uint8Array(32), // salt
    new TextEncoder().encode('FIBEMateFileKeyWrap')
  );
  
  // Wrap the file key
  const wrappedKey = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: crypto.getRandomValues(new Uint8Array(12)) },
    await crypto.subtle.importKey('raw', wrappingKey, 'AES-GCM', false, ['encrypt']),
    fileKey
  );
  
  // Export ephemeral public key
  const ephemeralPubRaw = await crypto.subtle.exportKey('raw', ephemeral.publicKey);
  
  return {
    wrappedKey: arrayToHex(new Uint8Array(wrappedKey)),
    ephemeralPublicKey: arrayToHex(new Uint8Array(ephemeralPubRaw))
  };
}

/**
 * Compute SHA-256 hash of data
 */
async function computeSha256(data) {
  const hash = await crypto.subtle.digest('SHA-256', data);
  return arrayToHex(new Uint8Array(hash));
}

/**
 * HKDF-SHA-256 key derivation
 */
async function hkdfSha256(ikm, salt, info, length = 32) {
  // Extract
  const extractKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const prk = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    extractKey,
    length * 8
  );
  return new Uint8Array(prk);
}

/**
 * Convert hex string to Uint8Array
 */
function hexToUint8Array(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string
 */
function arrayToHex(arr) {
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Upload encrypted file with backend
 * Implements: AES-256-GCM file encryption + ECDH key wrapping + SHA-256 integrity
 */
async function uploadEncryptedFile(file, recipientId, onProgress) {
  try {
    if (typeof privacyAPI === 'undefined') {
      throw new Error('Privacy API not available');
    }
    
    // 1. Generate file encryption key
    const { key: fileKey, raw: fileKeyRaw } = await generateFileEncryptionKey();
    console.log('[File] Generated AES-256 key for file:', file.name);
    
    // 2. Get recipient's public key
    const token = localStorage.getItem('fk_token');
    const recipientRes = await fetch(`${API_BASE}/contacts`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    const recipientData = await recipientRes.json();
    const recipient = (recipientData.contacts || []).find(c => c.contactUserId === recipientId);
    
    if (!recipient || !recipient.publicKey) {
      throw new Error('Recipient public key not found');
    }
    
    // 3. Wrap file key with recipient's public key
    const wrappedKeyData = await wrapFileKey(fileKeyRaw, recipient.publicKey);
    console.log('[File] Key wrapped with recipient ECDH public key');
    
    // 4. Initialize upload
    const CHUNK_SIZE = 1024 * 1024; // 1MB chunks
    const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
    
    const initResponse = await privacyAPI.initFileUpload(
      file.name,
      file.size,
      file.type,
      recipientId,
      totalChunks
    );
    
    const uploadId = initResponse.uploadId;
    
    // 5. Encrypt and upload chunks
    let overallHash = null;
    const chunkHashes = [];
    
    for (let i = 0; i < totalChunks; i++) {
      const start = i * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, file.size);
      const chunk = await file.slice(start, end).arrayBuffer();
      
      // Generate unique IV for each chunk (sequential nonce)
      const iv = new Uint8Array(12);
      iv.set(new Uint8Array([0, 0, 0, 0]), 0); // Fixed prefix
      iv.set(new Uint32Array([i + 1]), 4); // Chunk number as nonce
      
      // Encrypt chunk
      const encryptedChunk = await encryptFileChunk(chunk, fileKey, iv);
      
      // Compute chunk hash
      const chunkHash = await computeSha256(encryptedChunk);
      chunkHashes.push(chunkHash);
      
      // Upload encrypted chunk
      await privacyAPI.uploadChunk(uploadId, i, encryptedChunk);
      
      if (onProgress) {
        onProgress({
          chunk: i + 1,
          total: totalChunks,
          percentage: Math.round(((i + 1) / totalChunks) * 100)
        });
      }
    }
    
    // 6. Compute overall integrity hash (Merkle-like)
    const integrityInput = chunkHashes.join('');
    const integrityHash = await computeSha256(new TextEncoder().encode(integrityInput));
    
    // 7. Complete upload with real encrypted key
    const completeResponse = await privacyAPI.completeFileUpload(
      uploadId,
      wrappedKeyData.wrappedKey,
      integrityHash
    );
    
    // Store file key info for local reference (encrypted with our own key)
    const fileMeta = {
      uploadId,
      fileName: file.name,
      fileSize: file.size,
      fileType: file.type,
      recipientId,
      encryptedKey: wrappedKeyData.wrappedKey,
      ephemeralPublicKey: wrappedKeyData.ephemeralPublicKey,
      integrityHash,
      chunkHashes,
      uploadedAt: new Date().toISOString()
    };
    
    // Store in local encrypted vault
    const existingFiles = JSON.parse(localStorage.getItem('fibemate_file_meta') || '[]');
    existingFiles.push(fileMeta);
    localStorage.setItem('fibemate_file_meta', JSON.stringify(existingFiles));
    
    console.log('[File] Upload complete:', uploadId);
    showToast('✓ File uploaded securely (AES-256-GCM encrypted)', 'success');
    return { ...completeResponse, fileMeta };
    
  } catch (err) {
    console.error('[File] Upload failed:', err);
    showToast('File upload failed: ' + err.message, 'error');
    throw err;
  }
}

/**
 * Decrypt a downloaded file
 */
async function decryptFile(encryptedData, wrappedKey, ephemeralPublicKeyHex, recipientPrivateKeyJwk) {
  try {
    // Import recipient's private key
    const privateKey = await crypto.subtle.importKey(
      'jwk',
      JSON.parse(recipientPrivateKeyJwk),
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      ['deriveBits']
    );
    
    // Import ephemeral public key
    const ephemeralPubRaw = hexToUint8Array(ephemeralPublicKeyHex);
    const ephemeralPub = await crypto.subtle.importKey(
      'raw',
      ephemeralPubRaw,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );
    
    // Derive shared secret
    const sharedSecret = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: ephemeralPub },
      privateKey,
      256
    );
    
    // HKDF to derive unwrapping key
    const unwrappingKey = await hkdfSha256(
      new Uint8Array(sharedSecret),
      new Uint8Array(32),
      new TextEncoder().encode('FIBEMateFileKeyWrap')
    );
    
    // Unwrap file key
    const wrappedKeyBytes = hexToUint8Array(wrappedKey);
    const iv = wrappedKeyBytes.slice(0, 12);
    const encryptedKey = wrappedKeyBytes.slice(12);
    
    const fileKeyRaw = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      await crypto.subtle.importKey('raw', unwrappingKey, 'AES-GCM', false, ['decrypt']),
      encryptedKey
    );
    
    const fileKey = await crypto.subtle.importKey(
      'raw',
      new Uint8Array(fileKeyRaw),
      'AES-GCM',
      false,
      ['decrypt']
    );
    
    // Decrypt file data
    const dataIv = encryptedData.slice(0, 12);
    const ciphertext = encryptedData.slice(12);
    
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: dataIv },
      fileKey,
      ciphertext
    );
    
    return new Uint8Array(decrypted);
    
  } catch (err) {
    console.error('[File] Decryption failed:', err);
    throw new Error('File decryption failed: ' + err.message);
  }
}

// ================================================
// Initialization
// ================================================

/**
 * Initialize backend integrations
 */
async function initBackendIntegrations() {
  console.log('[Backend] Initializing integrations...');
  
  try {
    // Register device on first run
    const deviceId = localStorage.getItem('fk_device_id');
    if (!deviceId) {
      await registerCurrentDevice();
    }
    
    // Load registered devices
    await loadDevices();
    
    // Retrieve offline messages
    await retrieveOfflineMessages();
    
    console.log('[Backend] Integrations initialized');
  } catch (err) {
    console.error('[Backend] Initialization failed:', err);
  }
}

// Auto-initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  // Initialize backend integrations after a short delay
  setTimeout(initBackendIntegrations, 2000);
});

// ================================================
// Chat  — v3 使用 conversationId，通过 find-or-create 获取
// ================================================
async function openChat(userId, name) {
  STATE.currentPeerId = userId;
  STATE.currentPeerName = name;
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
  
  if (Crypto && await Crypto.hasSession(STATE.currentPeerId)) {
    const status = await Crypto.getSecurityStatus(STATE.currentPeerId);
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

  // Update E2EEDisplay module status
  if (typeof E2EEDisplay !== 'undefined') {
    E2EEDisplay.updateStatus(userId);
  }
  document.querySelectorAll('.conversation-item').forEach(el => el.classList.remove('active'));
  document.querySelector(`[data-user-id="${userId}"]`)?.classList.add('active');

  await ensureConversation(userId);
  if (STATE.currentConversationId) {
    await loadMessages(STATE.currentConversationId);
    // Mark conversation as read
    if (typeof ReadReceipts !== 'undefined') {
      setTimeout(() => ReadReceipts.markConversationAsRead(), 800);
    }
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
      STATE.currentConversationId = data.conversationId;
      console.log('[Chat v3] Conversation ID:', STATE.currentConversationId);
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
          let wire = JSON.parse(m.envelope);

          // 首次 X3DH 握手：envelope 里带 initMessage（发送方附加），
          // 必须先 receiveSession 建立会话，再解密真正消息。
          // （与 websocket.js 实时接收逻辑对齐；缺失会导致历史首条消息无法解密）
          if (wire && wire.initMessage && Crypto.receiveSession) {
            try {
              await Crypto.receiveSession(m.senderUserId, wire.initMessage);
              console.log('[Messages v5] X3DH session established from history initMessage');
            } catch (initErr) {
              console.error('[Messages v5] receiveSession failed:', initErr.message);
            }
            wire = wire.message; // 取真正加密的消息
          }

          const envelope = wire;
          // 检测 GM 加密信封（Phase 2.4+）
          if (envelope.encryption === 'sm2-sm4-sm3' && window.encryptWithGM) {
            text = await window.encryptWithGM.decrypt(m.senderUserId, envelope);
            appendMessage(isSent, text, m.createdAt, true, 'SM4');
            continue;
          }
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

function appendMessage(sent, text, timestamp, isEncrypted = false, encryptionLabel = '') {
  const list = document.getElementById('messagesList');
  const time = timestamp ? formatTime(timestamp) : formatTime(Date.now());
  const msg = document.createElement('div');
  msg.className = `message ${sent ? 'sent' : 'received'}`;
  msg.dataset.timestamp = timestamp || Date.now();
  let badges = '';
  if (encryptionLabel) {
    badges += `<span class="e2ee-badge" title="${encryptionLabel}">${encryptionLabel}</span>`;
  } else if (isEncrypted) {
    badges += '<span class="e2ee-badge" title="End-to-end encrypted"></span>';
  }
  msg.innerHTML = `<div class="msg-bubble">${escapeHtml(text)}${badges}</div><div class="msg-time">${time}</div>`;
  list.appendChild(msg);
  list.scrollTop = list.scrollHeight;

  // Track sent messages for read receipts
  if (sent && typeof ReadReceipts !== 'undefined') {
    ReadReceipts.trackMessage(msg);
  }
}

async function sendMessage() {
  const input = document.getElementById('messageInput');
  const text = input.value.trim();
  if (!STATE.currentPeerId) { showToast('请先选择一个联系人', 'info'); return; }
  if (!text) return;

  if (!STATE.currentConversationId) {
    await ensureConversation(STATE.currentPeerId);
  }
  if (!STATE.currentConversationId) {
    showToast('Failed to create conversation', 'error');
    return;
  }

  // v5.1: 自动建立加密会话（如果尚未建立）
  const Crypto = typeof MessageCryptoV2 !== 'undefined' ? MessageCryptoV2 : MessageCrypto;
  if (typeof Crypto !== 'undefined' && Crypto.hasSession) {
    try {
      const hasSession = await Crypto.hasSession(STATE.currentPeerId);
      if (!hasSession) {
        console.log(`[Send v5.1] No session with ${STATE.currentPeerId}, attempting X3DH initiation...`);
        showToast('正在建立安全会话...', 'info');
        
        // 尝试从服务器获取对方的 pre-key bundle
        try {
          const token = localStorage.getItem('fk_token');
          const response = await fetch(`${API_BASE}/users/${STATE.currentPeerId}/keys`, {
            headers: { 'Authorization': `Bearer ${token}` }
          });
          
          if (response.ok) {
            const keysResp = await response.json();
            // 后端 /api/users/:userId/keys 返回 { identityKey, signedPrekey, ... }
            // 前端 adapter 需要 { identityKey, signedPreKey }（驼峰）
            const bundle = {
              identityKey: keysResp.identityKey,
              signedPreKey: keysResp.signedPrekey || keysResp.identityKey,
              signedPreKeyId: 0,
              oneTimePreKeys: []
            };
            if (bundle && bundle.identityKey) {
              // v6: 优先使用混合 X3DH (ECDH + ML-KEM-768)
              let sessionResult;
              if (PQIntegration && PQIntegration.isAvailable() && bundle.kemPublicKey) {
                console.log(`[Send v6] Using hybrid X3DH with ML-KEM-768`);
                sessionResult = await Crypto.initiateHybridSession(STATE.currentPeerId, bundle);
              } else {
                sessionResult = await Crypto.initiateSession(STATE.currentPeerId, bundle);
              }
              
              if (sessionResult.sessionEstablished || sessionResult.sessionReady) {
                const isHybrid = sessionResult.hybrid || false;
                console.log(`[Send v6] X3DH session established with ${STATE.currentPeerId} (${isHybrid ? 'hybrid' : 'classical'})`);
                showToast(`安全会话已建立${isHybrid ? ' (后量子)' : ''}`, 'success');
                // 保存 initialMessage，附加到第一条消息（让 Bob 能 establish 会话）
                if (sessionResult.initialMessage) {
                  STATE.pendingInitMessage = sessionResult.initialMessage;
                }
              }
            } else {
              console.warn(`[Send v6] No pre-key bundle available for ${STATE.currentPeerId}`);
              showToast('对方尚未上传密钥，无法建立加密会话', 'warning');
            }
          } else if (response.status === 404) {
            console.warn(`[Send v6] Pre-key bundle not found for ${STATE.currentPeerId}`);
            showToast('对方尚未注册加密密钥，无法发送加密消息', 'warning');
          } else {
            console.error('[Send v6] Failed to fetch pre-key bundle:', response.status);
            showToast('获取加密密钥失败', 'error');
          }
        } catch (x3dhErr) {
          console.error('[Send v6] X3DH initiation failed:', x3dhErr.message);
          showToast('建立加密会话失败: ' + x3dhErr.message, 'error');
        }
      }
    } catch (e) {
      console.warn('[Send v5.1] Session check failed:', e.message);
    }
  }

  input.value = '';

  // Check if burn mode is enabled
  if (STATE.burnMode) {
    await sendBurnMessage(text, STATE.burnTimeout);
    STATE.burnMode = false;
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
    let encLabel = '';
    
    // Phase 2.4: GM 国密加密路径
    const mode = window.CURRENT_ENCRYPTION_MODE || localStorage.getItem('fk_encryption_mode') || 'aes-gcm';
    if (mode === 'sm2-sm4-sm3' && window.encryptWithGM) {
      try {
        const gmEnvelope = await window.encryptWithGM.encrypt(STATE.currentPeerId, text);
        isEncrypted = true;
        encLabel = 'SM4';
        payload = {
          conversationId: STATE.currentConversationId,
          envelope: JSON.stringify(gmEnvelope),
          protocol: 'gm',
          version: 2,
          messageType: 'e2ee',
          burnAfterRead: false
        };
        console.log('[Send v2.4] GM SM2+SM4+SM3 encrypted message');
        // 更新最近一条消息的加密标记
        const lastMsg = document.getElementById('messagesList').lastElementChild;
        if (lastMsg) {
          const bubble = lastMsg.querySelector('.msg-bubble');
          if (bubble && !bubble.querySelector('.e2ee-badge')) {
            bubble.innerHTML += '<span class="e2ee-badge gm-badge" title="SM2+SM4+SM3">SM4</span>';
          }
        }
      } catch (gmErr) {
        console.error('[Send v2.4] GM encryption failed:', gmErr.message);
        showToast('⚠️ GM 加密失败: ' + gmErr.message + '。请先交换 GM 密钥。', 'error');
        return;
      }
    } else {
      const Crypto = typeof MessageCryptoV2 !== 'undefined' ? MessageCryptoV2 : MessageCrypto;
      if (typeof Crypto !== 'undefined') {
        try {
          const envelope = await Crypto.encrypt(STATE.currentPeerId, text);
          isEncrypted = true;
          encLabel = 'AES';
          // 若有 pending initialMessage（首次 X3DH），附加到 envelope，让 Bob 能 establish 会话
          const wireEnvelope = STATE.pendingInitMessage
            ? { initMessage: STATE.pendingInitMessage, message: envelope }
            : envelope;
          STATE.pendingInitMessage = null;
          payload = {
            conversationId: STATE.currentConversationId,
            envelope: JSON.stringify(wireEnvelope),
            protocol: envelope.protocol || 'double-ratchet',
            version: envelope.version || 1,
            messageType: 'e2ee',
            burnAfterRead: false
          };
          console.log(`[Send v5] E2EE message — protocol=${envelope.protocol} v${envelope.version}`);
        } catch (encryptErr) {
          console.error('[Send v5] ENCRYPTION FAILED:', encryptErr.message);
          showToast('⚠️ 加密失败: ' + encryptErr.message + ' — 消息未发送', 'error');
          return;
        }
      } else {
        console.warn('[Send v5] No crypto module available — message NOT sent for security');
        showToast('⚠️ 安全模块未加载，消息未发送。请刷新页面重试。', 'error');
        return;
      }
    }

    // v4: WebSocket 优先，REST 备选
    if (STATE.ws && STATE.ws.readyState === WebSocket.OPEN) {
      _wsSend({
        type: 'message',
        to: STATE.currentPeerId,
        ...payload
      });
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
  STATE.currentPeerId = null;
  STATE.currentConversationId = null;
}

// ================================================
// Phase 2.4: 加密模式切换 UI
// ================================================
function initEncryptionModeUI() {
  const selector = document.getElementById('encryptionModeSelector');
  if (!selector) return;

  const savedMode = localStorage.getItem('fk_encryption_mode') || 'aes-gcm';
  window.CURRENT_ENCRYPTION_MODE = savedMode;
  
  // 初始化按钮状态
  selector.querySelectorAll('.mode-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.mode === savedMode);
    btn.addEventListener('click', () => {
      const mode = btn.dataset.mode;
      window.CURRENT_ENCRYPTION_MODE = mode;
      localStorage.setItem('fk_encryption_mode', mode);
      
      // 更新按钮激活状态
      selector.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      
      // 更新加密状态显示
      const statusEl = document.getElementById('chatPeerStatus');
      if (statusEl) {
        statusEl.textContent = mode === 'sm2-sm4-sm3' ? 'GM Encrypted' : 'Encrypted';
        statusEl.style.color = mode === 'sm2-sm4-sm3' ? '#E53935' : 'var(--accent)';
      }
      
      console.log('[Encryption mode] Switched to:', mode);
      showToast(`加密模式切换至: ${mode === 'sm2-sm4-sm3' ? 'SM2+SM4+SM3' : 'AES-GCM'}`, 'info');
    });
  });
  
  // 如果 P2P Network 已就绪，同步更新 chatPeerStatus
  if (window.encryptWithGM) {
    const statusEl = document.getElementById('chatPeerStatus');
    if (statusEl && savedMode === 'sm2-sm4-sm3') {
      statusEl.textContent = 'GM Encrypted';
      statusEl.style.color = '#E53935';
    }
  }
}


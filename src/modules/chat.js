// ================================================
// Chat  — v3 使用 conversationId，通过 find-or-create 获取
// ================================================

// 3.3.13: 会话切换的同步占位。openChat 一进入就调用，确保在
// find-or-create / 握手 / 解密任何 await 完成之前，旧会话的消息已经离开 DOM。
function renderChatPlaceholder(title, detail) {
  const list = document.getElementById('messagesList');
  if (!list) return;
  list.replaceChildren();
  const box = document.createElement('div');
  box.className = 'chat-placeholder';
  const headline = document.createElement('div');
  headline.className = 'chat-placeholder-title';
  headline.textContent = title;
  box.appendChild(headline);
  if (detail) {
    const sub = document.createElement('div');
    sub.className = 'chat-placeholder-detail';
    sub.textContent = detail;
    box.appendChild(sub);
  }
  list.appendChild(box);
  if (list.dataset) list.dataset.conversationId = '';
}

function showChatLoading(name) {
  renderChatPlaceholder('正在加载会话', name ? `与 ${name} 的消息` : '正在连接…');
  const bar = document.getElementById('msgLoadingBar');
  if (bar) bar.style.display = 'block';
}

function showChatUnavailable(name) {
  renderChatPlaceholder('无法打开会话', name ? `暂时无法加载与 ${name} 的会话` : '请稍后重试');
  const bar = document.getElementById('msgLoadingBar');
  if (bar) bar.style.display = 'none';
}

async function openChat(userId, name) {
  STATE.currentPeerId = userId;
  STATE.currentPeerName = name;
  hideAllMainViews();
  document.getElementById('chatWindow').style.display = 'flex';
  document.getElementById('chatPeerName').textContent = name;
  document.getElementById('chatPeerAvatar').textContent = name.charAt(0).toUpperCase();
  // 3.3.13: 切联系人时先清掉上一会话。任何 await（握手状态、find-or-create）
  // 期间都不得把上一个联系人的消息留在新联系人的面板里。
  STATE.currentConversationId = null;
  showChatLoading(name);
  // v5: 显示前向保密状态
  const Crypto = typeof MessageCryptoV2 !== 'undefined' ? MessageCryptoV2 : (typeof MessageCrypto !== 'undefined' ? MessageCrypto : null);
  const e2eeBar = document.getElementById('e2eeStatusBar');
  const e2eeIcon = document.getElementById('e2eeStatusIcon');
  const e2eeText = document.getElementById('e2eeStatusText');
  const e2eeDetail = document.getElementById('e2eeStatusDetail');
  
  try {
  if (Crypto && await Crypto.hasSession(STATE.currentPeerId)) {
    const status = await Crypto.getSecurityStatus(STATE.currentPeerId);
    // 更新旧版状态文本
    document.getElementById('chatPeerStatus').textContent = 'Encrypted';
    document.getElementById('chatPeerStatus').style.color = 'var(--text-secondary)';
    // 显示新版 E2EE 状态栏
    if (e2eeBar) {
      e2eeBar.style.display = 'inline-flex';
      const isPQ = !!(status.hybrid || status.pqMode);
      e2eeBar.className = isPQ ? 'e2ee-status-bar pq' : 'e2ee-status-bar secure';
      e2eeIcon.textContent = isPQ ? '🔐' : '🔒';
      e2eeText.textContent = isPQ ? 'PQ-E2EE' : 'E2EE';
      const sent = Number(status.messagesSent) || 0;
      const received = Number(status.messagesReceived) || 0;
      const msgs = (sent + received) > 0 ? ` · ${sent + received} msgs` : '';
      e2eeDetail.textContent = `${status.curve || 'X25519'}${msgs}`;
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
  } catch (statusErr) {
    // A corrupt/missing session must not abort openChat before ensureConversation.
    console.warn('[Chat] E2EE status unavailable:', statusErr && statusErr.message ? statusErr.message : statusErr);
  }

  // Update E2EEDisplay module status
  if (typeof E2EEDisplay !== 'undefined') {
    E2EEDisplay.updateStatus(userId);
  }
  document.querySelectorAll('.conversation-item').forEach(el => el.classList.remove('active'));
  document.querySelector(`[data-user-id="${userId}"]`)?.classList.add('active');

  const myPeer = userId;
  const cid = await ensureConversation(myPeer);
  // 3.3.12: 守卫——await 期间用户可能已切到别的联系人。
  // 不校验会导致 A 的会话 ID 被拿去加载、并写进 B 的面板（串会话渲染）。
  if (STATE.currentPeerId !== myPeer) return;
  if (!cid) {
    showChatUnavailable(name);
    return;
  }
  STATE.currentConversationId = cid;
  await loadMessages(cid);
  // Mark conversation as read
  if (typeof ReadReceipts !== 'undefined' && STATE.currentPeerId === myPeer) {
    setTimeout(() => ReadReceipts.markConversationAsRead(), 800);
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
      // 3.3.13: 只有仍然停留在该联系人时才写全局 conversationId。
      // 否则 A 的迟到 find-or-create 响应会覆盖 B 的会话 ID。
      if (STATE.currentPeerId === userId) STATE.currentConversationId = data.conversationId;
      console.log('[Chat v3] Conversation ID:', data.conversationId);
      return data.conversationId;
    }
    console.error('[Chat v3] Failed to create conversation:', res.status);
    return null;
  } catch (err) {
    console.error('[Chat v3] Error:', err);
    return null;
  }
}

// v3: 使用 conversationId 加载消息（v2 用的是 peerId）
async function loadMessages(conversationId) {
  const list = document.getElementById('messagesList');
  const _t0 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
  // 3.3.12: 切会话时作废旧请求——abort 旧 fetch，且用 ac 身份比对丢弃迟到响应。
  if (STATE._msgAbort) { try { STATE._msgAbort.abort(); } catch (_) {} }
  const ac = new AbortController();
  STATE._msgAbort = ac;
  // 3.3.13: 只要目标会话和当前已渲染的会话不同，先清空旧会话内容。
  // 这里不能沿用 3.3.12 的「保留旧内容置灰」：切到 B 时旧内容仍然可见，
  // 就是跨会话串台。加载期间显示占位，不再显示 A 的消息。
  if ((list.dataset && list.dataset.conversationId || '') !== conversationId) {
    showChatLoading(STATE.currentPeerName || '');
  }
  const loader = document.getElementById('msgLoadingBar');
  if (loader) loader.style.display = 'block';
  list.classList.add('is-loading');
  const frag = document.createDocumentFragment();
  const divider = document.createElement('div');
  divider.className = 'date-divider';
  divider.innerHTML = '<span>Today</span>';
  frag.appendChild(divider);
  // 3.3.13: 目标容器显式传入（frag），不再用全局可变量做渲染目标。
  // 若用全局目标，两个并发加载会互相覆盖，导致 A 的循环往 B 的 fragment 里写（本身也是一类串会话）。
  const _append = (sent, text, ts, enc, label, id) => appendMessage(sent, text, ts, enc, label, id, frag);
  try {
    const token = localStorage.getItem('fk_token');
    const res = await fetch(`${API_BASE}/conversations/${conversationId}/messages?limit=50`, {
      headers: { Authorization: `Bearer ${token}` },
      signal: ac.signal
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    // 守卫：响应回来时已经不是这个请求 / 不是这个会话 → 整批丢弃
    if (STATE._msgAbort !== ac || STATE.currentConversationId !== conversationId) return;
    const msgs = data.messages || [];
    msgs.sort((a, b) => a.createdAt - b.createdAt);
    for (const m of msgs) {
      if (STATE._msgAbort !== ac || STATE.currentConversationId !== conversationId) return;
      const isSent = m.senderUserId === localStorage.getItem('fk_uid');
      let text;

      // 3.3.10: 历史消息一律不进入实时 DR 会话解密。
      // 旧实现把 50 条历史逐条喂进同一个棘轮会话，消耗/回退 recv chain，
      // 之后到达的实时消息全部落到旧链、被判 duplicate 丢弃（2026-11-22 双机故障根因）。
      if (!isSent) {
        const _hid = m.id || m._id;
        let _cached = null;
        if (_hid) { try { _cached = localStorage.getItem('fibemate_pt_' + _hid); } catch (e) {} }
        _append(false, _cached || '🔒 历史消息（旧会话，无法解密）', m.createdAt, true, '', _hid);
        continue;
      }
      
      // v5: 前向保密解密 — 支持 v2 envelope 和 v1 兼容
      const Crypto = typeof MessageCryptoV2 !== 'undefined' ? MessageCryptoV2 : MessageCrypto;
      if (m.envelope && typeof Crypto !== 'undefined') {
        try {
          let wire = JSON.parse(m.envelope);

          // 首次 X3DH 握手：envelope 里带 initMessage（发送方附加），
          // 必须先 receiveSession 建立会话，再解密真正消息。
          // （与 websocket.js 实时接收逻辑对齐；缺失会导致历史首条消息无法解密）
          if (wire && wire.initMessage && Crypto.receiveSession) {
            // 跳过历史 initMessage——如果已有有效 session（recovery 刚建好的），
            // 防止覆盖导致 AEAD 失败无限循环
            if (typeof Crypto.hasSession === 'function') {
              const has = await Crypto.hasSession(m.senderUserId);
              if (has) {
                console.log('[Messages v5] Skipping receiveSession — valid session exists for ' + m.senderUserId);
                wire = wire.message;
              } else {
                try {
                  await Crypto.receiveSession(m.senderUserId, wire.initMessage);
                  console.log('[Messages v5] X3DH session established from history initMessage');
                } catch (initErr) {
                  console.error('[Messages v5] receiveSession failed:', initErr.message);
                }
                wire = wire.message;
              }
            } else {
              try {
                await Crypto.receiveSession(m.senderUserId, wire.initMessage);
                console.log('[Messages v5] X3DH session established from history initMessage');
              } catch (initErr) {
                console.error('[Messages v5] receiveSession failed:', initErr.message);
              }
              wire = wire.message;
            }
          }

          const envelope = wire;
          // 检测 GM 加密信封（Phase 2.4+）
          if (envelope.encryption === 'sm2-sm4-sm3' && window.encryptWithGM) {
            if (isSent) {
              text = m.content || m.plaintext || '[已发送]';
            } else {
              text = await window.encryptWithGM.decrypt(m.senderUserId, envelope);
              if (text === null) {
                console.debug('[Messages v5] Skipping duplicate GM message:', m.id || m._id);
                continue;
              }
            }
            _append(isSent, text, m.createdAt, true, 'SM4');
            continue;
          }
          if (isSent) {
            // 自己发的消息：DR 会话 key 是对端，不是自己的 userId
            // 优先用后端返回的明文，否则占位显示
            text = m.content || m.plaintext || '[已发送]';
          } else {
            // Short-circuit: 如果这条消息之前已解密失败，不再重试
            const mid = m.id || m._id;
            const failedKey = 'fibemate_df_' + mid;
            if (mid && localStorage.getItem(failedKey)) {
              // 之前已解密失败：不再重试，但仍渲染失败占位（与下方 catch 分支一致）
              _append(false, '⚠️ 解密失败', m.createdAt, true);
              continue;
            }
            text = await Crypto.decrypt(m.senderUserId, envelope);
            // null = duplicate / replay → silently skip this message
            if (text === null) {
              console.debug('[Messages v5] Skipping duplicate message:', mid);
              continue;
            }
          }
        } catch (e) {
          console.error('[Messages v5] Decrypt failed:', e.message);
          // 标记这条消息为解密失败，下次 loadMessages 不再重试
          const mid = m.id || m._id;
          if (mid) {
            try { localStorage.setItem('fibemate_df_' + mid, '1'); } catch (_) {}
          }
          text = isSent ? '[已发送]' : `⚠️ 解密失败: ${e.message}`;
        }
      } else if (m.encryptedContent && typeof MessageCrypto !== 'undefined') {
        try {
          if (isSent) {
            text = m.content || m.plaintext || '[已发送]';
          } else {
            text = await MessageCrypto.decrypt(m.senderUserId, m.encryptedContent);
            if (text === null) {
              console.debug('[Messages v5] Skipping duplicate legacy message:', m.id || m._id);
              continue;
            }
          }
        } catch (e) {
          console.error('[Messages v5] Legacy decrypt failed:', e);
          text = isSent ? '[已发送]' : '[⚠️ 无法解密（旧格式）]';
        }
      } else {
        text = decodeCiphertext(m.ciphertext);
      }
      
      // 标记加密消息（v2 envelope 或 encryptedContent）
      const isEncrypted = !!(m.envelope || m.encryptedContent);
      _append(isSent, text || '[Unable to decrypt]', m.createdAt, isEncrypted, '', m.id || m._id);
    }
    // 守卫通过：一次性替换，避免逐条往可见列表里长（闪动 + 交错渲染）
    list.replaceChildren(frag);
    if (list.dataset) list.dataset.conversationId = conversationId;
    list.scrollTop = list.scrollHeight;
    if (typeof console !== 'undefined') console.debug('[Messages v3] rendered', conversationId, (data.messages || []).length, Math.round(((typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now()) - _t0) + 'ms');
  } catch (err) {
    if (err && err.name === 'AbortError') return;   // 切会话主动取消，静默
    console.error('[Messages v3] Load failed:', err);
    if (STATE.currentConversationId === conversationId) {
      showChatUnavailable(STATE.currentPeerName || '');
    }
  } finally {
    if (STATE._msgAbort === ac) {
      list.classList.remove('is-loading');
      const bar = document.getElementById('msgLoadingBar');
      if (bar) bar.style.display = 'none';
    }
  }
  if (STATE.currentConversationId === conversationId) document.getElementById('messageInput').focus();
}

function appendMessage(sent, text, timestamp, isEncrypted = false, encryptionLabel = '', msgId = '', target = null) {
  // 3.3.13: target 由调用方显式给出；历史加载传 DocumentFragment，实时消息不传（走 #messagesList）。
  const list = target || document.getElementById('messagesList');
  // 3.3.12: 同一条消息可能被离线批次和历史加载各渲染一次，靠 messageId 去重；
  // 顺带把 id 写进 dataset，已读回执靠它认消息（旧实现从未设置，回执永远是空数组）。
  // 用 dataset 遍历比较，不拼 CSS 选择器：messageId 由发送方给出，含引号会让 selector 抛错。
  if (msgId && Array.prototype.some.call(list.querySelectorAll('.message'),
    (el) => el.dataset.messageId === msgId)) return;
  const time = timestamp ? formatTime(timestamp) : formatTime(Date.now());
  const msg = document.createElement('div');
  msg.className = `message ${sent ? 'sent' : 'received'}`;
  if (msgId) msg.dataset.messageId = msgId;
  msg.dataset.timestamp = timestamp || Date.now();
  let badges = '';
  if (encryptionLabel) {
    badges += `<span class="e2ee-badge" title="${encryptionLabel}">${encryptionLabel}</span>`;
  } else if (isEncrypted) {
    badges += '<span class="e2ee-badge" title="End-to-end encrypted"></span>';
  }
  msg.innerHTML = `<div class="msg-bubble">${escapeHtml(text)}${badges}</div><div class="msg-time">${time}</div>`;
  list.appendChild(msg);
  // fragment 没有滚动位置，仅真实列表滚动到底
  if (list.scrollHeight !== undefined && list.id === 'messagesList') list.scrollTop = list.scrollHeight;

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

  const peer = STATE.currentPeerId;
  let conversationId = STATE.currentConversationId;
  if (!conversationId) {
    const cid = await ensureConversation(peer);
    if (STATE.currentPeerId !== peer) return;
    if (!cid) {
      showToast('Failed to create conversation', 'error');
      return;
    }
    conversationId = cid;
    STATE.currentConversationId = cid;
  }

  // v5.1: 自动建立加密会话（如果尚未建立）
  const Crypto = typeof MessageCryptoV2 !== 'undefined' ? MessageCryptoV2 : MessageCrypto;
  if (typeof Crypto !== 'undefined' && Crypto.hasSession) {
    try {
      const hasSession = await Crypto.hasSession(peer);
      if (STATE.currentPeerId !== peer) return;
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
              oneTimePreKeys: [],
              // Hybrid PQ advertisement (if responder uploaded one)
              _hybridKeyId: keysResp.hybridKeyId || null,
              _hybridBundleHex: keysResp.hybridBundleHex || null,
              _hybridMode: keysResp.hybridMode || null
            };
            if (bundle.identityKey) {
              // v7: 优先使用混合 PQ 握手 (X25519 + ML-KEM-768) —— 对方 bundle 携带 hybrid 通告时
              //     走 adapter.initiateHybridSession（真实 PQ 握手）；否则纯 X3DH 降级
              let sessionResult;
              if (bundle._hybridBundleHex) {
                console.log(`[Send v7] Using hybrid PQ handshake (X25519 + ML-KEM-768)`);
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
          conversationId: conversationId,
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
          const envelope = await Crypto.encrypt(peer, text);
          isEncrypted = true;
          encLabel = 'AES';
          // 若有 pending initialMessage（首次 X3DH），附加到 envelope，让 Bob 能 establish 会话
          const wireEnvelope = STATE.pendingInitMessage
            ? { initMessage: STATE.pendingInitMessage, message: envelope }
            : envelope;
          STATE.pendingInitMessage = null;
          payload = {
            conversationId: conversationId,
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
    if (STATE.currentPeerId !== peer) return;

    if (STATE.ws && STATE.ws.readyState === WebSocket.OPEN) {
      _wsSend({
        type: 'message',
        to: peer,
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


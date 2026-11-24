// ================================================
// WebSocket  — v3 改为 ws://localhost:3001/ws
// ================================================

// ════════════════════════════════════════════════════════════════
// 会话自愈：解密失败时自动重建 X3DH 会话，避免永久卡死
// ════════════════════════════════════════════════════════════════
const _recoveryGuard = {};
// A single duplicate frame is normal: reconnects replay the last one. A *streak*
// is not — our receive chain has already advanced past what the peer keeps
// sending, so the two sides have diverged. The tie-break below assumes "the
// initiator notices first"; when the initiator's own chain is healthy it never
// notices anything, so a streak has to be allowed to override the tie-break.
const _dropStreak = {};
const _forcedRebuildGuard = {};
function _noteDrop(peerId) {
  const n = (_dropStreak[peerId] || 0) + 1;
  _dropStreak[peerId] = n;
  return n;
}
function _noteDecryptOk(peerId) {
  _dropStreak[peerId] = 0;
}

// ═══ 3.3.12: 离线批次消费 + 设备级回执 ═══
// 服务端在 WS 认证后把未送达消息放进**单帧** offline_messages；旧客户端只打印
// count 就把 messages 整包丢掉，于是对端离线期间发的消息永远收不到
// （2026-11-24 实测：重放 44 条，客户端 E2EE decrypted 0 条）。
// 消费时必须守住 3.3.10 的教训：历史消息绝不回流实时棘轮。
const _receiptSent = new Set();

// 基线用「该对端最后一条成功解密的消息时间」，不用 getSessionCreatedAt：
// 会话时间戳重启后会丢（3.3.11 实测返回 0），拿它判新旧会把所有离线消息判成历史。
function _lastSeenKey(peerId) { return 'fibemate_lastseen_' + peerId; }
function _lastSeen(peerId) {
  try { return Number(localStorage.getItem(_lastSeenKey(peerId))) || 0; } catch (e) { return 0; }
}
function _noteLastSeen(peerId, createdAt) {
  const t = Number(createdAt) || 0;
  if (!t) return;
  try {
    if (t > _lastSeen(peerId)) localStorage.setItem(_lastSeenKey(peerId), String(t));
  } catch (e) {}
}

function _sendReadReceipt(messageId) {
  if (!messageId || _receiptSent.has(messageId)) return;
  _receiptSent.add(messageId);
  _wsSend({ type: 'read_receipt', messageId });
}

// 3.3.14: real-time messages from a peer whose chat is not open still have to
// advance the ratchet and leave plaintext behind. Otherwise switching back
// hits loadMessages(), which intentionally refuses to decrypt received
// history, and the message is shown as “旧会话，无法解密”. Decrypting only the
// active peer also means the sender sees no progress until the user returns.
async function _cacheInactiveRealTimeMessage(msg, Crypto) {
  const mid = msg.messageId || msg.id;
  if (!mid || !Crypto || !Crypto.decrypt) return;
  if (msg.messageType === 'voice') return; // voice renderer needs the active view
  let wire = null;
  if (msg.envelope) {
    try { wire = JSON.parse(msg.envelope); } catch (e) { return; }
    // The global X3DH block above already consumed initMessage. Decrypt only
    // the actual payload; re-running receiveSession here would double-apply it.
    if (wire && wire.initMessage) wire = wire.message;
  } else if (msg.encryptedContent) {
    wire = msg.encryptedContent;
  }
  if (!wire || typeof wire !== 'object') return;
  try {
    const text = await Crypto.decrypt(msg.from, wire);
    if (typeof text === 'string') {
      localStorage.setItem('fibemate_pt_' + mid, text);
      _noteLastSeen(msg.from, msg.createdAt);
      console.log('[WS v11] cached inactive message');
    }
  } catch (e) {
    // Do not surface a toast while another conversation is focused; the
    // sender can retry and the message remains available in history.
    console.warn('[WS v11] inactive decrypt failed');
  }
}

async function _handleOfflineBatch(list) {
  const Crypto = (typeof MessageCryptoV2 !== 'undefined') ? MessageCryptoV2 : MessageCrypto;
  const myUid = localStorage.getItem('fk_uid');
  let handled = 0;
  for (const m of list) {
    const peerId = m.senderUserId || m.from;
    const mid = m.id || m.messageId;
    if (!peerId || !mid || peerId === myUid) continue;
    handled++;

    let text = null;
    try { text = localStorage.getItem('fibemate_pt_' + mid); } catch (e) {}

    if (text == null && m.envelope && Crypto) {
      const createdAt = Number(m.createdAt) || 0;
      const seen = _lastSeen(peerId);
      const sessionAt = (typeof Crypto.getSessionCreatedAt === 'function')
        ? (Crypto.getSessionCreatedAt(peerId) || 0)
        : 0;
      // 只有确实比「已解过的最后一条」更新的消息才试解；更早的一律当历史，
      // 不碰棘轮（2026-11-22 事故）。没有基线时退到会话时间，二者都无则不试。
      const candidate = seen > 0 ? createdAt > seen : (sessionAt > 0 && createdAt >= sessionAt);
      if (candidate) {
        try {
          let wire = JSON.parse(m.envelope);
          // 离线批次一律不建会话：历史 initMessage 会把接收链带回旧状态（2026-11-22）。
          if (wire && wire.initMessage) wire = wire.message;
          if (wire && typeof wire === 'object') {
            const out = await Crypto.decrypt(peerId, wire);
            if (typeof out === 'string') {
              text = out;
              try { localStorage.setItem('fibemate_pt_' + mid, text); } catch (e) {}
            }
          }
        } catch (e) {
          // 连 e.name 都不带：错误对象来自解密路径，其字段仍可能回填对端内容。
          console.warn('[WS v10] offline decrypt failed');
        }
      }
    }

    // 不是当前窗口的会话就不渲染，等用户打开时由历史加载补上；
    // 但回执必须先发：readBy 是「这台设备已收到」的标记，离线重放按它收敛，
    // 与用户正开哪个会话无关。放在 guard 之后会让其它会话的消息永远重推。
    _sendReadReceipt(mid);
    if (peerId !== STATE.currentPeerId) continue;

    if (text != null) {
      if (m.messageType === 'voice' && typeof VoiceMessage !== 'undefined') {
        VoiceMessage.handleIncomingVoiceMessage(m);
      } else {
        appendMessage(false, text, m.createdAt || Date.now(), true, '', mid);
      }
    } else {
      appendMessage(false, '🔒 离线消息（旧会话，无法解密）', m.createdAt || Date.now(), true, '', mid);
    }
    // 解不开的也回执：再重发依然解不开，只会每次重连把同一批再推一遍。
  }
  if (handled > 0) console.log('[WS v10] offline batch consumed:', handled);
}
async function forceRebuildSession(peerId, conversationId) {
  const now = Date.now();
  if (_forcedRebuildGuard[peerId] && now - _forcedRebuildGuard[peerId] < 15000) return false;
  _forcedRebuildGuard[peerId] = now;
  _dropStreak[peerId] = 0;
  delete _recoveryGuard[peerId]; // a streak outranks the "we just rebuilt" cooldown
  console.warn('[Recovery] drop streak reached 3 — rebuilding unconditionally');
  return await trySessionRecovery(peerId, conversationId);
}
async function trySessionRecovery(peerId, conversationId) {
  const now = Date.now();
  if (_recoveryGuard[peerId] && now - _recoveryGuard[peerId] < 10000) return false;
  _recoveryGuard[peerId] = now;
  try {
    const Crypto = (typeof MessageCryptoV2 !== 'undefined') ? MessageCryptoV2 : MessageCrypto;
    if (!Crypto || !Crypto.initiateSession) return false;
    const token = localStorage.getItem('fk_token');
    const resp = await fetch(`${API_BASE}/users/${peerId}/keys`, { headers: { 'Authorization': 'Bearer ' + token } });
    if (!resp.ok) return false;
    const keys = await resp.json();
    const bundle = {
      identityKey: keys.identityKey,
      signedPreKey: keys.signedPrekey || keys.identityKey,
      signedPreKeyId: keys.signedPrekeyId || 0,
      oneTimePreKeys: [],
      identitySigningKey: keys.identitySigningKey || null,
      signedPreKeySignature: keys.signedPreKeySignature || null,
      // ⚠️ 2026-10-09 修复：recovery 必须走与正常发送相同的协议。
      //    之前缺 hybrid 字段 → recovery 总走 classical → 覆盖掉 hybrid session → 双向失配。
      _hybridKeyId: keys.hybridKeyId || null,
      _hybridBundleHex: keys.hybridBundleHex || null,
      _hybridMode: keys.hybridMode || null
    };
    console.log('[Recovery DEBUG] bundle keys:', Object.keys(bundle).join(','), 'iskType:', typeof bundle.identitySigningKey, 'iskLen:', bundle.identitySigningKey?.length, 'spsType:', typeof bundle.signedPreKeySignature, 'spsLen:', bundle.signedPreKeySignature?.length, 'hybrid:', !!bundle._hybridBundleHex);
    const sr = (bundle._hybridBundleHex && Crypto.initiateHybridSession)
      ? await Crypto.initiateHybridSession(peerId, bundle)
      : await Crypto.initiateSession(peerId, bundle);
    if (!sr || !sr.initialMessage) return false;
    const dummy = await Crypto.encrypt(peerId, '🔄 安全会话已重建');
    const wire = { initMessage: sr.initialMessage, message: dummy };
    _wsSend({
      type: 'message', context: 'recovery',
      to: peerId,
      conversationId: conversationId,
      envelope: JSON.stringify(wire),
      protocol: 'double-ratchet',
      version: 3,
      messageType: 'e2ee',
      burnAfterRead: false,
      sessionRecovery: true
    });
    console.log('[Recovery] Re-established session with ' + peerId);
    return true;
  } catch (err) {
    console.error('[Recovery] failed:', err && err.message ? err.message : err);
    return false;
  }
}

// ════════════════════════════════════════════════════════════════
// 2026-10-09 修复#1：恢复握手单侧化 —— 防「双侧同时 initiate → 交叉握手 → 活锁」
//   约定：fk_uid 字典序小者 = initiator（两端判断确定性一致）；
//   大者只等对方 initiate，10s 内没等到（对方离线/卡住）再兜底自己发起，避免单侧化死锁。
// ════════════════════════════════════════════════════════════════
const _recoveryFallbackTimers = {};
function _iAmRecoveryInitiator(peerId) {
  const myId = localStorage.getItem('fk_uid') || '';
  if (!myId || !peerId) return true; // 信息不全 → 保持旧行为，不阻塞收发
  return myId < peerId;
}
async function maybeRecoverSession(peerId, conversationId) {
  if (_iAmRecoveryInitiator(peerId)) {
    return await trySessionRecovery(peerId, conversationId);
  }
  console.log('[Recovery] waiting for peer to initiate (tie-break: myUid > peerId):', peerId);
  if (_recoveryFallbackTimers[peerId]) return false;
  // Snapshot the session timestamp. hasSession() answers "is there a session
  // object", which is true both before and after a peer re-handshake, so it
  // cannot tell "peer already initiated" from "peer never did" — the exact
  // misjudgement that left the pair deadlocked.
  const CryptoBefore = (typeof MessageCryptoV2 !== 'undefined') ? MessageCryptoV2 : MessageCrypto;
  const createdAtBefore = (CryptoBefore && CryptoBefore.getSessionCreatedAt)
    ? CryptoBefore.getSessionCreatedAt(peerId)
    : 0;
  _recoveryFallbackTimers[peerId] = setTimeout(async () => {
    delete _recoveryFallbackTimers[peerId];
    try {
      const Crypto = (typeof MessageCryptoV2 !== 'undefined') ? MessageCryptoV2 : MessageCrypto;
      const createdAtAfter = (Crypto && Crypto.getSessionCreatedAt)
        ? Crypto.getSessionCreatedAt(peerId)
        : 0;
      if (createdAtAfter > createdAtBefore) {
        console.log('[Recovery] peer re-handshaked (' + createdAtBefore + ' -> ' + createdAtAfter + ') — no fallback needed for', peerId);
        return;
      }
      console.warn('[Recovery] peer did not re-handshake in 10s (createdAt still ' + createdAtAfter + ') — fallback initiate for', peerId);
      await trySessionRecovery(peerId, conversationId);
    } catch (e) { console.warn('[Recovery] fallback failed:', e && e.message ? e.message : e); }
  }, 10000);
  return false;
}

function connectWebSocket() {
  const token = localStorage.getItem('fk_token');
  if (!token) return;
  try {
    // 使用与 API 相同的地址，但协议改为 STATE.ws
    const apiBase = API_BASE.replace(/^http/, 'ws').replace(/\/api$/, '');
    STATE.ws = new WebSocket(`${apiBase}/ws?token=${token}`);
    STATE.ws.binaryType = 'arraybuffer';
    STATE.ws.onopen = () => {
      console.log('[WS v3] Connected to proxy');
      // 后端 WS 认证协议：发送 { type: 'auth', token }（经 WsPadding 混淆）
      if (STATE.ws.readyState === 1) {
        _wsSend({ type: 'auth', token });
      }
      // Re-init WebRTC module in case it was loaded after WS connected
      if (typeof WebRTCModule !== 'undefined') {
        WebRTCModule.init(STATE.ws);
        console.log('[WebRTC] Module initialized');
      }
      // P1: Notify satellite integration of connection
      if (window.satelliteIntegration) {
        window.satelliteIntegration.core.emit('websocketConnected');
      }
    };
    STATE.ws.onclose = (event) => {
      console.log('[WS v3] Connection closed:', event.code, event.reason);
      // P1: Notify satellite integration of disconnection
      if (window.satelliteIntegration) {
        window.satelliteIntegration.core.emit('websocketClose', event);
      }
    };
    STATE.ws.onmessage = async (e) => {
      try {
        const raw = _wsUnpad(e.data);
        if (raw == null) return; // cover traffic 丢弃
        const msg = JSON.parse(raw);
        console.log('[WS v4] Received:', encodeURIComponent(JSON.stringify(msg.type)));

        const Crypto = typeof MessageCryptoV2 !== 'undefined' ? MessageCryptoV2 : MessageCrypto;

        // ═══ 治本：X3DH 握手必须在全局处理，而非仅当前打开窗口 ═══
        // 首条消息可能带 initMessage（发送方附加）。若接收方未打开该聊天窗口，
        // 旧逻辑会忽略 initMessage → 不回传 key_exchange_response →
        // 发起方 confirmSession 永远不来 → recv_public_key 全零 → 后续互发全部乱码。
        if (msg.type === 'new_message') {
          try {
            if (msg.envelope && Crypto && Crypto.receiveSession) {
              const wire = JSON.parse(msg.envelope);
              if (wire && wire.initMessage) {
                const result = await Crypto.receiveSession(msg.from, wire.initMessage);
                if (result && result.responseMessage) {
                  _wsSend({ type: 'key_exchange_response', to: msg.from, responsePayload: { responseMessage: result.responseMessage } });
                  console.log('[WS v8] X3DH session established (global) + response sent');
                }
              }
            }
          } catch (initErr) {
            console.error('[WS v8] Global X3DH receiveSession failed:', encodeURIComponent(JSON.stringify(initErr && initErr.message)));
          }
        }

        if (msg.type === 'new_message' && msg.from === STATE.currentPeerId) {
          // FIX(voice): dispatch BEFORE the text decrypt below. Else the text path consumes
          // the ratchet step and handleIncomingVoiceMessage's own decrypt sees a duplicate
          // → returns null → `if (!audioData) return` → nothing rendered (对面收不到).
          if (msg.messageType === 'voice' && typeof VoiceMessage !== 'undefined') {
            VoiceMessage.handleIncomingVoiceMessage(msg);
            return;
          }
          let text;
          console.log('[WS-DEBUG] msg.from:', msg.from, 'currentPeerId:', STATE.currentPeerId)// v6: 前向保密解密 — 支持 hybrid PQ + v2 envelope + v1 兼容
          if (msg.envelope && typeof Crypto !== 'undefined') {
            // v6 opaque envelope 格式
            try {
              let wire = JSON.parse(msg.envelope);

              // 首次 X3DH 握手：envelope 里带 initMessage（Alice 附加）
              if (wire && wire.initMessage && Crypto.receiveSession) {
                try {
                  await Crypto.receiveSession(msg.from, wire.initMessage);
                } catch (initErr) {
                  console.error('[WS v7] X3DH receiveSession failed:', encodeURIComponent(JSON.stringify(initErr.message)));
                }
                wire = wire.message; // 取真正加密的消息
              }

              const envelope = wire;
              if (!envelope || typeof envelope !== 'object') {
                appendMessage(false, '[空消息]', msg.createdAt || Date.now());
                return;
              }

              // 检测 GM 加密信封（Phase 2.4+）
              if (envelope.encryption === 'sm2-sm4-sm3' && window.encryptWithGM) {
                text = await window.encryptWithGM.decrypt(msg.from, envelope);
                // null = duplicate / replay → silently drop
                if (text === null) {
                  console.debug('[WS v2.4] Skipping duplicate GM message from', msg.from);
                  return;
                }
                console.log('[WS v2.4] GM SM2+SM4+SM3 message decrypted');
                appendMessage(false, text, msg.createdAt || Date.now(), true, 'SM4');
                return;
              }
              
              // Check if this is an X3DH init message (first contact, legacy P-256)
              if (envelope.ephemeralPublicKey && !envelope.ciphertext) {
                // This is a session init message, not an encrypted payload
                const initSuccess = await handleX3DHInitMessage(msg);
                if (initSuccess) {
                  // Don't display init messages in chat
                  return;
                }
              }
              
              text = await Crypto.decrypt(msg.from, envelope);
              // 3.3.10: null = 棘轮判重（旧链）。旧实现静默丢弃，故障永不自愈。
              // 3.3.11: 单次重复属正常（重连会重放最后一帧）；连续重复说明接收链已
              //         越过对端发送点，即两端已分叉。此时不能等 tie-break 的发起方
              //         ——若它自己是健康的一方，它永远不会察觉。
              if (text === null) {
                const streak = _noteDrop(msg.from);
                console.warn('[WS v6] MESSAGE_DROP from', msg.from, '- streak ' + streak + '/3');
                if (streak >= 3) {
                  const rebuilt = await forceRebuildSession(msg.from, msg.conversationId);
                  if (rebuilt) appendMessage(false, '🔄 正在重建安全会话…', Date.now());
                } else {
                  await maybeRecoverSession(msg.from, msg.conversationId);
                }
                return;
              }
              _noteDecryptOk(msg.from);
              _noteLastSeen(msg.from, msg.createdAt);
              {
                const _mid = msg.messageId || msg.id;
                if (_mid) { try { localStorage.setItem('fibemate_pt_' + _mid, text); } catch (e) {} }
                _sendReadReceipt(_mid);
              }
              console.log(`[WS v6] E2EE message decrypted (protocol=${encodeURIComponent(JSON.stringify(envelope.protocol))})`);
            } catch (decryptErr) {
              // 断裂点 #3 修复：不静默降级，明确告警
              console.error('[WS v6] DECRYPT FAILED:', decryptErr && decryptErr.message ? decryptErr.message : decryptErr);
              // recovery guard 期内（刚建过 session），静默忽略——消息是旧 session 加密的
              if (_recoveryGuard[msg.from] && Date.now() - _recoveryGuard[msg.from] < 30000) {
                console.debug('[WS v6] Silently skipping — recovery guard active for', msg.from);
                return;
              }
              const recovered = await maybeRecoverSession(msg.from, msg.conversationId);
              if (recovered) {
                appendMessage(false, '🔄 正在重建安全会话…', Date.now());
                return;
              }
              appendMessage(false, `⚠️ 解密失败\n${decryptErr && decryptErr.message ? decryptErr.message : decryptErr}`, msg.createdAt || Date.now());
              showToast('🔒 安全警告: 消息解密失败', 'error', 8000);
              return;  // 不显示假消息
            }
          } else if (msg.encryptedContent && typeof MessageCrypto !== 'undefined') {
            // v4 兼容格式（旧版客户端）
            try {
              text = await MessageCrypto.decrypt(msg.from, msg.encryptedContent);
              // null = duplicate / replay → silently drop
              if (text === null) {
                console.debug('[WS v5] Skipping duplicate legacy message from', msg.from);
                return;
              }
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

          // Voice message handling
          if (msg.messageType === 'voice' && typeof VoiceMessage !== 'undefined') {
            VoiceMessage.handleIncomingVoiceMessage(msg);
            return;
          }

          appendMessage(false, text || '[Unable to decrypt]', msg.createdAt || Date.now(), true, '', msg.messageId || msg.id);
        } else if (msg.type === 'new_message') {
          // 3.3.14: keep the receive ratchet moving even when another chat is open.
          // loadMessages() deliberately does not decrypt received history, so
          // without this cache the message reappears as “旧会话，无法解密”.
          try {
            await _cacheInactiveRealTimeMessage(msg, Crypto);
          } catch (_) {
            console.warn('[WS v11] inactive cache failed');
          }
          showToast(`New message from ${msg.from}`, 'info');
          loadConversations();
        } else if (msg.type === 'key_exchange_response') {
          // Alice 收到 Bob 的 x3dh_accept_rust → receiveSession (sets peer DR key)
          const Crypto = typeof MessageCryptoV2 !== 'undefined' ? MessageCryptoV2 : MessageCrypto;
          if (Crypto && msg.payload) {
            try {
              const acceptRust = msg.payload.responseMessage || msg.payload;
              if (acceptRust && (acceptRust.type === 'x3dh_accept_rust' || acceptRust.type === 'hybrid_accept_rust')) {
                await Crypto.receiveSession(msg.from, acceptRust);
                console.log('[WS v9] Session confirmed from ' + encodeURIComponent(JSON.stringify(acceptRust.type)) + ' (from ' + encodeURIComponent(JSON.stringify(msg.from)) + ')');
              }
            } catch (e) {
              console.error('[WS v9] receiveSession failed:', encodeURIComponent(JSON.stringify(e.message)));
            }
          }
        } else if (msg.type === 'message_recall') {
          // 消息撤回
          if (typeof MessageRecall !== 'undefined') {
            MessageRecall.handleRemoteRecall(msg);
          }
          document.dispatchEvent(new CustomEvent('ws-message-recall', { detail: msg }));
        } else if (msg.type === 'read_receipt') {
          // 已读回执
          document.dispatchEvent(new CustomEvent('ws-read-receipt', { detail: msg }));
        } else if (msg.type === 'offline_messages') {
          const batch = Array.isArray(msg.messages) ? msg.messages : [];
          // 数量也不打：batch 来自服务端，.length 同样被算作用户可控。
          console.log('[WS v4] Offline messages: consuming batch');
          await _handleOfflineBatch(batch);
        }
      } catch (err) {
        console.error('[WS v4] Parse error:', err);
      }
    };
    STATE.ws.onclose = () => {
      console.log('[WS v3] Disconnected, reconnecting...');
      setTimeout(connectWebSocket, 5000);
    };
    STATE.ws.onerror = (err) => console.error('[WS v3] Error:', err);
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
// WS 流量混淆层（WsPadding）：发送 pad / 接收 unpad
// 与后端 /opt/fibemate-full/src/crypto/ws-padding.js 对齐
// ================================================
function _wsSend(obj) {
  if (!STATE.ws || STATE.ws.readyState !== 1) return false;
  try {
    if (typeof WsPadding !== 'undefined') {
      STATE.ws.send(WsPadding.pad(JSON.stringify(obj)));
    } else {
      STATE.ws.send(JSON.stringify(obj));
    }
    return true;
  } catch (e) {
    console.error('[WS] _wsSend error:', e);
    return false;
  }
}

function _wsUnpad(data) {
  try {
    if (typeof WsPadding !== 'undefined') {
      const buf = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
      const un = WsPadding.unpad(buf);
      if (un.isCover) return null; // cover traffic，丢弃
      return new TextDecoder().decode(un.payload);
    }
    // 无 WsPadding 时按明文处理
    if (data instanceof ArrayBuffer) {
      return new TextDecoder().decode(data);
    }
    return data;
  } catch (e) {
    console.error('[WS] _wsUnpad error:', e);
    return data;
  }
}


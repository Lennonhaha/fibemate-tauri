// ================================================
// WebSocket  — v3 改为 ws://localhost:3001/ws
// ================================================

// ════════════════════════════════════════════════════════════════
// 会话自愈：解密失败时自动重建 X3DH 会话，避免永久卡死
// ════════════════════════════════════════════════════════════════
const _recoveryGuard = {};
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
      signedPreKeyId: 0,
      oneTimePreKeys: []
    };
    const sr = await Crypto.initiateSession(peerId, bundle);
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
      // Initialize WebRTC module
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
        console.log('[WS v4] Received:', msg.type);

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
            console.error('[WS v8] Global X3DH receiveSession failed:', initErr && initErr.message);
          }
        }

        if (msg.type === 'new_message' && msg.from === STATE.currentPeerId) {
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
                  console.error('[WS v7] X3DH receiveSession failed:', initErr.message);
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
              console.log(`[WS v6] E2EE message decrypted (protocol=${envelope.protocol})`);
            } catch (decryptErr) {
              // 断裂点 #3 修复：不静默降级，明确告警
              console.error('[WS v6] DECRYPT FAILED:', decryptErr && decryptErr.message ? decryptErr.message : decryptErr);
              const recovered = await trySessionRecovery(msg.from, msg.conversationId);
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

          appendMessage(false, text || '[Unable to decrypt]', msg.createdAt || Date.now(), true);
        } else if (msg.type === 'new_message') {
          showToast(`New message from ${msg.from}`, 'info');
          loadConversations();
        } else if (msg.type === 'key_exchange_response') {
          // Alice 收到 Bob 的 x3dh_accept_rust → receiveSession (sets peer DR key)
          const Crypto = typeof MessageCryptoV2 !== 'undefined' ? MessageCryptoV2 : MessageCrypto;
          if (Crypto && msg.payload) {
            try {
              const acceptRust = msg.payload.responseMessage || msg.payload;
              if (acceptRust && acceptRust.type === 'x3dh_accept_rust') {
                const result = await Crypto.receiveSession(msg.from, acceptRust);
                console.log('[WS v9] Session confirmed from x3dh_accept_rust (from ' + msg.from + ')');
              }
            } catch (e) {
              console.error('[WS v9] receiveSession failed:', e.message);
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
          console.log('[WS v4] Offline messages:', msg.count);
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


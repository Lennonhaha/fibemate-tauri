// ================================================
// WebSocket  — v3 改为 ws://localhost:3001/ws
// ================================================
function connectWebSocket() {
  const token = localStorage.getItem('fk_token');
  if (!token) return;
  try {
    // 使用与 API 相同的地址，但协议改为 STATE.ws
    const apiBase = API_BASE.replace('http://', 'ws://').replace('/api', '');
    STATE.ws = new WebSocket(`${apiBase}/ws?token=${token}`);
    STATE.ws.onopen = () => {
      console.log('[WS v3] Connected to proxy');
      // Register user for WebRTC signaling
      const username = localStorage.getItem('fk_uname');
      if (username && STATE.ws.readyState === 1) {
        STATE.ws.send(JSON.stringify({ type: 'register', userId: username }));
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
        const msg = JSON.parse(e.data);
        console.log('[WS v4] Received:', msg.type);
        
        if (msg.type === 'new_message' && msg.from === STATE.currentPeerId) {
          let text;
          // v6: 前向保密解密 — 支持 hybrid PQ + v2 envelope + v1 兼容
          const Crypto = typeof MessageCryptoV2 !== 'undefined' ? MessageCryptoV2 : MessageCrypto;
          if (msg.envelope && typeof Crypto !== 'undefined') {
            // v6 opaque envelope 格式
            try {
              const envelope = JSON.parse(msg.envelope);
              
              // 检测 GM 加密信封（Phase 2.4+）
              if (envelope.encryption === 'sm2-sm4-sm3' && window.encryptWithGM) {
                text = await window.encryptWithGM.decrypt(msg.from, envelope);
                console.log('[WS v2.4] GM SM2+SM4+SM3 message decrypted');
                appendMessage(false, text, msg.createdAt || Date.now(), true, 'SM4');
                return;
              }
              
              // Check if this is an X3DH init message (first contact)
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

          // Voice message handling
          if (msg.messageType === 'voice' && typeof VoiceMessage !== 'undefined') {
            VoiceMessage.handleIncomingVoiceMessage(msg);
            return;
          }

          appendMessage(false, text || '[Unable to decrypt]', msg.createdAt || Date.now(), true);
        } else if (msg.type === 'new_message') {
          showToast(`New message from ${msg.from}`, 'info');
          loadConversations();
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


/**
 * FIBEMATE - Main Entry Point (refactored from v3)
 * Loads modular components, initializes application
 */
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
        console.log('[Init v5] Pre-key bundle ready, identity key established');
        // 上传 bundle 到服务器（后端无 /pre-keys 路由，用 /api/auth/update-keys）
        const userId = localStorage.getItem('fk_uid') || localStorage.getItem('fk_uname');
        try {
          const token = localStorage.getItem('fk_token');
          await fetch(`${API_BASE}/auth/update-keys`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
            body: JSON.stringify({
              publicKey: bundle.identityKey,
              // SPK 独立化新字段（Tauri >= 2c3b021）
              identitySigningKey: bundle.identitySigningKey || null,
              signedPreKey: bundle.signedPreKey || bundle.identityKey,
              signedPreKeySignature: bundle.signedPreKeySignature || null,
              // backward compat (server accepts both naming conventions)
              signedPrekey: bundle.signedPreKey || bundle.identityKey,
              prekeySignature: bundle.signedPreKeySignature || ''
            })
          });
          console.log('[Init v5] Pre-key bundle uploaded to server (update-keys)');
        } catch (uploadErr) {
          console.warn('[Init v5] Pre-key upload failed:', uploadErr.message);
        }
        // P1-2: 启动 OPK 自动补充
        MessageCryptoV2.startOPKAutoReplenish();
      }).catch(e => console.warn('[Init v5] Pre-key generation deferred:', e.message));
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
  try { loadVault(); } catch (e) { console.error('[Init] loadVault failed:', e); }
  try { renderKeyManagement(); } catch (e) { console.error('[Init] renderKeyManagement failed:', e); }
  try { renderSettings(); } catch (e) { console.error('[Init] renderSettings failed:', e); }
  bindEvents();
  connectWebSocket();

  // P1: Initialize satellite network adaptation
  initSatelliteAdaptation();

  // P2: Initialize quantum city network
  initQuantumAdaptation();

  // P3: Initialize 5G-A network
  init5GAdaptation();

  // Phase 2.4: 初始化 GM 国密加密 (SM2+SM4+SM3)
  if (typeof MessageGM !== 'undefined' && typeof P2PNetwork !== 'undefined') {
    try {
      const p2p = new P2PNetwork();
      await p2p.init();
      p2p.setEncryptionMode('sm2-sm4-sm3');
      
      const currentUserId = localStorage.getItem('fk_uid') || localStorage.getItem('fk_uname');
      
      // 创建 encryptWithGM 桥接对象（供 chat.js/websocket.js 使用）
      window.encryptWithGM = {
        encrypt: async (peerId, text) => {
          // 自动同步 GM 公钥（如果已交换）
          const peerPub = p2p.getGMPeerPublicKey(peerId);
          if (!peerPub) {
            throw new Error(`No GM public key for ${peerId}. Please exchange GM keys first.`);
          }
          return p2p.encryptMessage(peerId, text);
        },
        decrypt: async (senderId, envelope) => {
          return p2p.decryptMessage(senderId, {
            ciphertext: envelope.ciphertext,
            iv: envelope.iv,
            ephemeralPK: envelope.ephemeralPK,
            wrappedKey: envelope.wrappedKey,
            hmac: envelope.hmac,
            signature: envelope.signature,
            encryption: envelope.encryption
          });
        },
        getMyPublicKey: () => p2p.getGMPublicKey(),
        setPeerKey: (peerId, pubKey) => p2p.setGMPeerPublicKey(peerId, pubKey),
        // 暴露 p2p 实例供密钥交换 UI 使用
        _p2p: p2p
      };
      console.log('[Init v2.4] GM encryption bridge ready (SM2+SM4+SM3), myPubKey:',
        p2p.getGMPublicKey()?.substring(0, 20) + '...');
    } catch (e) {
      console.warn('[Init v2.4] GM encryption bridge init failed:', e.message);
    }
  } else {
    console.warn('[Init v2.4] GM modules not loaded (MessageGM/P2PNetwork missing)');
  }

  // 初始化加密模式选择器 UI
  if (typeof initEncryptionModeUI === 'function') {
    initEncryptionModeUI();
  }

  // Voice Message Module
  if (typeof VoiceMessage !== 'undefined') {
    VoiceMessage.init();
    console.log('[Main] VoiceMessage initialized');
  }

  // E2EE Status Display
  if (typeof E2EEDisplay !== 'undefined') {
    E2EEDisplay.init();
    console.log('[Main] E2EEDisplay initialized');
  }

  // Mobile Adaptation
  if (typeof MobileAdapt !== 'undefined') {
    MobileAdapt.init();
    console.log('[Main] MobileAdapt initialized');
  }

  // Two-Factor Auth
  if (typeof TwoFactorAuth !== 'undefined') {
    TwoFactorAuth.init();
    console.log('[Main] TwoFactorAuth initialized');
  }

  // Message Recall
  if (typeof MessageRecall !== 'undefined') {
    MessageRecall.init();
    console.log('[Main] MessageRecall initialized');
  }

  // Read Receipts
  if (typeof ReadReceipts !== 'undefined') {
    ReadReceipts.init();
    console.log('[Main] ReadReceipts initialized');
  }

  // Phone Verification
  if (typeof PhoneVerify !== 'undefined') {
    PhoneVerify.init();
    console.log('[Main] PhoneVerify initialized');
  }
});

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
    if (STATE.currentPeerId) {
      verifyContactSafetyNumbers(STATE.currentPeerId);
    } else {
      showToast('Key verification: Compare safety numbers in person', 'info');
    }
  });
  document.getElementById('btnBurn')?.addEventListener('click', toggleBurnMode);
  document.getElementById('searchInput')?.addEventListener('input', (e) => handleSearch(e.target.value));

  document.getElementById('btnAddContact')?.addEventListener('click', () => showModal('modalAddContact'));
  document.getElementById('btnAddContactEmpty')?.addEventListener('click', () => showModal('modalAddContact'));
  document.getElementById('btnConfirmAddContact')?.addEventListener('click', addContactFromInput);
  document.getElementById('contactUsername')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') addContactFromInput(); });

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

  // Voice call (WebRTC)
  document.getElementById('btnVoiceCall')?.addEventListener('click', () => {
    if (!STATE.currentPeerId) {
      showToast('请先选择一个联系人', 'error');
      return;
    }
    if (typeof WebRTCModule !== 'undefined') {
      WebRTCModule.startCall(STATE.currentPeerId, 'voice');
    }
  });
  document.getElementById('btnHangup')?.addEventListener('click', endCall);
  document.getElementById('btnMute')?.addEventListener('click', toggleMute);
  document.getElementById('btnSpeaker')?.addEventListener('click', toggleSpeaker);
  
  // Video call (WebRTC module)
  document.getElementById('btnVideoCall')?.addEventListener('click', () => {
    if (!STATE.currentPeerId) {
      showToast('请先选择一个联系人', 'error');
      return;
    }
    VideoCallUI.showVideoSelectModal();
  });

  // Initialize VideoCallUI with WebRTC callbacks
  if (typeof VideoCallUI !== 'undefined' && typeof WebRTCModule !== 'undefined') {
    VideoCallUI.init({
      onStartCall: (callType) => {
        if (STATE.currentPeerId) {
          WebRTCModule.startCall(STATE.currentPeerId, callType);
        }
      },
      onEndCall: () => {
        WebRTCModule.endCall();
      },
      onAcceptCall: () => {
        WebRTCModule.acceptCall();
      },
      onRejectCall: () => {
        WebRTCModule.rejectCall();
      },
      onToggleVideo: () => {
        WebRTCModule.toggleVideo();
      },
      onToggleMute: () => {
        WebRTCModule.toggleMute();
      }
    });
    console.log('[Init] VideoCallUI initialized with WebRTC');
  }

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
      const modal = btn.dataset.modal;
      if (modal) hideModal(modal);
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
    if (STATE.ws) STATE.ws.close();
    window.location.href = 'index.html';
  }
}

function handleSearch(query) {
  const lower = query.toLowerCase();
  if (STATE.currentTab === 'messages') {
    document.querySelectorAll('.conversation-item').forEach(item => {
      const name = item.dataset.name?.toLowerCase() || '';
      item.style.display = name.includes(lower) ? 'flex' : 'none';
    });
  } else if (STATE.currentTab === 'contacts') {
    document.querySelectorAll('.contact-item').forEach(item => {
      const name = item.dataset.name?.toLowerCase() || '';
      item.style.display = name.includes(lower) ? 'flex' : 'none';
    });
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

// ================================================
// Satellite Network Adaptation (P1)
// ================================================

/**
 * Initialize satellite network adaptation
 * Auto-detects network type and switches to satellite mode when needed
 */
function initSatelliteAdaptation() {
  if (typeof SatelliteIntegration === 'undefined') {
    console.warn('[Satellite] SatelliteIntegration not available');
    return;
  }

  console.log('[Satellite] Initializing satellite network adaptation...');

  // Create mock FIBEMATE core adapter
  const fibemateCore = createSatelliteCoreAdapter();

  // Initialize satellite integration
  const integration = new SatelliteIntegration(fibemateCore, {
    autoDetect: true,   // 自动检测网络类型
    autoSwitch: true,   // 自动切换模式
    debug: true         // 启用调试日志
  });

  integration.init();

  // Store globally for debugging
  window.satelliteIntegration = integration;

  console.log('[Satellite] Satellite adaptation initialized');

  // Show network status in UI
  updateNetworkStatusUI(integration.getStatus());
}

/**
 * Create FIBEMATE core adapter for satellite integration
 */
function createSatelliteCoreAdapter() {
  return {
    // Mixnet hops
    setMixnetHops(hops) {
      console.log(`[Satellite] Mixnet hops set to ${hops}`);
      // TODO: Integrate with actual mixnet configuration
    },

    // FEC
    setFEC(enabled, redundancy) {
      console.log(`[Satellite] FEC ${enabled ? 'enabled' : 'disabled'}${enabled ? ` (${redundancy * 100}%)` : ''}`);
      // TODO: Integrate with actual FEC implementation
    },

    // Heartbeat
    setHeartbeatInterval(interval) {
      if (window.wsManager && window.wsManager.setHeartbeatInterval) {
        window.wsManager.setHeartbeatInterval(interval);
      }
    },

    setHeartbeatTimeout(timeout) {
      if (window.wsManager && window.wsManager.setHeartbeatTimeout) {
        window.wsManager.setHeartbeatTimeout(timeout);
      }
    },

    // Reconnect policy
    setReconnectPolicy(policy) {
      console.log(`[Satellite] Reconnect policy:`, policy);
      // TODO: Integrate with actual reconnect logic
    },

    // Message buffer
    setMessageBufferSize(size) {
      console.log(`[Satellite] Message buffer size: ${size}`);
      // TODO: Integrate with actual message buffer
    },

    // Cover traffic
    setCoverTrafficInterval(interval) {
      console.log(`[Satellite] Cover traffic interval: ${interval}ms`);
      // TODO: Integrate with actual cover traffic
    },

    pauseCoverTraffic() {
      console.log('[Satellite] Cover traffic paused');
      // TODO: Implement
    },

    resumeCoverTraffic() {
      console.log('[Satellite] Cover traffic resumed');
      // TODO: Implement
    },

    // Packet size
    setMaxPacketSize(size) {
      console.log(`[Satellite] Max packet size: ${size}`);
      // TODO: Integrate with actual packet size limit
    },

    // Keep alive
    sendKeepAlive() {
      if (STATE.ws && STATE.ws.readyState === WebSocket.OPEN) {
        STATE.ws.send(JSON.stringify({ type: 'ping' }));
      }
    },

    // Events
    emit(event, data) {
      window.dispatchEvent(new CustomEvent(event, { detail: data }));
    },

    on(event, handler) {
      window.addEventListener(event, (e) => handler(e.detail));
    },

    // Message sending
    sendMessage(msg) {
      if (STATE.ws && STATE.ws.readyState === WebSocket.OPEN) {
        STATE.ws.send(JSON.stringify(msg));
      }
    },

    // WebSocket
    createWebSocket() {
      return connectWebSocket();
    },

    setPacketEncoder(encoder) {
      // TODO: Integrate with actual packet encoding
    },

    setPacketDecoder(decoder) {
      // TODO: Integrate with actual packet decoding
    }
  };
}

/**
 * Update network status in UI
 */
function updateNetworkStatusUI(status) {
  // Create or update network status indicator
  let indicator = document.getElementById('networkStatusIndicator');
  if (!indicator) {
    indicator = document.createElement('div');
    indicator.id = 'networkStatusIndicator';
    indicator.style.cssText = `
      position: fixed;
      top: 10px;
      right: 10px;
      padding: 6px 12px;
      border-radius: 12px;
      font-size: 12px;
      font-weight: 600;
      z-index: 1000;
      transition: all 0.3s ease;
    `;
    document.body.appendChild(indicator);
  }

  const networkType = status.networkType || 'unknown';
  const isSatellite = networkType === 'satellite';

  if (isSatellite) {
    indicator.textContent = '🛰️ 卫星模式';
    indicator.style.background = 'rgba(255, 152, 0, 0.9)';
    indicator.style.color = '#000';
  } else if (networkType === '5g') {
    indicator.textContent = '📶 5G';
    indicator.style.background = 'rgba(0, 229, 195, 0.9)';
    indicator.style.color = '#000';
  } else if (networkType === 'offline') {
    indicator.textContent = '⚠️ 离线';
    indicator.style.background = 'rgba(244, 67, 54, 0.9)';
    indicator.style.color = '#fff';
  } else {
    indicator.textContent = '📡 ' + networkType.toUpperCase();
    indicator.style.background = 'rgba(100, 100, 100, 0.9)';
    indicator.style.color = '#fff';
  }
}

// Listen for network changes
window.addEventListener('networkChanged', (e) => {
  console.log('[Satellite] Network changed:', e.detail);
  updateNetworkStatusUI(e.detail);
});

window.addEventListener('satelliteModeEntered', () => {
  showToast('已进入卫星网络模式', 'info');
});

window.addEventListener('normalModeEntered', () => {
  showToast('已切换到普通网络模式', 'info');
});

// P2: Quantum network events
window.addEventListener('quantumEnabled', () => {
  showToast('量子增强已启用', 'info');
});

window.addEventListener('quantumDisabled', () => {
  showToast('量子增强已禁用', 'info');
});

// Auto-initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  // Initialize backend integrations after a short delay
  setTimeout(initBackendIntegrations, 2000);
});

// ================================================
// P2: Quantum City Network Adaptation
// ================================================

function initQuantumAdaptation() {
  if (typeof QuantumIntegration === 'undefined') {
    console.warn('[Quantum] QuantumIntegration not available');
    return;
  }

  const fibemateCore = createQuantumCoreAdapter();
  const quantum = new QuantumIntegration(fibemateCore, {
    qkdEndpoint: 'http://localhost:8080',  // TODO: Configure actual QKD endpoint
    qrngEndpoint: 'http://localhost:8081', // TODO: Configure actual QRNG endpoint
    autoDetect: true,
    autoEnable: true,
    debug: true
  });

  quantum.init().then(available => {
    if (available) {
      console.log('[Quantum] Quantum city network adaptation initialized');
    } else {
      console.log('[Quantum] Quantum network not available, using classical encryption');
    }
  }).catch(err => {
    console.warn('[Quantum] Initialization failed:', err.message);
  });

  window.quantumIntegration = quantum;
}

function createQuantumCoreAdapter() {
  return {
    emit(event, data) {
      window.dispatchEvent(new CustomEvent(event, { detail: data }));
    },
    
    on(event, callback) {
      window.addEventListener(event, (e) => callback(e.detail));
    }
  };
}

// ================================================
// P3: 5G-A Network Adaptation
// ================================================

function init5GAdaptation() {
  if (typeof FiveGIntegration === 'undefined') {
    console.warn('[5G-A] FiveGIntegration not available');
    return;
  }

  const fibemateCore = create5GCoreAdapter();
  const fiveG = new FiveGIntegration(fibemateCore, {
    edgeEndpoints: [],  // TODO: Configure actual edge endpoints
    autoDetect: true,
    autoEnable: true,
    debug: true
  });

  fiveG.init().then(available => {
    if (available) {
      console.log('[5G-A] 5G-A network adaptation initialized');
    } else {
      console.log('[5G-A] 5G network not available, using normal mode');
    }
  }).catch(err => {
    console.warn('[5G-A] Initialization failed:', err.message);
  });

  window.fiveGIntegration = fiveG;
}

function create5GCoreAdapter() {
  return {
    emit(event, data) {
      window.dispatchEvent(new CustomEvent(event, { detail: data }));
    },
    
    on(event, callback) {
      window.addEventListener(event, (e) => callback(e.detail));
    }
  };
}

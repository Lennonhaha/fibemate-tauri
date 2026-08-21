// ================================================
// Privacy Features Integration (NEW)
// ================================================
// let STATE.privacyManager declaration moved to app-state.js
// let STATE.screenshotDetector declaration moved to app-state.js
// let STATE.antiScreenshot declaration moved to app-state.js
// let STATE.burnMode declaration moved to app-state.js
// let STATE.burnTimeout declaration moved to app-state.js

/**
 * Initialize privacy features
 */
async function initPrivacyFeatures() {
  try {
    // Import privacy layers
    const { PrivacyLayerManager } = await import('./privacy-layers/index.js');
    
    STATE.privacyManager = new PrivacyLayerManager({
      burnAfterRead: true,
      screenshotDetection: true,
      keyRotation: true,
      deviceBinding: true,
      offlineMessages: true,
      encryptedFileTransfer: true,
      safetyNumbers: true
    });
    
    // Initialize screenshot detection
    if (STATE.privacyManager.modules.screenshotDetector) {
      STATE.screenshotDetector = STATE.privacyManager.modules.screenshotDetector;
      STATE.screenshotDetector.onScreenshot = handleScreenshotDetected;
      STATE.screenshotDetector.onScreenRecording = handleScreenRecordingDetected;
      STATE.screenshotDetector.startMonitoring();
    }
    
    // Initialize anti-screenshot
    if (STATE.privacyManager.modules.antiScreenshot) {
      STATE.antiScreenshot = STATE.privacyManager.modules.antiScreenshot;
    }
    
    // Initialize key rotation
    if (STATE.privacyManager.modules.keyRotation) {
      STATE.privacyManager.modules.keyRotation.onRotation = handleKeyRotated;
      STATE.privacyManager.modules.keyRotation.startAutoRotation();
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
  if (STATE.antiScreenshot) STATE.antiScreenshot.blur();
  showToast('⚠️ Screenshot detected! Content blurred.', 'warning');
  setTimeout(() => { if (STATE.antiScreenshot) STATE.antiScreenshot.unblur(); }, 3000);
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
  STATE.burnMode = !STATE.burnMode;
  const btn = document.getElementById('btnBurn');
  if (btn) {
    btn.classList.toggle('active', STATE.burnMode);
    btn.style.color = STATE.burnMode ? '#ef4444' : '';
  }
  showToast(STATE.burnMode ? '🔥 Burn after read: ON' : 'Burn after read: OFF', 'info');
}

/**
 * Send burn-after-read message (with backend API)
 */
async function sendBurnMessage(text, timeout = 30) {
  if (!STATE.currentPeerId || !STATE.currentConversationId) {
    showToast('No active conversation', 'error');
    return;
  }
  
  try {
    const token = localStorage.getItem('fk_token');
    const burnData = STATE.privacyManager.createBurnMessage(text, timeout, true);
    
    // Encrypt message with v5 forward secrecy
    let envelope;
    const Crypto = typeof MessageCryptoV2 !== 'undefined' ? MessageCryptoV2 : MessageCrypto;
    if (typeof Crypto !== 'undefined') {
      try {
        envelope = await Crypto.encrypt(STATE.currentPeerId, text);
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
        STATE.currentConversationId,
        JSON.stringify(envelope),
        timeout,
        burnData.messageId
      );
    } else {
      // Fallback: direct API call
      const payload = {
        conversationId: STATE.currentConversationId,
        envelope: JSON.stringify(envelope),
        protocol: 'double-ratchet',
        version: 2,
        messageType: 'burn',
        burnAfterRead: true,
        burnTimeout: timeout,
        burnMessageId: burnData.messageId
      };
      
      if (STATE.ws && STATE.ws.readyState === WebSocket.OPEN) {
        STATE.ws.send(JSON.stringify({ type: 'message', to: STATE.currentPeerId, ...payload }));
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
  if (STATE.privacyManager) STATE.privacyManager.markMessageRead(messageId);
  
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
  if (STATE.antiScreenshot) {
    STATE.antiScreenshot.enable();
    showToast('🛡️ Anti-screenshot enabled', 'success');
  }
}

/**
 * Disable anti-screenshot protection
 */
function disableAntiScreenshot() {
  if (STATE.antiScreenshot) {
    STATE.antiScreenshot.disable();
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
 * Handle incoming X3DH init message (with PQ hybrid support)
 * Called when receiving a message with x3dhInit or x3dhHybridInit envelope
 */
async function handleX3DHInitMessage(msg) {
  try {
    const Crypto = typeof MessageCryptoV2 !== 'undefined' ? MessageCryptoV2 : MessageCrypto;
    if (!Crypto || !Crypto.receiveSession) {
      console.warn('[X3DH] MessageCryptoV2 not available');
      return false;
    }
    
    const envelope = JSON.parse(msg.envelope);
    
    // v6: Check for hybrid PQ + X3DH init
    if (envelope.pqCiphertext && envelope.kemPublicKey && Crypto.receiveHybridSession) {
      console.log('[X3DH v6] Processing hybrid PQ+ECDH session init from', msg.from);
      const result = await Crypto.receiveHybridSession(msg.from, envelope);
      
      if (result.sessionReady || result.sessionEstablished) {
        console.log('[X3DH v6] Hybrid session established with', msg.from);
        showToast(`🔐 安全会话已建立 (后量子)`, 'success');
        
        // Store PQ metadata
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
    
    // v5: Standard X3DH init
    if (envelope.ephemeralPublicKey) {
      console.log('[X3DH v5] Processing classical X3DH session init from', msg.from);
      const result = await Crypto.receiveSession(msg.from, envelope);
      
      if (result.sessionReady || result.sessionEstablished) {
        console.log('[X3DH v5] Classical session established with', msg.from);
        showToast(`🔐 安全会话已建立`, 'success');
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
  if (!STATE.privacyManager) return null;
  return STATE.privacyManager.getStatus();
}


/**
 * FIBEMATE Privacy Features Integration
 * Integrates new security modules into existing message flow
 */

// Privacy features manager instance
let privacyManager = null;
let screenshotDetector = null;
let antiScreenshot = null;

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
    return true;
  } catch (err) {
    console.error('[Privacy] Initialization failed:', err);
    return false;
  }
}

/**
 * Handle screenshot detected
 */
function handleScreenshotDetected(info) {
  console.warn('[Privacy] Screenshot detected:', info);
  
  // Blur chat content
  if (antiScreenshot) {
    antiScreenshot.blur();
  }
  
  // Show warning toast
  showToast('⚠️ Screenshot detected! Content blurred for security.', 'warning');
  
  // Notify peer if in active chat
  if (currentPeerId && ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({
      type: 'security_alert',
      to: currentPeerId,
      alertType: 'screenshot_detected',
      timestamp: Date.now()
    }));
  }
  
  // Auto-unblur after 3 seconds
  setTimeout(() => {
    if (antiScreenshot) {
      antiScreenshot.unblur();
    }
  }, 3000);
}

/**
 * Handle screen recording detected
 */
function handleScreenRecordingDetected(info) {
  console.warn('[Privacy] Screen recording detected:', info);
  showToast('⚠️ Screen recording detected! Consider enabling anti-screenshot.', 'warning');
}

/**
 * Handle key rotated
 */
function handleKeyRotated(oldVersion, newVersion) {
  console.log(`[Privacy] Keys rotated: ${oldVersion} -> ${newVersion}`);
  showToast('🔑 Encryption keys rotated successfully', 'success');
}

/**
 * Send burn-after-read message
 */
async function sendBurnMessage(text, timeout = 30) {
  if (!currentPeerId) {
    showToast('No active conversation', 'error');
    return;
  }
  
  try {
    const token = localStorage.getItem('fibemate_token');
    
    // Create burn message
    const burnData = privacyManager.createBurnMessage(text, timeout, true);
    
    // Send via API
    const res = await fetch(`${API_BASE}/messages`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json', 
        Authorization: `Bearer ${token}` 
      },
      body: JSON.stringify({
        conversationId: currentConversationId,
        ciphertext: btoa(unescape(encodeURIComponent(text))),
        messageType: 'burn',
        burnAfterRead: true,
        burnTimeout: timeout,
        burnMessageId: burnData.messageId
      })
    });
    
    if (!res.ok) throw new Error('Send failed');
    
    // Show in UI with burn indicator
    appendBurnMessage(true, text, Date.now(), timeout, burnData.messageId);
    
  } catch (err) {
    showToast('Failed to send burn message: ' + err.message, 'error');
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
  
  // Start countdown if received
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
  
  // Also burn on click
  msgElement.addEventListener('click', () => {
    clearInterval(interval);
    burnMessage(messageId, msgElement);
  });
}

/**
 * Burn (destroy) message
 */
function burnMessage(messageId, msgElement) {
  // Mark as read/burned
  if (privacyManager) {
    privacyManager.markMessageRead(messageId);
  }
  
  // Animate and remove
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
 * Verify contact safety numbers
 */
async function verifyContactSafetyNumbers(contactId) {
  try {
    // Get contact's public key
    const contact = await getContact(contactId);
    if (!contact || !contact.publicKey) {
      showToast('Contact public key not found', 'error');
      return;
    }
    
    const userId = localStorage.getItem('fibemate_userId');
    const userKeyPair = await MessageCrypto.getKeyPair();
    
    // Generate safety numbers
    const safetyNumbers = await privacyManager.generateSafetyNumbers(
      userId, userKeyPair.publicKey,
      contactId, contact.publicKey
    );
    
    // Show verification dialog
    showSafetyNumbersDialog(contact, safetyNumbers);
    
  } catch (err) {
    showToast('Failed to generate safety numbers: ' + err.message, 'error');
  }
}

/**
 * Show safety numbers verification dialog
 */
function showSafetyNumbersDialog(contact, safetyNumbers) {
  const numbers = safetyNumbers.numbers;
  const html = `
    <div class="safety-numbers-dialog">
      <h4>🔐 Verify Safety Numbers</h4>
      <p>Compare these numbers with ${contact.name} to verify encryption</p>
      <div class="safety-numbers-grid">
        ${numbers.map(n => `<span class="safety-number">${n}</span>`).join('')}
      </div>
      <p class="safety-numbers-hash">Hash: ${safetyNumbers.hash.substring(0, 16)}...</p>
      <div class="dialog-actions">
        <button class="btn-secondary" onclick="hideModal('modalSafetyNumbers')">Cancel</button>
        <button class="btn-primary" onclick="confirmSafetyNumbers('${contact.userId}')">✓ Verified</button>
      </div>
    </div>
  `;
  
  // Create or update modal
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
 * Confirm safety numbers verified
 */
async function confirmSafetyNumbers(contactId) {
  try {
    await privacyManager.modules.safetyNumbers.markAsVerified(contactId);
    hideModal('modalSafetyNumbers');
    showToast('✓ Safety numbers verified', 'success');
    
    // Update contact UI
    const contactEl = document.querySelector(`[data-user-id="${contactId}"]`);
    if (contactEl) {
      contactEl.classList.add('verified');
    }
  } catch (err) {
    showToast('Verification failed: ' + err.message, 'error');
  }
}

/**
 * Get contact by ID
 */
async function getContact(contactId) {
  const contacts = JSON.parse(localStorage.getItem('fibemate_contacts') || '[]');
  return contacts.find(c => c.userId === contactId);
}

/**
 * Handle incoming security alert
 */
function handleSecurityAlert(alert) {
  switch (alert.alertType) {
    case 'screenshot_detected':
      showToast(`⚠️ ${alert.from || 'Peer'} took a screenshot!`, 'warning');
      break;
    case 'key_changed':
      showToast(`🔑 ${alert.from || 'Peer'}'s key has changed`, 'warning');
      break;
    default:
      console.log('[Security] Alert:', alert);
  }
}

/**
 * Get privacy status for settings UI
 */
function getPrivacyStatus() {
  if (!privacyManager) return null;
  return privacyManager.getStatus();
}

// Export for use in main.js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    initPrivacyFeatures,
    sendBurnMessage,
    enableAntiScreenshot,
    disableAntiScreenshot,
    verifyContactSafetyNumbers,
    handleSecurityAlert,
    getPrivacyStatus
  };
}
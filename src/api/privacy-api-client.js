/**
 * FIBEMATE Privacy API Client
 * Backend integration for all privacy features
 */

// P1 FIX 2026-05-29: Use relative path or configurable hostname instead of hardcoded IP
// In production, nginx reverse-proxies /api to backend, so relative path works.
// For development, set via FIBEMATE_API_BASE env or localStorage
const API_BASE = (typeof window !== 'undefined' && window.FIBEMATE_CONFIG?.apiBase)
  || (typeof window !== 'undefined' && window.__FIBEMATE_CONFIG__?.apiBase)
  || (typeof localStorage !== 'undefined' && localStorage.getItem('fk_api_base'))
  || (typeof localStorage !== 'undefined' && localStorage.getItem('fibemate_api_base'))
  || 'https://fibemate.net/api';

class PrivacyAPIClient {
  constructor() {
    this.baseUrl = API_BASE;
    this.token = localStorage.getItem('fk_token');
  }

  // ================================================
  // Helper Methods
  // ================================================

  getHeaders() {
    return {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${this.token}`
    };
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;
    const config = {
      ...options,
      headers: {
        ...this.getHeaders(),
        ...options.headers
      }
    };

    try {
      const response = await fetch(url, config);
      
      if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.message || `HTTP ${response.status}`);
      }

      return await response.json();
    } catch (err) {
      console.error(`[PrivacyAPI] ${endpoint} failed:`, err);
      throw err;
    }
  }

  // ================================================
  // 1. Burn After Read
  // ================================================

  /**
   * Send a burn-after-read message
   */
  async sendBurnMessage(conversationId, encryptedContent, burnTimeout = 30, burnMessageId) {
    return this.request('/messages', {
      method: 'POST',
      body: JSON.stringify({
        conversationId,
        encryptedContent,
        messageType: 'burn',
        burnAfterRead: true,
        burnTimeout,
        burnMessageId
      })
    });
  }

  /**
   * Mark burn message as read (triggers server-side deletion)
   */
  async markBurnMessageRead(messageId) {
    return this.request(`/messages/burn/${messageId}/read`, {
      method: 'POST'
    });
  }

  /**
   * Get burn message status
   */
  async getBurnMessageStatus(messageId) {
    return this.request(`/messages/burn/${messageId}/status`);
  }

  // ================================================
  // 2. Device Binding
  // ================================================

  /**
   * List registered devices
   */
  async getDevices() {
    return this.request('/devices');
  }

  /**
   * Register a new device
   */
  async registerDevice(deviceInfo) {
    return this.request('/devices/register', {
      method: 'POST',
      body: JSON.stringify(deviceInfo)
    });
  }

  /**
   * Verify a pending device
   */
  async verifyDevice(deviceId, approved, verifierDeviceId) {
    return this.request(`/devices/${deviceId}/verify`, {
      method: 'POST',
      body: JSON.stringify({ approved, verifierDeviceId })
    });
  }

  /**
   * Remove a device
   */
  async removeDevice(deviceId) {
    return this.request(`/devices/${deviceId}`, {
      method: 'DELETE'
    });
  }

  // ================================================
  // 3. Offline Messages
  // ================================================

  /**
   * Store an offline message
   */
  async storeOfflineMessage(recipientId, encryptedContent, options = {}) {
    return this.request('/offline-messages', {
      method: 'POST',
      body: JSON.stringify({
        recipientId,
        encryptedContent,
        messageType: options.messageType || 'text',
        ttl: options.ttl || 3600,
        priority: options.priority || 'normal'
      })
    });
  }

  /**
   * Get offline messages for current user
   */
  async getOfflineMessages() {
    return this.request('/offline-messages');
  }

  /**
   * Mark offline message as delivered
   */
  async markOfflineMessageDelivered(messageId) {
    return this.request(`/offline-messages/${messageId}/delivered`, {
      method: 'POST'
    });
  }

  // ================================================
  // 4. Encrypted File Transfer
  // ================================================

  /**
   * Initialize file upload
   */
  async initFileUpload(filename, fileSize, mimeType, recipientId, totalChunks) {
    return this.request('/files/upload-init', {
      method: 'POST',
      body: JSON.stringify({
        filename,
        fileSize,
        mimeType,
        recipientId,
        totalChunks
      })
    });
  }

  /**
   * Upload a file chunk
   */
  async uploadChunk(uploadId, chunkIndex, chunkData) {
    return this.request(`/files/upload/${uploadId}/chunk/${chunkIndex}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream'
      },
      body: chunkData
    });
  }

  /**
   * Complete file upload
   */
  async completeFileUpload(uploadId, encryptedKey, integrityHash) {
    return this.request(`/files/upload/${uploadId}/complete`, {
      method: 'POST',
      body: JSON.stringify({ encryptedKey, integrityHash })
    });
  }

  /**
   * Download encrypted file
   */
  async downloadFile(fileId) {
    const response = await fetch(`${this.baseUrl}/files/${fileId}/download`, {
      headers: {
        'Authorization': `Bearer ${this.token}`
      }
    });

    if (!response.ok) {
      throw new Error(`Download failed: HTTP ${response.status}`);
    }

    return response.blob();
  }

  // ================================================
  // 5. Safety Numbers
  // ================================================

  /**
   * Get safety numbers for a contact
   */
  async getSafetyNumbers(contactId) {
    return this.request(`/safety-numbers/${contactId}`);
  }

  /**
   * Verify safety numbers for a contact
   */
  async verifySafetyNumbers(contactId, numbers, hash) {
    return this.request(`/safety-numbers/${contactId}/verify`, {
      method: 'POST',
      body: JSON.stringify({ numbers, hash })
    });
  }

  // ================================================
  // 6. Key Rotation
  // ================================================

  /**
   * Rotate encryption keys
   */
  async rotateKeys() {
    return this.request('/keys/rotate', {
      method: 'POST'
    });
  }

  /**
   * Get current encryption key
   */
  async getCurrentKey() {
    return this.request('/keys/current');
  }

  /**
   * Get key rotation history
   */
  async getKeyHistory() {
    return this.request('/keys/history');
  }

  // ================================================
  // 7. X3DH Pre-Key Bundle Management (v2 P-256 + v3 X25519)
  // ================================================
  // Protocol version detection helper
  detectBundleVersion(bundle) {
    if (!bundle || typeof bundle !== 'object') return 0;
    if (bundle.version >= 3 || bundle._rustVersion >= 3) return 3;          // X25519 hex
    if (bundle.version === 2 || bundle.identitySigningKey !== undefined) return 2; // P-256 bytes
    if (typeof bundle.identityKey === 'string' && bundle.identityKey.length === 64) return 3; // Heuristic: 64-char hex = X25519
    if (Array.isArray(bundle.identityKey)) return 2;                          // Byte array = P-256
    return 0;
  }

  /**
   * Upload pre-key bundle to server.
   * Auto-detects version and sends correct format.
   *
   * v2 (P-256):  { identityKey: number[], identitySigningKey: number[], signedPreKey: number[],
   *                  signedPreKeyId: number, signedPreKeySignature: number[], oneTimePreKeys: [...] }
   * v3 (X25519): { version: 3, protocol: 'x25519-double-ratchet', identityKey: "<hex>",
   *                  signedPreKey: "<hex>", signedPreKeyId: number, oneTimePreKeys?: [], kemPublicKey?: "<hex>" }
   */
  async uploadPreKeyBundle(userId, bundle) {
    // 后端无 /pre-keys 路由，映射到 /api/auth/update-keys
    return this.request(`/auth/update-keys`, {
      method: 'POST',
      body: JSON.stringify({
        publicKey: bundle.identityKey,
        signedPrekey: bundle.signedPreKey || bundle.identityKey,
        prekeySignature: bundle.signedPreKeySignature || ''
      })
    });
  }

  /**
   * Fetch pre-key bundle for a peer (to initiate X3DH session).
   * Server consumes one OPK on read (v2 only; v3 uses per-session ephemerals).
   *
   * @returns v2 bundle: { identityKey: number[], identitySigningKey?:, signedPreKey: number[],
   *                       signedPreKeyId, signedPreKeySignature?, oneTimePreKey?, oneTimePreKeyId? }
   * @returns v3 bundle: { version: 3, protocol: 'x25519-double-ratchet', curve: 'x25519',
   *                       identityKey: "<hex>", signedPreKey: "<hex>", signedPreKeyId, kemPublicKey? }
   */
  async fetchPreKeyBundle(userId) {
    // 后端无 /pre-keys 路由，映射到 GET /api/users/:userId/keys
    const keysResp = await this.request(`/users/${userId}/keys`);
    return {
      identityKey: keysResp.identityKey,
      signedPreKey: keysResp.signedPrekey || keysResp.identityKey,
      signedPreKeyId: 0,
      oneTimePreKeys: keysResp.oneTimePreKey ? [keysResp.oneTimePreKey] : [],
      oneTimePreKey: keysResp.oneTimePreKey || null,
      kemPublicKey: keysResp.kemPublicKey || null
    };
  }

  /**
   * Fetch pre-key bundle with version metadata.
   * Convenience wrapper that adds ._apiVersion detection.
   */
  async fetchPreKeyBundleV3(userId) {
    const bundle = await this.fetchPreKeyBundle(userId);
    bundle._apiVersion = this.detectBundleVersion(bundle);
    return bundle;
  }

  /**
   * Get pre-key bundle status (debugging + OPK replenishment check).
   * v3 clients: oneTimePreKeysAvailable is always 0 (no pool needed).
   */
  async getPreKeyBundleStatus(userId) {
    return this.request(`/pre-keys/${userId}/status`);
  }

  /**
   * Replenish one-time pre-keys.
   * v2 (P-256): sends new OPKs to server.
   * v3 (X25519): returns no-op (per-session ephemerals, no pool).
   */
  async replenishOPKs(userId, bundle) {
    const version = this.detectBundleVersion(bundle);
    if (version >= 3) {
      // X25519: OPK pools not needed
      return { userId, version: 3, status: 'ok', oneTimePreKeyCount: 0,
               message: 'X25519 protocol: per-session ephemerals, no OPK pool' };
    }
    return this.request(`/pre-keys/${userId}/replenish`, {
      method: 'POST',
      body: JSON.stringify(bundle)
    });
  }

  /**
   * Send X3DH initial message to peer via server.
   * Supports both v2 (P-256 bytes) and v3 (X25519 hex) initialMessage formats.
   */
  async sendX3DHInit(from, to, initialMessage) {
    const version = initialMessage.version || 2;
    return this.request('/x3dh/init', {
      method: 'POST',
      body: JSON.stringify({ from, to, initialMessage, version,
        protocol: version >= 3 ? 'x25519-double-ratchet' : 'p256-x3dh' })
    });
  }

  /**
   * Poll for pending X3DH init messages (Bob side).
   * Returns both v2 and v3 init messages.
   */
  async getPendingX3DHInit(userId) {
    return this.request(`/x3dh/pending/${userId}`);
  }

  // ================================================
  // 8. Screenshot Detection Webhook (Optional)
  // ================================================

  /**
   * Report screenshot detection to server (optional)
   */
  async reportScreenshotDetection(deviceId, type = 'screenshot') {
    return this.request('/webhooks/screenshot', {
      method: 'POST',
      body: JSON.stringify({
        deviceId,
        timestamp: new Date().toISOString(),
        type
      })
    });
  }
}

// Export singleton instance
const privacyAPI = new PrivacyAPIClient();

// Export for both module and script usage
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { PrivacyAPIClient, privacyAPI };
}

if (typeof window !== 'undefined') {
  window.PrivacyAPIClient = PrivacyAPIClient;
  window.privacyAPI = privacyAPI;
}
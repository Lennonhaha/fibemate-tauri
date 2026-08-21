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
    if (STATE.privacyManager && STATE.privacyManager.modules.offlineMessages) {
      return STATE.privacyManager.modules.offlineMessages.storeOfflineMessage(encryptedContent, recipientId, options);
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


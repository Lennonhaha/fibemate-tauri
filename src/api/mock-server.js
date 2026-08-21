/**
 * FIBEMATE Privacy API Mock Server
 * For frontend development and testing
 * 
 * Usage: node mock-server.js
 * Server runs on http://localhost:3002
 */

const http = require('http');
const url = require('url');

const PORT = 3002;

// In-memory storage
const storage = {
  burnMessages: new Map(),
  devices: new Map(),
  offlineMessages: new Map(),
  files: new Map(),
  safetyNumbers: new Map(),
  keys: new Map(),
  // OPK Low Threshold — when OPK count drops below this, server warns client to replenish
  OPK_LOW_THRESHOLD: 5,

  // X3DH Pre-Key Bundles: userId -> { identityKey, signedPreKey, signedPreKeyId, oneTimePreKeys: [{keyId, publicKey}], uploadedAt }
  preKeyBundles: new Map(),
  // X3DH Session Initial Messages: messageId -> { from, to, initialMessage, createdAt }
  x3dhInitMessages: new Map()
};

// Helper functions
function generateId() {
  return Math.random().toString(36).substr(2, 9) + Date.now().toString(36);
}

function generateSafetyNumbers() {
  return Array.from({ length: 12 }, () => 
    String(Math.floor(Math.random() * 99999)).padStart(5, '0')
  );
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (e) {
        resolve({});
      }
    });
  });
}

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function authMiddleware(req, res) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    sendJson(res, 401, { error: { code: 'UNAUTHORIZED', message: 'Missing or invalid token' } });
    return false;
  }
  return true;
}

// Route handlers
const routes = {
  // Burn Messages
  'POST /messages': async (req, res, body) => {
    const messageId = generateId();
    const message = {
      messageId,
      conversationId: body.conversationId,
      encryptedContent: body.encryptedContent,
      messageType: body.messageType || 'text',
      burnAfterRead: body.burnAfterRead || false,
      burnTimeout: body.burnTimeout || 30,
      status: 'sent',
      createdAt: new Date().toISOString()
    };
    
    storage.burnMessages.set(messageId, message);
    
    // Auto-delete after timeout
    if (message.burnAfterRead) {
      setTimeout(() => {
        storage.burnMessages.delete(messageId);
        console.log(`[Mock] Burn message ${messageId} auto-deleted`);
      }, message.burnTimeout * 1000);
    }
    
    sendJson(res, 201, message);
  },

  'POST /messages/burn/:messageId/read': async (req, res, body, params) => {
    const message = storage.burnMessages.get(params.messageId);
    if (!message) {
      return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Message not found' } });
    }
    
    message.status = 'burned';
    message.burnedAt = new Date().toISOString();
    
    // Delete immediately
    setTimeout(() => storage.burnMessages.delete(params.messageId), 1000);
    
    sendJson(res, 200, {
      messageId: params.messageId,
      status: 'burned',
      burnedAt: message.burnedAt
    });
  },

  'GET /messages/burn/:messageId/status': async (req, res, body, params) => {
    const message = storage.burnMessages.get(params.messageId);
    if (!message) {
      return sendJson(res, 200, {
        messageId: params.messageId,
        status: 'burned',
        remainingTime: 0
      });
    }
    
    const elapsed = (Date.now() - new Date(message.createdAt).getTime()) / 1000;
    const remaining = Math.max(0, message.burnTimeout - elapsed);
    
    sendJson(res, 200, {
      messageId: params.messageId,
      status: remaining > 0 ? 'pending' : 'burned',
      remainingTime: Math.round(remaining)
    });
  },

  // Devices
  'GET /devices': async (req, res) => {
    const devices = Array.from(storage.devices.values());
    sendJson(res, 200, { devices });
  },

  'POST /devices/register': async (req, res, body) => {
    const deviceId = body.deviceId || generateId();
    const isFirstDevice = storage.devices.size === 0;
    
    const device = {
      deviceId,
      deviceName: body.deviceName || 'Unknown Device',
      deviceType: body.deviceType || 'desktop',
      verified: isFirstDevice,
      verificationId: isFirstDevice ? null : generateId(),
      lastActive: new Date().toISOString(),
      trustScore: isFirstDevice ? 100 : 0,
      publicKey: body.publicKey || '',
      deviceFingerprint: body.deviceFingerprint || ''
    };
    
    storage.devices.set(deviceId, device);
    
    sendJson(res, 201, {
      deviceId,
      status: isFirstDevice ? 'verified' : 'pending',
      verificationId: device.verificationId
    });
  },

  'POST /devices/:deviceId/verify': async (req, res, body, params) => {
    const device = storage.devices.get(params.deviceId);
    if (!device) {
      return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Device not found' } });
    }
    
    device.verified = body.approved;
    device.verifiedAt = new Date().toISOString();
    device.trustScore = body.approved ? 100 : 0;
    
    sendJson(res, 200, {
      deviceId: params.deviceId,
      verified: body.approved,
      verifiedAt: device.verifiedAt
    });
  },

  'DELETE /devices/:deviceId': async (req, res, body, params) => {
    storage.devices.delete(params.deviceId);
    sendJson(res, 200, { deviceId: params.deviceId, removed: true });
  },

  // Offline Messages
  'POST /offline-messages': async (req, res, body) => {
    const messageId = generateId();
    const message = {
      messageId,
      recipientId: body.recipientId,
      encryptedContent: body.encryptedContent,
      messageType: body.messageType || 'text',
      priority: body.priority || 'normal',
      status: 'stored',
      storedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + (body.ttl || 3600) * 1000).toISOString()
    };
    
    if (!storage.offlineMessages.has(body.recipientId)) {
      storage.offlineMessages.set(body.recipientId, []);
    }
    storage.offlineMessages.get(body.recipientId).push(message);
    
    // Auto-cleanup after TTL
    setTimeout(() => {
      const messages = storage.offlineMessages.get(body.recipientId);
      if (messages) {
        const index = messages.findIndex(m => m.messageId === messageId);
        if (index > -1) messages.splice(index, 1);
      }
    }, (body.ttl || 3600) * 1000);
    
    sendJson(res, 201, {
      messageId,
      status: 'stored',
      expiresAt: message.expiresAt
    });
  },

  'GET /offline-messages': async (req, res) => {
    // In real implementation, filter by authenticated user
    const allMessages = [];
    storage.offlineMessages.forEach((messages, recipientId) => {
      allMessages.push(...messages.filter(m => m.status === 'stored'));
    });
    
    sendJson(res, 200, { messages: allMessages });
  },

  'POST /offline-messages/:messageId/delivered': async (req, res, body, params) => {
    let found = false;
    storage.offlineMessages.forEach(messages => {
      const msg = messages.find(m => m.messageId === params.messageId);
      if (msg) {
        msg.status = 'delivered';
        msg.deliveredAt = new Date().toISOString();
        found = true;
      }
    });
    
    if (!found) {
      return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Message not found' } });
    }
    
    sendJson(res, 200, { messageId: params.messageId, status: 'delivered' });
  },

  // File Upload
  'POST /files/upload-init': async (req, res, body) => {
    const uploadId = generateId();
    const file = {
      uploadId,
      filename: body.filename,
      fileSize: body.fileSize,
      mimeType: body.mimeType,
      recipientId: body.recipientId,
      totalChunks: body.totalChunks,
      chunks: [],
      status: 'uploading',
      createdAt: new Date().toISOString()
    };
    
    storage.files.set(uploadId, file);
    
    sendJson(res, 201, {
      uploadId,
      chunkSize: Math.ceil(body.fileSize / body.totalChunks),
      uploadUrl: `/files/upload/${uploadId}/chunk`
    });
  },

  'POST /files/upload/:uploadId/chunk/:chunkIndex': async (req, res, body, params) => {
    const file = storage.files.get(params.uploadId);
    if (!file) {
      return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Upload not found' } });
    }
    
    file.chunks[parseInt(params.chunkIndex)] = true;
    
    sendJson(res, 200, {
      chunkIndex: parseInt(params.chunkIndex),
      status: 'received'
    });
  },

  'POST /files/upload/:uploadId/complete': async (req, res, body, params) => {
    const file = storage.files.get(params.uploadId);
    if (!file) {
      return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Upload not found' } });
    }
    
    const fileId = generateId();
    file.fileId = fileId;
    file.status = 'ready';
    file.encryptedKey = body.encryptedKey;
    file.integrityHash = body.integrityHash;
    file.completedAt = new Date().toISOString();
    
    sendJson(res, 200, {
      fileId,
      status: 'ready',
      downloadUrl: `/files/${fileId}/download`
    });
  },

  'GET /files/:fileId/download': async (req, res, body, params) => {
    // In real implementation, return actual file bytes
    sendJson(res, 200, { 
      fileId: params.fileId,
      status: 'ready',
      message: 'In mock mode, file content would be returned here'
    });
  },

  // Safety Numbers
  'GET /safety-numbers/:contactId': async (req, res, body, params) => {
    let record = storage.safetyNumbers.get(params.contactId);
    
    if (!record) {
      const generatedNumbers = generateSafetyNumbers();
      record = {
        numbers: generatedNumbers,  // Always store as flat array
        hash: 'sha256-' + generateId(),
        verified: false
      };
      storage.safetyNumbers.set(params.contactId, record);
    }
    
    // Normalize: ensure numbers is always a flat array
    let numbers = record.numbers;
    if (numbers && typeof numbers === 'object' && !Array.isArray(numbers)) {
      // Defensive: handle legacy nested format { numbers: [...] }
      numbers = numbers.numbers || [];
    }
    if (!Array.isArray(numbers)) {
      numbers = generateSafetyNumbers();  // Fallback to fresh generation
    }
    
    sendJson(res, 200, {
      contactId: params.contactId,
      numbers: numbers,  // Always a flat array
      hash: record.hash,
      verified: record.verified,
      verifiedAt: record.verifiedAt
    });
  },

  'POST /safety-numbers/:contactId/verify': async (req, res, body, params) => {
    const stored = storage.safetyNumbers.get(params.contactId);
    const match = stored && JSON.stringify(stored.numbers) === JSON.stringify(body.numbers);
    
    if (stored) {
      stored.verified = match;
      stored.verifiedAt = match ? new Date().toISOString() : null;
    }
    
    sendJson(res, 200, {
      contactId: params.contactId,
      verified: match,
      match
    });
  },

  // Key Rotation
  'POST /keys/rotate': async (req, res) => {
    const keyId = generateId();
    const version = storage.keys.size + 1;
    
    const key = {
      keyId,
      version,
      publicKey: 'pk-' + generateId(),
      createdAt: new Date().toISOString()
    };
    
    storage.keys.set(keyId, key);
    
    sendJson(res, 201, key);
  },

  'GET /keys/current': async (req, res) => {
    const keys = Array.from(storage.keys.values());
    const current = keys[keys.length - 1] || {
      keyId: generateId(),
      version: 1,
      publicKey: 'pk-' + generateId(),
      createdAt: new Date().toISOString()
    };
    
    sendJson(res, 200, current);
  },

  'GET /keys/history': async (req, res) => {
    const keys = Array.from(storage.keys.values());
    sendJson(res, 200, { keys });
  },

  // ============================================================
  // X3DH Pre-Key Bundle Endpoints
  // Signal Protocol: clients upload pre-key bundles, peers download to initiate sessions
  // ============================================================

  /**
   * Upload pre-key bundle (called by each client after generating keys)
   * POST /pre-keys/:userId
   * Body: { identityKey: number[], signedPreKey: number[], signedPreKeyId: number, oneTimePreKeys?: [{keyId, publicKey}] }
   */
  'POST /pre-keys/:userId': async (req, res, body, params) => {
    const userId = params.userId;

    if (!body.identityKey || !body.signedPreKey || !body.signedPreKeyId) {
      return sendJson(res, 400, {
        error: { code: 'BAD_REQUEST', message: 'Missing required fields: identityKey, signedPreKey, signedPreKeyId' }
      });
    }

    // P1-1: Validate ECDSA signature info if present
    if (body.signedPreKeySignature && body.identitySigningKey) {
      console.log(`[Mock] SPK signature received for ${userId} (ECDSA verification happens client-side)`);
    } else {
      console.warn(`[Mock] No SPK signature in bundle for ${userId} — MITM protection disabled`);
    }

    const bundle = {
      userId,
      identityKey: body.identityKey,
      identitySigningKey: body.identitySigningKey || null,           // P1-1: ECDSA public key (SPKI)
      signedPreKey: body.signedPreKey,
      signedPreKeyId: body.signedPreKeyId,
      signedPreKeySignature: body.signedPreKeySignature || null,     // P1-1: ECDSA signature
      oneTimePreKeys: body.oneTimePreKeys || [],
      uploadedAt: new Date().toISOString()
    };

    // Merge one-time pre-keys if bundle already exists (append, don't replace)
    const existing = storage.preKeyBundles.get(userId);
    if (existing && body.oneTimePreKeys) {
      // Append new OPKs, skip duplicates by keyId
      const existingIds = new Set(existing.oneTimePreKeys.map(k => k.keyId));
      for (const opk of body.oneTimePreKeys) {
        if (!existingIds.has(opk.keyId)) {
          existing.oneTimePreKeys.push(opk);
        }
      }
      // Update signed pre-key (rotation)
      existing.identityKey = body.identityKey;
      existing.identitySigningKey = body.identitySigningKey || existing.identitySigningKey;
      existing.signedPreKey = body.signedPreKey;
      existing.signedPreKeyId = body.signedPreKeyId;
      existing.signedPreKeySignature = body.signedPreKeySignature || existing.signedPreKeySignature;
      existing.uploadedAt = bundle.uploadedAt;
    } else {
      storage.preKeyBundles.set(userId, bundle);
    }

    const currentBundle = storage.preKeyBundles.get(userId);
    console.log(`[Mock] Pre-key bundle uploaded for ${userId} (SPK id=${body.signedPreKeyId}, OPKs=${(body.oneTimePreKeys || []).length}, signed=${!!body.signedPreKeySignature})`);

    // P1-2: Check OPK level and warn if low
    const opkCount = currentBundle.oneTimePreKeys.length;
    const opkWarning = opkCount < storage.OPK_LOW_THRESHOLD
      ? { lowOPKs: true, current: opkCount, threshold: storage.OPK_LOW_THRESHOLD, message: `OPK count low (${opkCount}/${storage.OPK_LOW_THRESHOLD}). Please upload more one-time pre-keys.` }
      : { lowOPKs: false };

    sendJson(res, 201, {
      userId,
      signedPreKeyId: body.signedPreKeyId,
      oneTimePreKeyCount: opkCount,
      uploadedAt: bundle.uploadedAt,
      ...opkWarning
    });
  },

  /**
   * Get pre-key bundle for a user (called by Alice to initiate X3DH with Bob)
   * GET /pre-keys/:userId
   * Returns: { identityKey, signedPreKey, signedPreKeyId, oneTimePreKey?, oneTimePreKeyId? }
   * One-time pre-key is consumed (deleted) on fetch — Signal spec: single-use
   */
  'GET /pre-keys/:userId': async (req, res, body, params) => {
    const userId = params.userId;
    const bundle = storage.preKeyBundles.get(userId);

    if (!bundle) {
      return sendJson(res, 404, {
        error: { code: 'NOT_FOUND', message: `No pre-key bundle found for user ${userId}` }
      });
    }

    // Consume one one-time pre-key (Signal spec: OPK is single-use)
    let oneTimePreKey = null;
    let oneTimePreKeyId = null;
    if (bundle.oneTimePreKeys.length > 0) {
      const opk = bundle.oneTimePreKeys.shift(); // Remove first OPK
      oneTimePreKey = opk.publicKey;
      oneTimePreKeyId = opk.keyId;
      console.log(`[Mock] Consumed OPK ${opk.keyId} for ${userId} (${bundle.oneTimePreKeys.length} remaining)`);
    } else {
      console.log(`[Mock] No OPKs available for ${userId}, X3DH will use 3-DH`);
    }

    sendJson(res, 200, {
      userId,
      identityKey: bundle.identityKey,
      identitySigningKey: bundle.identitySigningKey,               // P1-1: for SPK signature verification
      signedPreKey: bundle.signedPreKey,
      signedPreKeyId: bundle.signedPreKeyId,
      signedPreKeySignature: bundle.signedPreKeySignature,         // P1-1: ECDSA signature
      oneTimePreKey: oneTimePreKey,
      oneTimePreKeyId: oneTimePreKeyId
    });
  },

  /**
   * Get pre-key bundle status (for debugging)
   * GET /pre-keys/:userId/status
   */
  'GET /pre-keys/:userId/status': async (req, res, body, params) => {
    const userId = params.userId;
    const bundle = storage.preKeyBundles.get(userId);

    if (!bundle) {
      return sendJson(res, 404, {
        error: { code: 'NOT_FOUND', message: `No pre-key bundle found for user ${userId}` }
      });
    }

    // P1-2: Include OPK replenishment warning
    const opkCount = bundle.oneTimePreKeys.length;
    const opkWarning = opkCount < storage.OPK_LOW_THRESHOLD
      ? { lowOPKs: true, current: opkCount, threshold: storage.OPK_LOW_THRESHOLD }
      : { lowOPKs: false };

    sendJson(res, 200, {
      userId,
      hasIdentityKey: !!bundle.identityKey,
      hasSigningKey: !!bundle.identitySigningKey,                  // P1-1
      hasSPKSignature: !!bundle.signedPreKeySignature,             // P1-1
      signedPreKeyId: bundle.signedPreKeyId,
      oneTimePreKeysAvailable: opkCount,
      uploadedAt: bundle.uploadedAt,
      ...opkWarning
    });
  },

  /**
   * Replenish one-time pre-keys (P1-2: OPK auto-replenishment endpoint)
   * POST /pre-keys/:userId/replenish
   * Body: { identityKey, identitySigningKey, signedPreKey, signedPreKeyId, signedPreKeySignature, oneTimePreKeys: [{keyId, publicKey}] }
   * Merges new OPKs into existing bundle (append-only, skip duplicates)
   */
  'POST /pre-keys/:userId/replenish': async (req, res, body, params) => {
    const userId = params.userId;

    if (!body.oneTimePreKeys || !Array.isArray(body.oneTimePreKeys)) {
      return sendJson(res, 400, {
        error: { code: 'BAD_REQUEST', message: 'Missing or invalid oneTimePreKeys array' }
      });
    }

    let bundle = storage.preKeyBundles.get(userId);

    if (!bundle) {
      // First upload — create new bundle
      if (!body.identityKey || !body.signedPreKey || !body.signedPreKeyId) {
        return sendJson(res, 400, {
          error: { code: 'BAD_REQUEST', message: 'New bundle requires identityKey, signedPreKey, signedPreKeyId' }
        });
      }
      bundle = {
        userId,
        identityKey: body.identityKey,
        identitySigningKey: body.identitySigningKey || null,
        signedPreKey: body.signedPreKey,
        signedPreKeyId: body.signedPreKeyId,
        signedPreKeySignature: body.signedPreKeySignature || null,
        oneTimePreKeys: [],
        uploadedAt: new Date().toISOString()
      };
      storage.preKeyBundles.set(userId, bundle);
    }

    // Merge new OPKs (append-only, skip duplicates by keyId)
    const existingIds = new Set(bundle.oneTimePreKeys.map(k => k.keyId));
    let added = 0;
    for (const opk of body.oneTimePreKeys) {
      if (!existingIds.has(opk.keyId)) {
        bundle.oneTimePreKeys.push(opk);
        existingIds.add(opk.keyId);
        added++;
      }
    }

    // Update signed pre-key if provided (rotation)
    if (body.signedPreKey && body.signedPreKeyId) {
      bundle.signedPreKey = body.signedPreKey;
      bundle.signedPreKeyId = body.signedPreKeyId;
      bundle.signedPreKeySignature = body.signedPreKeySignature || bundle.signedPreKeySignature;
      bundle.identityKey = body.identityKey || bundle.identityKey;
      bundle.identitySigningKey = body.identitySigningKey || bundle.identitySigningKey;
    }

    bundle.uploadedAt = new Date().toISOString();

    const opkCount = bundle.oneTimePreKeys.length;
    const opkWarning = opkCount < storage.OPK_LOW_THRESHOLD
      ? { lowOPKs: true, current: opkCount, threshold: storage.OPK_LOW_THRESHOLD, message: `OPK count low (${opkCount}/${storage.OPK_LOW_THRESHOLD}). Please upload more one-time pre-keys.` }
      : { lowOPKs: false };

    console.log(`[Mock] OPK replenished for ${userId}: +${added} OPKs (total: ${opkCount})`);

    sendJson(res, 200, {
      userId,
      signedPreKeyId: bundle.signedPreKeyId,
      oneTimePreKeyCount: opkCount,
      added,
      uploadedAt: bundle.uploadedAt,
      ...opkWarning
    });
  },

  /**
   * Forward X3DH initial message (Alice → Bob via server)
   * POST /x3dh/init
   * Body: { from: string, to: string, initialMessage: { type, identityKey, ephemeralKey, signedPreKeyId, oneTimePreKeyId } }
   */
  'POST /x3dh/init': async (req, res, body) => {
    if (!body.from || !body.to || !body.initialMessage) {
      return sendJson(res, 400, {
        error: { code: 'BAD_REQUEST', message: 'Missing required fields: from, to, initialMessage' }
      });
    }

    const messageId = generateId();
    const message = {
      messageId,
      from: body.from,
      to: body.to,
      initialMessage: body.initialMessage,
      createdAt: new Date().toISOString()
    };

    storage.x3dhInitMessages.set(messageId, message);

    console.log(`[Mock] X3DH init: ${body.from} → ${body.to} (SPK=${body.initialMessage.signedPreKeyId}, OPK=${body.initialMessage.oneTimePreKeyId || 'none'})`);

    sendJson(res, 201, {
      messageId,
      status: 'delivered',
      createdAt: message.createdAt
    });
  },

  /**
   * Get pending X3DH init messages for a user (Bob polls this)
   * GET /x3dh/pending/:userId
   */
  'GET /x3dh/pending/:userId': async (req, res, body, params) => {
    const userId = params.userId;
    const pending = [];

    storage.x3dhInitMessages.forEach((msg, msgId) => {
      if (msg.to === userId) {
        pending.push(msg);
        // Remove after retrieval (consumed)
        storage.x3dhInitMessages.delete(msgId);
      }
    });

    console.log(`[Mock] X3DH pending for ${userId}: ${pending.length} messages`);

    sendJson(res, 200, {
      userId,
      pendingMessages: pending
    });
  },

  // Screenshot Webhook
  'POST /webhooks/screenshot': async (req, res, body) => {
    console.log('[Mock] Screenshot detected:', body);
    sendJson(res, 200, { received: true, timestamp: new Date().toISOString() });
  }
};

// Create server
const server = http.createServer(async (req, res) => {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }
  
  const parsedUrl = url.parse(req.url, true);
  const path = parsedUrl.pathname;
  
  console.log(`[Mock] ${req.method} ${path}`);
  
  // Find matching route
  let handler = null;
  let params = {};
  
  for (const [route, handlerFn] of Object.entries(routes)) {
    const [method, routePath] = route.split(' ');
    
    if (method !== req.method) continue;
    
    // Simple route matching with params
    const routeParts = routePath.split('/');
    const pathParts = path.split('/');
    
    if (routeParts.length !== pathParts.length) continue;
    
    let match = true;
    const extractedParams = {};
    
    for (let i = 0; i < routeParts.length; i++) {
      if (routeParts[i].startsWith(':')) {
        extractedParams[routeParts[i].slice(1)] = pathParts[i];
      } else if (routeParts[i] !== pathParts[i]) {
        match = false;
        break;
      }
    }
    
    if (match) {
      handler = handlerFn;
      params = extractedParams;
      break;
    }
  }
  
  if (!handler) {
    sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Endpoint not found' } });
    return;
  }
  
  // Auth check (skip for some endpoints if needed)
  if (!authMiddleware(req, res)) return;
  
  try {
    const body = await parseBody(req);
    await handler(req, res, body, params);
  } catch (err) {
    console.error('[Mock] Error:', err);
    sendJson(res, 500, { error: { code: 'INTERNAL_ERROR', message: err.message } });
  }
});

server.listen(PORT, () => {
  console.log(`
========================================
FIBEMATE Privacy API Mock Server
========================================
Server running on http://localhost:${PORT}

Available endpoints:
- POST   /messages
- POST   /messages/burn/:messageId/read
- GET    /messages/burn/:messageId/status
- GET    /devices
- POST   /devices/register
- POST   /devices/:deviceId/verify
- DELETE /devices/:deviceId
- POST   /offline-messages
- GET    /offline-messages
- POST   /offline-messages/:messageId/delivered
- POST   /files/upload-init
- POST   /files/upload/:uploadId/chunk/:chunkIndex
- POST   /files/upload/:uploadId/complete
- GET    /files/:fileId/download
- GET    /safety-numbers/:contactId
- POST   /safety-numbers/:contactId/verify
- POST   /keys/rotate
- GET    /keys/current
- GET    /keys/history
- POST   /pre-keys/:userId              ← X3DH upload bundle
- POST   /pre-keys/:userId/replenish   ← OPK auto-replenishment (P1-2)
- GET    /pre-keys/:userId              ← X3DH fetch bundle (consumes OPK)
- GET    /pre-keys/:userId/status       ← X3DH bundle status
- POST   /x3dh/init                     ← X3DH initial message
- GET    /x3dh/pending/:userId          ← X3DH pending messages
- POST   /webhooks/screenshot

Press Ctrl+C to stop
========================================
  `);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n[Mock] Shutting down...');
  server.close(() => {
    console.log('[Mock] Server stopped');
    process.exit(0);
  });
});
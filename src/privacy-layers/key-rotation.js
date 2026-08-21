/**
 * Key Rotation Module - Automatic Key Renewal
 * 
 * Implements periodic key rotation for enhanced forward secrecy.
 * Keys are automatically renewed at configurable intervals.
 */

class KeyRotation {
    constructor(options = {}) {
        this.rotationInterval = options.rotationInterval || 86400000; // 24 hours default
        this.maxMessagesPerKey = options.maxMessagesPerKey || 1000;
        this.autoRotate = options.autoRotate !== false;
        
        this.keys = new Map();
        this.rotationTimers = new Map();
        this.messageCounts = new Map();
        this.listeners = new Set();
        
        this.startRotationScheduler();
    }
    
    /**
     * Start automatic rotation scheduler
     */
    startRotationScheduler() {
        if (!this.autoRotate) return;
        
        // Check every minute for keys that need rotation
        this.schedulerInterval = setInterval(() => {
            this.checkKeysForRotation();
        }, 60000);
    }
    
    /**
     * Stop rotation scheduler
     */
    stopScheduler() {
        if (this.schedulerInterval) {
            clearInterval(this.schedulerInterval);
            this.schedulerInterval = null;
        }
    }
    
    /**
     * Generate new key pair
     */
    generateKeyPair(keyType = 'identity') {
        return crypto.subtle.generateKey(
            {
                name: 'RSA-OAEP',
                modulusLength: 4096,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256'
            },
            true, // extractable
            ['encrypt', 'decrypt']
        );
    }
    
    /**
     * Generate symmetric key
     */
    async generateSymmetricKey() {
        return crypto.subtle.generateKey(
            {
                name: 'AES-GCM',
                length: 256
            },
            true,
            ['encrypt', 'decrypt']
        );
    }
    
    /**
     * Add a new key for rotation
     * @param {string} keyId - Unique key identifier
     * @param {CryptoKey} key - The cryptographic key
     * @param {string} keyType - Type: 'identity', 'session', 'message'
     */
    addKey(keyId, key, keyType = 'session') {
        const keyInfo = {
            keyId,
            key,
            keyType,
            createdAt: Date.now(),
            lastRotated: Date.now(),
            rotationCount: 0,
            status: 'active'
        };
        
        this.keys.set(keyId, keyInfo);
        this.messageCounts.set(keyId, 0);
        
        // Schedule rotation
        this.scheduleRotation(keyId);
        
        this.emit('keyAdded', keyInfo);
        
        return keyInfo;
    }
    
    /**
     * Increment message count for a key
     */
    incrementMessageCount(keyId) {
        const count = (this.messageCounts.get(keyId) || 0) + 1;
        this.messageCounts.set(keyId, count);
        
        // Check if rotation needed
        if (count >= this.maxMessagesPerKey) {
            this.rotateKey(keyId);
        }
        
        return count;
    }
    
    /**
     * Schedule key rotation
     */
    scheduleRotation(keyId) {
        const keyInfo = this.keys.get(keyId);
        if (!keyInfo) return;
        
        // Clear existing timer
        if (this.rotationTimers.has(keyId)) {
            clearTimeout(this.rotationTimers.get(keyId));
        }
        
        const delay = this.rotationInterval;
        const timer = setTimeout(() => {
            this.rotateKey(keyId);
        }, delay);
        
        this.rotationTimers.set(keyId, timer);
    }
    
    /**
     * Rotate a specific key
     */
    async rotateKey(keyId) {
        const oldKey = this.keys.get(keyId);
        if (!oldKey) return null;
        
        // Generate new key
        let newKey;
        if (oldKey.keyType === 'symmetric') {
            newKey = await this.generateSymmetricKey();
        } else {
            newKey = await this.generateKeyPair(oldKey.keyType);
        }
        
        // Archive old key
        oldKey.status = 'rotated';
        oldKey.rotatedAt = Date.now();
        
        // Add new key
        const newKeyInfo = {
            keyId: `${keyId}_${Date.now()}`,
            key: newKey,
            keyType: oldKey.keyType,
            createdAt: Date.now(),
            lastRotated: Date.now(),
            rotationCount: oldKey.rotationCount + 1,
            status: 'active',
            previousKeyId: keyId
        };
        
        this.keys.set(newKeyInfo.keyId, newKeyInfo);
        this.messageCounts.set(newKeyInfo.keyId, 0);
        
        // Schedule next rotation
        this.scheduleRotation(newKeyInfo.keyId);
        
        // Clean up old key after grace period (24 hours)
        setTimeout(() => {
            this.deleteKey(keyId);
        }, 86400000);
        
        this.emit('keyRotated', {
            oldKeyId: keyId,
            newKeyId: newKeyInfo.keyId,
            rotationCount: newKeyInfo.rotationCount
        });
        
        return newKeyInfo;
    }
    
    /**
     * Rotate all active keys
     */
    async rotateAllKeys() {
        const results = [];
        
        for (const keyId of this.keys.keys()) {
            const key = this.keys.get(keyId);
            if (key.status === 'active') {
                const result = await this.rotateKey(keyId);
                results.push(result);
            }
        }
        
        this.emit('allKeysRotated', { count: results.length });
        
        return results;
    }
    
    /**
     * Delete a key
     */
    deleteKey(keyId) {
        if (this.rotationTimers.has(keyId)) {
            clearTimeout(this.rotationTimers.get(keyId));
            this.rotationTimers.delete(keyId);
        }
        
        this.messageCounts.delete(keyId);
        const key = this.keys.get(keyId);
        this.keys.delete(keyId);
        
        if (key) {
            this.emit('keyDeleted', { keyId });
        }
        
        return key ? { success: true, keyId } : { success: false };
    }
    
    /**
     * Manually destroy all session keys
     */
    destroyAllKeys() {
        const keyIds = [...this.keys.keys()];
        
        for (const keyId of keyIds) {
            this.deleteKey(keyId);
        }
        
        this.emit('allKeysDestroyed', { count: keyIds.length });
        
        return { success: true, destroyed: keyIds.length };
    }
    
    /**
     * Check if any keys need rotation
     */
    checkKeysForRotation() {
        const now = Date.now();
        const toRotate = [];
        
        for (const [keyId, keyInfo] of this.keys) {
            if (keyInfo.status !== 'active') continue;
            
            const age = now - keyInfo.lastRotated;
            const count = this.messageCounts.get(keyId) || 0;
            
            if (age >= this.rotationInterval || count >= this.maxMessagesPerKey) {
                toRotate.push(keyId);
            }
        }
        
        if (toRotate.length > 0) {
            this.emit('keysNeedRotation', { keyIds: toRotate });
        }
    }
    
    /**
     * Get current key
     */
    getKey(keyId) {
        return this.keys.get(keyId);
    }
    
    /**
     * Get all active keys
     */
    getActiveKeys() {
        return [...this.keys.values()].filter(k => k.status === 'active');
    }
    
    /**
     * Get key status
     */
    getStatus() {
        const keys = [...this.keys.values()];
        return {
            totalKeys: keys.length,
            activeKeys: keys.filter(k => k.status === 'active').length,
            rotatedKeys: keys.filter(k => k.status === 'rotated').length,
            autoRotate: this.autoRotate,
            rotationInterval: this.rotationInterval,
            maxMessagesPerKey: this.maxMessagesPerKey
        };
    }
    
    /**
     * Add event listener
     */
    on(event, callback) {
        this.listeners.add({ event, callback });
    }
    
    /**
     * Emit event
     */
    emit(event, data) {
        for (const listener of this.listeners) {
            if (listener.event === event) {
                listener.callback(data);
            }
        }
    }
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { KeyRotation };
}

if (typeof window !== 'undefined') {
    window.FIBEMATE = window.FIBEMATE || {};
    window.FIBEMATE.KeyRotation = KeyRotation;
}

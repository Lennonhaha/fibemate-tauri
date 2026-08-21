/**
 * Offline Message Encryption Module
 * 
 * Handles secure storage and retrieval of messages when recipient is offline.
 * Messages are encrypted locally and only decrypted upon delivery confirmation.
 */

class OfflineMessageStorage {
    constructor(options = {}) {
        this.maxStorage = options.maxStorage || 100; // Max messages
        this.maxSizePerMessage = options.maxSizePerMessage || 1048576; // 1MB
        this.autoCleanDays = options.autoCleanDays || 7;
        this.storageKey = 'fibemate_offline_messages';
        
        this.storage = this.loadStorage();
        this.listeners = new Set();
    }
    
    /**
     * Load storage from disk
     */
    loadStorage() {
        try {
            const data = localStorage.getItem(this.storageKey);
            return data ? JSON.parse(data) : { messages: [], metadata: {} };
        } catch {
            return { messages: [], metadata: {} };
        }
    }
    
    /**
     * Save storage to disk
     */
    saveStorage() {
        try {
            // Clean up old messages
            this.cleanupOldMessages();
            localStorage.setItem(this.storageKey, JSON.stringify(this.storage));
        } catch (e) {
            console.error('Failed to save offline storage:', e);
        }
    }
    
    /**
     * Store encrypted offline message
     */
    storeOfflineMessage(encryptedMessage, recipientId, options = {}) {
        if (this.storage.messages.length >= this.maxStorage) {
            return { success: false, error: 'Storage limit reached' };
        }
        
        const messageId = crypto.randomUUID();
        
        const offlineMessage = {
            messageId,
            recipientId,
            encryptedContent: encryptedMessage,
            senderId: options.senderId,
            timestamp: Date.now(),
            expiresAt: options.expiresAt || (Date.now() + this.autoCleanDays * 86400000),
            messageType: options.messageType || 'text',
            size: JSON.stringify(encryptedMessage).length,
            status: 'pending', // pending, delivered, expired
            deliveryAttempts: 0,
            metadata: options.metadata || {}
        };
        
        if (offlineMessage.size > this.maxSizePerMessage) {
            return { success: false, error: 'Message too large' };
        }
        
        this.storage.messages.push(offlineMessage);
        this.storage.metadata[messageId] = {
            storedAt: Date.now(),
            size: offlineMessage.size
        };
        
        this.saveStorage();
        this.emit('messageStored', offlineMessage);
        
        return { 
            success: true, 
            messageId,
            storedCount: this.storage.messages.length
        };
    }
    
    /**
     * Get pending offline messages for recipient
     */
    getOfflineMessages(recipientId) {
        return this.storage.messages.filter(m => 
            m.recipientId === recipientId && m.status === 'pending'
        );
    }
    
    /**
     * Mark message as delivered
     */
    markDelivered(messageId) {
        const message = this.storage.messages.find(m => m.messageId === messageId);
        if (!message) {
            return { success: false, error: 'Message not found' };
        }
        
        message.status = 'delivered';
        message.deliveredAt = Date.now();
        
        this.saveStorage();
        this.emit('messageDelivered', message);
        
        return { success: true, messageId };
    }
    
    /**
     * Delete specific message
     */
    deleteMessage(messageId) {
        const index = this.storage.messages.findIndex(m => m.messageId === messageId);
        if (index === -1) {
            return { success: false, error: 'Message not found' };
        }
        
        const message = this.storage.messages.splice(index, 1)[0];
        delete this.storage.metadata[messageId];
        
        this.saveStorage();
        this.emit('messageDeleted', message);
        
        return { success: true, messageId };
    }
    
    /**
     * Delete all messages for a recipient
     */
    deleteAllForRecipient(recipientId) {
        const toDelete = this.storage.messages.filter(m => m.recipientId === recipientId);
        
        this.storage.messages = this.storage.messages.filter(m => m.recipientId !== recipientId);
        
        for (const msg of toDelete) {
            delete this.storage.metadata[msg.messageId];
        }
        
        this.saveStorage();
        this.emit('allMessagesDeleted', { recipientId, count: toDelete.length });
        
        return { success: true, deleted: toDelete.length };
    }
    
    /**
     * Cleanup expired old messages
     */
    cleanupOldMessages() {
        const now = Date.now();
        const before = this.storage.messages.length;
        
        this.storage.messages = this.storage.messages.filter(m => {
            if (m.status === 'delivered') {
                // Keep delivered messages for 24 hours for receipt confirmation
                const deliveredAt = m.deliveredAt || 0;
                return now - deliveredAt < 86400000;
            }
            // Remove expired pending messages
            return m.expiresAt > now;
        });
        
        const cleaned = before - this.storage.messages.length;
        
        if (cleaned > 0) {
            this.emit('messagesCleaned', { count: cleaned });
        }
        
        return cleaned;
    }
    
    /**
     * Get storage status
     */
    getStatus() {
        return {
            totalMessages: this.storage.messages.length,
            maxStorage: this.maxStorage,
            pendingCount: this.storage.messages.filter(m => m.status === 'pending').length,
            deliveredCount: this.storage.messages.filter(m => m.status === 'delivered').length,
            autoCleanDays: this.autoCleanDays
        };
    }
    
    /**
     * Encrypt message for offline storage
     */
    async encryptForOffline(message, recipientKey) {
        const encoded = new TextEncoder().encode(JSON.stringify(message));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            recipientKey,
            encoded
        );
        
        return {
            iv: Array.from(iv),
            data: Array.from(new Uint8Array(encrypted))
        };
    }
    
    /**
     * Decrypt offline message
     */
    async decryptOfflineMessage(encryptedData, recipientKey) {
        const iv = new Uint8Array(encryptedData.iv);
        const data = new Uint8Array(encryptedData.data);
        
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            recipientKey,
            data
        );
        
        return JSON.parse(new TextDecoder().decode(decrypted));
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
    module.exports = { OfflineMessageStorage };
}

if (typeof window !== 'undefined') {
    window.FIBEMATE = window.FIBEMATE || {};
    window.FIBEMATE.OfflineMessageStorage = OfflineMessageStorage;
}

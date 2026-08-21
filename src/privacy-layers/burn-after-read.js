/**
 * Burn After Read Module - Self-Destructing Messages
 * 
 * Provides ephemeral message functionality that automatically
 * deletes messages after a specified timeout or once read.
 */

class BurnAfterRead {
    constructor(options = {}) {
        this.defaultTimeout = options.defaultTimeout || 30; // seconds
        this.maxTimeout = options.maxTimeout || 86400; // 24 hours max
        this.burnQueue = new Map(); // pending burns
        this.history = new Map(); // burn history for receipts
    }
    
    /**
     * Create a self-destructing message
     * @param {string} messageId - Unique message ID
     * @param {object} message - Message content
     * @param {number} timeout - Seconds until auto-delete (0 = immediate after read)
     * @param {boolean} notifyOnBurn - Send notification when burned
     */
    createBurnMessage(messageId, message, timeout, notifyOnBurn = true) {
        const burnConfig = {
            messageId,
            message,
            timeout: Math.min(timeout || this.defaultTimeout, this.maxTimeout),
            notifyOnBurn,
            createdAt: Date.now(),
            burnAt: null,
            readAt: null,
            status: 'pending' // pending, burning, burned
        };
        
        // If timeout > 0, schedule auto-burn
        if (burnConfig.timeout > 0) {
            burnConfig.burnAt = burnConfig.createdAt + (burnConfig.timeout * 1000);
            this.scheduleBurn(burnConfig);
        }
        
        return burnConfig;
    }
    
    /**
     * Mark message as read and start burn countdown
     */
    markAsRead(messageId) {
        const burn = this.burnQueue.get(messageId);
        if (!burn || burn.status !== 'pending') return null;
        
        burn.readAt = Date.now();
        
        // If timeout is 0, burn immediately after read confirmed
        // Otherwise, burn after read_at + timeout
        if (burn.timeout === 0) {
            this.burnMessage(messageId);
        } else {
            burn.burnAt = burn.readAt + (burn.timeout * 1000);
            this.scheduleBurn(burn);
        }
        
        return { 
            success: true, 
            burnAt: burn.burnAt,
            timeRemaining: burn.burnAt - Date.now()
        };
    }
    
    /**
     * Schedule message auto-deletion
     */
    scheduleBurn(burn) {
        const delay = burn.burnAt - Date.now();
        if (delay <= 0) {
            this.burnMessage(burn.messageId);
            return;
        }
        
        // Clear any existing timer
        if (burn.timer) clearTimeout(burn.timer);
        
        burn.timer = setTimeout(() => {
            this.burnMessage(burn.messageId);
        }, delay);
        
        burn.status = 'burning';
    }
    
    /**
     * Permanently delete message
     */
    burnMessage(messageId) {
        const burn = this.burnQueue.get(messageId);
        if (!burn) return null;
        
        // Clear timer
        if (burn.timer) clearTimeout(burn.timer);
        
        // Store in history before deleting (for receipt)
        this.history.set(messageId, {
            ...burn,
            burnedAt: Date.now(),
            status: 'burned'
        });
        
        // Delete actual message content
        burn.message = null;
        burn.status = 'burned';
        
        // Send burn notification if enabled
        if (burn.notifyOnBurn) {
            this.sendBurnReceipt(messageId);
        }
        
        // Remove from queue
        this.burnQueue.delete(messageId);
        
        return { success: true, messageId };
    }
    
    /**
     * Send burn receipt to sender
     */
    sendBurnReceipt(messageId) {
        // This would integrate with the messaging system
        return {
            type: 'burn_receipt',
            messageId,
            burnedAt: Date.now()
        };
    }
    
    /**
     * Cancel pending burn (if message recalled)
     */
    cancelBurn(messageId) {
        const burn = this.burnQueue.get(messageId);
        if (!burn) return { success: false, error: 'Message not found' };
        
        if (burn.timer) clearTimeout(burn.timer);
        this.burnQueue.delete(messageId);
        
        return { success: true };
    }
    
    /**
     * Get burn status for a message
     */
    getStatus(messageId) {
        const burn = this.burnQueue.get(messageId) || this.history.get(messageId);
        if (!burn) return { exists: false };
        
        return {
            exists: true,
            status: burn.status,
            createdAt: burn.createdAt,
            readAt: burn.readAt,
            burnAt: burn.burnAt,
            timeRemaining: burn.burnAt ? Math.max(0, burn.burnAt - Date.now()) : null
        };
    }
    
    /**
     * Clean up expired entries
     */
    cleanup() {
        const now = Date.now();
        for (const [id, burn] of this.burnQueue) {
            if (burn.burnAt && burn.burnAt < now) {
                this.burnMessage(id);
            }
        }
        
        // Clean old history (older than 24 hours)
        for (const [id, burn] of this.history) {
            if (burn.burnedAt && now - burn.burnedAt > 86400000) {
                this.history.delete(id);
            }
        }
    }
}

/**
 * Message wrapper with burn functionality
 */
class EphemeralMessage {
    static create(messageContent, options = {}) {
        const messageId = crypto.randomUUID();
        const burnModule = new BurnAfterRead();
        
        return {
            id: messageId,
            type: 'ephemeral',
            content: messageContent,
            burnConfig: {
                enabled: true,
                timeout: options.timeout || 30,
                notifyOnBurn: options.notifyOnBurn !== false
            },
            burnModule
        };
    }
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { BurnAfterRead, EphemeralMessage };
}

if (typeof window !== 'undefined') {
    window.FIBEMATE = window.FIBEMATE || {};
    window.FIBEMATE.BurnAfterRead = BurnAfterRead;
    window.FIBEMATE.EphemeralMessage = EphemeralMessage;
}
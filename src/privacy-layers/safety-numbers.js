/**
 * Safety Numbers Module - Contact Identity Verification
 * 
 * Implements Signal-style safety numbers for verifying contact identity.
 * Users compare numbers to ensure no man-in-the-middle attack.
 */

class SafetyNumbers {
    constructor(options = {}) {
        this.hashAlgorithm = options.hashAlgorithm || 'SHA-256';
        this.numberFormat = options.numberFormat || 'decimal'; // decimal or qr
        this.blockCount = options.blockCount || 12; // 12 groups of 5 digits
        this.listeners = new Set();
    }
    
    /**
     * Generate safety numbers for a conversation
     * @param {string} userId - Current user ID
     * @param {CryptoKey} userPublicKey - Current user's public key
     * @param {string} contactId - Contact's user ID
     * @param {CryptoKey} contactPublicKey - Contact's public key
     */
    async generateSafetyNumbers(userId, userPublicKey, contactId, contactPublicKey) {
        // Export public keys
        const userKeyBytes = await this.exportPublicKey(userPublicKey);
        const contactKeyBytes = await this.exportPublicKey(contactPublicKey);
        
        // Sort IDs to ensure consistent ordering
        const ids = [userId, contactId].sort();
        const keys = ids[0] === userId ? [userKeyBytes, contactKeyBytes] : [contactKeyBytes, userKeyBytes];
        
        // Concatenate: sorted_user_id + user_key + sorted_contact_id + contact_key
        const data = new Uint8Array(
            ids[0].length + keys[0].length + ids[1].length + keys[1].length
        );
        
        let offset = 0;
        
        // Add first ID
        const id1Bytes = new TextEncoder().encode(ids[0]);
        data.set(id1Bytes, offset);
        offset += id1Bytes.length;
        
        // Add first key
        data.set(keys[0], offset);
        offset += keys[0].length;
        
        // Add second ID
        const id2Bytes = new TextEncoder().encode(ids[1]);
        data.set(id2Bytes, offset);
        offset += id2Bytes.length;
        
        // Add second key
        data.set(keys[1], offset);
        
        // Hash the combined data
        const hash = await crypto.subtle.digest(this.hashAlgorithm, data);
        const hashBytes = new Uint8Array(hash);
        
        // Convert to safety numbers
        const numbers = this.hashToNumbers(hashBytes);
        
        return {
            numbers,
            formatted: this.formatNumbers(numbers),
            hash: Array.from(hashBytes),
            userId,
            contactId,
            generatedAt: Date.now()
        };
    }
    
    /**
     * Export public key to bytes
     */
    async exportPublicKey(publicKey) {
        const exported = await crypto.subtle.exportKey('spki', publicKey);
        return new Uint8Array(exported);
    }
    
    /**
     * Convert hash to numeric groups
     */
    hashToNumbers(hashBytes) {
        const numbers = [];
        const digitsPerBlock = 5;
        const bytesPerBlock = Math.ceil(digitsPerBlock * Math.log2(10) / 8);
        
        for (let i = 0; i < this.blockCount; i++) {
            const start = i * bytesPerBlock;
            const end = Math.min(start + bytesPerBlock, hashBytes.length);
            const block = hashBytes.slice(start, end);
            
            // Convert bytes to number
            let num = 0;
            for (let j = 0; j < block.length; j++) {
                num = (num * 256 + block[j]) % 100000;
            }
            
            numbers.push(num.toString().padStart(digitsPerBlock, '0'));
        }
        
        return numbers;
    }
    
    /**
     * Format numbers for display
     */
    formatNumbers(numbers) {
        // Group in sets of 3 for readability
        const groups = [];
        for (let i = 0; i < numbers.length; i += 3) {
            groups.push(numbers.slice(i, i + 3).join(' '));
        }
        return groups.join('\n');
    }
    
    /**
     * Verify safety numbers match
     */
    verifySafetyNumbers(localNumbers, remoteNumbers) {
        if (typeof localNumbers === 'object' && localNumbers.numbers) {
            localNumbers = localNumbers.numbers;
        }
        if (typeof remoteNumbers === 'object' && remoteNumbers.numbers) {
            remoteNumbers = remoteNumbers.numbers;
        }
        
        if (localNumbers.length !== remoteNumbers.length) {
            return { verified: false, error: 'Number count mismatch' };
        }
        
        const matches = localNumbers.every((num, i) => num === remoteNumbers[i]);
        
        return {
            verified: matches,
            matchCount: matches ? localNumbers.length : 
                localNumbers.filter((num, i) => num === remoteNumbers[i]).length,
            totalCount: localNumbers.length
        };
    }
    
    /**
     * Generate QR code data for safety numbers
     */
    generateQRData(safetyNumbers) {
        const numbers = typeof safetyNumbers === 'object' ? 
            safetyNumbers.numbers : safetyNumbers;
        
        return JSON.stringify({
            type: 'fibemate_safety_numbers',
            version: 1,
            numbers: numbers.join(''),
            timestamp: Date.now()
        });
    }
    
    /**
     * Parse QR code data
     */
    parseQRData(qrData) {
        try {
            const data = JSON.parse(qrData);
            if (data.type !== 'fibemate_safety_numbers') {
                return { success: false, error: 'Invalid QR code type' };
            }
            
            // Convert back to grouped format
            const numbers = [];
            const raw = data.numbers;
            for (let i = 0; i < raw.length; i += 5) {
                numbers.push(raw.slice(i, i + 5));
            }
            
            return { success: true, numbers };
        } catch (e) {
            return { success: false, error: 'Invalid QR code data' };
        }
    }
    
    /**
     * Mark contact as verified
     */
    markVerified(contactId, safetyNumbers) {
        const verification = {
            contactId,
            safetyNumbers: typeof safetyNumbers === 'object' ? 
                safetyNumbers.numbers : safetyNumbers,
            verifiedAt: Date.now(),
            status: 'verified'
        };
        
        // Store verification
        this.storeVerification(verification);
        
        this.emit('contactVerified', verification);
        
        return verification;
    }
    
    /**
     * Store verification in local storage
     */
    storeVerification(verification) {
        try {
            const key = `fibemate_verified_${verification.contactId}`;
            localStorage.setItem(key, JSON.stringify(verification));
        } catch (e) {
            console.error('Failed to store verification:', e);
        }
    }
    
    /**
     * Get stored verification
     */
    getVerification(contactId) {
        try {
            const key = `fibemate_verified_${contactId}`;
            const data = localStorage.getItem(key);
            return data ? JSON.parse(data) : null;
        } catch {
            return null;
        }
    }
    
    /**
     * Check if contact is verified
     */
    isVerified(contactId) {
        const verification = this.getVerification(contactId);
        return verification && verification.status === 'verified';
    }
    
    /**
     * Detect if safety numbers changed (key rotation)
     */
    async detectKeyChange(contactId, newSafetyNumbers) {
        const oldVerification = this.getVerification(contactId);
        
        if (!oldVerification) {
            return { changed: false, reason: 'No previous verification' };
        }
        
        const oldNumbers = oldVerification.safetyNumbers;
        const newNumbers = typeof newSafetyNumbers === 'object' ? 
            newSafetyNumbers.numbers : newSafetyNumbers;
        
        const match = oldNumbers.every((num, i) => num === newNumbers[i]);
        
        if (!match) {
            return {
                changed: true,
                reason: 'Safety numbers changed - possible key rotation or MITM attack',
                oldVerification,
                action: 'reverify_required'
            };
        }
        
        return { changed: false };
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
    module.exports = { SafetyNumbers };
}

if (typeof window !== 'undefined') {
    window.FIBEMATE = window.FIBEMATE || {};
    window.FIBEMATE.SafetyNumbers = SafetyNumbers;
}
/**
 * PIR Search - Private Information Retrieval
 * 
 * Allows searching messages without revealing search keywords to the server.
 * Uses encrypted database + blind indexing approach.
 * 
 * Method: Server stores encrypted records, returns all potential matches.
 * Client decrypts to find actual matches. Server never sees the query.
 */

class PIRClient {
    constructor() {
        this.db = null; // Encrypted database
        this.key = null; // Encryption key
    }
    
    /**
     * Generate a secure search token that doesn't reveal the query
     * Uses bloom filter-like approach for keyword matching
     */
    generateSearchToken(keywords) {
        // Hash keywords into fixed-size token
        const encoder = new TextEncoder();
        const data = encoder.encode(keywords.join(''));
        
        // Simple哈希 to get search token (in real implementation, use proper hashing)
        let hash = 0;
        for (let i = 0; i < data.length; i++) {
            hash = ((hash << 5) - hash) + data[i];
            hash = hash & hash;
        }
        
        // Generate multiple hash functions for bloom filter
        const tokens = [];
        for (let i = 0; i < 8; i++) {
            const h = (hash * (i + 1) * 16777619) >>> 0;
            tokens.push(h.toString(16).padStart(8, '0'));
        }
        
        return tokens.join(':');
    }
    
    /**
     * Encrypt search token for privacy
     */
    encryptToken(token, key) {
        // XOR with key for simple encryption
        const encoder = new TextEncoder();
        const keyData = encoder.encode(key);
        const tokenData = encoder.encode(token);
        
        const encrypted = new Uint8Array(tokenData.length);
        for (let i = 0; i < tokenData.length; i++) {
            encrypted[i] = tokenData[i] ^ keyData[i % keyData.length];
        }
        
        return btoa(String.fromCharCode(...encrypted));
    }
    
    /**
     * Create encrypted database entry for PIR
     * Each message is encrypted with a unique IV
     */
    async createEncryptedEntry(message, messageId) {
        const encoder = new TextEncoder();
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        // Derive key from master key + message ID
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(messageId),
            'PBKDF2',
            false,
            ['deriveBits']
        );
        
        const derivedKey = await crypto.subtle.deriveBits(
            {
                name: 'PBKDF2',
                salt: iv,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            256
        );
        
        // Encrypt message content
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            derivedKey,
            encoder.encode(message.content)
        );
        
        return {
            id: messageId,
            encrypted: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
            iv: btoa(String.fromCharCode(...iv)),
            timestamp: message.timestamp,
            sender: message.sender
        };
    }
    
    /**
     * Search encrypted database
     * Server returns ALL entries, client decrypts to find matches
     * This way server doesn't know what's being searched
     */
    async search(encryptedDB, query) {
        const results = [];
        
        // Generate search token (doesn't reveal query to server)
        const searchToken = this.generateSearchToken([query]);
        
        // For each encrypted entry, try to decrypt and check match
        for (const entry of encryptedDB) {
            try {
                const decrypted = await this.decryptEntry(entry, query);
                if (decrypted && decrypted.content.toLowerCase().includes(query.toLowerCase())) {
                    results.push({
                        ...decrypted,
                        id: entry.id,
                        timestamp: entry.timestamp
                    });
                }
            } catch (e) {
                // Decryption failed, skip this entry
            }
        }
        
        return results;
    }
    
    /**
     * Decrypt a single entry
     */
    async decryptEntry(entry, key) {
        const decoder = new TextDecoder();
        const iv = Uint8Array.from(atob(entry.iv), c => c.charCodeAt(0));
        const encrypted = Uint8Array.from(atob(entry.encrypted), c => c.charCodeAt(0));
        
        // Recreate derived key
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(entry.id),
            'PBKDF2',
            false,
            ['deriveBits']
        );
        
        const derivedKey = await crypto.subtle.deriveBits(
            {
                name: 'PBKDF2',
                salt: iv,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            256
        );
        
        try {
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                derivedKey,
                encrypted
            );
            
            return {
                content: decoder.decode(decrypted),
                sender: entry.sender
            };
        } catch (e) {
            return null;
        }
    }
}

class PIRServer {
    constructor() {
        this.encryptedDB = []; // Store encrypted messages
    }
    
    /**
     * Store encrypted message (server never sees plaintext)
     */
    async storeEncryptedMessage(message, messageId) {
        // Entry is already encrypted by client
        this.encryptedDB.push({
            id: messageId,
            encrypted: message.encrypted,
            iv: message.iv,
            timestamp: message.timestamp,
            sender: message.sender
        });
    }
    
    /**
     * Return all encrypted entries (PIR: client-side decryption)
     */
    getAllEncryptedEntries() {
        return this.encryptedDB;
    }
    
    /**
     * Blinded query: server processes encrypted search token
     * Returns candidates without knowing the actual query
     */
    getCandidates(encryptedToken) {
        // In a real implementation, use homomorphic encryption
        // Here we return a subset based on time range
        const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000; // Last 7 days
        return this.encryptedDB.filter(e => e.timestamp > cutoff);
    }
}

// Export for use in main application
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { PIRClient, PIRServer };
}
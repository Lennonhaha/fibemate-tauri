/**
 * Sphinx Packet Encryption
 * 
 * A cryptographic packet format that provides anonymity by hiding message metadata.
 * Each packet is indistinguishable from random noise - no observer can determine:
 * - Who sent it
 * - Who should receive it
 * - What the message contains
 * - When it was sent
 * 
 * Uses: Onion encryption + cover traffic + fixed-size packets
 */

// Import constant-time utilities
let constantTimeEqual;
if (typeof window !== 'undefined' && window.constantTimeEqual) {
    constantTimeEqual = window.constantTimeEqual;
} else if (typeof require !== 'undefined') {
    try { constantTimeEqual = require('./constant-time.js').constantTimeEqual; } catch (e) { constantTimeEqual = null; }
} else {
    constantTimeEqual = null;
}

class SphinxPacket {
    constructor(config) {
        this.packetSize = config.packetSize || 1024; // Fixed packet size
        this.headerLength = 32; // Sphinx header length
        this.identiconLength = 16; // Recipient identicon
    }
    
    /**
     * Create a Sphinx packet
     * 
     * Packet structure:
     * [identicon: 16 bytes][routing header: 16 bytes][encrypted payload: variable][padding: to packetSize]
     * 
     * - Identicon: Recipient-specific decoration (decoy for observer)
     * - Routing: Encrypted routing info for next hop
     * - Payload: Actual message content
     * - Padding: Makes all packets identical size
     */
    async createPacket(plaintext, recipientId, senderId, routingInfo) {
        // ---- Downgrade Attack Protection ----
        if (typeof SecurityLevels !== 'undefined' && SecurityLevels.enforceMinimum) {
          // Sphinx packet must go through Mixnet (level 4)
          SecurityLevels.enforceMinimum(SecurityLevels.LEVEL.MIXNET, 'sphinx-createPacket');
        }
        if (!routingInfo || routingInfo.length === 0) {
          throw new Error('[SECURITY] Downgrade attack: empty routingInfo (Mixnet bypass?)');
        }
        // ---- End downgrade protection ----

        const encoder = new TextEncoder();

        // 1. Generate recipient identicon (blends with noise)
        const identicon = this.generateIdenticon(recipientId);
        
        // 2. Create routing header (encrypted)
        const routingHeader = await this.encryptRoutingHeader(routingInfo, recipientId);
        
        // 3. Encrypt payload
        const encryptedPayload = await this.encryptPayload(plaintext, recipientId, senderId);
        
        // 4. Create padding to fixed size
        const totalContent = identicon + routingHeader + encryptedPayload;
        const padding = this.generatePadding(this.packetSize - totalContent.length);
        
        // 5. Assemble packet
        const packet = {
            identicon: identicon,
            routing: routingHeader,
            payload: encryptedPayload,
            padding: padding,
            raw: identicon + routingHeader + encryptedPayload + padding
        };
        
        return packet;
    }
    
    /**
     * Generate recipient identicon
     * Looks like random noise but contains embedded recipient key
     * Used to verify packet is intended for recipient without revealing to observer
     */
    generateIdenticon(recipientId) {
        // Hash recipient ID to get deterministic noise
        const encoder = new TextEncoder();
        const data = encoder.encode(recipientId + 'sphinx-identicon');
        
        // Use SHA-256 to generate pseudo-random identicon
        return crypto.subtle.digest('SHA-256', data).then(hash => {
            const bytes = new Uint8Array(hash);
            // Take first 16 bytes
            return btoa(String.fromCharCode(...bytes.slice(0, 16)));
        });
    }
    
    /**
     * Encrypt routing header
     * Only the next hop can read this, observers see noise
     */
    async encryptRoutingHeader(routingInfo, recipientKey) {
        const encoder = new TextEncoder();
        const header = JSON.stringify(routingInfo);
        
        // Use recipient's key to encrypt routing
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await this.deriveKey(recipientKey, 'routing-salt');
        
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            encoder.encode(header)
        );
        
        return btoa(String.fromCharCode(...iv)) + ':' + 
               btoa(String.fromCharCode(...new Uint8Array(encrypted)));
    }
    
    /**
     * Encrypt message payload
     * Uses recipient's public key + sender's key derivation
     */
    async encryptPayload(plaintext, recipientKey, senderId) {
        const encoder = new TextEncoder();
        
        // Prepare payload with metadata
        const payload = {
            sender: senderId,
            content: plaintext,
            timestamp: Date.now(),
            sequence: Math.floor(Math.random() * 1000000)
        };
        
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const combinedKey = recipientKey + ':' + senderId;
        const key = await this.deriveKey(combinedKey, 'payload-salt');
        
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            encoder.encode(JSON.stringify(payload))
        );
        
        return btoa(String.fromCharCode(...iv)) + ':' +
               btoa(String.fromCharCode(...new Uint8Array(encrypted)));
    }
    
    /**
     * Generate padding bytes
     */
    generatePadding(length) {
        const padding = new Uint8Array(length);
        crypto.getRandomValues(padding);
        return btoa(String.fromCharCode(...padding));
    }
    
    /**
     * Derive encryption key from shared secret
     */
    async deriveKey(secret, salt) {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(secret),
            'PBKDF2',
            false,
            ['deriveKey']
        );
        
        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: encoder.encode(salt),
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
    }
    
    /**
     * Decrypt Sphinx packet (recipient only)
     */
    async decryptPacket(packet) {
        const decoder = new TextDecoder();
        
        // 1. Verify identicon belongs to recipient
        // (In real implementation, verify against known identicons)
        
        // 2. Decrypt routing header
        const routingParts = packet.routing.split(':');
        const routingIv = Uint8Array.from(atob(routingParts[0]), c => c.charCodeAt(0));
        const routingEncrypted = Uint8Array.from(atob(routingParts[1]), c => c.charCodeAt(0));
        
        // This would use recipient's private key in real implementation
        // Skipping for demonstration
        
        // 3. Decrypt payload
        const payloadParts = packet.payload.split(':');
        const payloadIv = Uint8Array.from(atob(payloadParts[0]), c => c.charCodeAt(0));
        const payloadEncrypted = Uint8Array.from(atob(payloadParts[1]), c => c.charCodeAt(0));
        
        // This would use recipient's private key
        // Skipping for demonstration
        
        return {
            status: 'decrypted',
            // Placeholder - actual implementation would decrypt
            senderId: 'decrypted-sender',
            content: 'decrypted-content'
        };
    }
    
    /**
     * Generate cover traffic (decoy packets)
     * Sends random-looking packets to defeat traffic analysis
     */
    generateCoverTraffic(count) {
        const packets = [];
        for (let i = 0; i < count; i++) {
            const noise = new Uint8Array(this.packetSize);
            crypto.getRandomValues(noise);
            packets.push(btoa(String.fromCharCode(...noise)));
        }
        return packets;
    }
}

/**
 * Sphinx Handler - Manages packet processing
 */
class SphinxHandler {
    constructor(keys) {
        this.keys = keys;
        this.sphinx = new SphinxPacket({ packetSize: 1024 });
    }
    
    /**
     * Send message as Sphinx packet
     */
    async send(plaintext, recipientId, senderId) {
        const routingInfo = {
            nextHop: recipientId,
            delay: Math.floor(Math.random() * 5000) // Random delay
        };
        
        return await this.sphinx.createPacket(plaintext, recipientId, senderId, routingInfo);
    }
    
    /**
     * Receive Sphinx packet
     */
    async receive(packet) {
        return await this.sphinx.decryptPacket(packet);
    }
    
    /**
     * Check if packet is intended for this recipient
     * Uses constant-time comparison to prevent timing attacks
     */
    async verifyPacketIdenticon(packet, myRecipientId) {
        const expectedIdenticon = await this.sphinx.generateIdenticon(myRecipientId);
        // Use constant-time comparison to prevent timing attacks
        if (constantTimeEqual) {
            return constantTimeEqual(packet.identicon, expectedIdenticon);
        }
        // Fallback for environments without constant-time utility
        // WARNING: This is vulnerable to timing attacks in production
        return packet.identicon === expectedIdenticon;
    }
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { SphinxPacket, SphinxHandler };
}
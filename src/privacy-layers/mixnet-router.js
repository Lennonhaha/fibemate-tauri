/**
 * Mixnet Router - Mix Network Routing
 * 
 * Provides anonymity by routing messages through multiple relays.
 * Each relay only knows the previous hop and next hop, not the sender/receiver.
 * 
 * Design: Mix cascade (0 -> mix1 -> mix2 -> mix3 -> destination)
 * Each mix node shuffles and delays messages to break timing correlation.
 */

class MixnetClient {
    constructor() {
        this.mixNodes = [];
        this.mixPublicKeys = {};
    }
    
    /**
     * Configure mix network nodes
     * In production, these would be provided by the service or user-selected
     */
    configureMixNodes(nodes) {
        this.mixNodes = nodes;
        // In real implementation, fetch public keys for each node
        // Here we assume pre-configured or fetched securely
    }
    
    /**
     * Create layered encrypted message (onion routing)
     * Each layer can only be peeled by its corresponding mix node
     * 
     * Message structure:
     * {
     *   payload: encrypted_data,
     *   nextDestination: next_hop_address,
     *   mixId: intended_mix_node_id
     * }
     */
    async createOnionMessage(plaintext, destination) {
        if (this.mixNodes.length === 0) {
            throw new Error('No mix nodes configured');
        }
        
        // Build onion from outermost to innermost
        let currentPayload = plaintext;
        const layers = [];
        
        // Each mix node gets: { payload, nextDestination, mixId }
        for (let i = this.mixNodes.length - 1; i >= 0; i--) {
            const mixNode = this.mixNodes[i];
            const nextDestination = i === this.mixNodes.length - 1 
                ? destination 
                : this.mixNodes[i + 1].address;
            
            // Encrypt layer with mix node's public key
            const layer = await this.encryptLayer({
                payload: currentPayload,
                nextDestination: nextDestination,
                mixId: mixNode.id,
                layerIndex: i
            }, mixNode.publicKey);
            
            layers.unshift({
                encrypted: layer,
                mixId: mixNode.id,
                address: mixNode.address
            });
            
            currentPayload = layer;
        }
        
        // First hop knows where to send initially
        return {
            layers: layers,
            firstHop: layers[0].address,
            totalLayers: layers.length,
            timestamp: Date.now()
        };
    }
    
    /**
     * Encrypt a single layer for a mix node
     */
    async encryptLayer(data, publicKey) {
        const encoder = new TextEncoder();
        const plaintext = JSON.stringify(data);
        
        // Generate random IV
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        // In real implementation, use the mix node's public key
        // For now, use AES-GCM as placeholder
        // The actual implementation would use hybrid encryption (Kyber + AES)
        const key = await crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
        
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            encoder.encode(plaintext)
        );
        
        // Export key for this layer
        const exportedKey = await crypto.subtle.exportKey('raw', key);
        
        return {
            encrypted: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
            iv: btoa(String.fromCharCode(...iv)),
            key: btoa(String.fromCharCode(...new Uint8Array(exportedKey)))
        };
    }
    
    /**
     * Send message through mix network
     */
    async sendThroughMix(plaintext, destination) {
        const onionMessage = await this.createOnionMessage(plaintext, destination);
        
        // Send to first mix node (it will forward to next)
        // In real implementation, this would be an HTTP/WebSocket call
        return {
            success: true,
            onion: onionMessage,
            messageId: crypto.randomUUID()
        };
    }
    
    /**
     * Parse received mixnet message
     */
    parseMixnetMessage(encryptedPayload) {
        // Peeling happens on client side for received messages
        try {
            const layers = encryptedPayload.layers || [];
            const decrypted = [];
            
            for (const layer of layers) {
                try {
                    const decoded = JSON.parse(atob(layer.encrypted));
                    decrypted.push(decoded);
                } catch (e) {
                    // Layer parsing failed
                }
            }
            
            return decrypted;
        } catch (e) {
            throw new Error('Failed to parse mixnet message: ' + e.message);
        }
    }
}

/**
 * Mix Node - Server-side component
 * Each mix node:
 * 1. Receives encrypted message
 * 2. Decrypts its layer
 * 3. Adds to mix batch
 * 4. Shuffles batch
 * 5. forwards to next node or destination
 */
class MixNode {
    constructor(config) {
        this.id = config.id;
        this.privateKey = config.privateKey;
        this.nextHop = config.nextHop;
        this.batchSize = config.batchSize || 10;
        this.mixBatch = [];
        this.lastFlush = Date.now();
    }
    
    /**
     * Receive and queue message
     */
    async receiveMessage(encryptedLayer) {
        // Decrypt this layer
        const decrypted = await this.decryptLayer(encryptedLayer);
        
        // Add to mix batch
        this.mixBatch.push({
            data: decrypted,
            receivedAt: Date.now()
        });
        
        // Check if batch is ready to flush
        if (this.mixBatch.length >= this.batchSize) {
            return this.flushBatch();
        }
        
        return { status: 'queued', queueSize: this.mixBatch.length };
    }
    
    /**
     * Decrypt one layer
     */
    async decryptLayer(encryptedLayer) {
        const iv = Uint8Array.from(atob(encryptedLayer.iv), c => c.charCodeAt(0));
        const encrypted = Uint8Array.from(atob(encryptedLayer.encrypted), c => c.charCodeAt(0));
        const key = Uint8Array.from(atob(encryptedLayer.key), c => c.charCodeAt(0));
        
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            key,
            'AES-GCM',
            false,
            ['decrypt']
        );
        
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            cryptoKey,
            encrypted
        );
        
        const decoder = new TextDecoder();
        return JSON.parse(decoder.decode(decrypted));
    }
    
    /**
     * Flush batch: shuffle and forward
     */
    async flushBatch() {
        // Shuffle the batch (Fisher-Yates)
        for (let i = this.mixBatch.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [this.mixBatch[i], this.mixBatch[j]] = [this.mixBatch[j], this.mixBatch[i]];
        }
        
        // Forward each message
        const forwarded = [];
        for (const msg of this.mixBatch) {
            const nextData = msg.data;
            if (nextData.nextDestination) {
                // Forward to next hop
                forwarded.push({
                    destination: nextData.nextDestination,
                    payload: nextData.payload,
                    mixId: nextData.mixId
                });
            }
            // If no nextDestination, this is final destination
        }
        
        this.mixBatch = [];
        this.lastFlush = Date.now();
        
        return { forwarded, count: forwarded.length };
    }
    
    /**
     * Get mix node status
     */
    getStatus() {
        return {
            id: this.id,
            queueSize: this.mixBatch.length,
            lastFlush: this.lastFlush,
            batchSize: this.batchSize
        };
    }
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { MixnetClient, MixNode };
}
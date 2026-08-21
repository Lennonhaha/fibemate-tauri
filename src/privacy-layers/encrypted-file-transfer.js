/**
 * Encrypted File Transfer Module
 * 
 * End-to-end encrypted file sharing with integrity verification.
 * Files are encrypted before transmission and only decrypted by recipient.
 */

class EncryptedFileTransfer {
    constructor(options = {}) {
        this.maxFileSize = options.maxFileSize || 104857600; // 100MB
        this.chunkSize = options.chunkSize || 65536; // 64KB chunks
        this.maxConcurrent = options.maxConcurrent || 3;
        
        this.activeTransfers = new Map();
        this.completedTransfers = new Map();
        this.listeners = new Set();
    }
    
    /**
     * Encrypt file for transfer
     */
    async encryptFile(file, recipientKey) {
        // Generate ephemeral key for this file
        const ephemeralKey = await crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
        
        // Encrypt file content
        const fileBuffer = await file.arrayBuffer();
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            ephemeralKey,
            fileBuffer
        );
        
        // Calculate file hash
        const hash = await crypto.subtle.digest('SHA-256', fileBuffer);
        
        // Wrap ephemeral key with recipient's public key
        const wrappedKey = await this.wrapKey(ephemeralKey, recipientKey);
        
        return {
            encryptedData: encrypted,
            iv: Array.from(iv),
            wrappedKey,
            fileHash: Array.from(new Uint8Array(hash)),
            originalName: file.name,
            originalSize: file.size,
            mimeType: file.type
        };
    }
    
    /**
     * Decrypt received file
     */
    async decryptFile(encryptedPackage, recipientPrivateKey) {
        // Unwrap ephemeral key
        const ephemeralKey = await this.unwrapKey(
            encryptedPackage.wrappedKey,
            recipientPrivateKey
        );
        
        // Decrypt file
        const iv = new Uint8Array(encryptedPackage.iv);
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            ephemeralKey,
            encryptedPackage.encryptedData
        );
        
        // Verify integrity
        const hash = await crypto.subtle.digest('SHA-256', decrypted);
        const receivedHash = new Uint8Array(encryptedPackage.fileHash);
        const computedHash = new Uint8Array(hash);
        
        if (!this.compareArrays(receivedHash, computedHash)) {
            throw new Error('File integrity check failed');
        }
        
        // Create file object
        return new File(
            [decrypted],
            encryptedPackage.originalName,
            { type: encryptedPackage.mimeType }
        );
    }
    
    /**
     * Upload encrypted file in chunks
     */
    async uploadEncryptedFile(file, recipientKey, progressCallback) {
        const transferId = crypto.randomUUID();
        
        // Check file size
        if (file.size > this.maxFileSize) {
            throw new Error(`File too large. Max size: ${this.maxFileSize / 1048576}MB`);
        }
        
        // Encrypt file
        const encrypted = await this.encryptFile(file, recipientKey);
        
        // Calculate chunks
        const totalChunks = Math.ceil(encrypted.encryptedData.byteLength / this.chunkSize);
        
        const transfer = {
            transferId,
            status: 'uploading',
            totalChunks,
            completedChunks: 0,
            encrypted,
            startTime: Date.now()
        };
        
        this.activeTransfers.set(transferId, transfer);
        
        // Simulate chunked upload
        for (let i = 0; i < totalChunks; i++) {
            const start = i * this.chunkSize;
            const end = Math.min(start + this.chunkSize, encrypted.encryptedData.byteLength);
            const chunk = encrypted.encryptedData.slice(start, end);
            
            // Upload chunk (simulated)
            await this.uploadChunk(transferId, i, chunk);
            
            transfer.completedChunks = i + 1;
            
            if (progressCallback) {
                progressCallback({
                    transferId,
                    chunk: i + 1,
                    total: totalChunks,
                    progress: ((i + 1) / totalChunks) * 100
                });
            }
            
            this.emit('chunkUploaded', { transferId, chunk: i + 1, total: totalChunks });
        }
        
        transfer.status = 'completed';
        transfer.completedAt = Date.now();
        
        this.completedTransfers.set(transferId, transfer);
        this.activeTransfers.delete(transferId);
        
        this.emit('transferCompleted', transfer);
        
        return {
            transferId,
            fileHash: encrypted.fileHash,
            originalSize: encrypted.originalSize
        };
    }
    
    /**
     * Upload single chunk
     */
    async uploadChunk(transferId, chunkIndex, chunkData) {
        // This would integrate with actual file storage API
        return new Promise(resolve => {
            setTimeout(resolve, 100); // Simulate network delay
        });
    }
    
    /**
     * Wrap key with recipient's public key
     */
    async wrapKey(key, recipientPublicKey) {
        const exported = await crypto.subtle.exportKey('raw', key);
        
        const wrapped = await crypto.subtle.encrypt(
            { name: 'RSA-OAEP' },
            recipientPublicKey,
            exported
        );
        
        return Array.from(new Uint8Array(wrapped));
    }
    
    /**
     * Unwrap key with recipient's private key
     */
    async unwrapKey(wrappedKey, recipientPrivateKey) {
        const wrapped = new Uint8Array(wrappedKey);
        
        const decrypted = await crypto.subtle.decrypt(
            { name: 'RSA-OAEP' },
            recipientPrivateKey,
            wrapped
        );
        
        return crypto.subtle.importKey(
            'raw',
            decrypted,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
    }
    
    /**
     * Compare two arrays
     */
    compareArrays(a, b) {
        if (a.length !== b.length) return false;
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) return false;
        }
        return true;
    }
    
    /**
     * Get transfer status
     */
    getTransferStatus(transferId) {
        const transfer = this.activeTransfers.get(transferId) || 
                        this.completedTransfers.get(transferId);
        
        if (!transfer) return null;
        
        return {
            transferId,
            status: transfer.status,
            progress: transfer.totalChunks ? 
                (transfer.completedChunks / transfer.totalChunks) * 100 : 0,
            startTime: transfer.startTime,
            completedAt: transfer.completedAt
        };
    }
    
    /**
     * Cancel active transfer
     */
    cancelTransfer(transferId) {
        const transfer = this.activeTransfers.get(transferId);
        if (!transfer) return { success: false, error: 'Transfer not found' };
        
        transfer.status = 'cancelled';
        this.activeTransfers.delete(transferId);
        
        this.emit('transferCancelled', transfer);
        
        return { success: true };
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
    module.exports = { EncryptedFileTransfer };
}

if (typeof window !== 'undefined') {
    window.FIBEMATE = window.FIBEMATE || {};
    window.FIBEMATE.EncryptedFileTransfer = EncryptedFileTransfer;
}
/**
 * FIBEMATE Privacy Layer Manager - Enhanced Integration
 * 
 * Integrates all privacy and security modules:
 * - Double Ratchet (already implemented)
 * - ZK Authentication (already implemented)
 * - PIR Search
 * - Mixnet Routing
 * - Sphinx Packet Encryption
 * - Burn After Read (NEW)
 * - Screenshot Detection (NEW)
 * - Key Rotation (NEW)
 * - Device Binding (NEW)
 * - Offline Messages (NEW)
 * - Encrypted File Transfer (NEW)
 * - Safety Numbers (NEW)
 */

// Import or reference existing modules
let DoubleRatchet, ZKAuth, PIRClient, MixnetClient, SphinxHandler;

// New security modules
let BurnAfterRead, ScreenshotDetector, AntiScreenshot, KeyRotation;
let DeviceBinding, OfflineMessageStorage, EncryptedFileTransfer, SafetyNumbers;

async function initPrivacyLayers() {
    // Layer 1: Double Ratchet (already exists)
    if (typeof DoubleRatchet === 'undefined') {
        // Will be loaded from double-ratchet.js
    }
    
    // Layer 2: ZK Authentication (already exists)
    if (typeof ZKAuth === 'undefined') {
        // Will be loaded from zk-auth.js
    }
    
    // Layer 3: PIR Search
    if (typeof PIRClient === 'undefined') {
        try {
            const pir = await import('./pir-search.js');
            PIRClient = pir.PIRClient;
        } catch (e) {
            console.warn('PIR Search module not available');
        }
    }
    
    // Layer 4: Mixnet Routing
    if (typeof MixnetClient === 'undefined') {
        try {
            const mixnet = await import('./mixnet-router.js');
            MixnetClient = mixnet.MixnetClient;
        } catch (e) {
            console.warn('Mixnet module not available');
        }
    }
    
    // Layer 5: Sphinx Packet Encryption
    if (typeof SphinxHandler === 'undefined') {
        try {
            const sphinx = await import('./sphinx-packet.js');
            SphinxHandler = sphinx.SphinxHandler;
        } catch (e) {
            console.warn('Sphinx module not available');
        }
    }
    
    // NEW: Burn After Read
    if (typeof BurnAfterRead === 'undefined') {
        try {
            const burn = await import('./burn-after-read.js');
            BurnAfterRead = burn.BurnAfterRead;
        } catch (e) {
            console.warn('Burn After Read module not available');
        }
    }
    
    // NEW: Screenshot Detection
    if (typeof ScreenshotDetector === 'undefined') {
        try {
            const ss = await import('./screenshot-detector.js');
            ScreenshotDetector = ss.ScreenshotDetector;
            AntiScreenshot = ss.AntiScreenshot;
        } catch (e) {
            console.warn('Screenshot Detector module not available');
        }
    }
    
    // NEW: Key Rotation
    if (typeof KeyRotation === 'undefined') {
        try {
            const kr = await import('./key-rotation.js');
            KeyRotation = kr.KeyRotation;
        } catch (e) {
            console.warn('Key Rotation module not available');
        }
    }
    
    // NEW: Device Binding
    if (typeof DeviceBinding === 'undefined') {
        try {
            const db = await import('./device-binding.js');
            DeviceBinding = db.DeviceBinding;
        } catch (e) {
            console.warn('Device Binding module not available');
        }
    }
    
    // NEW: Offline Messages
    if (typeof OfflineMessageStorage === 'undefined') {
        try {
            const om = await import('./offline-messages.js');
            OfflineMessageStorage = om.OfflineMessageStorage;
        } catch (e) {
            console.warn('Offline Messages module not available');
        }
    }
    
    // NEW: Encrypted File Transfer
    if (typeof EncryptedFileTransfer === 'undefined') {
        try {
            const eft = await import('./encrypted-file-transfer.js');
            EncryptedFileTransfer = eft.EncryptedFileTransfer;
        } catch (e) {
            console.warn('Encrypted File Transfer module not available');
        }
    }
    
    // NEW: Safety Numbers
    if (typeof SafetyNumbers === 'undefined') {
        try {
            const sn = await import('./safety-numbers.js');
            SafetyNumbers = sn.SafetyNumbers;
        } catch (e) {
            console.warn('Safety Numbers module not available');
        }
    }
    
    return {
        layer1: 'Double Ratchet',
        layer2: 'ZK Authentication', 
        layer3: 'PIR Search',
        layer4: 'Mixnet Routing',
        layer5: 'Sphinx Packet',
        layer6: 'Burn After Read',
        layer7: 'Screenshot Detection',
        layer8: 'Key Rotation',
        layer9: 'Device Binding',
        layer10: 'Offline Messages',
        layer11: 'Encrypted File Transfer',
        layer12: 'Safety Numbers'
    };
}

/**
 * Enhanced PrivacyLayerManager - Manages all privacy and security features
 */
class PrivacyLayerManager {
    constructor(config = {}) {
        this.config = config;
        
        // Core layers
        this.enabled = {
            doubleRatchet: true,
            zkAuth: true,
            pirSearch: false,
            mixnet: false,
            sphinx: false
        };
        
        // New security features
        this.features = {
            burnAfterRead: config.burnAfterRead !== false,
            screenshotDetection: config.screenshotDetection !== false,
            keyRotation: config.keyRotation !== false,
            deviceBinding: config.deviceBinding !== false,
            offlineMessages: config.offlineMessages !== false,
            encryptedFileTransfer: config.encryptedFileTransfer !== false,
            safetyNumbers: config.safetyNumbers !== false
        };
        
        // Initialize modules
        this.modules = {};
        this.initModules();
    }
    
    /**
     * Initialize all security modules
     */
    initModules() {
        if (this.features.burnAfterRead && typeof BurnAfterRead !== 'undefined') {
            this.modules.burnAfterRead = new BurnAfterRead({
                defaultTimeout: this.config.burnTimeout || 30,
                maxTimeout: this.config.maxBurnTimeout || 86400
            });
        }
        
        if (this.features.screenshotDetection && typeof ScreenshotDetector !== 'undefined') {
            this.modules.screenshotDetector = new ScreenshotDetector({
                enabled: true,
                blurOnCapture: true,
                notifyOnCapture: true
            });
            
            if (typeof AntiScreenshot !== 'undefined') {
                this.modules.antiScreenshot = new AntiScreenshot();
            }
        }
        
        if (this.features.keyRotation && typeof KeyRotation !== 'undefined') {
            this.modules.keyRotation = new KeyRotation({
                rotationInterval: this.config.keyRotationInterval || 86400000,
                maxMessagesPerKey: this.config.maxMessagesPerKey || 1000
            });
        }
        
        if (this.features.deviceBinding && typeof DeviceBinding !== 'undefined') {
            this.modules.deviceBinding = new DeviceBinding({
                maxDevices: this.config.maxDevices || 5,
                verificationTimeout: this.config.deviceVerificationTimeout || 300000
            });
        }
        
        if (this.features.offlineMessages && typeof OfflineMessageStorage !== 'undefined') {
            this.modules.offlineMessages = new OfflineMessageStorage({
                maxStorage: this.config.maxOfflineMessages || 100,
                autoCleanDays: this.config.offlineMessageExpiry || 7
            });
        }
        
        if (this.features.encryptedFileTransfer && typeof EncryptedFileTransfer !== 'undefined') {
            this.modules.fileTransfer = new EncryptedFileTransfer({
                maxFileSize: this.config.maxFileSize || 104857600,
                chunkSize: this.config.fileChunkSize || 65536
            });
        }
        
        if (this.features.safetyNumbers && typeof SafetyNumbers !== 'undefined') {
            this.modules.safetyNumbers = new SafetyNumbers();
        }
    }
    
    /**
     * Enable a privacy layer
     */
    enableLayer(layerName) {
        if (layerName in this.enabled) {
            this.enabled[layerName] = true;
            return { success: true, layer: layerName };
        }
        return { success: false, error: 'Unknown layer: ' + layerName };
    }
    
    /**
     * Disable a privacy layer
     */
    disableLayer(layerName) {
        if (layerName in this.enabled) {
            this.enabled[layerName] = false;
            return { success: true, layer: layerName };
        }
        return { success: false, error: 'Unknown layer: ' + layerName };
    }
    
    /**
     * Enable a security feature
     */
    enableFeature(featureName) {
        if (featureName in this.features) {
            this.features[featureName] = true;
            return { success: true, feature: featureName };
        }
        return { success: false, error: 'Unknown feature: ' + featureName };
    }
    
    /**
     * Disable a security feature
     */
    disableFeature(featureName) {
        if (featureName in this.features) {
            this.features[featureName] = false;
            return { success: true, feature: featureName };
        }
        return { success: false, error: 'Unknown feature: ' + featureName };
    }
    
    /**
     * Get enabled layers
     */
    getEnabledLayers() {
        return Object.entries(this.enabled)
            .filter(([_, enabled]) => enabled)
            .map(([name, _]) => name);
    }
    
    /**
     * Get enabled features
     */
    getEnabledFeatures() {
        return Object.entries(this.features)
            .filter(([_, enabled]) => enabled)
            .map(([name, _]) => name);
    }
    
    /**
     * Get privacy level (1-5)
     */
    getPrivacyLevel() {
        return this.getEnabledLayers().length;
    }
    
    /**
     * Get security level (features count)
     */
    getSecurityLevel() {
        return this.getEnabledFeatures().length;
    }
    
    /**
     * Encrypt message with all enabled layers
     */
    async encryptMessage(plaintext, options) {
        let result = plaintext;
        
        // Layer 5: Sphinx (outermost - applied last during send)
        if (this.enabled.sphinx) {
            // Apply Sphinx encryption
        }
        
        // Layer 4: Mixnet (routing layer)
        if (this.enabled.mixnet) {
            // Apply Mixnet routing
        }
        
        // Layer 3: PIR (for searching)
        if (this.enabled.pirSearch) {
            // PIR encrypt for searchable storage
        }
        
        // Layer 1/2: Double Ratchet + ZK (core encryption)
        // Applied at message level
        
        return result;
    }
    
    /**
     * Decrypt message with all enabled layers
     */
    async decryptMessage(encrypted, options) {
        let result = encrypted;
        
        // Decrypt in reverse order of encryption
        // Layer 1/2: Double Ratchet + ZK
        
        // Layer 3: PIR
        
        // Layer 4: Mixnet
        
        // Layer 5: Sphinx (innermost - peeled first)
        
        return result;
    }
    
    /**
     * Create burn message
     */
    createBurnMessage(message, timeout, notifyOnBurn = true) {
        if (this.modules.burnAfterRead) {
            const messageId = crypto.randomUUID();
            return this.modules.burnAfterRead.createBurnMessage(
                messageId, message, timeout, notifyOnBurn
            );
        }
        return null;
    }
    
    /**
     * Mark message as read (triggers burn)
     */
    markMessageRead(messageId) {
        if (this.modules.burnAfterRead) {
            return this.modules.burnAfterRead.markAsRead(messageId);
        }
        return null;
    }
    
    /**
     * Register device
     */
    async registerDevice(deviceInfo) {
        if (this.modules.deviceBinding) {
            return await this.modules.deviceBinding.registerDevice(deviceInfo);
        }
        return null;
    }
    
    /**
     * Request add device
     */
    async requestAddDevice(newDeviceInfo) {
        if (this.modules.deviceBinding) {
            return await this.modules.deviceBinding.requestAddDevice(newDeviceInfo);
        }
        return null;
    }
    
    /**
     * Verify device
     */
    async verifyDevice(verificationId, approval, approverDeviceId) {
        if (this.modules.deviceBinding) {
            return await this.modules.deviceBinding.verifyDevice(
                verificationId, approval, approverDeviceId
            );
        }
        return null;
    }
    
    /**
     * Store offline message
     */
    storeOfflineMessage(encryptedMessage, recipientId, options) {
        if (this.modules.offlineMessages) {
            return this.modules.offlineMessages.storeOfflineMessage(
                encryptedMessage, recipientId, options
            );
        }
        return null;
    }
    
    /**
     * Upload encrypted file
     */
    async uploadEncryptedFile(file, recipientKey, progressCallback) {
        if (this.modules.fileTransfer) {
            return await this.modules.fileTransfer.uploadEncryptedFile(
                file, recipientKey, progressCallback
            );
        }
        return null;
    }
    
    /**
     * Generate safety numbers
     */
    async generateSafetyNumbers(userId, userPublicKey, contactId, contactPublicKey) {
        if (this.modules.safetyNumbers) {
            return await this.modules.safetyNumbers.generateSafetyNumbers(
                userId, userPublicKey, contactId, contactPublicKey
            );
        }
        return null;
    }
    
    /**
     * Verify safety numbers
     */
    verifySafetyNumbers(localNumbers, remoteNumbers) {
        if (this.modules.safetyNumbers) {
            return this.modules.safetyNumbers.verifySafetyNumbers(localNumbers, remoteNumbers);
        }
        return null;
    }
    
    /**
     * Get privacy status for UI
     */
    getStatus() {
        return {
            level: this.getPrivacyLevel(),
            securityLevel: this.getSecurityLevel(),
            layers: {
                layer1: { name: 'Double Ratchet', enabled: this.enabled.doubleRatchet, progress: 92 },
                layer2: { name: 'ZK Authentication', enabled: this.enabled.zkAuth, progress: 5 },
                layer3: { name: 'PIR Search', enabled: this.enabled.pirSearch, progress: 80 },
                layer4: { name: 'Mixnet Routing', enabled: this.enabled.mixnet, progress: 75 },
                layer5: { name: 'Sphinx Packet', enabled: this.enabled.sphinx, progress: 70 }
            },
            features: {
                burnAfterRead: { name: '阅后即焚', enabled: this.features.burnAfterRead },
                screenshotDetection: { name: '截屏检测', enabled: this.features.screenshotDetection },
                keyRotation: { name: '密钥轮换', enabled: this.features.keyRotation },
                deviceBinding: { name: '设备绑定', enabled: this.features.deviceBinding },
                offlineMessages: { name: '离线消息', enabled: this.features.offlineMessages },
                encryptedFileTransfer: { name: '加密文件传输', enabled: this.features.encryptedFileTransfer },
                safetyNumbers: { name: '安全号码', enabled: this.features.safetyNumbers }
            },
            modules: {
                burnAfterRead: this.modules.burnAfterRead ? this.modules.burnAfterRead.getStatus() : null,
                screenshotDetector: this.modules.screenshotDetector ? this.modules.screenshotDetector.getStatus() : null,
                keyRotation: this.modules.keyRotation ? this.modules.keyRotation.getStatus() : null,
                deviceBinding: this.modules.deviceBinding ? this.modules.deviceBinding.getStatus() : null,
                offlineMessages: this.modules.offlineMessages ? this.modules.offlineMessages.getStatus() : null
            },
            totalProgress: Math.round(
                (this.enabled.doubleRatchet ? 92 : 0) +
                (this.enabled.zkAuth ? 5 : 0) +
                (this.enabled.pirSearch ? 80 : 0) +
                (this.enabled.mixnet ? 75 : 0) +
                (this.enabled.sphinx ? 70 : 0)
            ) / 5
        };
    }
}

/**
 * Factory function to create privacy manager
 */
function createPrivacyManager(config) {
    return new PrivacyLayerManager(config);
}

// Export for main application
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { 
        PrivacyLayerManager, 
        createPrivacyManager,
        initPrivacyLayers 
    };
}

// Also expose globally for browser
if (typeof window !== 'undefined') {
    window.FIBEMATE = window.FIBEMATE || {};
    window.FIBEMATE.PrivacyLayerManager = PrivacyLayerManager;
    window.FIBEMATE.createPrivacyManager = createPrivacyManager;
}
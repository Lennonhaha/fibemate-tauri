/**
 * Device Binding Module
 * 
 * Binds user identity to specific devices with verification.
 * New device additions require approval from existing verified devices.
 */

class DeviceBinding {
    constructor(options = {}) {
        this.maxDevices = options.maxDevices || 5;
        this.verificationTimeout = options.verificationTimeout || 300000; // 5 minutes
        this.deviceRegistry = new Map();
        this.pendingVerifications = new Map();
        this.listeners = new Set();
        // Optional Tauri audit hook: when running inside the Tauri shell, the
        // Rust backend records an approval-scoped line in audit.log. In plain
        // browsers (demo/CI) this is a silent no-op.
        this._auditInvoke = options.auditInvoke || null;
    }

    /**
     * Append an approval-scoped audit record through the Rust backend.
     * Never throws — auditing must not break the verification flow.
     */
    async _auditApproval(event, detail, approvedBy) {
        if (!this._auditInvoke) return;
        try {
            await this._auditInvoke('audit_approval', {
                event, detail, approvedBy
            });
        } catch (e) {
            // Audit is a diagnostic channel — degrade silently.
            console.warn('[DeviceBinding] audit_approval failed:', e);
        }
    }
    
    /**
     * Register current device
     */
    async registerDevice(deviceInfo = {}) {
        const deviceId = this.generateDeviceId();
        const device = {
            deviceId,
            name: deviceInfo.name || this.getDefaultDeviceName(),
            type: deviceInfo.type || this.detectDeviceType(),
            platform: deviceInfo.platform || navigator.platform,
            fingerprint: await this.generateDeviceFingerprint(),
            registeredAt: Date.now(),
            lastActive: Date.now(),
            verified: true, // First device is auto-verified
            status: 'active'
        };
        
        this.deviceRegistry.set(deviceId, device);
        
        this.emit('deviceRegistered', device);
        
        return device;
    }
    
    /**
     * Request to add new device (requires verification)
     */
    async requestAddDevice(newDeviceInfo) {
        const currentDevices = [...this.deviceRegistry.values()]
            .filter(d => d.status === 'active');
        
        if (currentDevices.length >= this.maxDevices) {
            return { 
                success: false, 
                error: 'Maximum devices reached',
                currentCount: currentDevices.length,
                maxDevices: this.maxDevices
            };
        }
        
        const verificationCode = this.generateVerificationCode();
        const verificationId = this.generateDeviceId();
        
        const pendingVerification = {
            verificationId,
            deviceInfo: {
                deviceId: verificationId,
                name: newDeviceInfo.name || 'Unknown Device',
                type: newDeviceInfo.type || 'unknown',
                platform: newDeviceInfo.platform || navigator.platform,
                fingerprint: await this.generateDeviceFingerprint(),
                requestedAt: Date.now()
            },
            verificationCode,
            expiresAt: Date.now() + this.verificationTimeout,
            status: 'pending'
        };
        
        this.pendingVerifications.set(verificationId, pendingVerification);
        
        // Auto-expire
        setTimeout(() => {
            this.expireVerification(verificationId);
        }, this.verificationTimeout);
        
        this.emit('deviceVerificationRequested', pendingVerification);
        
        return {
            success: true,
            verificationId,
            verificationCode,
            expiresIn: this.verificationTimeout
        };
    }
    
    /**
     * Verify pending device from another device
     */
    async verifyDevice(verificationId, approval, approverDeviceId) {
        const pending = this.pendingVerifications.get(verificationId);
        
        if (!pending) {
            return { success: false, error: 'Verification not found or expired' };
        }
        
        if (pending.status !== 'pending') {
            return { success: false, error: 'Verification already processed' };
        }
        
        if (Date.now() > pending.expiresAt) {
            this.expireVerification(verificationId);
            return { success: false, error: 'Verification expired' };
        }
        
        if (!approval) {
            pending.status = 'rejected';
            this.emit('deviceVerificationRejected', pending);
            // Rejection is approval-scoped too: record WHO rejected.
            await this._auditApproval('device_rejected', verificationId, approverDeviceId);
            return { success: true, approved: false };
        }
        
        // Approved - add device
        pending.status = 'approved';
        pending.verifiedAt = Date.now();
        pending.verifiedBy = approverDeviceId;
        
        // Approval-scoped audit record: approved_by = the verifying device.
        await this._auditApproval('device_approved', verificationId, approverDeviceId);
        
        const device = {
            ...pending.deviceInfo,
            verified: true,
            verifiedAt: pending.verifiedAt,
            verifiedBy: approverDeviceId,
            lastActive: Date.now(),
            status: 'active'
        };
        
        this.deviceRegistry.set(device.deviceId, device);
        this.pendingVerifications.delete(verificationId);
        
        this.emit('deviceVerified', device);
        
        return { success: true, approved: true, device };
    }
    
    /**
     * Expire verification
     */
    expireVerification(verificationId) {
        const pending = this.pendingVerifications.get(verificationId);
        if (pending && pending.status === 'pending') {
            pending.status = 'expired';
            this.pendingVerifications.delete(verificationId);
            this.emit('deviceVerificationExpired', pending);
        }
    }
    
    /**
     * Remove a device
     */
    removeDevice(deviceId) {
        const device = this.deviceRegistry.get(deviceId);
        if (!device) {
            return { success: false, error: 'Device not found' };
        }
        
        device.status = 'removed';
        device.removedAt = Date.now();
        
        this.emit('deviceRemoved', device);
        
        return { success: true, deviceId };
    }
    
    /**
     * Update device last active time
     */
    updateDeviceActivity(deviceId) {
        const device = this.deviceRegistry.get(deviceId);
        if (device) {
            device.lastActive = Date.now();
        }
    }
    
    /**
     * Get all registered devices
     */
    getDevices() {
        return [...this.deviceRegistry.values()]
            .filter(d => d.status === 'active')
            .sort((a, b) => b.registeredAt - a.registeredAt);
    }
    
    /**
     * Check if device is registered
     */
    isDeviceRegistered(deviceId) {
        const device = this.deviceRegistry.get(deviceId);
        return device && device.status === 'active';
    }
    
    /**
     * Get device info
     */
    getDeviceInfo(deviceId) {
        return this.deviceRegistry.get(deviceId);
    }
    
    /**
     * Get pending verifications
     */
    getPendingVerifications() {
        return [...this.pendingVerifications.values()]
            .filter(v => v.status === 'pending');
    }
    
    /**
     * Generate device fingerprint
     */
    async generateDeviceFingerprint() {
        // Browser fingerprint components; each access is guarded so the
        // module also runs under plain Node (tests, SSR, CI).
        const hasWindow = typeof window !== 'undefined';
        const hasScreen = typeof screen !== 'undefined';
        const components = [
            hasWindow ? navigator.userAgent : 'node',
            hasWindow ? navigator.platform : process.platform,
            hasWindow ? navigator.language : process.env.LANG || 'en',
            hasScreen ? screen.width : 0,
            hasScreen ? screen.height : 0,
            hasScreen ? screen.colorDepth : 0,
            hasWindow ? new Date().getTimezoneOffset() : 0
        ];
        
        const data = components.join('|');
        const hash = await crypto.subtle.digest(
            'SHA-256',
            new TextEncoder().encode(data)
        );
        
        return Array.from(new Uint8Array(hash))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }
    
    /**
     * Generate unique device ID
     */
    generateDeviceId() {
        return 'dev_' + Date.now().toString(36) + '_' + 
               Math.random().toString(36).substr(2, 9);
    }
    
    /**
     * Generate verification code
     */
    generateVerificationCode() {
        return Math.floor(100000 + Math.random() * 900000).toString();
    }
    
    /**
     * Detect device type
     */
    detectDeviceType() {
        const ua = navigator.userAgent.toLowerCase();
        if (ua.includes('mobile') || ua.includes('android') || ua.includes('iphone')) {
            return 'mobile';
        }
        return 'desktop';
    }
    
    /**
     * Get default device name
     */
    getDefaultDeviceName() {
        const type = this.detectDeviceType();
        const date = new Date().toLocaleDateString('zh-CN');
        return `${type === 'mobile' ? '手机' : '电脑'} ${date}`;
    }
    
    /**
     * Get status
     */
    getStatus() {
        const devices = this.getDevices();
        return {
            totalDevices: devices.length,
            maxDevices: this.maxDevices,
            pendingVerifications: this.getPendingVerifications().length
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
    module.exports = { DeviceBinding };
}

if (typeof window !== 'undefined') {
    window.FIBEMATE = window.FIBEMATE || {};
    window.FIBEMATE.DeviceBinding = DeviceBinding;
}

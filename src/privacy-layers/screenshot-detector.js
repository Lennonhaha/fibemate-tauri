/**
 * Screenshot Detection Module
 * 
 * Detects when user takes screenshots or screen recordings
 * and automatically blurs/hides content + notifies the conversation partner.
 */

class ScreenshotDetector {
    constructor(options = {}) {
        this.enabled = options.enabled !== false;
        this.blurOnCapture = options.blurOnCapture !== false;
        this.notifyOnCapture = options.notifyOnCapture !== false;
        this.blockCapture = options.blockCapture || false;
        
        this.listeners = new Set();
        this.captureHistory = [];
        this.isBlurred = false;
        
        this.init();
    }
    
    init() {
        if (typeof window !== 'undefined' && typeof desktopCapturer !== 'undefined') {
            this.setupDesktopCapture();
        }
        
        // Also check for media devices
        if (navigator.mediaDevices && navigator.mediaDevices.getDisplayMedia) {
            this.setupDisplayMediaMonitor();
        }
    }
    
    /**
     * Setup Electron desktopCapturer listener
     */
    setupDesktopCapture() {
        // Electron desktopCapturer API
        if (typeof desktopCapturer !== 'undefined') {
            desktopCapturer.on('capture', (event, sourceType, sourceId) => {
                this.handleCapture(sourceType, sourceId);
            });
        }
    }
    
    /**
     * Monitor display media for screen recording
     */
    setupDisplayMediaMonitor() {
        const originalGetDisplayMedia = navigator.mediaDevices.getDisplayMedia;
        
        navigator.mediaDevices.getDisplayMedia = async (constraints) => {
            try {
                const stream = await originalGetDisplayMedia.call(navigator.mediaDevices, constraints);
                this.handleCapture('screen_share', stream.id);
                
                // Monitor when stream ends
                stream.getVideoTracks()[0].onended = () => {
                    this.handleCaptureEnd('screen_share');
                };
                
                return stream;
            } catch (err) {
                console.error('Display capture error:', err);
                throw err;
            }
        };
    }
    
    /**
     * Handle any capture attempt
     */
    handleCapture(sourceType, sourceId) {
        const captureEvent = {
            type: sourceType,
            sourceId,
            timestamp: Date.now()
        };
        
        this.captureHistory.push(captureEvent);
        
        // Limit history
        if (this.captureHistory.length > 100) {
            this.captureHistory.shift();
        }
        
        // Trigger blur if enabled
        if (this.blurOnCapture && !this.isBlurred) {
            this.blurContent();
        }
        
        // Send notification if enabled
        if (this.notifyOnCapture) {
            this.notifyPartner(captureEvent);
        }
        
        // Emit event
        this.emit('capture', captureEvent);
        
        // Block capture if enabled (experimental - may not work on all platforms)
        if (this.blockCapture) {
            this.blockCaptureAttempt(captureEvent);
        }
    }
    
    /**
     * Handle capture end
     */
    handleCaptureEnd(sourceType) {
        const event = {
            type: sourceType,
            ended: true,
            timestamp: Date.now()
        };
        
        this.emit('captureEnd', event);
        
        // Unblur content
        if (this.isBlurred) {
            this.unblurContent();
        }
    }
    
    /**
     * Blur/hide content when capture detected
     */
    blurContent() {
        this.isBlurred = true;
        
        // Dispatch event for UI to handle blur
        window.dispatchEvent(new CustomEvent('fibemate:blurContent', {
            detail: { blurred: true }
        }));
        
        // Also emit to our listeners
        this.emit('blur', { blurred: true });
    }
    
    /**
     * Unblur content after capture ends
     */
    unblurContent() {
        this.isBlurred = false;
        
        window.dispatchEvent(new CustomEvent('fibemate:blurContent', {
            detail: { blurred: false }
        }));
        
        this.emit('blur', { blurred: false });
    }
    
    /**
     * Manually toggle blur
     */
    toggleBlur() {
        if (this.isBlurred) {
            this.unblurContent();
        } else {
            this.blurContent();
        }
        return this.isBlurred;
    }
    
    /**
     * Notify conversation partner about capture attempt
     */
    notifyPartner(captureEvent) {
        // This would integrate with the messaging system
        const notification = {
            type: 'security_alert',
            alertType: 'screenshot_detected',
            timestamp: captureEvent.timestamp,
            sourceType: captureEvent.type
        };
        
        // Send via secure channel
        this.emit('securityAlert', notification);
        
        return notification;
    }
    
    /**
     * Attempt to block capture (limited effectiveness)
     */
    blockCaptureAttempt(captureEvent) {
        // Some platforms allow blocking
        // This is a best-effort approach
        console.warn('Capture blocked:', captureEvent);
        
        // CSS-based attempt (for web content)
        document.body.style.filter = 'blur(20px)';
        
        setTimeout(() => {
            if (!this.isBlurred) {
                document.body.style.filter = '';
            }
        }, 100);
    }
    
    /**
     * Add event listener
     */
    on(event, callback) {
        this.listeners.add({ event, callback });
    }
    
    /**
     * Remove event listener
     */
    off(event, callback) {
        for (const listener of this.listeners) {
            if (listener.event === event && listener.callback === callback) {
                this.listeners.delete(listener);
                break;
            }
        }
    }
    
    /**
     * Emit event
     */
    emit(event, data) {
        for (const listener of this.listeners) {
            if (listener.event === event) {
                try {
                    listener.callback(data);
                } catch (err) {
                    console.error('Listener error:', err);
                }
            }
        }
    }
    
    /**
     * Get capture history
     */
    getHistory(limit = 20) {
        return this.captureHistory.slice(-limit);
    }
    
    /**
     * Check if content is currently blurred
     */
    isContentBlurred() {
        return this.isBlurred;
    }
    
    /**
     * Get current status
     */
    getStatus() {
        return {
            enabled: this.enabled,
            isBlurred: this.isBlurred,
            blurOnCapture: this.blurOnCapture,
            notifyOnCapture: this.notifyOnCapture,
            blockCapture: this.blockCapture,
            captureCount: this.captureHistory.length
        };
    }
    
    /**
     * Enable/disable detector
     */
    setEnabled(enabled) {
        this.enabled = enabled;
    }
}

/**
 * Anti-screenshot protection (CSS + DOM based)
 */
class AntiScreenshot {
    constructor() {
        this.protected = false;
    }
    
    /**
     * Enable anti-screenshot protection
     */
    enable() {
        if (this.protected) return;
        
        // Add CSS to prevent common screenshot methods
        const style = document.createElement('style');
        style.id = 'fibemate-anti-screenshot';
        style.textContent = `
            /* Prevent text selection copy */
            * {
                -webkit-user-select: none !important;
                -moz-user-select: none !important;
                -ms-user-select: none !important;
                user-select: none !important;
            }
            
            /* Prevent context menu */
            body {
                -webkit-context-menu: none !important;
                context-menu: none !important;
            }
            
            /*Prevent screen capturereflection */
            @media screen {
                body {
                    /* Some browsers respect this */
                    -webkit-filter: blur(0px);
                }
            }
        `;
        
        document.head.appendChild(style);
        this.protected = true;
        
        // Prevent right-click
        document.addEventListener('contextmenu', this.preventDefault);
        
        // Prevent keyboard capture
        document.addEventListener('keydown', this.preventCopy);
    }
    
    /**
     * Disable protection
     */
    disable() {
        if (!this.protected) return;
        
        const style = document.getElementById('fibemate-anti-screenshot');
        if (style) style.remove();
        
        document.removeEventListener('contextmenu', this.preventDefault);
        document.removeEventListener('keydown', this.preventCopy);
        
        this.protected = false;
    }
    
    preventDefault(e) {
        e.preventDefault();
        return false;
    }
    
    preventCopy(e) {
        // Ctrl+Shift+I (DevTools), Ctrl+P (Print), etc.
        if (e.ctrlKey && e.shiftKey) {
            e.preventDefault();
            return false;
        }
        // PrtScn key
        if (e.key === 'PrintScreen') {
            e.preventDefault();
            return false;
        }
    }
}

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { ScreenshotDetector, AntiScreenshot };
}

if (typeof window !== 'undefined') {
    window.FIBEMATE = window.FIBEMATE || {};
    window.FIBEMATE.ScreenshotDetector = ScreenshotDetector;
    window.FIBEMATE.AntiScreenshot = AntiScreenshot;
}
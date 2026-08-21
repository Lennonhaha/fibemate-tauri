# FIBEMATE Privacy Layers API Documentation

## Overview

FIBEMATE Privacy Layers provide 7 core security features for end-to-end encrypted messaging:

1. **Burn After Read** - Self-destructing messages
2. **Screenshot Detection** - Detect and respond to screen captures
3. **Key Rotation** - Automatic encryption key rotation
4. **Device Binding** - Multi-device verification
5. **Offline Messages** - Encrypted offline message storage
6. **Encrypted File Transfer** - End-to-end encrypted file sharing
7. **Safety Numbers** - Contact identity verification

## Quick Start

```javascript
// Initialize privacy features
await initPrivacyFeatures();

// Send a burn-after-read message
await sendBurnMessage('Secret text', 30); // 30 second timeout

// Verify contact identity
await verifyContactSafetyNumbers('contact-id');

// Enable anti-screenshot protection
enableAntiScreenshot();
```

## Module Details

### 1. Burn After Read

Messages that automatically delete after being read.

```javascript
// Toggle burn mode in UI
toggleBurnMode();

// Send burn message programmatically
await sendBurnMessage('content', 30); // timeout in seconds

// Handle incoming burn message
function appendBurnMessage(sent, text, timestamp, timeout, messageId) {
  // UI will show countdown timer
  // Message auto-destructs when timer expires or clicked
}
```

**Configuration:**
- `defaultTimeout`: Default burn timeout (default: 30s)
- `maxTimeout`: Maximum allowed timeout (default: 86400s)

### 2. Screenshot Detection

Detects when user takes screenshots or starts screen recording.

```javascript
// Detection is automatic when privacy features are initialized
// Handle detection events:
function handleScreenshotDetected(info) {
  // Content is auto-blurred
  // Peer is notified (if in active chat)
}
```

**Features:**
- Desktop screenshot detection (Windows/macOS)
- Screen recording detection
- Automatic content blur
- Peer notification

### 3. Key Rotation

Automatically rotates encryption keys on schedule or message count.

```javascript
// Key rotation is automatic, but can be controlled:
if (privacyManager.modules.keyRotation) {
  // Start/stop auto rotation
  privacyManager.modules.keyRotation.startAutoRotation();
  privacyManager.modules.keyRotation.stopAutoRotation();
  
  // Manual rotation
  privacyManager.modules.keyRotation.rotateAllKeys();
}
```

**Configuration:**
- `rotationInterval`: Time between rotations (default: 24h)
- `maxMessagesPerKey`: Rotate after N messages (default: 1000)

### 4. Device Binding

Verify and manage trusted devices.

```javascript
// Register new device
await privacyManager.registerDevice({
  deviceId: 'unique-id',
  deviceName: 'My Laptop',
  deviceType: 'desktop'
});

// Request add device (requires approval)
await privacyManager.requestAddDevice(newDeviceInfo);

// Verify device
await privacyManager.verifyDevice(verificationId, true, approverDeviceId);
```

**Features:**
- First device auto-verified
- New devices require existing device approval
- Maximum 5 devices per account
- Device fingerprinting

### 5. Offline Messages

Store and forward encrypted messages when recipient is offline.

```javascript
// Store message for offline recipient
privacyManager.storeOfflineMessage(encryptedContent, recipientId, {
  ttl: 3600, // Time to live in seconds
  priority: 'normal'
});

// Retrieve offline messages (on reconnect)
const messages = privacyManager.modules.offlineMessages.getOfflineMessagesForRecipient(userId);
```

**Configuration:**
- `maxStorage`: Maximum stored messages (default: 100)
- `autoCleanDays`: Auto cleanup after N days (default: 7)

### 6. Encrypted File Transfer

End-to-end encrypted file sharing with integrity verification.

```javascript
// Upload file
await privacyManager.uploadEncryptedFile(file, recipientPublicKey, (progress) => {
  console.log(`Upload: ${progress.percentage}%`);
});

// Download and decrypt
const decrypted = await privacyManager.modules.fileTransfer.downloadAndDecryptFile(
  fileMetadata,
  privateKey
);
```

**Features:**
- AES-GCM encryption
- Chunked upload/download
- SHA-256 integrity check
- Progress callbacks

### 7. Safety Numbers

Verify contact identity to prevent MITM attacks.

```javascript
// Generate safety numbers for contact
const numbers = await privacyManager.generateSafetyNumbers(
  userId, userPublicKey,
  contactId, contactPublicKey
);

// Verify (compare in person or via QR code)
const result = privacyManager.verifySafetyNumbers(localNumbers, remoteNumbers);
if (result.verified) {
  // Contact identity confirmed
}
```

**Features:**
- Signal-style 60-digit numbers
- QR code verification
- Key change detection
- Verification status tracking

## Integration with Main App

### Message Sending Flow

```javascript
async function sendMessage() {
  // Check if burn mode is enabled
  if (burnMode) {
    await sendBurnMessage(text, burnTimeout);
    return;
  }
  
  // Normal encrypted message
  const encrypted = await MessageCrypto.encrypt(peerId, text);
  // Send via WebSocket or REST...
}
```

### Settings Panel

New privacy settings are automatically added to the settings panel:
- Anti-Screenshot toggle
- Screenshot Detection toggle
- Auto Key Rotation toggle

### UI Elements

New UI elements added:
- 🔥 Burn button in chat input bar
- ✓ Verify button in contact actions
- Safety numbers verification dialog

## Testing

Run the test suite:

```javascript
// In browser console
const results = await runPrivacyTests();
console.log(`Passed: ${results.passed}/${results.total}`);

// Or import in code
import { runAllTests } from './test-privacy-features.js';
const results = await runAllTests();
```

## Security Considerations

### Threat Model

FIBEMATE privacy layers protect against:
- **Passive eavesdropping** - End-to-end encryption
- **Message history theft** - Burn after read
- **Screen capture** - Screenshot detection + blur
- **Key compromise** - Automatic rotation
- **Device theft** - Device binding + verification
- **MITM attacks** - Safety numbers verification
- **Server compromise** - Offline message encryption

### Limitations

- Screenshot detection has platform-specific limitations
- Burn after read requires recipient cooperation (honest client)
- Key rotation does not protect against active real-time compromise
- Device binding requires at least one trusted device

## Changelog

### v1.0.0 (2026-05-08)
- Initial release of 7 privacy features
- Integration with FIBEMATE v3.0
- WebSocket + REST API support
- Full test coverage

## License

MIT License - See LICENSE file for details
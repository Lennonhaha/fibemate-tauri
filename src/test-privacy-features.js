/**
 * FIBEMATE Privacy Features Test Suite
 * Tests all new security modules
 */

// Test configuration
const TEST_CONFIG = {
  verbose: true,
  timeout: 5000
};

// Test results
let testResults = [];

function log(msg, type = 'info') {
  if (TEST_CONFIG.verbose) {
    const prefix = { info: '[TEST]', pass: '[PASS]', fail: '[FAIL]', warn: '[WARN]' }[type] || '[TEST]';
    console.log(`${prefix} ${msg}`);
  }
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || 'Assertion failed');
  }
}

// ================================================
// Test Cases
// ================================================

async function testBurnAfterRead() {
  log('Testing Burn After Read...');
  
  try {
    const { BurnAfterRead } = await import('./privacy-layers/burn-after-read.js');
    const burn = new BurnAfterRead({ defaultTimeout: 5 });
    
    // Test creating burn message
    const msg = burn.createBurnMessage('test-1', 'Secret message', 5, true);
    assert(msg.messageId === 'test-1', 'Message ID mismatch');
    assert(msg.content === 'Secret message', 'Content mismatch');
    assert(msg.timeout === 5, 'Timeout mismatch');
    log('Create burn message: PASS', 'pass');
    
    // Test marking as read
    const readResult = burn.markAsRead('test-1');
    assert(readResult !== null, 'Mark as read failed');
    assert(readResult.status === 'burned', 'Status should be burned');
    log('Mark as read: PASS', 'pass');
    
    // Test that message is deleted
    const deleted = burn.getBurnMessage('test-1');
    assert(deleted === null, 'Message should be deleted after burn');
    log('Message deletion: PASS', 'pass');
    
    return { name: 'Burn After Read', status: 'PASS' };
  } catch (err) {
    log(`Burn After Read failed: ${err.message}`, 'fail');
    return { name: 'Burn After Read', status: 'FAIL', error: err.message };
  }
}

async function testScreenshotDetection() {
  log('Testing Screenshot Detection...');
  
  try {
    const { ScreenshotDetector } = await import('./privacy-layers/screenshot-detector.js');
    const detector = new ScreenshotDetector();
    
    // Test initialization
    assert(detector !== null, 'Detector initialization failed');
    assert(detector.enabled === true, 'Detector should be enabled by default');
    log('Initialization: PASS', 'pass');
    
    // Test status
    const status = detector.getStatus();
    assert(status.enabled === true, 'Status should show enabled');
    log('Status check: PASS', 'pass');
    
    return { name: 'Screenshot Detection', status: 'PASS' };
  } catch (err) {
    log(`Screenshot Detection failed: ${err.message}`, 'fail');
    return { name: 'Screenshot Detection', status: 'FAIL', error: err.message };
  }
}

async function testKeyRotation() {
  log('Testing Key Rotation...');
  
  try {
    const { KeyRotation } = await import('./privacy-layers/key-rotation.js');
    const rotation = new KeyRotation({ rotationInterval: 1000, maxMessagesPerKey: 5 });
    
    // Test initialization
    assert(rotation !== null, 'KeyRotation initialization failed');
    log('Initialization: PASS', 'pass');
    
    // Test key generation
    const key = rotation.generateNewKey('test-key');
    assert(key !== null, 'Key generation failed');
    assert(key.version === 1, 'Initial version should be 1');
    log('Key generation: PASS', 'pass');
    
    // Test rotation
    rotation.rotateKey('test-key');
    const rotatedKey = rotation.getCurrentKey('test-key');
    assert(rotatedKey.version === 2, 'Version should increment after rotation');
    log('Key rotation: PASS', 'pass');
    
    return { name: 'Key Rotation', status: 'PASS' };
  } catch (err) {
    log(`Key Rotation failed: ${err.message}`, 'fail');
    return { name: 'Key Rotation', status: 'FAIL', error: err.message };
  }
}

async function testDeviceBinding() {
  log('Testing Device Binding...');
  
  try {
    // Capture approval-scoped audit calls through the injected hook.
    const auditCalls = [];
    const fakeAuditInvoke = async (event, args) => {
      auditCalls.push({ event, ...args });
      return null;
    };
    const { DeviceBinding } = await import('./privacy-layers/device-binding.js');
    const binding = new DeviceBinding({ maxDevices: 3, auditInvoke: fakeAuditInvoke });
    
    // Test device registration
    const device1 = await binding.registerDevice({
      deviceId: 'device-1',
      deviceName: 'Test Device 1',
      deviceType: 'desktop'
    });
    assert(device1.verified === true, 'First device should be auto-verified');
    log('Device registration: PASS', 'pass');
    
    // Test device limit: registerDevice is unconstrained (first-device
    // bootstrap path); the limit is enforced at requestAddDevice time.
    await binding.registerDevice({ deviceId: 'device-2', deviceName: 'Test 2', deviceType: 'mobile' });
    await binding.registerDevice({ deviceId: 'device-3', deviceName: 'Test 3', deviceType: 'tablet' });
    await binding.registerDevice({ deviceId: 'device-4', deviceName: 'Test 4', deviceType: 'desktop' });
    const limitReq = await binding.requestAddDevice({ name: 'Over Limit', type: 'laptop' });
    assert(limitReq.success === false, 'requestAddDevice must enforce max devices');
    log('Device limit enforced: PASS', 'pass');
    
    // Free slots (maxDevices=3) using real registered device ids, then run
    // the approval flow.
    const registered = binding.getDevices();
    // Leave 2 active so a pending request (1 more) fits under maxDevices=3.
    binding.removeDevice(registered[registered.length - 1].deviceId);
    binding.removeDevice(registered[registered.length - 2].deviceId);
    const req = await binding.requestAddDevice({ name: 'New Laptop', type: 'laptop' });
    assert(req.success === true, 'requestAddDevice must succeed after freeing a slot');
    const ok = await binding.verifyDevice(req.verificationId, true, 'device-1');
    assert(ok.approved === true, 'verifyDevice(true) must approve');
    assert(
      auditCalls.some(c => c.event === 'device_approved' && c.approvedBy === 'device-1'),
      'approval must emit device_approved with approver device id'
    );
    log('Device approval audit: PASS', 'pass');

    // Free a slot again before requesting the rejection-path device.
    const afterApprove = binding.getDevices();
    binding.removeDevice(afterApprove[afterApprove.length - 1].deviceId);
    const req2 = await binding.requestAddDevice({ name: 'Rogue Phone', type: 'mobile' });
    assert(req2.success === true, 'second requestAddDevice must succeed');
    const rejected = await binding.verifyDevice(req2.verificationId, false, 'device-1');
    assert(rejected.approved === false, 'verifyDevice(false) must reject');
    assert(
      auditCalls.some(c => c.event === 'device_rejected' && c.approvedBy === 'device-1'),
      'rejection must emit device_rejected with approver device id'
    );
    log('Device rejection audit: PASS', 'pass');
    
    return { name: 'Device Binding', status: 'PASS' };
  } catch (err) {
    log(`Device Binding failed: ${err.message}`, 'fail');
    return { name: 'Device Binding', status: 'FAIL', error: err.message };
  }
}

async function testOfflineMessages() {
  log('Testing Offline Messages...');
  
  try {
    const { OfflineMessageStorage } = await import('./privacy-layers/offline-messages.js');
    const storage = new OfflineMessageStorage({ maxStorage: 10 });
    
    // Test storing message
    const msg = await storage.storeOfflineMessage('encrypted-content', 'user-1', { ttl: 3600 });
    assert(msg !== null, 'Store message failed');
    assert(msg.recipientId === 'user-1', 'Recipient ID mismatch');
    log('Store message: PASS', 'pass');
    
    // Test retrieving messages
    const messages = storage.getOfflineMessagesForRecipient('user-1');
    assert(messages.length === 1, 'Should have 1 message');
    log('Retrieve messages: PASS', 'pass');
    
    // Test marking as delivered
    const delivered = storage.markAsDelivered(msg.messageId);
    assert(delivered === true, 'Mark as delivered failed');
    log('Mark delivered: PASS', 'pass');
    
    return { name: 'Offline Messages', status: 'PASS' };
  } catch (err) {
    log(`Offline Messages failed: ${err.message}`, 'fail');
    return { name: 'Offline Messages', status: 'FAIL', error: err.message };
  }
}

async function testEncryptedFileTransfer() {
  log('Testing Encrypted File Transfer...');
  
  try {
    const { EncryptedFileTransfer } = await import('./privacy-layers/encrypted-file-transfer.js');
    const transfer = new EncryptedFileTransfer();
    
    // Test initialization
    assert(transfer !== null, 'Initialization failed');
    log('Initialization: PASS', 'pass');
    
    // Test chunk calculation
    const chunks = transfer.calculateChunks(1024 * 1024); // 1MB
    assert(chunks > 0, 'Should have chunks');
    log('Chunk calculation: PASS', 'pass');
    
    return { name: 'Encrypted File Transfer', status: 'PASS' };
  } catch (err) {
    log(`Encrypted File Transfer failed: ${err.message}`, 'fail');
    return { name: 'Encrypted File Transfer', status: 'FAIL', error: err.message };
  }
}

async function testSafetyNumbers() {
  log('Testing Safety Numbers...');
  
  try {
    const { SafetyNumbers } = await import('./privacy-layers/safety-numbers.js');
    const safety = new SafetyNumbers();
    
    // Test generation
    const numbers = await safety.generateSafetyNumbers('user-1', 'pubkey1', 'user-2', 'pubkey2');
    assert(numbers !== null, 'Generation failed');
    assert(numbers.numbers.length === 12, 'Should have 12 numbers');
    assert(numbers.hash.length > 0, 'Should have hash');
    log('Generate numbers: PASS', 'pass');
    
    // Test verification
    const verified = safety.verifySafetyNumbers(numbers.numbers, numbers.numbers);
    assert(verified.verified === true, 'Same numbers should verify');
    log('Verification: PASS', 'pass');
    
    return { name: 'Safety Numbers', status: 'PASS' };
  } catch (err) {
    log(`Safety Numbers failed: ${err.message}`, 'fail');
    return { name: 'Safety Numbers', status: 'FAIL', error: err.message };
  }
}

// ================================================
// Test Runner
// ================================================

async function runAllTests() {
  console.log('\n========================================');
  console.log('FIBEMATE Privacy Features Test Suite');
  console.log('========================================\n');
  
  const tests = [
    testBurnAfterRead,
    testScreenshotDetection,
    testKeyRotation,
    testDeviceBinding,
    testOfflineMessages,
    testEncryptedFileTransfer,
    testSafetyNumbers
  ];
  
  for (const test of tests) {
    const result = await test();
    testResults.push(result);
  }
  
  // Print summary
  console.log('\n========================================');
  console.log('Test Summary');
  console.log('========================================');
  
  const passed = testResults.filter(r => r.status === 'PASS').length;
  const failed = testResults.filter(r => r.status === 'FAIL').length;
  
  testResults.forEach(r => {
    const icon = r.status === 'PASS' ? '✓' : '✗';
    console.log(`${icon} ${r.name}: ${r.status}`);
    if (r.error) console.log(`  Error: ${r.error}`);
  });
  
  console.log(`\nTotal: ${tests.length} | Passed: ${passed} | Failed: ${failed}`);
  console.log('========================================\n');
  
  return { passed, failed, total: tests.length, results: testResults };
}

// Export for use
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { runAllTests };
}

// Auto-run if in browser
if (typeof window !== 'undefined') {
  window.runPrivacyTests = runAllTests;
}
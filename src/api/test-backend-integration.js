/**
 * FIBEMATE Backend Integration Tests
 * Tests all privacy API endpoints
 * 
 * Prerequisites:
 * 1. Start mock server: node mock-server.js
 * 2. Open test page in browser or run with Node.js
 */

const API_BASE = 'http://localhost:3002'; // Mock server URL
const TEST_TOKEN = 'test-token-12345';

// Test state
let testResults = [];
let testDeviceId = null;
let testMessageId = null;
let testUploadId = null;
let testFileId = null;

function log(msg, type = 'info') {
  const prefix = { info: '[TEST]', pass: '[PASS]', fail: '[FAIL]', warn: '[WARN]' }[type] || '[TEST]';
  console.log(`${prefix} ${msg}`);
}

async function request(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const config = {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${TEST_TOKEN}`,
      ...options.headers
    }
  };

  const response = await fetch(url, config);
  
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.message || `HTTP ${response.status}`);
  }

  return response.json();
}

// ================================================
// Test Cases
// ================================================

async function testBurnMessages() {
  log('\n--- Testing Burn Messages ---');
  
  try {
    // Test 1: Send burn message
    log('1. Sending burn message...');
    const sendResponse = await request('/messages', {
      method: 'POST',
      body: JSON.stringify({
        conversationId: 'conv-123',
        encryptedContent: 'encrypted-test-content',
        messageType: 'burn',
        burnAfterRead: true,
        burnTimeout: 30,
        burnMessageId: 'burn-' + Date.now()
      })
    });
    
    testMessageId = sendResponse.messageId;
    log(`   Message sent: ${testMessageId}`, 'pass');
    
    // Test 2: Check status
    log('2. Checking message status...');
    const statusResponse = await request(`/messages/burn/${testMessageId}/status`);
    log(`   Status: ${statusResponse.status}, Remaining: ${statusResponse.remainingTime}s`, 'pass');
    
    // Test 3: Mark as read
    log('3. Marking as read...');
    const readResponse = await request(`/messages/burn/${testMessageId}/read`, {
      method: 'POST'
    });
    log(`   Burned at: ${readResponse.burnedAt}`, 'pass');
    
    return { name: 'Burn Messages', status: 'PASS' };
  } catch (err) {
    log(`Failed: ${err.message}`, 'fail');
    return { name: 'Burn Messages', status: 'FAIL', error: err.message };
  }
}

async function testDeviceBinding() {
  log('\n--- Testing Device Binding ---');
  
  try {
    // Test 1: Register first device (auto-verified)
    log('1. Registering first device...');
    const regResponse = await request('/devices/register', {
      method: 'POST',
      body: JSON.stringify({
        deviceName: 'Test Desktop',
        deviceType: 'desktop',
        publicKey: 'pk-test-123',
        deviceFingerprint: 'fp-test-123'
      })
    });
    
    testDeviceId = regResponse.deviceId;
    log(`   Device registered: ${testDeviceId}, Status: ${regResponse.status}`, 'pass');
    
    // Test 2: List devices
    log('2. Listing devices...');
    const listResponse = await request('/devices');
    log(`   Found ${listResponse.devices.length} device(s)`, 'pass');
    
    // Test 3: Register second device (pending)
    log('3. Registering second device...');
    const reg2Response = await request('/devices/register', {
      method: 'POST',
      body: JSON.stringify({
        deviceName: 'Test Mobile',
        deviceType: 'mobile',
        publicKey: 'pk-test-456',
        deviceFingerprint: 'fp-test-456'
      })
    });
    
    log(`   Device registered: ${reg2Response.deviceId}, Status: ${reg2Response.status}`, 'pass');
    
    // Test 4: Verify second device
    log('4. Verifying second device...');
    const verifyResponse = await request(`/devices/${reg2Response.deviceId}/verify`, {
      method: 'POST',
      body: JSON.stringify({ approved: true, verifierDeviceId: testDeviceId })
    });
    
    log(`   Verified: ${verifyResponse.verified}`, 'pass');
    
    return { name: 'Device Binding', status: 'PASS' };
  } catch (err) {
    log(`Failed: ${err.message}`, 'fail');
    return { name: 'Device Binding', status: 'FAIL', error: err.message };
  }
}

async function testOfflineMessages() {
  log('\n--- Testing Offline Messages ---');
  
  try {
    // Test 1: Store offline message
    log('1. Storing offline message...');
    const storeResponse = await request('/offline-messages', {
      method: 'POST',
      body: JSON.stringify({
        recipientId: 'user-456',
        encryptedContent: 'encrypted-offline-msg',
        messageType: 'text',
        ttl: 3600,
        priority: 'normal'
      })
    });
    
    const messageId = storeResponse.messageId;
    log(`   Message stored: ${messageId}`, 'pass');
    
    // Test 2: Retrieve offline messages
    log('2. Retrieving offline messages...');
    const retrieveResponse = await request('/offline-messages');
    log(`   Found ${retrieveResponse.messages.length} message(s)`, 'pass');
    
    // Test 3: Mark as delivered
    if (retrieveResponse.messages.length > 0) {
      log('3. Marking as delivered...');
      const deliveredResponse = await request(`/offline-messages/${messageId}/delivered`, {
        method: 'POST'
      });
      log(`   Status: ${deliveredResponse.status}`, 'pass');
    }
    
    return { name: 'Offline Messages', status: 'PASS' };
  } catch (err) {
    log(`Failed: ${err.message}`, 'fail');
    return { name: 'Offline Messages', status: 'FAIL', error: err.message };
  }
}

async function testFileTransfer() {
  log('\n--- Testing Encrypted File Transfer ---');
  
  try {
    // Test 1: Initialize upload
    log('1. Initializing file upload...');
    const initResponse = await request('/files/upload-init', {
      method: 'POST',
      body: JSON.stringify({
        filename: 'test-file.txt',
        fileSize: 1024,
        mimeType: 'text/plain',
        recipientId: 'user-456',
        totalChunks: 2
      })
    });
    
    testUploadId = initResponse.uploadId;
    log(`   Upload initialized: ${testUploadId}`, 'pass');
    
    // Test 2: Upload chunks
    log('2. Uploading chunks...');
    for (let i = 0; i < 2; i++) {
      const chunkResponse = await request(`/files/upload/${testUploadId}/chunk/${i}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: 'chunk-data'
      });
      log(`   Chunk ${i}: ${chunkResponse.status}`, 'pass');
    }
    
    // Test 3: Complete upload
    log('3. Completing upload...');
    const completeResponse = await request(`/files/upload/${testUploadId}/complete`, {
      method: 'POST',
      body: JSON.stringify({
        encryptedKey: 'enc-key-123',
        integrityHash: 'sha256-hash-123'
      })
    });
    
    testFileId = completeResponse.fileId;
    log(`   Upload complete: ${testFileId}`, 'pass');
    
    // Test 4: Download file
    log('4. Downloading file...');
    const downloadResponse = await request(`/files/${testFileId}/download`);
    log(`   Download status: ${downloadResponse.status}`, 'pass');
    
    return { name: 'File Transfer', status: 'PASS' };
  } catch (err) {
    log(`Failed: ${err.message}`, 'fail');
    return { name: 'File Transfer', status: 'FAIL', error: err.message };
  }
}

async function testSafetyNumbers() {
  log('\n--- Testing Safety Numbers ---');
  
  try {
    const contactId = 'user-789';
    
    // Test 1: Get safety numbers
    log('1. Getting safety numbers...');
    const getResponse = await request(`/safety-numbers/${contactId}`);
    log(`   Numbers: ${getResponse.numbers.slice(0, 3).join(', ')}...`, 'pass');
    
    // Test 2: Verify safety numbers
    log('2. Verifying safety numbers...');
    const verifyResponse = await request(`/safety-numbers/${contactId}/verify`, {
      method: 'POST',
      body: JSON.stringify({
        numbers: getResponse.numbers,
        hash: getResponse.hash
      })
    });
    
    log(`   Verified: ${verifyResponse.verified}, Match: ${verifyResponse.match}`, 'pass');
    
    return { name: 'Safety Numbers', status: 'PASS' };
  } catch (err) {
    log(`Failed: ${err.message}`, 'fail');
    return { name: 'Safety Numbers', status: 'FAIL', error: err.message };
  }
}

async function testKeyRotation() {
  log('\n--- Testing Key Rotation ---');
  
  try {
    // Test 1: Rotate keys
    log('1. Rotating keys...');
    const rotateResponse = await request('/keys/rotate', {
      method: 'POST'
    });
    
    log(`   New key: ${rotateResponse.keyId}, Version: ${rotateResponse.version}`, 'pass');
    
    // Test 2: Get current key
    log('2. Getting current key...');
    const currentResponse = await request('/keys/current');
    log(`   Current version: ${currentResponse.version}`, 'pass');
    
    // Test 3: Get key history
    log('3. Getting key history...');
    const historyResponse = await request('/keys/history');
    log(`   Key history: ${historyResponse.keys.length} key(s)`, 'pass');
    
    return { name: 'Key Rotation', status: 'PASS' };
  } catch (err) {
    log(`Failed: ${err.message}`, 'fail');
    return { name: 'Key Rotation', status: 'FAIL', error: err.message };
  }
}

async function testScreenshotWebhook() {
  log('\n--- Testing Screenshot Webhook ---');
  
  try {
    log('1. Sending screenshot detection...');
    const response = await request('/webhooks/screenshot', {
      method: 'POST',
      body: JSON.stringify({
        deviceId: testDeviceId || 'device-test',
        timestamp: new Date().toISOString(),
        type: 'screenshot'
      })
    });
    
    log(`   Webhook received: ${response.received}`, 'pass');
    
    return { name: 'Screenshot Webhook', status: 'PASS' };
  } catch (err) {
    log(`Failed: ${err.message}`, 'fail');
    return { name: 'Screenshot Webhook', status: 'FAIL', error: err.message };
  }
}

// ================================================
// Test Runner
// ================================================

async function runBackendTests() {
  console.log('\n========================================');
  console.log('FIBEMATE Backend Integration Tests');
  console.log(`API Base: ${API_BASE}`);
  console.log('========================================\n');
  
  const tests = [
    testBurnMessages,
    testDeviceBinding,
    testOfflineMessages,
    testFileTransfer,
    testSafetyNumbers,
    testKeyRotation,
    testScreenshotWebhook
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
  module.exports = { runBackendTests };
}

if (typeof window !== 'undefined') {
  window.runBackendTests = runBackendTests;
}

// Auto-run if executed directly
if (typeof require !== 'undefined' && require.main === module) {
  runBackendTests().then(results => {
    process.exit(results.failed > 0 ? 1 : 0);
  });
}
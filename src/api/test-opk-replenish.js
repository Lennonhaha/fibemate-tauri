/**
 * FIBEMATE OPK Auto-Replenishment Test (P1-2)
 * Tests one-time pre-key automatic replenishment mechanism
 * 
 * Run: node test-opk-replenish.js
 */

const http = require('http');

const MOCK_PORT = 3002;
const MOCK_URL = `http://localhost:${MOCK_PORT}`;

// Test state
let testUserId = 'test-user-' + Date.now();
let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  ✓ ${message}`);
    passed++;
  } else {
    console.error(`  ✗ ${message}`);
    failed++;
  }
}

async function request(endpoint, options = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(endpoint, MOCK_URL);
    const req = http.request(url, {
      method: options.method || 'GET',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer test-token',
        ...options.headers
      }
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(data) });
        } catch (e) {
          resolve({ status: res.statusCode, body: data });
        }
      });
    });
    req.on('error', reject);
    if (options.body) req.write(JSON.stringify(options.body));
    req.end();
  });
}

// ============================================================
// Test Suite
// ============================================================

async function runTests() {
  console.log('\n========================================');
  console.log('FIBEMATE OPK Auto-Replenishment Test');
  console.log('========================================\n');

  // Test 1: Check OPK status for non-existent user
  console.log('Test 1: OPK status for new user (should be 404)');
  {
    const res = await request(`/pre-keys/${testUserId}/status`);
    assert(res.status === 404, 'Returns 404 for non-existent user');
    assert(res.body.error?.code === 'NOT_FOUND', 'Error code is NOT_FOUND');
  }

  // Test 2: Replenish OPKs for new user (creates bundle)
  console.log('\nTest 2: Replenish OPKs for new user');
  {
    const opks = Array.from({ length: 25 }, (_, i) => ({
      keyId: 1000 + i,
      publicKey: Array.from(Buffer.from(`opk-public-${i}`, 'utf8'))
    }));

    const res = await request(`/pre-keys/${testUserId}/replenish`, {
      method: 'POST',
      body: {
        identityKey: Array.from(Buffer.from('identity-key', 'utf8')),
        identitySigningKey: Array.from(Buffer.from('signing-key', 'utf8')),
        signedPreKey: Array.from(Buffer.from('spk-public', 'utf8')),
        signedPreKeyId: 5000,
        signedPreKeySignature: Array.from(Buffer.from('signature', 'utf8')),
        oneTimePreKeys: opks
      }
    });

    assert(res.status === 200, 'Returns 200');
    assert(res.body.added === 25, 'Added 25 OPKs');
    assert(res.body.oneTimePreKeyCount === 25, 'Total OPK count is 25');
    assert(res.body.lowOPKs === false, 'No low OPK warning (25 >= 5)');
  }

  // Test 3: Check status after replenishment
  console.log('\nTest 3: Check OPK status after replenishment');
  {
    const res = await request(`/pre-keys/${testUserId}/status`);
    assert(res.status === 200, 'Returns 200');
    assert(res.body.oneTimePreKeysAvailable === 25, '25 OPKs available');
    assert(res.body.hasIdentityKey === true, 'Has identity key');
    assert(res.body.hasSPKSignature === true, 'Has SPK signature');
    assert(res.body.lowOPKs === false, 'No low OPK warning');
  }

  // Test 4: Consume an OPK (simulate X3DH fetch)
  console.log('\nTest 4: Consume OPK via fetch bundle');
  {
    const res = await request(`/pre-keys/${testUserId}`);
    assert(res.status === 200, 'Returns 200');
    assert(res.body.oneTimePreKey !== null, 'Got a one-time pre-key');
    assert(res.body.oneTimePreKeyId !== null, 'Got OPK ID');
  }

  // Test 5: Check status after consumption
  console.log('\nTest 5: Check status after OPK consumption');
  {
    const res = await request(`/pre-keys/${testUserId}/status`);
    assert(res.status === 200, 'Returns 200');
    assert(res.body.oneTimePreKeysAvailable === 24, '24 OPKs remaining');
  }

  // Test 6: Replenish more OPKs (append-only)
  console.log('\nTest 6: Replenish more OPKs (append-only, no duplicates)');
  {
    const newOpks = Array.from({ length: 10 }, (_, i) => ({
      keyId: 2000 + i,  // Different IDs
      publicKey: Array.from(Buffer.from(`new-opk-${i}`, 'utf8'))
    }));

    const res = await request(`/pre-keys/${testUserId}/replenish`, {
      method: 'POST',
      body: {
        oneTimePreKeys: newOpks
      }
    });

    assert(res.status === 200, 'Returns 200');
    assert(res.body.added === 10, 'Added 10 new OPKs');
    assert(res.body.oneTimePreKeyCount === 34, 'Total is 34 (24 + 10)');
  }

  // Test 7: Try to replenish with duplicate keyIds (should skip)
  console.log('\nTest 7: Replenish with duplicate keyIds (should skip duplicates)');
  {
    // First get current count
    const statusBefore = await request(`/pre-keys/${testUserId}/status`);
    const countBefore = statusBefore.body.oneTimePreKeysAvailable;

    // Note: keyId 1000 was consumed in Test 4, so use keyId 1001 which still exists
    const dupOpks = [
      { keyId: 1001, publicKey: Array.from(Buffer.from('duplicate', 'utf8')) },  // Already exists (not consumed in Test 4)
      { keyId: 3000, publicKey: Array.from(Buffer.from('new-opk', 'utf8')) }     // New
    ];

    const res = await request(`/pre-keys/${testUserId}/replenish`, {
      method: 'POST',
      body: {
        oneTimePreKeys: dupOpks
      }
    });

    assert(res.status === 200, 'Returns 200');
    assert(res.body.added === 1, 'Only 1 new OPK added (duplicate skipped)');
    assert(res.body.oneTimePreKeyCount === countBefore + 1, `Total is ${countBefore + 1} (${countBefore} + 1)`);
  }

  // Test 8: Invalid replenish (missing oneTimePreKeys)
  console.log('\nTest 8: Invalid replenish request');
  {
    const res = await request(`/pre-keys/${testUserId}/replenish`, {
      method: 'POST',
      body: {
        identityKey: 'test'
        // Missing oneTimePreKeys
      }
    });

    assert(res.status === 400, 'Returns 400 for invalid request');
    assert(res.body.error?.code === 'BAD_REQUEST', 'Error code is BAD_REQUEST');
  }

  // Test 9: New user replenish without full bundle
  console.log('\nTest 9: New user replenish without required fields');
  {
    const newUserId = 'new-user-' + Date.now();
    const res = await request(`/pre-keys/${newUserId}/replenish`, {
      method: 'POST',
      body: {
        oneTimePreKeys: [{ keyId: 1, publicKey: [1, 2, 3] }]
        // Missing identityKey, signedPreKey, signedPreKeyId
      }
    });

    assert(res.status === 400, 'Returns 400 for new user without required fields');
  }

  // Test 10: SPK rotation via replenish
  console.log('\nTest 10: SPK rotation via replenish');
  {
    const res = await request(`/pre-keys/${testUserId}/replenish`, {
      method: 'POST',
      body: {
        identityKey: Array.from(Buffer.from('new-identity', 'utf8')),
        identitySigningKey: Array.from(Buffer.from('new-signing', 'utf8')),
        signedPreKey: Array.from(Buffer.from('new-spk', 'utf8')),
        signedPreKeyId: 6000,
        signedPreKeySignature: Array.from(Buffer.from('new-sig', 'utf8')),
        oneTimePreKeys: []
      }
    });

    assert(res.status === 200, 'Returns 200');
    assert(res.body.signedPreKeyId === 6000, 'SPK ID updated');

    // Verify status reflects new SPK
    const statusRes = await request(`/pre-keys/${testUserId}/status`);
    assert(statusRes.body.signedPreKeyId === 6000, 'Status shows new SPK ID');
  }

  // ============================================================
  // Summary
  // ============================================================
  console.log('\n========================================');
  console.log(`Test Results: ${passed} passed, ${failed} failed`);
  console.log('========================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

// Check if mock server is running
async function checkServer() {
  try {
    await request('/pre-keys/test/status');
    return true;
  } catch (e) {
    return false;
  }
}

async function main() {
  const running = await checkServer();
  if (!running) {
    console.error('Mock server not running. Please start it first:');
    console.error('  node mock-server.js');
    process.exit(1);
  }

  await runTests();
}

main().catch(err => {
  console.error('Test error:', err);
  process.exit(1);
});

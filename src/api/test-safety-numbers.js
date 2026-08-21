/**
 * FIBEMATE Safety Numbers Integration Test
 * Tests safety number generation and verification
 */

const http = require('http');
const crypto = require('crypto');

const MOCK_PORT = 3002;
const MOCK_URL = `http://localhost:${MOCK_PORT}`;

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

// Simple Safety Numbers implementation for testing
class TestSafetyNumbers {
  constructor() {
    this.blockCount = 12;
  }

  async generateSafetyNumbers(userId, userPublicKeyBytes, contactId, contactPublicKeyBytes) {
    const ids = [userId, contactId].sort();
    const keys = ids[0] === userId 
      ? [userPublicKeyBytes, contactPublicKeyBytes]
      : [contactPublicKeyBytes, userPublicKeyBytes];

    const id1Bytes = Buffer.from(ids[0], 'utf8');
    const id2Bytes = Buffer.from(ids[1], 'utf8');
    
    const data = Buffer.concat([id1Bytes, keys[0], id2Bytes, keys[1]]);
    const hash = crypto.createHash('sha256').update(data).digest();
    
    const numbers = [];
    for (let i = 0; i < this.blockCount; i++) {
      const start = i * 2;
      const end = Math.min(start + 2, hash.length);
      const block = hash.slice(start, end);
      let num = 0;
      for (let j = 0; j < block.length; j++) {
        num = (num * 256 + block[j]) % 100000;
      }
      numbers.push(num.toString().padStart(5, '0'));
    }
    
    return { numbers, userId, contactId };
  }

  verifySafetyNumbers(local, remote) {
    const matches = local.every((num, i) => num === remote[i]);
    return { verified: matches, matchCount: matches ? local.length : local.filter((n, i) => n === remote[i]).length };
  }
}

async function runTests() {
  console.log('========================================');
  console.log('FIBEMATE Safety Numbers Test');
  console.log('========================================\n');

  const sn = new TestSafetyNumbers();
  const userId = 'alice';
  const contactId = 'bob';
  const userKey = crypto.randomBytes(33);  // P-256 compressed public key
  const contactKey = crypto.randomBytes(33);

  // Test 1: Generate safety numbers
  console.log('Test 1: Generate safety numbers');
  {
    const result = await sn.generateSafetyNumbers(userId, userKey, contactId, contactKey);
    assert(result.numbers.length === 12, 'Generates 12 number blocks');
    assert(result.numbers.every(n => n.length === 5), 'Each block is 5 digits');
    assert(result.numbers.every(n => /^\d{5}$/.test(n)), 'Each block is numeric');
    assert(result.userId === userId, 'Includes userId');
    assert(result.contactId === contactId, 'Includes contactId');
  }

  // Test 2: Deterministic generation
  console.log('\nTest 2: Deterministic generation (same inputs = same output)');
  {
    const result1 = await sn.generateSafetyNumbers(userId, userKey, contactId, contactKey);
    const result2 = await sn.generateSafetyNumbers(userId, userKey, contactId, contactKey);
    assert(JSON.stringify(result1.numbers) === JSON.stringify(result2.numbers), 'Same inputs produce same numbers');
  }

  // Test 3: Order independence
  console.log('\nTest 3: Order independence (Alice→Bob == Bob→Alice)');
  {
    const aliceView = await sn.generateSafetyNumbers(userId, userKey, contactId, contactKey);
    const bobView = await sn.generateSafetyNumbers(contactId, contactKey, userId, userKey);
    assert(JSON.stringify(aliceView.numbers) === JSON.stringify(bobView.numbers), 'Both sides compute same numbers');
  }

  // Test 4: Different keys produce different numbers
  console.log('\nTest 4: Different keys produce different numbers');
  {
    const differentKey = crypto.randomBytes(33);
    const result1 = await sn.generateSafetyNumbers(userId, userKey, contactId, contactKey);
    const result2 = await sn.generateSafetyNumbers(userId, userKey, contactId, differentKey);
    assert(JSON.stringify(result1.numbers) !== JSON.stringify(result2.numbers), 'Different keys produce different numbers');
  }

  // Test 5: Verify matching numbers
  console.log('\nTest 5: Verify matching safety numbers');
  {
    const result = await sn.generateSafetyNumbers(userId, userKey, contactId, contactKey);
    const verify = sn.verifySafetyNumbers(result.numbers, result.numbers);
    assert(verify.verified === true, 'Identical numbers verify as matching');
    assert(verify.matchCount === 12, 'All 12 blocks match');
  }

  // Test 6: Verify non-matching numbers
  console.log('\nTest 6: Verify non-matching safety numbers');
  {
    const result1 = await sn.generateSafetyNumbers(userId, userKey, contactId, contactKey);
    const result2 = await sn.generateSafetyNumbers(userId, userKey, contactId, crypto.randomBytes(33));
    const verify = sn.verifySafetyNumbers(result1.numbers, result2.numbers);
    assert(verify.verified === false, 'Different numbers verify as non-matching');
    assert(verify.matchCount < 12, 'Some blocks differ');
  }

  // Test 7: Backend API endpoint
  console.log('\nTest 7: Backend safety numbers endpoint');
  {
    const res = await request(`/safety-numbers/${contactId}`);
    assert(res.status === 200, 'Returns 200');
    assert(res.body.numbers !== undefined, 'Returns numbers field');
    // Handle both flat array and nested { numbers: [...] } format
    let numbers = res.body.numbers;
    if (numbers && typeof numbers === 'object' && !Array.isArray(numbers) && numbers.numbers) {
      numbers = numbers.numbers;
    }
    assert(Array.isArray(numbers), `Returns numbers array (got: ${typeof numbers})`);
    assert(numbers.length === 12, `Returns 12 number blocks (got: ${numbers.length})`);
    assert(numbers.every(n => typeof n === 'string' && /^\d{5}$/.test(n)), 'Each block is 5-digit string');
  }

  // Test 8: Backend verify endpoint
  console.log('\nTest 8: Backend safety numbers verification');
  {
    const res = await request(`/safety-numbers/${contactId}/verify`, {
      method: 'POST',
      body: { numbers: ['12345', '67890', '11111', '22222', '33333', '44444', '55555', '66666', '77777', '88888', '99999', '00000'] }
    });
    assert(res.status === 200, 'Returns 200');
    assert(typeof res.body.verified === 'boolean', 'Returns verification result');
  }

  console.log('\n========================================');
  console.log(`Test Results: ${passed} passed, ${failed} failed`);
  console.log('========================================\n');

  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch(err => {
  console.error('Test error:', err);
  process.exit(1);
});

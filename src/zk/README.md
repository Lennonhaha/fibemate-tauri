# FIBEMATE ZK Module v2.1

Zero-Knowledge Proof Authentication Module

## Architecture

```
zk/
├── zk-browser.js          # Browser compatibility layer
├── schnorr-prover.js      # Schnorr identity proof (LEGACY - has math bug)
├── schnorr-prover-v2.js   # Schnorr identity proof (CORRECT - EC implementation)
├── schnorr-verifier.js    # Schnorr verification (server)
├── bulletproofs.js        # Range proofs for anonymous credentials
├── zk-auth.js             # Main authentication orchestrator
├── zk-integration.js      # Bridge with existing P-256 auth
├── index.js               # Module entry point
├── test-zk.html           # Browser test page (legacy)
├── test-zk-v2.html        # Browser test page (correct EC)
└── README.md              # This file
```

## ⚠️ Important: Math Bug Fix

**schnorr-prover.js (v1)**: Uses modular exponentiation (`g^x mod p`) which is **mathematically incorrect** for elliptic curves.

**schnorr-prover-v2.js (v2)**: Uses proper elliptic curve point operations (`k * G`, point addition) on P-256.

**Always use v2 for new code.** v1 is kept for backward compatibility only.

## Features

- **Schnorr Proofs v2**: Correct EC-based proof of knowledge
- **Bulletproofs**: Range proofs for anonymous credential attributes
- **ZK Auth**: Combined authentication with both proof types
- **Backward Compatible**: Falls back to existing P-256 ZK if needed

## Usage

```javascript
// Generate ZK login proof (v2)
const zk = new ZKAuth();
await zk.init();
const proof = await zk.generateLoginProof('username', 'password');

// Direct EC Schnorr (v2)
const prover = new SchnorrProverV2();
await prover.init();
const proof = await prover.prove(privateKey, publicKey);
const valid = await prover.verify(proof, publicKey);

// Verify on server
const verifier = new SchnorrVerifier();
const valid = await verifier.verify(proof.schnorrProof, publicParams);
```

## Integration

Added to index.html:
```html
<script src="zk/zk-browser.js"></script>
<script src="zk/schnorr-prover-v2.js"></script>  <!-- Use v2! -->
<script src="zk/schnorr-verifier.js"></script>
<script src="zk/bulletproofs.js"></script>
<script src="zk/zk-auth.js"></script>
<script src="zk/zk-integration.js"></script>
```

## Testing

- `test-zk.html` - Legacy tests (may have false passes due to math bug)
- `test-zk-v2.html` - Correct EC implementation tests

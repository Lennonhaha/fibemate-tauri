// ============================================================
// FIBEMATE JS Double Ratchet (X25519) — Rust 协议对齐版
// ============================================================
// 纯 WebCrypto + tweetnacl 实现，字节级对齐 Rust 端
// `src-tauri/src/double_ratchet.rs` 的协议：
//   - X25519 (tweetnacl scalarMult)
//   - X3DH: DH1||DH2||DH3 (96 bytes) → HKDF-SHA256(salt=None) expand "shared_secret" → 32 bytes
//   - DR init: HKDF(None, shared_secret) expand "send_chain_key"/"recv_chain_key"
//   - ratchet_step: HKDF(None, dh) expand "chain_key"/"next_chain"
//   - message key: HKDF(None, chain_key) expand "message_key"/"next_chain"
//   - AEAD: AES-256-GCM, AAD = 发送方 X25519 public key (32 bytes)
//
// 与 Rust 端 EncryptedMessage 结构一致：
//   { public_key: [u8;32], message_num: u32, previous_chain_length: u32,
//     nonce: [u8;12], ciphertext: Vec<u8> }  → JSON 序列化
// ============================================================
(function () {
  'use strict';

  // ── 依赖：tweetnacl 提供 X25519 ─────────────────────────────
  // nacl.scalarMult(n, p) 返回共享密钥；nacl.box.keyPair() 生成密钥对
  let nacl = (typeof window !== 'undefined' && window.nacl) ? window.nacl : null;

  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  // ── Hex ↔ Bytes ────────────────────────────────────────────
  function hexToBytes(hex) {
    const len = hex.length / 2;
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }
  function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // ── HKDF-SHA256 ────────────────────────────────────────────
  // 对齐 Rust hkdf::Hkdf::<Sha256>::new(None, ikm) 语义：
  //   salt=None 时，HKDF 使用全零 32 字节 salt（RFC 5869）
  async function hkdfExpand(ikm, info, length = 32) {
    const salt = new Uint8Array(32); // 全零 salt，等价 Rust None
    const hmacKey = await crypto.subtle.importKey('raw', salt, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const prk = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, ikm));
    const n = Math.ceil(length / 32);
    const okm = [];
    let prev = new Uint8Array(0);
    const infoBuf = typeof info === 'string' ? encoder.encode(info) : info;
    for (let i = 1; i <= n; i++) {
      const data = new Uint8Array(prev.length + infoBuf.length + 1);
      data.set(prev, 0);
      data.set(infoBuf, prev.length);
      data[data.length - 1] = i;
      const tKey = await crypto.subtle.importKey('raw', prk, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      prev = new Uint8Array(await crypto.subtle.sign('HMAC', tKey, data));
      okm.push(...prev);
    }
    return new Uint8Array(okm.slice(0, length));
  }

  // ── X25519 DH ──────────────────────────────────────────────
  function x25519DH(privateKey, publicKey) {
    if (!nacl) throw new Error('[JS-DR] nacl 未加载');
    return nacl.scalarMult(privateKey, publicKey); // 返回 Uint8Array(32)
  }

  // ── X3DH ───────────────────────────────────────────────────
  // initiator: DH1=DH(ik, their_spk), DH2=DH(ek, their_ik), DH3=DH(ek, their_spk)
  // （对齐 Signal X3DH 规范，与修复后的 Rust 端一致）
  function x3dhInitiator(myIkPriv, myEkPriv, theirIkPub, theirSpkPub) {
    const dh1 = x25519DH(myIkPriv, theirSpkPub);
    const dh2 = x25519DH(myEkPriv, theirIkPub);
    const dh3 = x25519DH(myEkPriv, theirSpkPub);
    return concat96(dh1, dh2, dh3);
  }
  // responder: DH1=DH(spk, their_ik), DH2=DH(ik, their_ek), DH3=DH(spk, their_ek)
  function x3dhResponder(myIkPriv, mySpkPriv, theirIkPub, theirEkPub) {
    const dh1 = x25519DH(mySpkPriv, theirIkPub);
    const dh2 = x25519DH(myIkPriv, theirEkPub);
    const dh3 = x25519DH(mySpkPriv, theirEkPub);
    return concat96(dh1, dh2, dh3);
  }
  function concat96(a, b, c) {
    const out = new Uint8Array(96);
    out.set(a, 0); out.set(b, 32); out.set(c, 64);
    return out;
  }

  // ── AES-256-GCM ────────────────────────────────────────────
  async function aesGcmEncrypt(key, plaintext, aad) {
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const aesKey = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, aesKey, plaintext));
    return { nonce, ciphertext: ct };
  }
  async function aesGcmDecrypt(key, nonce, ciphertext, aad) {
    const aesKey = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt']);
    const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, aesKey, ciphertext));
    return pt;
  }

  // ── 会话状态 ───────────────────────────────────────────────
  // 对齐 Rust RatchetState 字段
  class SessionState {
    constructor(sharedSecret, isInitiator) {
      // 待填充：send_chain_key/recv_chain_key 由 init 计算
      this.send_chain_key = null;
      this.recv_chain_key = null;
      this.send_public_key = null;
      this.recv_public_key = new Uint8Array(32); // 全零初始
      this.send_message_num = 0;
      this.recv_message_num = 0;
      this.previous_send_keys = new Map();
      this.skipped_messages = 0;
    }
  }

  // 生成新 DH 密钥对（X25519）
  function generateKeyPair() {
    const kp = nacl.box.keyPair();
    return { publicKey: new Uint8Array(kp.publicKey), privateKey: new Uint8Array(kp.secretKey) };
  }

  // ── Double Ratchet 引擎 ────────────────────────────────────
  class JSDoubleRatchet {
    constructor() {
      this.sessions = new Map(); // sessionId → SessionState
    }

    async createSession(sessionId, sharedSecret, isInitiator) {
      const state = new SessionState(sharedSecret, isInitiator);
      // HKDF expand "send_chain_key" / "recv_chain_key"
      const sendKey = await hkdfExpand(sharedSecret, 'send_chain_key', 32);
      const recvKey = await hkdfExpand(sharedSecret, 'recv_chain_key', 32);
      const kp = generateKeyPair();
      state.send_chain_key = isInitiator ? sendKey : recvKey;
      state.recv_chain_key = isInitiator ? recvKey : sendKey;
      state.send_public_key = kp.publicKey;
      state.recv_public_key = new Uint8Array(32);
      this.sessions.set(sessionId, state);
      return state;
    }

    getState(sessionId) {
      const s = this.sessions.get(sessionId);
      if (!s) throw new Error(`Session not found: ${sessionId}`);
      return s;
    }

    async setPeerKey(sessionId, peerPublicKey) {
      const s = this.getState(sessionId);
      s.recv_public_key = new Uint8Array(peerPublicKey);
    }

    async ratchetStep(state, theirPublicKey) {
      // 对齐 Rust ratchet_step
      state.previous_send_keys.set(state.send_message_num, state.send_chain_key.slice());
      const newKp = generateKeyPair();
      const shared = x25519DH(newKp.privateKey, theirPublicKey);
      state.send_chain_key = await hkdfExpand(shared, 'chain_key', 32);
      state.recv_chain_key = await hkdfExpand(shared, 'next_chain', 32);
      state.send_public_key = newKp.publicKey;
      state.recv_public_key = new Uint8Array(theirPublicKey);
      state.send_message_num = 0;
      state.skipped_messages = 0;
    }

    // 消息密钥链
    async nextMessageKey(chainKey) {
      const messageKey = await hkdfExpand(chainKey, 'message_key', 32);
      const nextChain = await hkdfExpand(chainKey, 'next_chain', 32);
      return { messageKey, nextChainKey: nextChain };
    }

    async encrypt(sessionId, plaintextBytes) {
      const state = this.getState(sessionId);
      const { messageKey, nextChainKey } = await this.nextMessageKey(state.send_chain_key);
      state.send_chain_key = nextChainKey;
      const aad = state.send_public_key;
      const { nonce, ciphertext } = await aesGcmEncrypt(messageKey, plaintextBytes, aad);
      const msg = {
        public_key: Array.from(state.send_public_key),
        message_num: state.send_message_num,
        previous_chain_length: state.skipped_messages,
        nonce: Array.from(nonce),
        ciphertext: Array.from(ciphertext),
      };
      state.send_message_num += 1;
      return msg;
    }

    async decrypt(sessionId, message) {
      const state = this.getState(sessionId);
      const msgPk = new Uint8Array(message.public_key);
      // 检查是否需 ratchet step
      if (!bytesEqual(msgPk, state.recv_public_key)) {
        await this.ratchetStep(state, msgPk);
      }
      let chainKey = state.recv_chain_key;
      // 跳过消息（对齐 Rust skip 逻辑）
      if (message.message_num > state.recv_message_num) {
        const skipCount = message.message_num - state.recv_message_num;
        for (let i = 0; i < skipCount; i++) {
          const r = await this.nextMessageKey(chainKey);
          chainKey = r.nextChainKey;
        }
        state.skipped_messages += skipCount;
      }
      const { messageKey, nextChainKey } = await this.nextMessageKey(chainKey);
      state.recv_chain_key = nextChainKey;
      const aad = msgPk;
      const nonce = new Uint8Array(message.nonce);
      const ciphertext = new Uint8Array(message.ciphertext);
      const plaintext = await aesGcmDecrypt(messageKey, nonce, ciphertext, aad);
      state.recv_message_num = message.message_num + 1;
      return plaintext;
    }
  }

  function bytesEqual(a, b) {
    if (!a || !b) return a === b;
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  // ── 导出 ──────────────────────────────────────────────────
  const api = {
    hkdfExpand,
    x25519DH,
    x3dhInitiator,
    x3dhResponder,
    generateKeyPair,
    hexToBytes,
    bytesToHex,
    JSDoubleRatchet,
    SessionState,
    setNacl: (n) => { nacl = n; },
    isAvailable: () => !!nacl,
  };

  if (typeof window !== 'undefined') {
    window.JSDoubleRatchetLib = api;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
})();

/**
 * FIBEMATE P2P 核心模块
 * 手机直连，无需服务器
 */

// ================================================
// 协议常量
// ================================================
const PROTOCOL_VERSION = 2;          // v2: 支持 GM 加密
const ENCRYPTION_AES_GCM = 'aes-gcm';
const ENCRYPTION_GM = 'sm2-sm4-sm3';
const SUPPORTED_ENCRYPTIONS = [ENCRYPTION_AES_GCM, ENCRYPTION_GM];

class P2PNetwork {
  constructor() {
    this.peers = new Map(); // peerId -> PeerConnection
    this.localId = this.generateId();
    this.localKeyPair = null;
    this.gmKeypair = null;        // SM2 keypair for GM encryption (纯 JS 回退)
    this.gmKeyId = null;          // Tauri 后端 KeyStore 的 key_id
    this.gmPublicKey = null;      // 本端 SM2 公钥（后端模式）
    this.encryptionMode = ENCRYPTION_AES_GCM; // 'aes-gcm' | 'sm2-sm4-sm3'
    this.peerCapabilities = new Map(); // peerId -> { encryptions, protocolVersion }
    this.dataChannels = new Map();
    this.messageHandlers = new Set();
    this.store = new LocalMessageStore();
  }
  
  // 生成唯一ID
  generateId() {
    return Array.from(crypto.getRandomValues(new Uint8Array(16)))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }
  
  // 初始化
  async init() {
    this._ready = false;
    
    // 生成 ECDH 密钥对（AES-GCM 路径）
    this.localKeyPair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey']
    );
    
    // 加载/生成 GM 密钥对
    await this.initGM();
    
    // 启动局域网发现
    this.startLanDiscovery();
    
    this._ready = true;
    console.log('[P2P] Initialized with ID:', this.localId);
  }

  isReady() {
    return this._ready === true;
  }
  
  // ================================================
  // 局域网发现 (mDNS模拟)
  // ================================================
  
  startLanDiscovery() {
    // 使用WebRTC的ICE候选收集发现局域网IP
    const pc = new RTCPeerConnection({
      iceServers: [] // 不需要STUN，仅局域网
    });
    
    pc.createDataChannel('discovery');
    
    pc.onicecandidate = (e) => {
      if (e.candidate) {
        const ip = this.extractIpFromCandidate(e.candidate.candidate);
        if (this.isLanIp(ip)) {
          this.broadcastPresence(ip);
        }
      }
    };
    
    pc.createOffer().then(offer => pc.setLocalDescription(offer));
  }
  
  extractIpFromCandidate(candidate) {
    const match = candidate.match(/(\d+\.\d+\.\d+\.\d+)/);
    return match ? match[1] : null;
  }
  
  isLanIp(ip) {
    if (!ip || typeof ip !== 'string') return false;
    return ip.startsWith('192.168.') || 
           ip.startsWith('10.') || 
           ip.startsWith('172.16.');
  }
  
  // 广播自己的存在 (通过UDP或WebSocket广播)
  broadcastPresence(ip) {
    // 简化版：通过已知端口范围扫描
    // 注意：原实现调用了不存在的 this.tryConnect()，导致每次 ICE 候选
    // 收集时抛 "this.tryConnect is not a function"，被 ErrorBoundary 捕获。
    // 改用真实存在的 connectToPeer()，并捕获 async rejection 静默失败。
    const ports = [3001, 3002, 3003, 8080, 8081];
    ports.forEach(port => {
      this.connectToPeer(ip, port).catch(() => {});
    });
  }
  
  // ================================================
  // 连接管理
  // ================================================
  
  async connectToPeer(ip, port, peerPublicKey = null) {
    const peerId = `${ip}:${port}`;
    
    if (this.peers.has(peerId)) {
      return this.peers.get(peerId);
    }
    
    const pc = new RTCPeerConnection({
      iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
    });
    
    // 创建数据通道
    const dc = pc.createDataChannel('messages', {
      ordered: true,
      maxRetransmits: 3
    });
    
    this.setupDataChannel(dc, peerId);
    
    // 创建offer
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    
    // 等待ICE完成
    await this.waitForIceComplete(pc);
    
    // 发送offer (通过某种方式，如二维码、局域网广播等)
    this.peers.set(peerId, pc);
    
    return pc;
  }
  
  setupDataChannel(dc, peerId) {
    dc.onopen = () => {
      console.log('[P2P] DataChannel opened with', peerId);
      this.dataChannels.set(peerId, dc);
      
      // 发送握手：广播本端能力 + GM 公钥
      this.sendHandshake(peerId);
      this.sendPendingMessages(peerId);
    };
    
    dc.onmessage = (e) => {
      this.handleMessage(peerId, e.data);
    };
    
    dc.onclose = () => {
      console.log('[P2P] DataChannel closed with', peerId);
      this.dataChannels.delete(peerId);
    };
    
    dc.onerror = (err) => {
      console.error('[P2P] DataChannel error:', err);
    };
  }
  
  waitForIceComplete(pc) {
    return new Promise((resolve) => {
      if (pc.iceGatheringState === 'complete') {
        resolve();
        return;
      }
      
      pc.onicegatheringstatechange = () => {
        if (pc.iceGatheringState === 'complete') {
          resolve();
        }
      };
      
      // 超时
      setTimeout(resolve, 5000);
    });
  }
  
  // ================================================
  // 消息处理
  // ================================================
  
  // ================================================
  // 握手协议
  // ================================================
  
  sendHandshake(peerId) {
    const dc = this.dataChannels.get(peerId);
    if (!dc || dc.readyState !== 'open') return;
    
    const handshake = {
      type: 'handshake',
      protocol: PROTOCOL_VERSION,
      encryptions: SUPPORTED_ENCRYPTIONS,
      gmPublicKey: this.getGMPublicKey()
    };
    
    dc.send(JSON.stringify(handshake));
    console.log('[P2P] Handshake sent to', peerId);
  }
  
  handleHandshake(peerId, msg) {
    const caps = {
      protocolVersion: msg.protocol || 1,
      encryptions: msg.encryptions || [ENCRYPTION_AES_GCM],
      gmPublicKey: msg.gmPublicKey || null
    };
    
    this.peerCapabilities.set(peerId, caps);
    
    // 如果对端发来了 GM 公钥，自动存储
    if (caps.gmPublicKey) {
      this.setGMPeerPublicKey(peerId, caps.gmPublicKey);
    }
    
    console.log('[P2P] Peer capabilities:', peerId, caps.encryptions);
    
    // 通知 UI
    this.messageHandlers.forEach(h => {
      h({ type: 'peer_capabilities', peerId, capabilities: caps });
    });
  }
  
  // 判断对端是否支持某种加密
  peerSupportsEncryption(peerId, encryption) {
    const caps = this.peerCapabilities.get(peerId);
    if (!caps) return encryption === ENCRYPTION_AES_GCM; // 未知对端，保守假设仅 AES
    return caps.encryptions.includes(encryption);
  }
  
  // 取两端共同支持的最高优先级加密
  negotiateEncryption(peerId, preference) {
    const caps = this.peerCapabilities.get(peerId);
    if (!caps) return ENCRYPTION_AES_GCM;
    if (caps.encryptions.includes(preference)) return preference;
    return ENCRYPTION_AES_GCM; // 退回到双方都支持的基础加密
  }
  
  async handleMessage(peerId, data) {
    try {
      const msg = JSON.parse(data);
      
      switch (msg.type) {
        case 'handshake':
          this.handleHandshake(peerId, msg);
          break;
        case 'chat':
          await this.handleChatMessage(peerId, msg);
          break;
        case 'file':
          await this.handleFileTransfer(peerId, msg);
          break;
        case 'call':
          await this.handleCallSignal(peerId, msg);
          break;
        case 'presence':
          this.handlePresence(peerId, msg);
          break;
      }
    } catch (err) {
      console.error('[P2P] Message handling error:', err);
    }
  }
  
  async handleChatMessage(peerId, msg) {
    // 解密消息
    const decrypted = await this.decryptMessage(peerId, msg.encrypted);
    const encryption = msg.encrypted?.encryption || ENCRYPTION_AES_GCM;
    
    // 存储到本地
    await this.store.saveMessage({
      id: msg.id,
      peerId: peerId,
      content: decrypted,
      encryption: encryption,
      timestamp: msg.timestamp,
      direction: 'received',
      status: 'delivered'
    });
    
    // 通知UI
    this.messageHandlers.forEach(handler => {
      handler({
        type: 'new_message',
        peerId: peerId,
        content: decrypted,
        encryption: encryption,
        timestamp: msg.timestamp
      });
    });
    
    // 发送已读回执
    this.sendReceipt(peerId, msg.id);
  }
  
  // ================================================
  // 发送消息
  // ================================================
  
  async sendMessage(peerId, content, options = {}) {
    const msgId = crypto.randomUUID();
    const timestamp = Date.now();
    
    // 协商加密方式：如果指定了 mode 且对端支持，使用它；否则退回 AES
    const requestedMode = options.mode || this.encryptionMode;
    const effectiveMode = this.negotiateEncryption(peerId, requestedMode);
    if (requestedMode !== effectiveMode) {
      console.warn(`[P2P] GM not supported by peer, falling back to ${effectiveMode}`);
    }
    
    // 加密
    const currentMode = this.encryptionMode;
    this.encryptionMode = effectiveMode;
    const encrypted = await this.encryptMessage(peerId, content);
    this.encryptionMode = currentMode; // 恢复全局设置
    
    const msg = {
      type: 'chat',
      protocol: PROTOCOL_VERSION,
      id: msgId,
      from: this.localId,
      encrypted: encrypted,
      timestamp: timestamp
    };
    
    // 存储到本地
    await this.store.saveMessage({
      id: msgId,
      peerId: peerId,
      content: content,
      encryption: encrypted.encryption || effectiveMode,
      timestamp: timestamp,
      direction: 'sent',
      status: 'pending'
    });
    
    // 尝试发送
    const dc = this.dataChannels.get(peerId);
    if (dc && dc.readyState === 'open') {
      dc.send(JSON.stringify(msg));
      await this.store.updateMessageStatus(msgId, 'delivered');
    } else {
      // 离线，加入待发送队列
      this.queueMessage(peerId, msg);
    }
    
    return msgId;
  }
  
  // ================================================
  // GM 密钥管理
  // ================================================
  
  async initGM() {
    try {
      // ── Tauri 后端路径：私钥收进 Rust KeyStore ──
      if (typeof window !== 'undefined' && window.SM2 && typeof window.SM2.importKey === 'function') {
        const KEY_ID_STORAGE = 'fibemate_gm_key_id';
        const storedId = localStorage.getItem(KEY_ID_STORAGE);
        if (storedId) {
          this.gmKeyId = storedId;
          const pk = await window.SM2.getPublicKey(storedId);
          this.gmPublicKey = pk.publicKeyHex;
          console.log('[P2P] GM key loaded from Rust KeyStore:', storedId);
        } else {
          const legacy = localStorage.getItem('p2p_gm_keypair');
          if (legacy) {
            const legacyKp = JSON.parse(legacy);
            const imported = await window.SM2.importKey(legacyKp.privateKey);
            this.gmKeyId = imported.keyId;
            this.gmPublicKey = imported.publicKeyHex;
            localStorage.setItem(KEY_ID_STORAGE, this.gmKeyId);
            localStorage.removeItem('p2p_gm_keypair');  // 删除明文私钥
            console.log('[P2P] Legacy GM key migrated to Rust KeyStore:', this.gmKeyId);
          } else {
            const generated = await window.SM2.generateKeyPair();
            this.gmKeyId = generated.keyId;
            this.gmPublicKey = generated.publicKeyHex;
            localStorage.setItem(KEY_ID_STORAGE, this.gmKeyId);
            console.log('[P2P] GM key generated in Rust KeyStore:', this.gmKeyId);
          }
        }
        return;
      }

      // ── 纯 JS 回退路径 ──
      const stored = localStorage.getItem('p2p_gm_keypair');
      if (stored) {
        this.gmKeypair = JSON.parse(stored);
        console.log('[P2P] GM keypair loaded from storage');
      } else if (typeof window.MessageGM !== 'undefined') {
        this.gmKeypair = window.MessageGM.generateKeypair();
        localStorage.setItem('p2p_gm_keypair', JSON.stringify(this.gmKeypair));
        console.log('[P2P] GM keypair generated');
      }
    } catch (e) {
      console.warn('[P2P] GM init skipped:', e.message);
    }
  }
  
  getGMPublicKey() {
    if (this.gmPublicKey) return this.gmPublicKey;
    return this.gmKeypair?.publicKey || null;
  }
  
  _gmKeyRef() {
    // 返回 { keyId } 或明文私钥字符串（回退）
    if (this.gmKeyId) return { keyId: this.gmKeyId };
    if (this.gmKeypair) return this.gmKeypair.privateKey;
    return null;
  }
  
  setGMPeerPublicKey(peerId, publicKey) {
    localStorage.setItem(`p2p_gm_peer_${peerId}`, publicKey);
  }
  
  getGMPeerPublicKey(peerId) {
    return localStorage.getItem(`p2p_gm_peer_${peerId}`);
  }
  
  setEncryptionMode(mode) {
    if (!SUPPORTED_ENCRYPTIONS.includes(mode)) {
      throw new Error(`Invalid encryption mode, use ${SUPPORTED_ENCRYPTIONS.join(' or ')}`);
    }
    this.encryptionMode = mode;
    console.log('[P2P] Encryption mode set to:', mode);
  }
  
  // ================================================
  // 加密/解密
  // ================================================
  
  async encryptMessage(peerId, content) {
    // GM 分支
    if (this.encryptionMode === ENCRYPTION_GM) {
      return this._encryptGM(peerId, content);
    }
    
    // AES-GCM 路径（默认）
    const key = await this.getSharedKey(peerId);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();
    
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      encoder.encode(content)
    );
    
    return {
      ciphertext: Array.from(new Uint8Array(encrypted)),
      iv: Array.from(iv),
      encryption: 'aes-gcm'
    };
  }
  
  async _encryptGM(peerId, content) {
    const keyRef = this._gmKeyRef();
    if (!keyRef) {
      throw new Error('GM keypair not initialized');
    }
    
    const recipientPubKey = this.getGMPeerPublicKey(peerId);
    if (!recipientPubKey) {
      throw new Error(`No GM public key for peer ${peerId}. Exchange keys first.`);
    }
    
    const envelope = await window.MessageGM.encryptMessage(
      content,
      recipientPubKey,
      keyRef
    );
    
    // Convert hex strings to arrays for transport consistency
    return {
      ciphertext: envelope.ciphertext,
      iv: envelope.iv,
      ephemeralPK: envelope.ephemeralPK,
      wrappedKey: envelope.wrappedKey,
      hmac: envelope.hmac,
      signature: envelope.signature,
      encryption: ENCRYPTION_GM
    };
  }
  
  async decryptMessage(peerId, encrypted) {
    // Auto-detect encryption type from envelope
    if (encrypted.encryption === ENCRYPTION_GM || encrypted.encryption === 'gm') {
      return this._decryptGM(peerId, encrypted);
    }
    
    // AES-GCM path (default)
    const key = await this.getSharedKey(peerId);
    const iv = new Uint8Array(encrypted.iv);
    const ciphertext = new Uint8Array(encrypted.ciphertext);
    
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      ciphertext
    );
    
    return new TextDecoder().decode(decrypted);
  }
  
  async _decryptGM(peerId, envelope) {
    const keyRef = this._gmKeyRef();
    if (!keyRef) {
      throw new Error('GM keypair not initialized');
    }
    
    const senderPubKey = this.getGMPeerPublicKey(peerId);
    if (!senderPubKey) {
      throw new Error(`No GM public key for peer ${peerId}`);
    }
    
    const result = await window.MessageGM.decryptMessage(
      envelope,
      keyRef,
      senderPubKey
    );
    
    if (!result.verified) {
      throw new Error(`GM decryption failed: ${result.error || 'verification failed'}`);
    }
    
    return result.plaintext;
  }
  
  async getSharedKey(peerId) {
    // 从存储获取或生成
    let keyData = localStorage.getItem(`p2p_key_${peerId}`);
    
    if (!keyData) {
      // 生成新密钥 (实际应通过X3DH)
      const key = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      );
      
      const exported = await crypto.subtle.exportKey('raw', key);
      keyData = Array.from(new Uint8Array(exported));
      localStorage.setItem(`p2p_key_${peerId}`, JSON.stringify(keyData));
    } else {
      keyData = JSON.parse(keyData);
    }
    
    return crypto.subtle.importKey(
      'raw',
      new Uint8Array(keyData),
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt']
    );
  }
  
  // ================================================
  // 二维码连接
  // ================================================
  
  generateConnectionQR() {
    const info = {
      id: this.localId,
      // 获取本地IP
      addrs: this.getLocalAddresses(),
      // 公钥指纹
      keyFingerprint: this.getKeyFingerprint()
    };
    
    return JSON.stringify(info);
  }
  
  getLocalAddresses() {
    // 从RTCPeerConnection获取本地IP
    const addresses = [];
    // 简化版，实际应遍历ICE candidates
    return addresses;
  }
  
  getKeyFingerprint() {
    // 生成公钥指纹用于验证
    return this.localId.substring(0, 16);
  }
  
  async connectByQR(qrData) {
    const info = JSON.parse(qrData);
    
    // 尝试所有地址
    for (const addr of info.addrs) {
      try {
        await this.connectToPeer(addr.ip, addr.port);
        console.log('[P2P] Connected via QR to', info.id);
        return true;
      } catch (err) {
        console.warn('[P2P] Failed to connect to', addr);
      }
    }
    
    return false;
  }
  
  // ================================================
  // 语音通话 (WebRTC)
  // ================================================
  
  async startVoiceCall(peerId) {
    const pc = this.peers.get(peerId);
    if (!pc) {
      throw new Error('Not connected to peer');
    }
    
    // 获取麦克风
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    
    // 添加轨道
    stream.getTracks().forEach(track => {
      pc.addTrack(track, stream);
    });
    
    // 创建offer
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    
    // 通过数据通道发送
    this.sendSignal(peerId, {
      type: 'call',
      action: 'offer',
      sdp: offer.sdp
    });
    
    return stream;
  }
  
  sendSignal(peerId, signal) {
    const dc = this.dataChannels.get(peerId);
    if (dc && dc.readyState === 'open') {
      dc.send(JSON.stringify(signal));
    }
  }
  
  // ================================================
  // 工具方法
  // ================================================
  
  onMessage(handler) {
    this.messageHandlers.add(handler);
    return () => this.messageHandlers.delete(handler);
  }
  
  getConnectedPeers() {
    return Array.from(this.dataChannels.keys());
  }
  
  isConnected(peerId) {
    const dc = this.dataChannels.get(peerId);
    return dc && dc.readyState === 'open';
  }
  
  queueMessage(peerId, msg) {
    const queue = JSON.parse(localStorage.getItem(`queue_${peerId}`) || '[]');
    queue.push(msg);
    localStorage.setItem(`queue_${peerId}`, JSON.stringify(queue));
  }
  
  async sendPendingMessages(peerId) {
    const queue = JSON.parse(localStorage.getItem(`queue_${peerId}`) || '[]');
    localStorage.removeItem(`queue_${peerId}`);
    
    for (const msg of queue) {
      const dc = this.dataChannels.get(peerId);
      if (dc && dc.readyState === 'open') {
        dc.send(JSON.stringify(msg));
      }
    }
  }
  
  sendReceipt(peerId, messageId) {
    this.sendSignal(peerId, {
      type: 'receipt',
      messageId: messageId,
      status: 'read'
    });
  }
}

// ================================================
// 本地消息存储
// ================================================

class LocalMessageStore {
  constructor() {
    this.db = null;
    this.init();
  }
  
  async init() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open('fibemate_p2p', 1);
      
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        this.db = request.result;
        resolve();
      };
      
      request.onupgradeneeded = (e) => {
        const db = e.target.result;
        
        if (!db.objectStoreNames.contains('messages')) {
          const store = db.createObjectStore('messages', { keyPath: 'id' });
          store.createIndex('peerId', 'peerId', { unique: false });
          store.createIndex('timestamp', 'timestamp', { unique: false });
        }
        
        if (!db.objectStoreNames.contains('peers')) {
          const store = db.createObjectStore('peers', { keyPath: 'id' });
          store.createIndex('lastSeen', 'lastSeen', { unique: false });
        }
      };
    });
  }
  
  async saveMessage(msg) {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(['messages'], 'readwrite');
      const store = tx.objectStore('messages');
      const request = store.put(msg);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }
  
  async getMessages(peerId, limit = 50) {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(['messages'], 'readonly');
      const store = tx.objectStore('messages');
      const index = store.index('peerId');
      const request = index.openCursor(peerId, 'prev');
      
      const messages = [];
      request.onsuccess = (e) => {
        const cursor = e.target.result;
        if (cursor && messages.length < limit) {
          messages.push(cursor.value);
          cursor.continue();
        } else {
          resolve(messages.reverse());
        }
      };
      request.onerror = () => reject(request.error);
    });
  }
  
  async updateMessageStatus(id, status) {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(['messages'], 'readwrite');
      const store = tx.objectStore('messages');
      const request = store.get(id);
      
      request.onsuccess = () => {
        const msg = request.result;
        if (msg) {
          msg.status = status;
          store.put(msg);
        }
        resolve();
      };
      request.onerror = () => reject(request.error);
    });
  }
}

// ================================================
// 导出
// ================================================

window.P2PNetwork = P2PNetwork;
window.LocalMessageStore = LocalMessageStore;

console.log('[P2P] Core module loaded');

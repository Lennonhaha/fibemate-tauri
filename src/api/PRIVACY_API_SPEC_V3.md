# FIBEMATE Pre-Key Bundle API v3 — X25519 协议扩展

## 概述

FIBEMATE 从 v2 (P-256 ECDSA X3DH + Double Ratchet) 升级到 v3 (X25519 Rust Double Ratchet)。  
本规范定义了 v3 pre-key bundle 的 API 扩展，同时保持 v2 向后兼容。

## 协议版本

| Version | Curve | 身份密钥格式 | SPK 格式 | OPK 池 |
|---------|-------|------------|---------|--------|
| 2 | P-256 (65B) | byte[] | byte[] (65B) | 需要（Signal 式 OPK 池） |
| 3 | X25519 (32B) | hex 字符串 (64ch) | hex 字符串 (64ch) | 不需要（按会话生成 ephemeral） |

## API 端点

### 1. 上传 Pre-Key Bundle

```
POST /api/pre-keys/{userId}
Authorization: Bearer <token>
Content-Type: application/json
```

#### v3 (X25519 Rust DR) 请求体
```json
{
  "version": 3,
  "protocol": "x25519-double-ratchet",
  "curve": "x25519",
  "identityKey": "a1b2c3d4e5f6...",       // 64-char hex (X25519 32B 公钥)
  "signedPreKey": "e5f6a7b8c9d0...",       // 64-char hex (X25519 32B SPK 公钥)
  "signedPreKeyId": 1719000000000,          // Unix ms timestamp
  "oneTimePreKeys": [],                     // v3 不使用 OPK 池
  "kemPublicKey": "00a1b2c3..."             // 可选：ML-KEM-768 公钥 (hex, ~1184 chars)
}
```

#### v2 (P-256 legacy) 请求体（向后兼容）
```json
{
  "version": 2,
  "protocol": "p256-x3dh",
  "identityKey": [65, 4, 27, ...],          // SPKI 编码 P-256 公钥 (65 bytes)
  "identitySigningKey": [48, 89, ...],      // SPKI 编码 ECDSA 公钥 (91 bytes)
  "signedPreKey": [4, ...],                 // 原始 P-256 公钥 (65 bytes)
  "signedPreKeyId": 1719000000,
  "signedPreKeySignature": [48, 70, ...],   // DER 编码 ECDSA 签名
  "oneTimePreKeys": [                        // OPK 列表
    {"keyId": 1719000001, "publicKey": [4, ...]}
  ]
}
```

#### 响应（v3 和 v2）
```json
{
  "userId": "alice",
  "version": 3,
  "protocol": "x25519-double-ratchet",
  "signedPreKeyId": 1719000000000,
  "oneTimePreKeyCount": 0,
  "lowOPKs": false,
  "uploadedAt": "2026-06-19T02:07:00Z"
}
```

---

### 2. 获取 Pre-Key Bundle

```
GET /api/pre-keys/{userId}
Authorization: Bearer <token>
```

#### 响应（v3 — 返回用户上传的格式）
```json
{
  "userId": "bob",
  "version": 3,
  "protocol": "x25519-double-ratchet",
  "curve": "x25519",
  "identityKey": "a1b2c3d4e5f6...",
  "signedPreKey": "e5f6a7b8c9d0...",
  "signedPreKeyId": 1719000000000,
  "kemPublicKey": null,
  "oneTimePreKeyCount": 0,
  "uploadedAt": "2026-06-19T02:07:00Z"
}
```

v2 用户返回原始 byte[] 格式；客户端自动检测。

---

### 3. 补充 OPK（v3 为 No-Op）

```
POST /api/pre-keys/{userId}/replenish
Authorization: Bearer <token>
```

v3 请求体：
```json
{
  "version": 3,
  "protocol": "x25519-double-ratchet",
  "identityKey": "hex...",
  "signedPreKey": "hex...",
  "signedPreKeyId": 1719000000000,
  "oneTimePreKeys": []
}
```

v3 响应（no-op）：
```json
{
  "userId": "alice",
  "version": 3,
  "status": "ok",
  "oneTimePreKeyCount": 0,
  "message": "X25519 protocol: per-session ephemerals, no OPK pool"
}
```

v2 行为不变：添加 OPK 到现有池。

---

### 4. Pre-Key Bundle 状态

```
GET /api/pre-keys/{userId}/status
Authorization: Bearer <token>
```

v3 响应示例：
```json
{
  "userId": "alice",
  "version": 3,
  "protocol": "x25519-double-ratchet",
  "hasIdentityKey": true,
  "signedPreKeyId": 1719000000000,
  "oneTimePreKeysAvailable": 0,
  "lowOPKs": false,
  "uploadedAt": "2026-06-19T02:07:00Z"
}
```

---

### 5. X3DH Init 消息（更新）

```
POST /api/x3dh/init
Authorization: Bearer <token>
```

v3 请求体：
```json
{
  "from": "alice",
  "to": "bob",
  "version": 3,
  "protocol": "x25519-double-ratchet",
  "initialMessage": {
    "type": "x3dh_init_rust",
    "version": 3,
    "protocol": "x25519-double-ratchet",
    "identityKey": "a1b2c3...",     // hex
    "ephemeralKey": "d4e5f6...",     // hex
    "drPublicKey": "9876...",        // hex
    "signedPreKeyId": 1719000000000
  }
}
```

v2 格式不变：
```json
{
  "from": "alice",
  "to": "bob",
  "version": 2,
  "protocol": "p256-x3dh",
  "initialMessage": {
    "type": "x3dh_init",
    "identityKey": [65, 4, ...],
    "ephemeralKey": [4, ...],
    "signedPreKeyId": 1719000000
  }
}
```

---

### 6. 待处理 X3DH Init 消息

```
GET /api/x3dh/pending/{userId}
Authorization: Bearer <token>
```

返回格式不变 — 包含 v2 和 v3 格式的 init 消息：
```json
{
  "userId": "bob",
  "pendingMessages": [
    {
      "messageId": "uuid",
      "from": "alice",
      "to": "bob",
      "version": 3,
      "initialMessage": {
        "type": "x3dh_init_rust",
        "version": 3,
        "protocol": "x25519-double-ratchet",
        "identityKey": "hex...",
        "ephemeralKey": "hex...",
        "drPublicKey": "hex...",
        "signedPreKeyId": 1719000000000
      },
      "createdAt": "2026-06-19T02:07:00Z"
    }
  ]
}
```

---

## 服务端实现要点

### 存储
- 添加 `version` (int) 和 `protocol` (string) 字段到 pre-key bundle 表
- v3 用户的 `oneTimePreKeys` 数组为空
- v3 用户不存储 `identitySigningKey` 和 `signedPreKeySignature`（X25519 不需要 ECDSA 签名）
- 当用户从 v2 升级到 v3，覆盖旧记录

### 版本检测
- 读取请求体 `version` 字段决定格式
- 如果 `version >= 3`：以 hex 字符串形式存储密钥，`oneTimePreKeys` 留空
- 如果 `version` 缺失或为 2：以 byte[] 形式存储（向后兼容）

### OPK 处理
- v3：`replenish` 端点直接返回成功（no-op）
- v3：`fetch` 端点不需要消耗/标记 OPK（v3 不使用 OPK 池）
- v2：行为不变

### X3DH Init
- 存储 `version` 和 `protocol` 字段
- v3 init 消息不走响应/完成路径（X25519 握手在客户端完成）

---

## 客户端集成（已实施）

| 文件 | 变更 |
|------|-----|
| `api/privacy-api-client.js` | `detectBundleVersion()`, v3 上传/获取/补充 OPK |
| `main-v3.js` | 使用 `privacyAPI.fetchPreKeyBundle()` 替代直接 fetch；v3 检测；X3DH init 处理 |
| `tauri-message-crypto-adapter.js` | `getSecurityStatus`, `hasSession`, `_getIdentityKey`, `_getSession` |
| `main.html` | 移除 `message-crypto-v2.js` 的 `defer`（确保 fallback 保存顺序） |

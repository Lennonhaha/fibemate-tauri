# FIBEMATE Privacy Features - Backend API Specification

## Overview
This document defines the backend API endpoints required to support the 7 privacy features integrated into FIBEMATE v3.0.

## Base URL
```
https://fibemate.net/api
```

## Authentication
All endpoints require Bearer token authentication:
```
Authorization: Bearer <token>
```

---

## 1. Burn After Read Messages

### POST /messages/burn
Send a burn-after-read message.

**Request:**
```json
{
  "conversationId": "string",
  "encryptedContent": "string",
  "messageType": "burn",
  "burnAfterRead": true,
  "burnTimeout": 30,
  "burnMessageId": "uuid"
}
```

**Response:**
```json
{
  "messageId": "uuid",
  "status": "sent",
  "burnTimeout": 30,
  "createdAt": "2026-05-08T01:30:00Z"
}
```

### POST /messages/burn/:messageId/read
Mark a burn message as read (triggers deletion).

**Response:**
```json
{
  "messageId": "uuid",
  "status": "burned",
  "burnedAt": "2026-05-08T01:30:30Z"
}
```

### GET /messages/burn/:messageId/status
Check burn message status.

**Response:**
```json
{
  "messageId": "uuid",
  "status": "pending|read|burned",
  "remainingTime": 15
}
```

---

## 2. Device Binding

### GET /devices
List registered devices.

**Response:**
```json
{
  "devices": [
    {
      "deviceId": "string",
      "deviceName": "string",
      "deviceType": "desktop|mobile|tablet",
      "verified": true,
      "lastActive": "2026-05-08T01:30:00Z",
      "trustScore": 100
    }
  ]
}
```

### POST /devices/register
Register a new device.

**Request:**
```json
{
  "deviceId": "string",
  "deviceName": "string",
  "deviceType": "desktop|mobile|tablet",
  "publicKey": "string",
  "deviceFingerprint": "string"
}
```

**Response:**
```json
{
  "deviceId": "string",
  "status": "verified|pending",
  "verificationId": "uuid"
}
```

### POST /devices/:deviceId/verify
Verify a pending device.

**Request:**
```json
{
  "approved": true,
  "verifierDeviceId": "string"
}
```

**Response:**
```json
{
  "deviceId": "string",
  "verified": true,
  "verifiedAt": "2026-05-08T01:30:00Z"
}
```

### DELETE /devices/:deviceId
Remove a device.

**Response:**
```json
{
  "deviceId": "string",
  "removed": true
}
```

---

## 3. Offline Messages

### POST /offline-messages
Store an offline message.

**Request:**
```json
{
  "recipientId": "string",
  "encryptedContent": "string",
  "messageType": "text|file|voice",
  "ttl": 3600,
  "priority": "low|normal|high"
}
```

**Response:**
```json
{
  "messageId": "uuid",
  "status": "stored",
  "expiresAt": "2026-05-08T02:30:00Z"
}
```

### GET /offline-messages
Retrieve offline messages for current user.

**Response:**
```json
{
  "messages": [
    {
      "messageId": "uuid",
      "senderId": "string",
      "encryptedContent": "string",
      "messageType": "text",
      "storedAt": "2026-05-08T01:00:00Z",
      "expiresAt": "2026-05-08T02:00:00Z"
    }
  ]
}
```

### POST /offline-messages/:messageId/delivered
Mark offline message as delivered.

**Response:**
```json
{
  "messageId": "uuid",
  "status": "delivered"
}
```

---

## 4. Encrypted File Transfer

### POST /files/upload-init
Initialize encrypted file upload.

**Request:**
```json
{
  "filename": "string",
  "fileSize": 1048576,
  "mimeType": "string",
  "recipientId": "string",
  "totalChunks": 10
}
```

**Response:**
```json
{
  "uploadId": "uuid",
  "chunkSize": 104857,
  "uploadUrl": "string"
}
```

### POST /files/upload/:uploadId/chunk/:chunkIndex
Upload a file chunk.

**Request:**
```
Content-Type: application/octet-stream
Body: <chunk bytes>
```

**Response:**
```json
{
  "chunkIndex": 0,
  "status": "received"
}
```

### POST /files/upload/:uploadId/complete
Complete file upload.

**Request:**
```json
{
  "encryptedKey": "string",
  "integrityHash": "sha256"
}
```

**Response:**
```json
{
  "fileId": "uuid",
  "status": "ready",
  "downloadUrl": "string"
}
```

### GET /files/:fileId/download
Download encrypted file.

**Response:**
```
Content-Type: application/octet-stream
Body: <encrypted file bytes>
```

---

## 5. Safety Numbers

### GET /safety-numbers/:contactId
Get safety numbers for a contact.

**Response:**
```json
{
  "contactId": "string",
  "numbers": ["12345", "67890", "..."],
  "hash": "sha256",
  "verified": true,
  "verifiedAt": "2026-05-08T01:30:00Z"
}
```

### POST /safety-numbers/:contactId/verify
Verify safety numbers for a contact.

**Request:**
```json
{
  "numbers": ["12345", "67890", "..."],
  "hash": "sha256"
}
```

**Response:**
```json
{
  "contactId": "string",
  "verified": true,
  "match": true
}
```

---

## 6. Key Rotation

### POST /keys/rotate
Rotate encryption keys.

**Response:**
```json
{
  "keyId": "uuid",
  "version": 2,
  "publicKey": "string",
  "createdAt": "2026-05-08T01:30:00Z"
}
```

### GET /keys/current
Get current encryption key.

**Response:**
```json
{
  "keyId": "uuid",
  "version": 2,
  "publicKey": "string",
  "createdAt": "2026-05-08T01:30:00Z"
}
```

### GET /keys/history
Get key rotation history.

**Response:**
```json
{
  "keys": [
    {
      "keyId": "uuid",
      "version": 1,
      "createdAt": "2026-05-07T01:30:00Z",
      "rotatedAt": "2026-05-08T01:30:00Z"
    }
  ]
}
```

---

## 7. Screenshot Detection (Client-Side Only)

Screenshot detection is handled entirely client-side via `privacy-layers/screenshot-detector.js`.

Server-side webhook (optional):

### POST /webhooks/screenshot
Notify server of screenshot detection (optional).

**Request:**
```json
{
  "deviceId": "string",
  "timestamp": "2026-05-08T01:30:00Z",
  "type": "screenshot|screenrecording"
}
```

---

## Error Responses

All endpoints return standard error format:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human readable message",
    "details": {}
  }
}
```

Common error codes:
- `UNAUTHORIZED` - Invalid or missing token
- `FORBIDDEN` - Insufficient permissions
- `NOT_FOUND` - Resource not found
- `VALIDATION_ERROR` - Invalid request data
- `RATE_LIMITED` - Too many requests
- `DEVICE_LIMIT` - Maximum devices reached

---

## WebSocket Events

### Client → Server
```json
{
  "type": "message",
  "to": "userId",
  "conversationId": "uuid",
  "encryptedContent": "string",
  "messageType": "text|burn|file",
  "burnAfterRead": false,
  "burnTimeout": 30
}
```

### Server → Client
```json
{
  "type": "message",
  "from": "userId",
  "messageId": "uuid",
  "encryptedContent": "string",
  "messageType": "burn",
  "burnTimeout": 30,
  "timestamp": "2026-05-08T01:30:00Z"
}
```

### Burn Notification
```json
{
  "type": "burn",
  "messageId": "uuid",
  "status": "burned",
  "timestamp": "2026-05-08T01:30:30Z"
}
```

---

## Implementation Notes

1. **Burn Messages**: Server should auto-delete burn messages after timeout, even if not read
2. **Offline Messages**: Implement TTL-based cleanup, max 100 messages per recipient
3. **File Upload**: Support chunked upload for large files, max 100MB per file
4. **Device Binding**: First device auto-verified, subsequent devices require approval
5. **Key Rotation**: Maintain backward compatibility for 1 version during rotation
6. **Rate Limiting**: 100 requests/minute for file operations, 1000/minute for messages

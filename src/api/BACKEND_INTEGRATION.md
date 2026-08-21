# FIBEMATE Backend Integration Guide

## Overview
This guide documents the backend API integration for FIBEMATE privacy features.

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   FIBEMATE      │     │   Backend API   │     │   Database      │
│   Electron App  │◄───►│   (Node.js)     │◄───►│   (PostgreSQL)  │
│                 │     │                 │     │                 │
│ - Privacy Layers│     │ - REST API      │     │ - Messages      │
│ - API Client    │     │ - WebSocket     │     │ - Devices       │
│ - UI Components │     │ - File Storage  │     │ - Files         │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

## Quick Start

### 1. Start Mock Server (Development)

```bash
cd src/api
node mock-server.js
```

Server runs on `http://localhost:3002`

### 2. Configure API Base URL

In `src/api/privacy-api-client.js`:
```javascript
const API_BASE = 'http://localhost:3002'; // Development
// const API_BASE = 'http://8.156.77.68:3001/api'; // Production
```

### 3. Use API Client

```javascript
// Import the API client
import { privacyAPI } from './api/privacy-api-client.js';

// Send burn message
await privacyAPI.sendBurnMessage(conversationId, encryptedContent, 30, messageId);

// Register device
await privacyAPI.registerDevice({
  deviceId: 'my-device',
  deviceName: 'My Laptop',
  deviceType: 'desktop'
});
```

## API Endpoints

### Burn Messages

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/messages` | Send message (including burn) |
| POST | `/messages/burn/:id/read` | Mark burn message as read |
| GET | `/messages/burn/:id/status` | Check burn message status |

### Device Binding

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/devices` | List registered devices |
| POST | `/devices/register` | Register new device |
| POST | `/devices/:id/verify` | Verify pending device |
| DELETE | `/devices/:id` | Remove device |

### Offline Messages

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/offline-messages` | Store offline message |
| GET | `/offline-messages` | Retrieve offline messages |
| POST | `/offline-messages/:id/delivered` | Mark as delivered |

### File Transfer

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/files/upload-init` | Initialize upload |
| POST | `/files/upload/:id/chunk/:index` | Upload chunk |
| POST | `/files/upload/:id/complete` | Complete upload |
| GET | `/files/:id/download` | Download file |

### Safety Numbers

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/safety-numbers/:contactId` | Get safety numbers |
| POST | `/safety-numbers/:contactId/verify` | Verify numbers |

### Key Rotation

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/keys/rotate` | Rotate keys |
| GET | `/keys/current` | Get current key |
| GET | `/keys/history` | Get key history |

## Data Flow

### Burn After Read

```
User sends burn message
    │
    ▼
Frontend: Create burn message with timeout
    │
    ▼
API: POST /messages (with burnAfterRead=true)
    │
    ▼
Backend: Store message with TTL
    │
    ▼
Recipient reads message
    │
    ▼
API: POST /messages/burn/:id/read
    │
    ▼
Backend: Mark as burned, delete content
    │
    ▼
Frontend: Animate message destruction
```

### Device Binding

```
New device registration
    │
    ▼
API: POST /devices/register
    │
    ▼
Backend: Check if first device
    │
    ├── Yes → Auto-verify
    │
    └── No → Create verification request
                │
                ▼
        Existing device receives notification
                │
                ▼
        API: POST /devices/:id/verify
                │
                ▼
        Backend: Update device status
```

### Offline Messages

```
Sender sends message to offline recipient
    │
    ▼
API: POST /offline-messages
    │
    ▼
Backend: Store encrypted message
    │
    ▼
Recipient comes online
    │
    ▼
API: GET /offline-messages
    │
    ▼
Backend: Return stored messages
    │
    ▼
API: POST /offline-messages/:id/delivered
    │
    ▼
Backend: Mark as delivered, schedule deletion
```

## Error Handling

All API errors follow this format:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human readable message",
    "details": {}
  }
}
```

Common errors:
- `UNAUTHORIZED` (401) - Invalid or missing token
- `FORBIDDEN` (403) - Insufficient permissions
- `NOT_FOUND` (404) - Resource not found
- `VALIDATION_ERROR` (400) - Invalid request data
- `RATE_LIMITED` (429) - Too many requests
- `DEVICE_LIMIT` (400) - Maximum devices reached

## Testing

### Run Mock Server Tests

```bash
# Start mock server
node src/api/mock-server.js

# In another terminal, run tests
node src/api/test-backend-integration.js
```

### Expected Results

```
========================================
FIBEMATE Backend Integration Tests
========================================

✓ Burn Messages: PASS
✓ Device Binding: PASS
✓ Offline Messages: PASS
✓ File Transfer: PASS
✓ Safety Numbers: PASS
✓ Key Rotation: PASS
✓ Screenshot Webhook: PASS

Total: 7 | Passed: 7 | Failed: 0
========================================
```

## Production Deployment

### Environment Variables

```bash
# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/fibemate

# JWT Secret
JWT_SECRET=your-secret-key

# File Storage
FILE_STORAGE_PATH=/var/lib/fibemate/files
MAX_FILE_SIZE=104857600  # 100MB

# Rate Limiting
RATE_LIMIT_WINDOW=60000  # 1 minute
RATE_LIMIT_MAX=1000      # requests per window

# Offline Message TTL
OFFLINE_MESSAGE_TTL=604800  # 7 days
OFFLINE_MESSAGE_MAX=100     # max per recipient
```

### Database Schema

```sql
-- Burn Messages
CREATE TABLE burn_messages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  conversation_id UUID NOT NULL,
  sender_id UUID NOT NULL,
  encrypted_content TEXT NOT NULL,
  burn_timeout INTEGER DEFAULT 30,
  status VARCHAR(20) DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT NOW(),
  burned_at TIMESTAMP
);

-- Devices
CREATE TABLE devices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  device_name VARCHAR(255),
  device_type VARCHAR(50),
  public_key TEXT,
  fingerprint VARCHAR(255),
  verified BOOLEAN DEFAULT FALSE,
  trust_score INTEGER DEFAULT 0,
  last_active TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Offline Messages
CREATE TABLE offline_messages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sender_id UUID NOT NULL,
  recipient_id UUID NOT NULL,
  encrypted_content TEXT NOT NULL,
  message_type VARCHAR(50) DEFAULT 'text',
  priority VARCHAR(20) DEFAULT 'normal',
  status VARCHAR(20) DEFAULT 'stored',
  expires_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW(),
  delivered_at TIMESTAMP
);

-- Files
CREATE TABLE encrypted_files (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  filename VARCHAR(255),
  file_size BIGINT,
  mime_type VARCHAR(100),
  sender_id UUID NOT NULL,
  recipient_id UUID NOT NULL,
  encrypted_key TEXT,
  integrity_hash VARCHAR(255),
  storage_path TEXT,
  status VARCHAR(20) DEFAULT 'uploading',
  created_at TIMESTAMP DEFAULT NOW(),
  completed_at TIMESTAMP
);

-- Safety Numbers
CREATE TABLE safety_numbers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  contact_id UUID NOT NULL,
  numbers TEXT[] NOT NULL,
  hash VARCHAR(255),
  verified BOOLEAN DEFAULT FALSE,
  verified_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Keys
CREATE TABLE encryption_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  version INTEGER NOT NULL,
  public_key TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  rotated_at TIMESTAMP
);
```

## Security Considerations

1. **Authentication**: All endpoints require valid JWT token
2. **Authorization**: Users can only access their own data
3. **Encryption**: All messages stored encrypted (end-to-end)
4. **File Storage**: Files stored encrypted at rest
5. **Rate Limiting**: Prevent abuse and DoS attacks
6. **Audit Logging**: Log sensitive operations
7. **Data Retention**: Auto-delete expired data

## Monitoring

Track these metrics in production:

- API response times
- Error rates by endpoint
- Active device count
- Offline message queue size
- File storage usage
- Key rotation frequency
- Burn message burn rate

## Next Steps

1. Implement actual backend API (Node.js/Express)
2. Set up PostgreSQL database
3. Configure file storage (S3/MinIO)
4. Set up monitoring (Prometheus/Grafana)
5. Implement WebSocket server for real-time events
6. Add push notifications for offline messages
7. Implement device fingerprinting
8. Add audit logging

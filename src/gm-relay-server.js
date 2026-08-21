// gm-relay-server.js — 超轻量内存消息中继
// 零 npm 依赖，仅用于本地 GM 加密双账号收发测试
// 启动: node gm-relay-server.js → http://localhost:3000

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ============ 内存存储 ============
const conversations = {};  // id → { id, participants: Set, messages: [] }
const messages = {};       // convId → [msgObj]

function uuid() {
  return crypto.randomUUID();
}

function findOrCreateConv(userA, userB) {
  // 查找已有双人会话
  for (const [id, conv] of Object.entries(conversations)) {
    if (conv.participants.has(userA) && conv.participants.has(userB) && conv.participants.size === 2) {
      return conv;
    }
  }
  // 创建新会话
  const convId = uuid();
  const conv = { id: convId, participants: new Set([userA, userB]), messages: [] };
  conversations[convId] = conv;
  return conv;
}

function sendJSON(res, code, obj) {
  res.writeHead(code, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  });
  res.end(JSON.stringify(obj));
}

// ============ MIME 类型表 ============
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.svg':  'image/svg+xml',
  '.png':  'image/png',
  '.json': 'application/json',
};

function serveFile(reqPath, res) {
  const safe = path.normalize(reqPath).replace(/^\.\./, '');
  const filePath = path.join(__dirname, safe);
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(err.code === 'ENOENT' ? 404 : 500);
      res.end('File not found');
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Access-Control-Allow-Origin': '*'
    });
    res.end(data);
  });
}

// ============ 路由 ============
function handleAPI(req, res, url, body) {
  // GET /api/conversations/:id/messages?limit=N
  const getMsgs = url.match(/^\/api\/conversations\/([^/]+)\/messages$/);
  if (req.method === 'GET' && getMsgs) {
    const convId = getMsgs[1];
    const msgs = messages[convId] || [];
    const sorted = msgs.slice().sort((a, b) => a.createdAt - b.createdAt);
    sendJSON(res, 200, { messages: sorted });
    return;
  }

  // POST /api/conversations/find-or-create
  if (req.method === 'POST' && url === '/api/conversations/find-or-create') {
    const { userId, myUserId } = body;
    const participantA = myUserId || 'alice';
    const participantB = userId || 'bob';
    const conv = findOrCreateConv(participantA, participantB);
    sendJSON(res, 200, {
      conversationId: conv.id,
      otherUser: { userId: participantB, username: participantB }
    });
    return;
  }

  // POST /api/messages
  if (req.method === 'POST' && url === '/api/messages') {
    const { conversationId, ciphertext, messageType, senderUserId } = body;
    if (!conversationId || !ciphertext) {
      sendJSON(res, 400, { error: 'missing conversationId or ciphertext' });
      return;
    }
    // 确定发送者
    const sender = senderUserId || 'alice';
    const msgObj = {
      id: uuid(),
      conversationId,
      senderUserId: sender,
      ciphertext,
      messageType: messageType || 'text',
      createdAt: Date.now()
    };
    messages[conversationId] = messages[conversationId] || [];
    messages[conversationId].push(msgObj);
    sendJSON(res, 201, { messageId: msgObj.id, createdAt: msgObj.createdAt });
    return;
  }

  // 404
  sendJSON(res, 404, { error: 'not found' });
}

// ============ HTTP Server ============
const server = http.createServer((req, res) => {
  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    });
    res.end();
    return;
  }

  const url = new URL(req.url, 'http://localhost');
  const pathname = url.pathname;

  // API 路由
  if (pathname.startsWith('/api/')) {
    let raw = '';
    req.on('data', chunk => raw += chunk);
    req.on('end', () => {
      let body = {};
      try { body = JSON.parse(raw || '{}'); } catch {}
      handleAPI(req, res, pathname, body);
    });
    return;
  }

  // 静态文件
  if (pathname === '/' || pathname === '/gm-chat.html' || pathname === '/gm-chat-local.html') {
    serveFile('/gm-chat-local.html', res);
    return;
  }
  serveFile(pathname, res);
});

server.listen(3000, () => {
  console.log('🚀 GM Relay Server 已启动: http://localhost:3000');
  console.log('   测试页面: http://localhost:3000/gm-chat-local.html');
  console.log('   端点: POST /api/conversations/find-or-create');
  console.log('         POST /api/messages');
  console.log('         GET  /api/conversations/:id/messages');
});

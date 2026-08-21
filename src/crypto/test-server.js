const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 3456;

const MIME_TYPES = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.wasm': 'application/wasm',
  '.css': 'text/css'
};

const server = http.createServer((req, res) => {
  let filePath = path.join(__dirname, req.url === '/' ? 'test-pq-wasm.html' : req.url);
  
  // Handle pq-wasm paths
  if (req.url.includes('/pq-wasm/')) {
    filePath = path.join(__dirname, '..', req.url.replace(/^\//, ''));
  }
  
  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';
  
  fs.readFile(filePath, (err, data) => {
    if (err) {
      console.error(`404: ${req.url}`);
      res.writeHead(404);
      res.end('Not found');
      return;
    }
    
    // CORS headers for WASM
    res.writeHead(200, {
      'Content-Type': contentType,
      'Access-Control-Allow-Origin': '*',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp'
    });
    res.end(data);
  });
});

server.listen(PORT, () => {
  console.log(`Test server running at http://localhost:${PORT}`);
  console.log('Open this URL in your browser to test PQ-WASM');
});

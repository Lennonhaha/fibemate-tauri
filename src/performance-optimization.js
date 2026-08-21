/**
 * FIBEMATE 性能优化模块
 * 无动画，纯实用优化
 */

// ================================================
// 1. 虚拟滚动（大数据量消息列表）
// ================================================

class VirtualScroller {
  constructor(container, itemHeight = 60) {
    this.container = container;
    this.itemHeight = itemHeight;
    this.items = [];
    this.visibleCount = Math.ceil(container.clientHeight / itemHeight) + 5;
    this.scrollTop = 0;
    
    this.container.addEventListener('scroll', () => {
      this.scrollTop = this.container.scrollTop;
      this.render();
    });
    
    window.addEventListener('resize', () => {
      this.visibleCount = Math.ceil(this.container.clientHeight / this.itemHeight) + 5;
      this.render();
    });
  }
  
  setItems(items) {
    this.items = items;
    this.container.style.height = `${items.length * this.itemHeight}px`;
    this.render();
  }
  
  render() {
    const startIdx = Math.floor(this.scrollTop / this.itemHeight);
    const endIdx = Math.min(startIdx + this.visibleCount, this.items.length);
    
    const fragment = document.createDocumentFragment();
    
    for (let i = startIdx; i < endIdx; i++) {
      const item = this.items[i];
      const el = this.renderItem(item, i);
      el.style.position = 'absolute';
      el.style.top = `${i * this.itemHeight}px`;
      el.style.left = '0';
      el.style.right = '0';
      fragment.appendChild(el);
    }
    
    this.container.innerHTML = '';
    this.container.appendChild(fragment);
  }
  
  renderItem(item, index) {
    // 由外部传入渲染函数
    return document.createElement('div');
  }
}

// ================================================
// 2. Web Worker 加密（不阻塞主线程）
// ================================================

class CryptoWorker {
  constructor() {
    this.worker = this.createWorker();
    this.pending = new Map();
    this.id = 0;
  }
  
  createWorker() {
    const workerScript = `
      self.onmessage = async (e) => {
        const { id, type, data } = e.data;
        try {
          let result;
          if (type === 'encrypt') {
            result = await encrypt(data);
          } else if (type === 'decrypt') {
            result = await decrypt(data);
          } else if (type === 'hash') {
            result = await hash(data);
          }
          self.postMessage({ id, result, error: null });
        } catch (error) {
          self.postMessage({ id, error: error.message });
        }
      };
      
      async function encrypt(data) {
        // 使用 WebCrypto API
        const encoder = new TextEncoder();
        const key = await crypto.subtle.generateKey(
          { name: 'AES-GCM', length: 256 },
          true,
          ['encrypt', 'decrypt']
        );
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv },
          key,
          encoder.encode(data)
        );
        return { encrypted, iv, key };
      }
      
      async function decrypt(data) {
        // 解密逻辑
        return data;
      }
      
      async function hash(data) {
        const encoder = new TextEncoder();
        const buffer = await crypto.subtle.digest('SHA-256', encoder.encode(data));
        return Array.from(new Uint8Array(buffer))
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');
      }
    `;
    
    const blob = new Blob([workerScript], { type: 'application/javascript' });
    return new Worker(URL.createObjectURL(blob));
  }
  
  async execute(type, data) {
    return new Promise((resolve, reject) => {
      const id = ++this.id;
      this.pending.set(id, { resolve, reject });
      this.worker.postMessage({ id, type, data });
    });
  }
  
  init() {
    this.worker.onmessage = (e) => {
      const { id, result, error } = e.data;
      const pending = this.pending.get(id);
      if (pending) {
        if (error) {
          pending.reject(new Error(error));
        } else {
          pending.resolve(result);
        }
        this.pending.delete(id);
      }
    };
  }
}

// ================================================
// 3. 内存管理（自动清理）
// ================================================

class MemoryManager {
  constructor() {
    this.cache = new Map();
    this.maxSize = 100; // 最大缓存条目
    this.ttl = 5 * 60 * 1000; // 5分钟过期
    
    // 定期清理
    setInterval(() => this.cleanup(), 60 * 1000);
  }
  
  set(key, value, ttl = this.ttl) {
    if (this.cache.size >= this.maxSize) {
      // LRU: 删除最旧的
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
    
    this.cache.set(key, {
      value,
      expires: Date.now() + ttl
    });
  }
  
  get(key) {
    const item = this.cache.get(key);
    if (!item) return null;
    
    if (Date.now() > item.expires) {
      this.cache.delete(key);
      return null;
    }
    
    return item.value;
  }
  
  cleanup() {
    const now = Date.now();
    for (const [key, item] of this.cache.entries()) {
      if (now > item.expires) {
        this.cache.delete(key);
      }
    }
    
    // 触发垃圾回收提示
    if (window.gc) {
      window.gc();
    }
  }
  
  clear() {
    this.cache.clear();
  }
}

// ================================================
// 4. 智能输入（无动画，纯功能）
// ================================================

class SmartInput {
  constructor(inputElement) {
    this.input = inputElement;
    this.suggestions = document.createElement('div');
    this.suggestions.className = 'input-suggestions';
    this.suggestions.style.cssText = `
      position: absolute;
      bottom: 100%;
      left: 0;
      right: 0;
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      max-height: 150px;
      overflow-y: auto;
      display: none;
      z-index: 100;
    `;
    
    this.input.parentElement.style.position = 'relative';
    this.input.parentElement.appendChild(this.suggestions);
    
    this.phrases = [
      'Hello',
      'How are you?',
      'Thank you',
      'See you later',
      'Good morning',
      'Good night',
      'What\'s up?',
      'I\'m fine',
      'Nice to meet you',
      'Take care'
    ];
    
    this.input.addEventListener('input', () => this.showSuggestions());
    this.input.addEventListener('keydown', (e) => this.handleKeydown(e));
    document.addEventListener('click', (e) => {
      if (!this.input.contains(e.target)) {
        this.hideSuggestions();
      }
    });
  }
  
  showSuggestions() {
    const value = this.input.value.toLowerCase();
    if (value.length < 1) {
      this.hideSuggestions();
      return;
    }
    
    const matches = this.phrases.filter(p => 
      p.toLowerCase().includes(value)
    ).slice(0, 5);
    
    if (matches.length === 0) {
      this.hideSuggestions();
      return;
    }
    
    this.suggestions.innerHTML = matches.map((phrase, i) => `
      <div class="suggestion-item" data-index="${i}" style="
        padding: 8px 12px;
        cursor: pointer;
        font-size: 14px;
        border-bottom: 1px solid var(--border-color);
      " onmouseover="this.style.background='rgba(0,229,195,0.1)'" 
      onmouseout="this.style.background='transparent'">
        ${phrase}
      </div>
    `).join('');
    
    this.suggestions.querySelectorAll('.suggestion-item').forEach(item => {
      item.addEventListener('click', () => {
        this.input.value = item.textContent.trim();
        this.hideSuggestions();
      });
    });
    
    this.suggestions.style.display = 'block';
  }
  
  hideSuggestions() {
    this.suggestions.style.display = 'none';
  }
  
  handleKeydown(e) {
    if (e.key === 'Escape') {
      this.hideSuggestions();
    }
  }
}

// ================================================
// 5. 批量操作优化
// ================================================

class BatchProcessor {
  constructor(batchSize = 10, delay = 100) {
    this.batchSize = batchSize;
    this.delay = delay;
    this.queue = [];
    this.processing = false;
  }
  
  add(task) {
    this.queue.push(task);
    if (!this.processing) {
      this.process();
    }
  }
  
  async process() {
    this.processing = true;
    
    while (this.queue.length > 0) {
      const batch = this.queue.splice(0, this.batchSize);
      await Promise.all(batch.map(task => task()));
      
      if (this.queue.length > 0) {
        await this.sleep(this.delay);
      }
    }
    
    this.processing = false;
  }
  
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// ================================================
// 6. 连接池管理
// ================================================

class ConnectionPool {
  constructor(maxConnections = 5) {
    this.maxConnections = maxConnections;
    this.connections = new Set();
    this.queue = [];
  }
  
  async acquire() {
    if (this.connections.size < this.maxConnections) {
      const conn = new WebSocketConnection();
      this.connections.add(conn);
      return conn;
    }
    
    return new Promise(resolve => {
      this.queue.push(resolve);
    });
  }
  
  release(conn) {
    this.connections.delete(conn);
    conn.close();
    
    if (this.queue.length > 0) {
      const resolve = this.queue.shift();
      this.acquire().then(resolve);
    }
  }
}

// ================================================
// 7. 压缩传输
// ================================================

class Compression {
  static async compress(data) {
    const stream = new CompressionStream('gzip');
    const writer = stream.writable.getWriter();
    const reader = stream.readable.getReader();
    
    const encoder = new TextEncoder();
    writer.write(encoder.encode(data));
    writer.close();
    
    const chunks = [];
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
    
    return new Blob(chunks);
  }
  
  static async decompress(blob) {
    const stream = blob.stream().pipeThrough(new DecompressionStream('gzip'));
    const reader = stream.getReader();
    
    const chunks = [];
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
    
    return new TextDecoder().decode(new Uint8Array(
      chunks.reduce((acc, chunk) => [...acc, ...chunk], [])
    ));
  }
}

// ================================================
// 8. 初始化优化
// ================================================

function initPerformanceOptimizations() {
  // 内存管理器
  window.memoryManager = new MemoryManager();
  
  // 批量处理器
  window.batchProcessor = new BatchProcessor();
  
  // 智能输入（如果有输入框）
  const messageInput = document.getElementById('messageInput');
  if (messageInput) {
    window.smartInput = new SmartInput(messageInput);
  }
  
  // 懒加载图片
  initLazyLoading();
  
  console.log('[Performance] Optimizations initialized');
}

function initLazyLoading() {
  if ('IntersectionObserver' in window) {
    const imageObserver = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const img = entry.target;
          if (img.dataset.src) {
            img.src = img.dataset.src;
            img.removeAttribute('data-src');
            imageObserver.unobserve(img);
          }
        }
      });
    });
    
    document.querySelectorAll('img[data-src]').forEach(img => {
      imageObserver.observe(img);
    });
  }
}

// DOM 加载完成后初始化
document.addEventListener('DOMContentLoaded', () => {
  if (window.location.pathname.endsWith('main.html')) {
    setTimeout(initPerformanceOptimizations, 500);
  }
});

console.log('[Performance] Optimization module loaded');

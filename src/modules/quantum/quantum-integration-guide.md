# FIBEMATE 量子城域网适配 - 集成指南

## 概述

本文档描述如何将量子城域网适配模块集成到 FIBEMATE 主应用。

## 集成步骤

### 1. 文件位置

将量子模块放置在 `src/modules/quantum/` 目录：

```
src/modules/quantum/
├── quantum-adapter.js          # QKD/QRNG适配器
├── quantum-crypto.js           # 量子密码学实现
├── quantum-integration.js      # 统一集成入口
├── quantum-test.js             # 测试套件
└── quantum-README.md           # 模块文档
```

### 2. HTML 引入

在 `main.html` 的 `<head>` 中添加：

```html
<!-- Quantum City Network -->
<script src="modules/quantum/quantum-adapter.js" defer></script>
<script src="modules/quantum/quantum-crypto.js" defer></script>
<script src="modules/quantum/quantum-integration.js" defer></script>
```

### 3. JavaScript 初始化

在 `main.js` 的 `DOMContentLoaded` 中添加：

```javascript
// P2: Initialize quantum city network
initQuantumAdaptation();
```

并定义初始化函数：

```javascript
function initQuantumAdaptation() {
  if (typeof QuantumIntegration === 'undefined') {
    console.warn('[Quantum] QuantumIntegration not available');
    return;
  }

  const fibemateCore = createQuantumCoreAdapter();
  const quantum = new QuantumIntegration(fibemateCore, {
    qkdEndpoint: 'http://localhost:8080',  // 配置实际QKD端点
    qrngEndpoint: 'http://localhost:8081', // 配置实际QRNG端点
    autoDetect: true,
    autoEnable: true,
    debug: true
  });

  quantum.init().then(available => {
    if (available) {
      console.log('[Quantum] Quantum city network adaptation initialized');
    } else {
      console.log('[Quantum] Quantum network not available, using classical encryption');
    }
  }).catch(err => {
    console.warn('[Quantum] Initialization failed:', err.message);
  });

  window.quantumIntegration = quantum;
}
```

### 4. 核心适配器

```javascript
function createQuantumCoreAdapter() {
  return {
    emit(event, data) {
      window.dispatchEvent(new CustomEvent(event, { detail: data }));
    },
    on(event, callback) {
      window.addEventListener(event, (e) => callback(e.detail));
    }
  };
}
```

### 5. 设置页面

在 `modules/settings.js` 中添加开关：

```javascript
<div class="setting-item">
  <div class="setting-info">
    <div class="setting-name">Quantum Enhancement</div>
    <div class="setting-desc">Use QKD/QRNG when available (requires quantum network)</div>
  </div>
  <label class="toggle">
    <input type="checkbox" data-setting="quantumMode" checked>
    <span class="toggle-slider"></span>
  </label>
</div>
```

### 6. 事件监听

```javascript
window.addEventListener('quantumEnabled', () => {
  showToast('量子增强已启用', 'info');
});

window.addEventListener('quantumDisabled', () => {
  showToast('量子增强已禁用', 'info');
});
```

## 配置选项

### QuantumIntegration

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `qkdEndpoint` | string | null | QKD服务URL |
| `qrngEndpoint` | string | null | QRNG服务URL |
| `autoDetect` | boolean | true | 自动检测量子网络 |
| `autoEnable` | boolean | true | 自动启用量子增强 |
| `debug` | boolean | false | 调试日志 |

## 事件

- `quantumEnabled`: 量子增强已启用
- `quantumDisabled`: 量子增强已禁用

## 测试

```javascript
const runner = new QuantumTestRunner();
await runner.runAllTests();
```

## 调试

### 控制台访问

```javascript
// 查看量子集成状态
window.quantumIntegration.getStatus();

// 手动启用/禁用
window.quantumIntegration.enable();
window.quantumIntegration.disable();

// 获取量子随机数
window.quantumIntegration.getQuantumRandom(32);
```

## 故障排除

### 模块未加载

检查浏览器控制台是否有 404 错误，确认文件路径正确。

### 量子网络不可用

模块会自动回退到经典加密，无需手动干预。

## 版本历史

- v1.0.0 (2026-05-13): 初始版本

## 参考

- [五网络融合战略](../../FIBEMATE_五网络融合战略.md)
- [卫星网络适配](../satellite/satellite-README.md)

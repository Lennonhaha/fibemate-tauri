# ADR-001: 桌面端选 Tauri 而非 Electron

## Status
Accepted

## Context

需要一个跨平台桌面客户端，且加密核心（KEM / 双棘轮）已经用 Rust 实现。两个现实约束：

1. 密码学逻辑必须留在 Rust 一侧，不能为了前端方便把它搬到 JS 里重写一份；
2. 安装包体积与内存占用要可控（本项目面向工程验证与演示，不希望分发一个几百 MB 的包）。

## Decision

采用 **Tauri 2** + 系统 WebView（Windows 上为 WebView2）：UI 仍是 Web，Rust 作为后端，两者通过 IPC 通信。

## Consequences

- ➕ 复用 Rust 加密核心，避免第二套实现（也就避免了两套实现不一致带来的「只在某一端出错」类故障）；
- ➕ 安装包与常驻内存远小于 Electron；
- ➖ **WebView2 成为最薄弱环节**：其漏洞与渲染层行为不在我们控制范围内（见 [威胁模型](../THREAT_MODEL.md)）；
- ➖ 前端依赖 `window.__TAURI__`，因此必须保留 `withGlobalTauri: true`；
- ➖ CSP 需要为现有内联脚本放行（`unsafe-inline` 尚未清除），这是已知待办。

## Alternatives considered

- **Electron**：生态更成熟，但要把加密逻辑再实现一遍（或在 Node 侧桥接），且体积代价大；
- **纯 Web + 本地服务**：分发与凭据保护更麻烦，落盘密钥的保护面更大。

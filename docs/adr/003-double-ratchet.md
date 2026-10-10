# ADR-003: 棘轮放在 Rust 侧，会话状态加密落盘

## Status
Accepted

## Context

消息加密需要前向保密与后向保密（双棘轮）。实现位置有两条路：放在前端 JS，或放在 Rust 后端。

## Decision

棘轮状态机放在 **Rust**（`src-tauri/src/`），前端通过 IPC 调用；会话状态持久化到应用数据目录，并且**落盘时加密**（AES-256-GCM），Windows 上设备密钥用 DPAPI 保护。

## Consequences

- ➕ 密钥不进 WebView 的 JS 堆，缩小了 XSS 的影响半径；
- ➕ 同一套棘轮实现也能被其它端复用；
- ➖ 会话生命周期必须被谨慎对待：**清理会话只能窄清**（只删 `fibemate_rust_sessions_<uid>`，**保留** `fibemate_rust_hybrid_<uid>`），否则会连带丢掉混合预钥缓存，触发「重生成密钥但服务端 bundle 陈旧」的连锁故障；
- ➖ 安全码（Safety Number）需要会话绑定双方身份；未绑定时安全码无法计算——已在握手路径补上自动补绑；
- ➖ 重放保护依赖棘轮消息计数（`MESSAGE_DROP`），乱序窗口需与对端一致。

## Alternatives considered

- **前端 JS 棘轮**：改动最快，但密钥暴露在渲染层，且与 Rust 侧已有实现重复；
- **不落盘**：每次启动都要重新握手，离线消息无法解密。

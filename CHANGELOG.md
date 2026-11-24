# Changelog

All notable changes to this project are documented here.
格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。
> 本文件自 v3.3.3 起维护；更早的历史见 git log 与各 tag 的 Release notes。

## [Unreleased]

### Added
- OpenSSF Scorecard 工作流（`ci(scorecard)`，#27）
- CI 安全加固：`setup-node` 改为 commit SHA 固定、`codeql.yml` 声明顶层最小权限（#28）

### Changed
- `release.yml` 写权限下沉到需要的 job（keyless 签名所需 `id-token: write` 保留在 `release-check`）（#29）

## [3.3.13] - 2026-11-24

### Fixed
- 会话切换串台：点击联系人后立即清空上一会话的消息并显示加载占位；在 `find-or-create`、握手状态检查等任何 `await` 完成前，旧会话内容不会留在新联系人面板。
- `find-or-create` 的迟到响应不再覆盖当前联系人的 `conversationId`；`sendMessage` 在切换联系人后也不会把消息发到上一个会话。
- 新增 `scripts/verify-conversation-isolation.cjs`：用真实 `chat.js` + 最小 DOM 模拟，验证切到 B 后列表不出现 A 的消息、A 的迟到响应不覆盖 B、失败时显示明确空状态。

## [3.3.12] - 2026-11-24

### Fixed
- 设备身份：登录提交按账号持久化的 UUID `deviceId`；服务端返回 `E_DEVICE_OWNED` 时只重新生成一次；注册返回的 `deviceId` 会保存。这是 readBy 落盘、离线重放收敛、未读数准确的前置条件。
- 聊天切换竞态（#99）：迟到响应不再污染当前会话；切换期间保留旧内容并显示加载条。

### Changed
- 服务端要求 `deviceId` 为 UUID；旧客户端不传仍可登录，但设备级回执保持降级。
- 说明：3.3.8–3.3.11 为内部构建，未单独发布；其中 3.3.11 构建自 `1f13f46`，不含 #99，3.3.12 补上。历史变更见 git log。

## [3.3.7] - 2026-10-10

### Fixed
- Release 流水线首次跑通：修复校验和清单生成（含空格文件名导致 `xargs` 分词失败）与 SLSA provenance 导出（`gh attestation download` 参数）
- 版本号对齐 tag（`package.json` / `Cargo.toml` / `tauri.conf.json` / 两个 lock 文件）

### Added
- 首个带 NSIS 安装包 + cosign 签名 + provenance 的 GitHub Release

## [3.3.6] - 2026-10-10

### Added
- E2EE 文字 + 语音 + 通话 + 安全码（Safety Number）全链路
- 混合预钥（hybrid pre-key）生成后自动上传（单飞 + 重入守卫）（#24）

### Fixed
- SM4-GCM GHASH：`gfMul` 进位方向错误导致非空输入的 tag 全错
- 会话复用守卫：增加协议校验与握手指纹，修复永久分叉 / 自愈活锁
- 语音消息被文字解密分支先行消费导致静默丢弃

## [3.3.5] - 2026-10-09

### Added
- 文字 + 语音 E2EE 双向互通

## [3.3.4] - 2026-10-09

### Added
- 文字 E2EE 双向互通（跨账号，冷重启复验通过）

## [3.3.3] - 2026-10-09

### Added
- 作为「回归基线」的可用快照（tag `v3.3.3-working`）


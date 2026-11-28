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

## [3.3.21] - 2026-11-28

### Fixed
- Device identity now lives outside the WebView2 profile: the per-account id is
  mirrored into `device_identities.json` in the app data directory (next to the
  encrypted key store) and restored at startup, so a reinstall no longer mints a
  new id. That was the root cause of one device row per install and of `isRead`
  staying false while orphan rows existed (fibemate-tauri#127).
- The client logs once when it has to mint an id instead of doing it silently.

## [3.3.20] - 2026-11-28

### Fixed

- Signing in to an account with 2FA looked like a hang. The login page (index.html)
  does not load the stylesheet that defines `.modal-overlay`, and the dialog only
  carried the class, so it rendered as a transparent block at the bottom of the
  document. The code dialog also wired Cancel and Verify with
  `document.getElementById()` before its subtree was attached, so neither button
  had a handler. The overlay is now attached first, every lookup stays scoped to
  the panel, and the overlay carries its own fixed-position/backdrop styles so it
  no longer depends on page CSS. The login button no longer sits on
  "processing" with nothing on screen.
- `scripts/test-client-dom.cjs` covers the login dialog: it must be visible
  (fixed position, non-empty background), both buttons must have handlers, and a
  submitted code must reach `/auth/2fa/verify-login` with the ticket.

## [3.3.19] - 2026-11-28

### Fixed

- The "Disable 2FA" dialog could not be dismissed. Both of its buttons were
  looked up with `document.getElementById()` before the overlay had been
  attached to the document, so the handlers silently bound to `null`: the
  modal opened, Cancel did nothing, Disable did nothing, and the window looked
  frozen behind a full-screen overlay. The overlay is now attached first and
  every lookup stays scoped to the panel. Escape also closes a 2FA modal now,
  so a missing handler can never trap the window again.
- `test-client-dom.cjs` covers the flow end to end: the dialog must open,
  Cancel must remove it, and Disable must post the code. Re-introducing the
  3.3.18 ordering makes that test fail.

## [3.3.18] - 2026-11-28

### Fixed

- 开启 2FA 后退出或重启会永久锁死：服务端对已启用 2FA 的账号返回 200 `{twoFARequired:true,ticket}`（不带 token），客户端只判断 `data.token` 就抛 "Login failed"，而 `showLogin2FA` 全仓没有任何调用点、登录页也没加载 2FA 模块。现在 `index.html` 加载 `modules/two-factor-auth.js`，`doLogin` 收到 `twoFARequired` 后用 ticket 换取 token 并写入会话，支持取消与恢复码，401/429 分别提示（#125）。
- 2FA 设置流程加防御：整体包 try/catch，渲染异常就关闭遮罩并提示，不再留下整窗空白与卡死的 `setupPhase`；`confirm-enable` 返回 409 视为已启用并直接展示恢复码；恢复码为空时给出说明而不是空网格。
- 登录页缺少 `API_BASE` / `showToast` 时的兜底：新增 `apiBase()`（回退 `localStorage.fk_api_url` 与 `https://fibemate.net/api`）与 `toast()` 包装，此前直接引用会抛 ReferenceError。

### Added

- `scripts/test-login-2fa.cjs`：5 个用例覆盖 2FA 交接、取消、模块缺失、普通登录、密码错误透传。
- `ui-dom` job 增加 2FA 登录交接一步，防止再次出现"模块存在但没接线"。

## [3.3.17] - 2026-11-27

### Fixed

- 2FA 二维码白框：vendored qrcode 的 `createDataURL()` 返回 `data:image/gif;base64,[object Object]`，WebView2 报 `net::ERR_INVALID_URL`，画布全白。改为按模块 `isDark()` + `fillRect` 直接绘制整数格，DOM 测试断言 `canvas.dataset.qrDrawn`、`fillRect` 调用数大于 200、且不出现 `drawImage`。
- 打开会话偶发 "Failed to create conversation"：`/api/conversations/find-or-create` 撞上 nginx `limit_req`（5r/m、burst=2）返回 429，客户端把非 2xx 一律当致命错误；现在会话 id 走模块级缓存、并发请求去重、429 时按 Retry-After 最多重试一次。服务端同步放宽为 30r/m、burst=10（fibemate#751）。
- 登出清理不彻底：现在清除 refresh token、会话与账号缓存、vault 元数据，并删除 IndexedDB `fibemate_vault`；保留设备身份、偏好、`fibemate_secure_keys`（已用账号密码加密，且是唯一本地副本）。
- 日志不再打印会话 id 与服务端响应正文，避免用户可控数据进入日志（Log hygiene 门禁）。

## [3.3.16] - 2026-11-26

### Fixed

- 设置页点 `Enable 2FA` 直接抛 `Cannot set properties of null (setting 'textContent')`：安装向导在浮层挂载到文档之前就去查 `#twofaSecretDisplay`，取到 null 后赋值中断，弹窗不出现、`setupPhase` 永久停在 true。现改为先挂载再渲染，并把查询收窄到弹窗自身子树。3.3.15 才把这个路径放出来，所以缺陷一直藏着。
- 会话列表不刷新：收发消息后不再只有气泡更新，列表行的预览、时间与未读角标会同步重取。此前"正在聊天"的接收分支与发送分支都不触发列表刷新。

### Added

- `scripts/test-client-dom.cjs`：用最小 DOM 桩把真实模块跑起来，点击 2FA 入口、断言安装向导渲染出密钥，并断言未读角标出现在会话行上；已在 CI 每个平台腿里执行。

## [3.3.15] - 2026-11-26

### Fixed

- 开启 2FA 的账号登录后不再丢失设备标识：服务端 `verify-login` 沿用密码步校验过的 `deviceId`，写入 JWT 与刷新令牌，已读回执与未读状态恢复正常（fibemate#707）。
- 恢复设置页的 2FA 启用入口；已启用 2FA 的账号仍可正常关闭。

## [3.3.14] - 2026-11-24

### Fixed
- 浅色主题的输入框对比度：切到 Light 后 `--bg-input` 与焦点态背景同步变亮，聊天输入、搜索框和表单字段不再出现“深底深字”。主题选择与右上角悬浮切换现在共用同一份持久化状态。
- 切到其他联系人后，来自非当前会话的实时消息现在也会在后台完成解密并写入 `fibemate_pt_*` 明文缓存；回到该联系人时不再显示“历史消息（旧会话，无法解密）”，也不会因未消费棘轮而让对端长时间等不到进展。后台解密不发送已读回执，也不把消息渲染到当前面板。
- 新增 `scripts/verify-inactive-message-cache.cjs`：覆盖后台解密、initMessage 只取 payload、语音跳过、解密失败/null 不缓存，6/6 PASS。

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


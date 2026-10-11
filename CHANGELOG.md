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


## What / 改了什么
-

## Why / 为什么
-

## Test plan / 验证

- [ ] 单元测试（`cargo test` / KAT）已补或已说明为何不需要
- [ ] e2e（`npm run e2e`）或手动步骤已记录
- [ ] 涉及密码学路径时：有外部参照验证（NIST/RFC 向量、对拍工具）
- [ ] 涉及密码学路径时：已检查是否需要更新 `docs/THREAT_MODEL.md`

## Rollback / 回滚
-

## Checklist

- [ ] commit 带 DCO `Signed-off-by`（`git commit --signoff`）
- [ ] 新增 `.js` 首行有 SPDX 头（`// SPDX-License-Identifier: GPL-3.0-only`）
- [ ] 无密钥 / 凭据 / 生产配置入库

# ML-KEM-768 修复总结

## 问题描述

ML-KEM-768 的 KAT（已知答案测试）失败，encapsulate/decapsulate 生成的共享密钥不匹配。

## 根因分析

**破坏性调用问题** —— `matVecMulTimeDomain` 和 `vecAccTimeDomain` 函数在内部调用 `invNTT` 修改了输入数组。

### 问题代码模式

```javascript
// 修改前 - 浅拷贝，修改原始数组
const a_td = new Int16Array(A_ntt[i][l]);
invNTT(a_td);  // 修改了 A_ntt[i][l]！
```

### 影响路径

在 `decapsulate` 中：
1. `matVecMulTimeDomain(AT, r_ntt, n)` —— 修改了 `AT` 和 `r_ntt`
2. `vecAccTimeDomain(t, r_ntt, n)` —— 但 `r_ntt` 已被修改！

这导致 re-encryption 路径与原始 encapsulation 不一致，从而共享密钥不匹配。

## 修复方案

**深拷贝输入数组**，确保不修改原始数据：

```javascript
// 修改后 - 深拷贝，保护原始数组
const a_td = new Int16Array(Array.from(A_ntt[i][l]));
invNTT(a_td);  // 只修改 a_td，不影响 A_ntt[i][l]
```

## 修改的文件

- `ml-kem-768.js`：
  - `matVecMulTimeDomain`：深拷贝 `A_ntt` 和 `v_ntt` 元素
  - `vecAccTimeDomain`：深拷贝 `a_ntt` 和 `b_ntt` 元素

## 测试文件

- `test-ml-kem-core.html`：基础功能测试（修复 API 引用）
- `test-ml-kem-fixed.html`：修复验证测试（20轮 + 同密钥对10次）
- `test-ml-kem-node.js`：Node.js 自动化测试

## 验证步骤

1. 在浏览器中打开 `test-ml-kem-fixed.html`
2. 检查控制台输出：
   - Single round: SHARED SECRET MATCH!
   - 20 rounds: 20/20 match
   - Same keypair 10x: 10/10 match

## 性能影响

深拷贝增加了少量内存分配，但对于 256 元素的 Int16Array 来说开销极小（约 512 字节/次）。

## 后续工作

1. 运行测试验证修复
2. 集成到 PQXDH 模块
3. 运行完整 KAT 测试向量验证

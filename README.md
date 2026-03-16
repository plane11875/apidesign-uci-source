# apidesign-uci-source

这个仓库用于验证：

- 通过 **SDFR/SDFU** 路由
- 调用自定义 provider **myoqsprov**
- 完成 **ML-DSA (sign/verify)** 和 **ML-KEM (encap/decap)**

> 重点：这里验证的是“接入流程与路由链路”。
> 算法实现来自 `liboqs.so`，测试用例验证 SDF 到 EVP 到 provider 的打通。

---

## 调用链路

`SDFR(AlgID路由) -> SDFU(统一接口) -> EVP(fetch algorithm + properties) -> myoqsprov.so -> liboqs.so`

关键点：

1. `SDFR_PATCH_FILE` 动态注册 AlgID 映射
2. `SDFU_LoadProvider()` 加载 `myoqsprov`
3. `UCI_KeyGenerate()` 通过 `EVP_PKEY_CTX_new_from_name(libctx, algorithm, properties)` 拉起对应算法
4. `UCI_Execute()` 执行 sign/verify 和 KEM encap/decap

---

## 示例测试（已包含）

见：`tests/test_sdfr_pq.c`

该示例覆盖：

- `0x00F0D501 -> mldsa65 provider=myoqsprov`
- `0x00F0D502 -> mlkem768 provider=myoqsprov`
- `SDFR_OP_SIGN` / `SDFR_OP_VERIFY`
- `SDFR_OP_KEM_ENCAPSULATE` / `SDFR_OP_KEM_DECAPSULATE`

详细步骤见：`docs/MYOQSPROV_SDFR_EXAMPLE.md`

---

## TODO（统一业务接口，策略1：保留旧 SDF 接口并内部转调）

> 要求1：每一项打勾前，必须完成“OpenSSL/liboqs 直调结果 vs SDF 接口结果”对比，并给出可核对数据（长度/哈希/验签结果）；只看 PASS 不算通过。
> 要求2：必须完成变种算法测试并通过：KEM 变种 `frodo640shake`、`efrodo640aes`；DSA 变种 `mayo1`、`falcon512`（后续新增变种需补充到此清单）。

- [x] 新增统一接口 `SDF_GenerateKeyWithEPK(algId, ...)`，内部按 `algId` 分发；覆盖并替代业务动作：`SDF_GenerateKeyWithEPK_RSA` / `SDF_GenerateKeyWithEPK_ECC`（已实现：SDFR优先，legacy回退；已修复 ECC 变长输出缓冲越界）
- [x] 新增统一接口 `SDF_GenerateKeyWithIPK(algId, ...)`；覆盖并替代业务动作：`SDF_GenerateKeyWithIPK_RSA` / `SDF_GenerateKeyWithIPK_ECC`（已实现：SDFR优先，legacy回退；RSA/ECC/PQ 实测通过）
- [x] 新增统一接口 `SDF_ImportKeyWithISK(algId, ...)`；覆盖并替代业务动作：`SDF_ImportKeyWithISK_RSA` / `SDF_ImportKeyWithISK_ECC`（已实现：SDFR优先，legacy回退；RSA/ECC/PQ 实测通过）
- [x] 新增统一接口 `SDF_ExportSignPublicKey(algId, keyIndex, ...)`；覆盖并替代业务动作：`SDF_ExportSignPublicKey_RSA` / `SDF_ExportSignPublicKey_ECC`（已实现：RSA/ECC 路由 + 统一长度回填；`test_sdf_export_sign_public_unified` 验证旧新一致）
- [x] 新增统一接口 `SDF_ExportEncPublicKey(algId, keyIndex, ...)`；覆盖并替代业务动作：`SDF_ExportEncPublicKey_RSA` / `SDF_ExportEncPublicKey_ECC`（已实现：RSA/ECC 路由 + 统一长度回填；`test_sdf_export_enc_public_unified` 验证旧新一致）
- [ ] 新增统一接口 `SDF_ExternalPublicKeyOperation(algId, opType, ...)`；统一承载现有 `RSA` 外部公钥运算与 `ECC` 外部加密业务
- [ ] 新增统一接口 `SDF_InternalSign(algId, ...)` / `SDF_InternalVerify(algId, ...)` / `SDF_ExternalVerify(algId, ...)`；逐步收敛 `ECC` 专用签名验签接口
- [ ] 建立统一分发规则：有 `algId` 映射优先走 `SDFR`，无映射走 legacy 回退
- [ ] 保留旧标准接口（兼容层），旧接口内部转调统一接口，不直接删除
- [ ] 补齐回归测试：统一接口对 `RSA/ECC/KEM` 的成功路径、失败码路径、边界参数路径
- [ ] 补齐文档：明确“新接口覆盖旧业务接口”的对照关系与迁移建议


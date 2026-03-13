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


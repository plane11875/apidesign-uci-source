# Algorithm Onboarding Contract (SDFR/SDFU + myoqsprov)

> 目标：让任何人按同一套规则，把“自己的算法”接入到 SDFR/SDFU 调用链中。

## 1. 命名契约

- Provider 名：`myoqsprov`
- EVP 算法名：小写字母数字组合（示例：`mldsa65` / `mlkem768` / `mysigdemo`）
- Properties：至少包含 `provider=myoqsprov`

## 2. AlgID 分配契约

- 测试/临时：`0x00F0D5xx`（避免与正式产品冲突）
- 项目内正式自定义：`0x00F1xxxx`（建议在仓库维护一份登记表）

示例：
- `0x00F0D501 -> mldsa65 provider=myoqsprov`
- `0x00F0D502 -> mlkem768 provider=myoqsprov`

## 3. 接口能力契约

### 签名类算法（SIGN）
必须支持：
- keygen
- sign
- verify

### KEM 类算法
必须支持：
- keygen
- encapsulate
- decapsulate

## 4. Provider 暴露契约（最小）

Provider 至少需要在 OpenSSL query operation 里暴露：
- KEYMGMT
- SIGNATURE（若是签名算法）
- KEM（若是 KEM 算法）

并确保算法条目的 property 包含：`provider=myoqsprov`

## 5. SDFR 路由契约

通过 `SDFR_PATCH_FILE` 动态注册：

```text
0x00F0D601 mysigdemo provider=myoqsprov
0x00F0D602 mykemdemo provider=myoqsprov
```

## 6. 验收契约（必须全部通过）

1) Provider 可加载：
```bash
OPENSSL_MODULES=/path/to/provider openssl list -providers -provider myoqsprov -provider default
```

2) 算法可见：
```bash
OPENSSL_MODULES=/path/to/provider openssl list -signature-algorithms -provider myoqsprov
OPENSSL_MODULES=/path/to/provider openssl list -kem-algorithms -provider myoqsprov
```

3) SDFR/SDFU 链路通过：
```bash
scripts/onboard_new_alg.sh myoqsprov <sign_alg> <kem_alg> <sign_algid> <kem_algid>
```

## 7. 常见失败与定位

- `SDR_NOTSUPPORT (0x01000002)`：provider 未加载成功（先查 `OPENSSL_MODULES`）
- `SDR_ALGNOTSUPPORT (0x01000009)`：算法 fetch 不到（先查算法名 + properties）
- `unsupported in evp_fetch`：property 不匹配（重点检查 `provider=myoqsprov`）


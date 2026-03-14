# SDFU 应用接口说明（上层应用视角）

> 目标：上层应用只使用 `SDFU_*` 接口，即可调用算法能力（含 `myoqsprov` 的 PQ 算法）。

## 1. 设计边界

- **应用层只调用 `SDFU_*`**。
- `SDFR_*` 属于 AlgID 路由层（可选），不是上层业务必需。
- 对于 provider 直连场景（如 `myoqsprov`），推荐显式 `properties="provider=myoqsprov"`。

---

## 2. 设备与会话管理

```c
LONG SDF_OpenDevice(HANDLE *phDeviceHandle);
LONG SDF_CloseDevice(HANDLE hDeviceHandle);
LONG SDF_OpenSession(HANDLE hDeviceHandle, HANDLE *phSessionHandle);
LONG SDF_CloseSession(HANDLE hSessionHandle);
```

---

## 3. SDFU 核心接口

### 3.1 Provider 生命周期

```c
LONG SDFU_LoadProvider(HANDLE hSessionHandle, const CHAR *pucProviderName,
                       HANDLE *phProviderHandle);
LONG SDFU_UnloadProvider(HANDLE hProviderHandle);
```

### 3.2 非对称密钥与公钥导入导出

```c
LONG SDFU_GenerateKeyPair(HANDLE hSessionHandle, const CHAR *pucAlgorithm,
                          const CHAR *pucProperties, HANDLE *phKeyHandle);

LONG SDFU_ExportPublicKey(HANDLE hSessionHandle, HANDLE hKeyHandle,
                          BYTE *pucPublicKey, ULONG *puiPublicKeyLength);

LONG SDFU_ImportPublicKey(HANDLE hSessionHandle, const BYTE *pucPublicKey,
                          ULONG uiPublicKeyLength, const CHAR *pucProperties,
                          HANDLE *phKeyHandle);
```

### 3.3 统一非对称执行

```c
typedef enum {
    SDFU_ASYM_OP_SIGN = 1,
    SDFU_ASYM_OP_VERIFY = 2,
    SDFU_ASYM_OP_PKEY_ENCRYPT = 3,
    SDFU_ASYM_OP_PKEY_DECRYPT = 4,
    SDFU_ASYM_OP_KEM_ENCAPSULATE = 5,
    SDFU_ASYM_OP_KEM_DECAPSULATE = 6
} SDFU_ASYM_OP;

typedef struct {
    ULONG uiOperation;
    const CHAR *pucAlgorithm;   // 对 SIGN/VERIFY：摘要名(如 SM3/SHA256)；可为 NULL
    const CHAR *pucProperties;  // 推荐 provider=myoqsprov 或 provider=default
    HANDLE hKeyHandle;
    const BYTE *pucInput;
    ULONG uiInputLength;
    const BYTE *pucExtraInput;  // VERIFY: signature; KEM_DECAPSULATE: ciphertext
    ULONG uiExtraInputLength;
} SDFU_ASYM_REQUEST;

typedef struct {
    BYTE *pucOutput;            // SIGN: signature; DECRYPT: plaintext; KEM: shared secret
    ULONG *puiOutputLength;
    BYTE *pucExtraOutput;       // KEM_ENCAPSULATE: ciphertext
    ULONG *puiExtraOutputLength;
    LONG lVerifyResult;         // VERIFY 结果，1=通过
} SDFU_ASYM_RESPONSE;

LONG SDFU_ExecuteAsymmetric(HANDLE hSessionHandle,
                            const SDFU_ASYM_REQUEST *pstRequest,
                            SDFU_ASYM_RESPONSE *pstResponse);
```

### 3.4 资源释放

```c
LONG SDF_DestroyKey(HANDLE hSessionHandle, HANDLE hKeyHandle);
```

---

## 4. 上层应用最小调用流程（只用 SDFU）

1. `SDF_OpenDevice` / `SDF_OpenSession`
2. `SDFU_LoadProvider(session, "myoqsprov", &prov)`
3. `SDFU_GenerateKeyPair(..., alg, "provider=myoqsprov", &key)`
4. 使用 `SDFU_ExecuteAsymmetric` 执行 SIGN/VERIFY 或 KEM
5. `SDF_DestroyKey` / `SDFU_UnloadProvider` / `SDF_CloseSession` / `SDF_CloseDevice`

---

## 5. 经过验证的 SDFU-only 能力（node3 实测）

### 5.1 myoqsprov（PQ）
- SIGN/VERIFY：`mldsa65`
- KEM_ENCAPSULATE/KEM_DECAPSULATE：`mlkem768`
- 测试文件：`tests/test_sdfu_myoqsprov_pq.c`
- 运行结果：

```text
[PASS] SDFU sign/verify(mldsa65) + KEM(mlkem768) via provider=myoqsprov
```

### 5.2 default provider（经典算法）
- RSA：签名验签 + 公钥加解密（内部/外部公钥）
- ECC(SM2)：签名验签 + 公钥加解密（内部/外部公钥）
- 测试文件：`tests/test_sdfu_rsa_ecc.c`
- 运行结果：

```text
[SUMMARY] capability checks passed = 10
```

---

## 6. 构建与运行

### 6.1 SDFU-only PQ 测试（myoqsprov）

```bash
cc -Iinclude tests/test_sdfu_myoqsprov_pq.c \
  -Lbuild -luci -lcrypto -Wl,-rpath,'$ORIGIN' \
  -o build/test_sdfu_myoqsprov_pq

export OPENSSL_MODULES=/root/project/myoqsprov
export LD_LIBRARY_PATH=/root/project/apidesign-uci-source/build:/usr/local/lib:$LD_LIBRARY_PATH
./build/test_sdfu_myoqsprov_pq
```

可选环境变量：
- `UCI_TEST_PROVIDER`（默认 `myoqsprov`）
- `UCI_TEST_SIGN_ALG`（默认 `mldsa65`）
- `UCI_TEST_KEM_ALG`（默认 `mlkem768`）

### 6.2 SDFU-only RSA/ECC 测试（default）

```bash
cc -Iinclude tests/test_sdfu_rsa_ecc.c \
  -Lbuild -luci -lcrypto -Wl,-rpath,'$ORIGIN' \
  -o build/test_sdfu_rsa_ecc

export LD_LIBRARY_PATH=/root/project/apidesign-uci-source/build:/usr/local/lib:$LD_LIBRARY_PATH
./build/test_sdfu_rsa_ecc
```

---

## 7. 返回码建议关注

- `SDR_OK (0x00000000)`：成功
- `SDR_NOTSUPPORT (0x01000002)`：provider/能力未加载
- `SDR_ALGNOTSUPPORT (0x01000009)`：算法未暴露或属性不匹配
- `SDR_SIGNERR (0x0100000D)`：签名失败
- `SDR_VERIFYERR (0x0100000E)`：验签失败
- `SDR_PKOPERR (0x0100000B)`：公钥运算失败
- `SDR_SKOPERR (0x0100000C)`：私钥运算失败


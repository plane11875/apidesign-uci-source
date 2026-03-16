#ifndef UCI_SDF_H
#define UCI_SDF_H

#include <stddef.h>
#include "uci.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SDF_BASIC_TYPES_DEFINED
typedef unsigned char BYTE;
typedef unsigned char CHAR;
typedef int LONG;
typedef unsigned int ULONG;
typedef unsigned int FLAGS;
typedef CHAR *LPSTR;
typedef void *HANDLE;
#define SDF_BASIC_TYPES_DEFINED 1
#endif

/* Return codes */
#define SDR_OK               0x00000000
#define SDR_BASE             0x01000000
#define SDR_UNKNOWERR        (SDR_BASE + 0x00000001)
#define SDR_NOTSUPPORT       (SDR_BASE + 0x00000002)
#define SDR_COMMFAIL         (SDR_BASE + 0x00000003)
#define SDR_HARDFAIL         (SDR_BASE + 0x00000004)
#define SDR_OPENDEVICE       (SDR_BASE + 0x00000005)
#define SDR_OPENSESSION      (SDR_BASE + 0x00000006)
#define SDR_PARDENY          (SDR_BASE + 0x00000007)
#define SDR_KEYNOTEXIST      (SDR_BASE + 0x00000008)
#define SDR_ALGNOTSUPPORT    (SDR_BASE + 0x00000009)
#define SDR_ALGMODNOTSUPPORT (SDR_BASE + 0x0000000A)
#define SDR_PKOPERR          (SDR_BASE + 0x0000000B)
#define SDR_SKOPERR          (SDR_BASE + 0x0000000C)
#define SDR_SIGNERR          (SDR_BASE + 0x0000000D)
#define SDR_VERIFYERR        (SDR_BASE + 0x0000000E)
#define SDR_SYMOPERR         (SDR_BASE + 0x0000000F)
#define SDR_STEPERR          (SDR_BASE + 0x00000010)
#define SDR_FILESIZEERR      (SDR_BASE + 0x00000011)
#define SDR_FILENOEXIST      (SDR_BASE + 0x00000012)
#define SDR_FILEOFSERR       (SDR_BASE + 0x00000013)
#define SDR_KEYTYPEERR       (SDR_BASE + 0x00000014)
#define SDR_KEYERR           (SDR_BASE + 0x00000015)
#define SDR_ENCDATAERR       (SDR_BASE + 0x00000016)
#define SDR_RANDERR          (SDR_BASE + 0x00000017)
#define SDR_PRKRERR          (SDR_BASE + 0x00000018)
#define SDR_MACERR           (SDR_BASE + 0x00000019)
#define SDR_FILEEXISTS       (SDR_BASE + 0x0000001A)
#define SDR_FILEWERR         (SDR_BASE + 0x0000001B)
#define SDR_NOBUFFER         (SDR_BASE + 0x0000001C)
#define SDR_INARGERR         (SDR_BASE + 0x0000001D)
#define SDR_OUTARGERR        (SDR_BASE + 0x0000001E)
#define SDR_USERIDERR        (SDR_BASE + 0x0000001F)

/* GM/T 0006 algorithm ids (subset used by this project) */
#define SGD_ECB              0x00000001u
#define SGD_CBC              0x00000002u
#define SGD_CFB              0x00000004u
#define SGD_OFB              0x00000008u
#define SGD_MAC              0x00000010u

#define SGD_SM4              0x00000400u
#define SGD_SM4_ECB          (SGD_SM4 | SGD_ECB)
#define SGD_SM4_CBC          (SGD_SM4 | SGD_CBC)
#define SGD_SM4_CFB          (SGD_SM4 | SGD_CFB)
#define SGD_SM4_OFB          (SGD_SM4 | SGD_OFB)
#define SGD_SM4_MAC          (SGD_SM4 | SGD_MAC)

#define SGD_SM3              0x00000001u
#define SGD_SHA1             0x00000002u
#define SGD_SHA256           0x00000004u

#define SGD_RSA              0x00010000u
#define SGD_SM2              0x00020100u
#define SGD_SM2_1            0x00020200u
#define SGD_SM2_2            0x00020400u
#define SGD_SM2_3            0x00020800u

/* Extension algorithm ids for anti-quantum migration */
#define SGD_MLKEM512         0x00810001u
#define SGD_MLKEM768         0x00810002u
#define SGD_MLKEM1024        0x00810003u
#define SGD_MLDSA44          0x00820001u
#define SGD_MLDSA65          0x00820002u
#define SGD_MLDSA87          0x00820003u
#define SGD_XOR_STREAM       0x00F00001u

#pragma pack(push, 1)

typedef struct DeviceInfo_st {
    CHAR IssuerName[40];
    CHAR DeviceName[16];
    CHAR DeviceSerial[16];
    ULONG DeviceVersion;
    ULONG StandardVersion;
    ULONG AsymAlgAbility[2];
    ULONG SymAlgAbility;
    ULONG HashAlgAbility;
    ULONG BufferSize;
} DEVICEINFO;

#define RSAref_MAX_BITS  2048
#define RSAref_MAX_LEN   ((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS ((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN  ((RSAref_MAX_PBITS + 7) / 8)

typedef struct RSArefPublicKey_st {
    ULONG bits;
    BYTE m[RSAref_MAX_LEN];
    BYTE e[RSAref_MAX_LEN];
} RSArefPublicKey;

typedef struct RSArefPrivateKey_st {
    ULONG bits;
    BYTE m[RSAref_MAX_LEN];
    BYTE e[RSAref_MAX_LEN];
    BYTE d[RSAref_MAX_LEN];
    BYTE prime[2][RSAref_MAX_PLEN];
    BYTE pexp[2][RSAref_MAX_PLEN];
    BYTE coef[RSAref_MAX_PLEN];
} RSArefPrivateKey;

#define ECCref_MAX_BITS 512
#define ECCref_MAX_LEN  ((ECCref_MAX_BITS + 7) / 8)

typedef struct ECCrefPublicKey_st {
    ULONG bits;
    BYTE x[ECCref_MAX_LEN];
    BYTE y[ECCref_MAX_LEN];
} ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st {
    ULONG bits;
    BYTE K[ECCref_MAX_LEN];
} ECCrefPrivateKey;

typedef struct ECCCipher_st {
    BYTE x[ECCref_MAX_LEN];
    BYTE y[ECCref_MAX_LEN];
    BYTE M[32];
    ULONG L;
    BYTE C[1];
} ECCCipher;

typedef struct ECCSignature_st {
    BYTE r[ECCref_MAX_LEN];
    BYTE s[ECCref_MAX_LEN];
} ECCSignature;

typedef struct EnvelopedECCKey_st {
    ULONG Version;
    ULONG ulSymmAlgID;
    ULONG ulBits;
    BYTE cbEncryptedPrivKey[ECCref_MAX_LEN];
    ECCrefPublicKey PubKey;
    ECCCipher ECCCipherBlob;
} EnvelopedECCKey;

#pragma pack(pop)

/* 6.2 设备管理类函数 */
LONG SDF_OpenDevice(HANDLE *phDeviceHandle);
LONG SDF_CloseDevice(HANDLE hDeviceHandle);
LONG SDF_OpenSession(HANDLE hDeviceHandle, HANDLE *phSessionHandle);
LONG SDF_CloseSession(HANDLE hSessionHandle);
LONG SDF_GetDeviceInfo(HANDLE hSessionHandle, DEVICEINFO *pstDeviceInfo);
LONG SDF_GenerateRandom(HANDLE hSessionHandle, ULONG uiLength, BYTE *pucRandom);
LONG SDF_GetPrivateKeyAccessRight(HANDLE hSessionHandle, ULONG uiKeyIndex,
                                  LPSTR pucPassword, ULONG uiPwdLength);
LONG SDF_ReleasePrivateKeyAccessRight(HANDLE hSessionHandle, ULONG uiKeyIndex);

/* 6.3 密钥管理类函数 */
LONG SDF_ExportSignPublicKey_RSA(HANDLE hSessionHandle, ULONG uiKeyIndex,
                                 RSArefPublicKey *pucPublicKey);
LONG SDF_ExportEncPublicKey_RSA(HANDLE hSessionHandle, ULONG uiKeyIndex,
                                RSArefPublicKey *pucPublicKey);
LONG SDF_GenerateKeyWithIPK_RSA(HANDLE hSessionHandle, ULONG uiIPKIndex,
                                ULONG uiKeyBits, BYTE *pucKey,
                                ULONG *puiKeyLength, HANDLE *phKeyHandle);
LONG SDF_GenerateKeyWithEPK_RSA(HANDLE hSessionHandle, ULONG uiKeyBits,
                                RSArefPublicKey *pucPublicKey, BYTE *pucKey,
                                ULONG *puiKeyLength, HANDLE *phKeyHandle);
LONG SDF_ImportKeyWithISK_RSA(HANDLE hSessionHandle, ULONG uiISKIndex,
                              BYTE *pucKey, ULONG uiKeyLength,
                              HANDLE *phKeyHandle);
LONG SDF_ExportSignPublicKey_ECC(HANDLE hSessionHandle, ULONG uiKeyIndex,
                                 ECCrefPublicKey *pucPublicKey);
LONG SDF_ExportEncPublicKey_ECC(HANDLE hSessionHandle, ULONG uiKeyIndex,
                                ECCrefPublicKey *pucPublicKey);

/* 统一签名公钥导出接口：RSA 输出 RSArefPublicKey，SM2/ECC 输出 ECCrefPublicKey。
 * 通过 uiAlgID 选择导出格式，输出缓冲长度由 puiKeyLength 传入/回填。
 */
LONG SDF_ExportSignPublicKey(HANDLE hSessionHandle, ULONG uiAlgID,
                             ULONG uiKeyIndex, BYTE *pucPublicKey,
                             ULONG *puiKeyLength);
LONG SDF_ExportEncPublicKey(HANDLE hSessionHandle, ULONG uiAlgID,
                            ULONG uiKeyIndex, BYTE *pucPublicKey,
                            ULONG *puiKeyLength);
LONG SDF_GenerateKeyWithIPK_ECC(HANDLE hSessionHandle, ULONG uiIPKIndex,
                                ULONG uiKeyBits, ECCCipher *pucKey,
                                HANDLE *phKeyHandle);

/* 统一内部公钥封装接口：按 uiAlgID 优先走 SDFR 路由，失败时回退 legacy。
 * legacy RSA/ECC 仍使用 uiIPKIndex 查内部密钥；扩展算法传 HANDLE 作为内部公钥句柄。
 */
LONG SDF_GenerateKeyWithIPK(HANDLE hSessionHandle, ULONG uiIPKIndex,
                            ULONG uiKeyBits, ULONG uiAlgID,
                            const void *pucPublicKeyOrHandle,
                            BYTE *pucKey, ULONG *puiKeyLength,
                            HANDLE *phKeyHandle);
LONG SDF_GenerateKeyWithEPK_ECC(HANDLE hSessionHandle, ULONG uiKeyBits,
                                ULONG uiAlgID, ECCrefPublicKey *pucPublicKey,
                                ECCCipher *pucKey, HANDLE *phKeyHandle);

/* 统一公钥封装接口：按 uiAlgID 优先走 SDFR 路由，失败时回退 legacy。
 * pucPublicKey: 兼容层参数，legacy RSA 传 RSArefPublicKey*，legacy ECC 传 ECCrefPublicKey*。
 * pucKey/puiKeyLength: 统一输出密文缓冲与长度。
 */
LONG SDF_GenerateKeyWithEPK(HANDLE hSessionHandle, ULONG uiKeyBits,
                            ULONG uiAlgID, const void *pucPublicKey,
                            BYTE *pucKey, ULONG *puiKeyLength,
                            HANDLE *phKeyHandle);
/* 统一内部私钥解封装接口：按 uiAlgID 优先走 SDFR 路由，失败时回退 legacy。
 */
LONG SDF_ImportKeyWithISK(HANDLE hSessionHandle, ULONG uiISKIndex,
                          ULONG uiAlgID, const void *pucPrivateKeyOrHandle,
                          const BYTE *pucEncKey, ULONG uiEncKeyLength,
                          HANDLE *phKeyHandle);
LONG SDF_ImportKeyWithISK_ECC(HANDLE hSessionHandle, ULONG uiISKIndex,
                              ECCCipher *pucKey, HANDLE *phKeyHandle);
LONG SDF_GenerateAgreementDataWithECC(HANDLE hSessionHandle, ULONG uiISKIndex,
                                      ULONG uiKeyBits, BYTE *pucSponsorID,
                                      ULONG uiSponsorIDLength,
                                      ECCrefPublicKey *pucSponsorPublicKey,
                                      ECCrefPublicKey *pucSponsorTmpPublicKey,
                                      HANDLE *phAgreementHandle);
LONG SDF_GenerateKeyWithECC(HANDLE hSessionHandle, BYTE *pucResponseID,
                            ULONG uiResponseIDLength,
                            ECCrefPublicKey *pucResponsePublicKey,
                            ECCrefPublicKey *pucResponseTmpPublicKey,
                            HANDLE hAgreementHandle,
                            HANDLE *phKeyHandle);
LONG SDF_GenerateAgreementDataAndKeyWithECC(HANDLE hSessionHandle,
                                            ULONG uiISKIndex, ULONG uiKeyBits,
                                            BYTE *pucResponseID,
                                            ULONG uiResponseIDLength,
                                            BYTE *pucSponsorID,
                                            ULONG uiSponsorIDLength,
                                            ECCrefPublicKey *pucSponsorPublicKey,
                                            ECCrefPublicKey *pucSponsorTmpPublicKey,
                                            ECCrefPublicKey *pucResponsePublicKey,
                                            ECCrefPublicKey *pucResponseTmpPublicKey,
                                            HANDLE *phKeyHandle);
LONG SDF_GenerateKeyWithKEK(HANDLE hSessionHandle, ULONG uiKeyBits,
                            ULONG uiAlgID, ULONG uiKEKIndex, BYTE *pucKey,
                            ULONG *puiKeyLength, HANDLE *phKeyHandle);
LONG SDF_ImportKeyWithKEK(HANDLE hSessionHandle, ULONG uiAlgID,
                          ULONG uiKEKIndex, BYTE *pucKey, ULONG uiKeyLength,
                          HANDLE *phKeyHandle);
LONG SDF_DestroyKey(HANDLE hSessionHandle, HANDLE hKeyHandle);

/* 6.4 非对称算法运算类函数 */
LONG SDF_ExternalPublicKeyOperation_RSA(HANDLE hSessionHandle,
                                        RSArefPublicKey *pucPublicKey,
                                        BYTE *pucDataInput, ULONG uiInputLength,
                                        BYTE *pucDataOutput,
                                        ULONG *puiOutputLength);
LONG SDF_InternalPublicKeyOperation_RSA(HANDLE hSessionHandle,
                                        ULONG uiKeyIndex, BYTE *pucDataInput,
                                        ULONG uiInputLength, BYTE *pucDataOutput,
                                        ULONG *puiOutputLength);
LONG SDF_InternalPrivateKeyOperation_RSA(HANDLE hSessionHandle,
                                         ULONG uiKeyIndex, BYTE *pucDataInput,
                                         ULONG uiInputLength, BYTE *pucDataOutput,
                                         ULONG *puiOutputLength);
LONG SDF_ExternalVerify_ECC(HANDLE hSessionHandle, ULONG uiAlgID,
                            ECCrefPublicKey *pucPublicKey, BYTE *pucDataInput,
                            ULONG uiInputLength, ECCSignature *pucSignature);
LONG SDF_InternalSign_ECC(HANDLE hSessionHandle, ULONG uiISKIndex,
                          BYTE *pucData, ULONG uiDataLength,
                          ECCSignature *pucSignature);
LONG SDF_InternalVerify_ECC(HANDLE hSessionHandle, ULONG uiIPKIndex,
                            BYTE *pucData, ULONG uiDataLength,
                            ECCSignature *pucSignature);
LONG SDF_ExternalEncrypt_ECC(HANDLE hSessionHandle, ULONG uiAlgID,
                             ECCrefPublicKey *pucPublicKey, BYTE *pucData,
                             ULONG uiDataLength, ECCCipher *pucEncData);

/* 6.5 对称算法运算类函数 */
LONG SDF_Encrypt(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                 BYTE *pucIV, BYTE *pucData, ULONG uiDataLength,
                 BYTE *pucEncData, ULONG *puiEncDataLength);
LONG SDF_Decrypt(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                 BYTE *pucIV, BYTE *pucEncData, ULONG uiEncDataLength,
                 BYTE *pucData, ULONG *puiDataLength);
LONG SDF_CalculateMAC(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                      BYTE *pucIV, BYTE *pucData, ULONG uiDataLength,
                      BYTE *pucMac, ULONG *puiMacLength);
LONG SDF_AuthEnc(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                 BYTE *pucStartVar, ULONG uiStartVarLength, BYTE *pucAad,
                 ULONG uiAadLength, BYTE *pucData, ULONG uiDataLength,
                 BYTE *pucEncData, ULONG *puiEncDataLength,
                 BYTE *pucAuthData, ULONG *puiAuthDataLength);
LONG SDF_AuthDec(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                 BYTE *pucStartVar, ULONG uiStartVarLength, BYTE *pucAad,
                 ULONG uiAadLength, BYTE *pucAuthData,
                 ULONG *puiAuthDataLength, BYTE *pucEncData,
                 ULONG uiEncDataLength, BYTE *pucData,
                 ULONG *puiDataLength);
LONG SDF_EncryptInit(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                     BYTE *pucIV, ULONG uiIVLength);
LONG SDF_EncryptUpdate(HANDLE hSessionHandle, BYTE *pucData,
                       ULONG uiDataLength, BYTE *pucEncData,
                       ULONG *puiEncDataLength);
LONG SDF_EncryptFinal(HANDLE hSessionHandle, BYTE *pucLastEncData,
                      ULONG *puiLastEncDataLength);
LONG SDF_DecryptInit(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                     BYTE *pucIV, ULONG uiIVLength);
LONG SDF_DecryptUpdate(HANDLE hSessionHandle, BYTE *pucEncData,
                       ULONG uiEncDataLength, BYTE *pucData,
                       ULONG *puiDataLength);
LONG SDF_DecryptFinal(HANDLE hSessionHandle, BYTE *pucLastData,
                      ULONG *puiLastDataLength);
LONG SDF_CalculateMACInit(HANDLE hSessionHandle, HANDLE hKeyHandle,
                          ULONG uiAlgID, BYTE *pucIV, ULONG uiIVLength);
LONG SDF_CalculateMACUpdate(HANDLE hSessionHandle, BYTE *pucData,
                            ULONG uiDataLength);
LONG SDF_CalculateMACFinal(HANDLE hSessionHandle, BYTE *pucMac,
                           ULONG *puiMacLength);
LONG SDF_AuthEncInit(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                     BYTE *pucStartVar, ULONG uiStartVarLength, BYTE *pucAad,
                     ULONG uiAadLength, ULONG uiDataLength);
LONG SDF_AuthEncUpdate(HANDLE hSessionHandle, BYTE *pucData,
                       ULONG uiDataLength, BYTE *pucEncData,
                       ULONG *puiEncDataLength);
LONG SDF_AuthEncFinal(HANDLE hSessionHandle, BYTE *pucLastEncData,
                      ULONG *puiLastEncDataLength, BYTE *pucAuthData,
                      ULONG *puiAuthDataLength);
LONG SDF_AuthDecInit(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                     BYTE *pucStartVar, ULONG uiStartVarLength, BYTE *pucAad,
                     ULONG uiAadLength, BYTE *pucAuthData,
                     ULONG uiAuthDataLength, ULONG uiDataLength);
LONG SDF_AuthDecUpdate(HANDLE hSessionHandle, BYTE *pucEncData,
                       ULONG uiEncDataLength, BYTE *pucData,
                       ULONG *puiDataLength);
LONG SDF_AuthDecFinal(HANDLE hSessionHandle, BYTE *pucLastData,
                      ULONG *puiLastDataLength);

/* 6.6 杂凑运算类函数 */
LONG SDF_HMACInit(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID);
LONG SDF_HMACUpdate(HANDLE hSessionHandle, BYTE *pucData, ULONG uiDataLength);
LONG SDF_HMACFinal(HANDLE hSessionHandle, BYTE *pucHmac, ULONG *puiHmacLength);
LONG SDF_HashInit(HANDLE hSessionHandle, ULONG uiAlgID,
                  ECCrefPublicKey *pucPublicKey, BYTE *pucID,
                  ULONG uiIDLength);
LONG SDF_HashUpdate(HANDLE hSessionHandle, BYTE *pucData, ULONG uiDataLength);
LONG SDF_HashFinal(HANDLE hSessionHandle, BYTE *pucHash, ULONG *puiHashLength);

/* 6.7 用户文件操作类函数 */
LONG SDF_CreateFile(HANDLE hSessionHandle, LPSTR pucFileName,
                    ULONG uiNameLen, ULONG uiFileSize);
LONG SDF_ReadFile(HANDLE hSessionHandle, LPSTR pucFileName,
                  ULONG uiNameLen, ULONG uiOffset,
                  ULONG *puiReadLength, BYTE *pucBuffer);
LONG SDF_WriteFile(HANDLE hSessionHandle, LPSTR pucFileName,
                   ULONG uiNameLen, ULONG uiOffset,
                   ULONG uiWriteLength, BYTE *pucBuffer);
LONG SDF_DeleteFile(HANDLE hSessionHandle, LPSTR pucFileName,
                    ULONG uiNameLen);

/* SDF 扩展：参数化统一接口（用于抗量子/新算法接入） */
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
    const CHAR *pucAlgorithm;
    const CHAR *pucProperties;
    HANDLE hKeyHandle;
    const BYTE *pucInput;
    ULONG uiInputLength;
    const BYTE *pucExtraInput;
    ULONG uiExtraInputLength;
} SDFU_ASYM_REQUEST;

typedef struct {
    BYTE *pucOutput;
    ULONG *puiOutputLength;
    BYTE *pucExtraOutput;
    ULONG *puiExtraOutputLength;
    LONG lVerifyResult;
} SDFU_ASYM_RESPONSE;

typedef enum {
    SDFU_SYM_OP_ENCRYPT = 1,
    SDFU_SYM_OP_DECRYPT = 2,
    SDFU_SYM_OP_MAC = 3,
    SDFU_SYM_OP_AUTH_ENCRYPT = 4,
    SDFU_SYM_OP_AUTH_DECRYPT = 5
} SDFU_SYM_OP;

typedef struct {
    ULONG uiOperation;
    const CHAR *pucAlgorithm;
    const CHAR *pucProperties;
    HANDLE hKeyHandle;
    const BYTE *pucIV;
    ULONG uiIVLength;
    const BYTE *pucAAD;
    ULONG uiAADLength;
    const BYTE *pucInput;
    ULONG uiInputLength;
    const BYTE *pucTag;
    ULONG uiTagLength;
} SDFU_SYM_REQUEST;

typedef struct {
    BYTE *pucOutput;
    ULONG *puiOutputLength;
    BYTE *pucTag;
    ULONG *puiTagLength;
} SDFU_SYM_RESPONSE;

typedef enum {
    SDFU_HASH_OP_DIGEST = 1,
    SDFU_HASH_OP_HMAC = 2
} SDFU_HASH_OP;

typedef struct {
    ULONG uiOperation;
    const CHAR *pucAlgorithm;
    const CHAR *pucProperties;
    HANDLE hKeyHandle;
    const BYTE *pucInput;
    ULONG uiInputLength;
} SDFU_HASH_REQUEST;

typedef struct {
    BYTE *pucOutput;
    ULONG *puiOutputLength;
} SDFU_HASH_RESPONSE;

LONG SDFU_LoadProvider(HANDLE hSessionHandle, const CHAR *pucProviderName,
                       HANDLE *phProviderHandle);
LONG SDFU_UnloadProvider(HANDLE hProviderHandle);
LONG SDFU_GenerateKeyPair(HANDLE hSessionHandle, const CHAR *pucAlgorithm,
                          const CHAR *pucProperties, HANDLE *phKeyHandle);
LONG SDFU_GenerateSessionKey(HANDLE hSessionHandle, ULONG uiKeyBits,
                             HANDLE *phKeyHandle);
LONG SDFU_ImportKey(HANDLE hSessionHandle, const BYTE *pucKey,
                    ULONG uiKeyLength, HANDLE *phKeyHandle);
LONG SDFU_ExportPublicKey(HANDLE hSessionHandle, HANDLE hKeyHandle,
                          BYTE *pucPublicKey, ULONG *puiPublicKeyLength);
LONG SDFU_ImportPublicKey(HANDLE hSessionHandle, const BYTE *pucPublicKey,
                          ULONG uiPublicKeyLength, const CHAR *pucProperties,
                          HANDLE *phKeyHandle);
LONG SDFU_ExecuteAsymmetric(HANDLE hSessionHandle,
                            const SDFU_ASYM_REQUEST *pstRequest,
                            SDFU_ASYM_RESPONSE *pstResponse);
LONG SDFU_ExecuteSymmetric(HANDLE hSessionHandle,
                           const SDFU_SYM_REQUEST *pstRequest,
                           SDFU_SYM_RESPONSE *pstResponse);
LONG SDFU_SymInit(HANDLE hSessionHandle, const SDFU_SYM_REQUEST *pstRequest,
                  HANDLE *phSymHandle);
LONG SDFU_SymUpdate(HANDLE hSymHandle, const BYTE *pucInput,
                    ULONG uiInputLength, BYTE *pucOutput,
                    ULONG *puiOutputLength);
LONG SDFU_SymFinal(HANDLE hSymHandle, BYTE *pucOutput,
                   ULONG *puiOutputLength, BYTE *pucTag,
                   ULONG *puiTagLength);
LONG SDFU_ExecuteHash(HANDLE hSessionHandle, const SDFU_HASH_REQUEST *pstRequest,
                      SDFU_HASH_RESPONSE *pstResponse);
LONG SDFU_HashInit(HANDLE hSessionHandle, const SDFU_HASH_REQUEST *pstRequest,
                   HANDLE *phHashHandle);
LONG SDFU_HashUpdate(HANDLE hHashHandle, const BYTE *pucInput,
                     ULONG uiInputLength);
LONG SDFU_HashFinal(HANDLE hHashHandle, BYTE *pucHash,
                    ULONG *puiHashLength);

/* SDF 扩展：EVP -> SDF 自动路由层 */
typedef enum {
    SDFR_OP_DIGEST = 1,
    SDFR_OP_HMAC = 2,
    SDFR_OP_SIGN = 3,
    SDFR_OP_VERIFY = 4,
    SDFR_OP_PKEY_ENCRYPT = 5,
    SDFR_OP_PKEY_DECRYPT = 6,
    SDFR_OP_KEM_ENCAPSULATE = 7,
    SDFR_OP_KEM_DECAPSULATE = 8,
    SDFR_OP_SYM_ENCRYPT = 9,
    SDFR_OP_SYM_DECRYPT = 10,
    SDFR_OP_SYM_MAC = 11,
    SDFR_OP_SYM_AUTH_ENCRYPT = 12,
    SDFR_OP_SYM_AUTH_DECRYPT = 13
} SDFR_OPERATION;

typedef struct {
    ULONG uiOperation;
    ULONG uiAlgID;
    ULONG uiDigestAlgID;
    const CHAR *pucAlgorithm;
    const CHAR *pucProperties;
    HANDLE hKeyHandle;
    const BYTE *pucIV;
    ULONG uiIVLength;
    const BYTE *pucAAD;
    ULONG uiAADLength;
    const BYTE *pucInput;
    ULONG uiInputLength;
    const BYTE *pucExtraInput;
    ULONG uiExtraInputLength;
    const BYTE *pucTag;
    ULONG uiTagLength;
} SDFR_REQUEST;

typedef struct {
    BYTE *pucOutput;
    ULONG *puiOutputLength;
    BYTE *pucExtraOutput;
    ULONG *puiExtraOutputLength;
    BYTE *pucTag;
    ULONG *puiTagLength;
    LONG lVerifyResult;
} SDFR_RESPONSE;

LONG SDFR_RegisterAlgName(ULONG uiAlgID, const CHAR *pucAlgorithm,
                          const CHAR *pucProperties);
LONG SDFR_UnregisterAlgName(ULONG uiAlgID);
LONG SDFR_LoadPatchFile(const CHAR *pucPatchFile);
LONG SDFR_ResolveAlgName(ULONG uiAlgID, const CHAR **ppucAlgorithm,
                         const CHAR **ppucProperties);
LONG SDFR_Execute(HANDLE hSessionHandle, const SDFR_REQUEST *pstRequest,
                  SDFR_RESPONSE *pstResponse);

#ifdef __cplusplus
}
#endif

#endif /* UCI_SDF_H */

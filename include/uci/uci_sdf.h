/*
 * UCI SDF-style Unified Interface
 *
 * Keeps password-device style handles (device/session/key),
 * while unifying cryptographic operations into a single API.
 */

#ifndef UCI_SDF_H
#define UCI_SDF_H

#include "uci_unified.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Basic data types aligned with GM/T 0018 style */
typedef unsigned char BYTE;
typedef unsigned char CHAR;
typedef int LONG;
typedef unsigned int ULONG;
typedef unsigned int FLAGS;
typedef CHAR *LPSTR;
typedef void *HANDLE;

/* Return codes (subset) */
#define SDR_OK               0x0
#define SDR_BASE             0x01000000
#define SDR_UNKNOWERR        (SDR_BASE + 0x00000001)
#define SDR_NOTSUPPORT       (SDR_BASE + 0x00000002)
#define SDR_PARDENY          (SDR_BASE + 0x00000007)
#define SDR_ALGNOTSUPPORT    (SDR_BASE + 0x00000009)
#define SDR_PKOPERR          (SDR_BASE + 0x0000000B)
#define SDR_SKOPERR          (SDR_BASE + 0x0000000C)
#define SDR_SIGNERR          (SDR_BASE + 0x0000000D)
#define SDR_VERIFYERR        (SDR_BASE + 0x0000000E)
#define SDR_SYMOPERR         (SDR_BASE + 0x0000000F)
#define SDR_KEYTYPEERR       (SDR_BASE + 0x00000014)
#define SDR_KEYERR           (SDR_BASE + 0x00000015)
#define SDR_RANDERR          (SDR_BASE + 0x00000017)
#define SDR_PRKRERR          (SDR_BASE + 0x00000018)
#define SDR_NOBUFFER         (SDR_BASE + 0x0000001C)
#define SDR_INARGERR         (SDR_BASE + 0x0000001D)
#define SDR_OUTARGERR        (SDR_BASE + 0x0000001E)

/* Device information */
typedef struct UCI_DEVICEINFO_st {
    CHAR IssuerName[40];
    CHAR DeviceName[16];
    CHAR DeviceSerial[16];
    ULONG DeviceVersion;
    ULONG StandardVersion;
    ULONG AsymAlgAbility[2];
    ULONG SymAlgAbility;
    ULONG HashAlgAbility;
    ULONG BufferSize;
} UCI_DEVICEINFO;

/* Unified operation identifiers */
#define UCI_OP_DIGEST            1u
#define UCI_OP_SIGN              2u
#define UCI_OP_VERIFY            3u
#define UCI_OP_KEM_ENCAPSULATE   4u
#define UCI_OP_KEM_DECAPSULATE   5u

typedef struct UCI_OP_REQUEST_st {
    ULONG uiOperation;
    const CHAR *pucAlgorithm;
    const CHAR *pucProperties;
    HANDLE hKeyHandle;

    const BYTE *pucInput;
    ULONG uiInputLength;

    const BYTE *pucExtraInput;
    ULONG uiExtraInputLength;
} UCI_OP_REQUEST;

typedef struct UCI_OP_RESPONSE_st {
    BYTE *pucOutput;
    ULONG *puiOutputLength;

    BYTE *pucExtraOutput;
    ULONG *puiExtraOutputLength;

    LONG lVerifyResult; /* 1 valid, 0 invalid (verify op only) */
} UCI_OP_RESPONSE;

/* Device/session APIs */
LONG UCI_OpenDevice(HANDLE *phDeviceHandle);
LONG UCI_CloseDevice(HANDLE hDeviceHandle);
LONG UCI_OpenSession(HANDLE hDeviceHandle, HANDLE *phSessionHandle);
LONG UCI_CloseSession(HANDLE hSessionHandle);
LONG UCI_GetDeviceInfo(HANDLE hSessionHandle, UCI_DEVICEINFO *pstDeviceInfo);
LONG UCI_GenerateRandom(HANDLE hSessionHandle, ULONG uiLength, BYTE *pucRandom);
LONG UCI_GetPrivateKeyAccessRight(HANDLE hSessionHandle, ULONG uiKeyIndex,
                                  LPSTR pucPassword, ULONG uiPwdLength);
LONG UCI_ReleasePrivateKeyAccessRight(HANDLE hSessionHandle, ULONG uiKeyIndex);

/* Provider management */
LONG UCI_LoadProvider(HANDLE hSessionHandle, const CHAR *pucProviderName,
                      HANDLE *phProviderHandle);
LONG UCI_UnloadProvider(HANDLE hProviderHandle);

/* Unified key management */
LONG UCI_GenerateKeyPair(HANDLE hSessionHandle, const CHAR *pucAlgorithm,
                         const CHAR *pucProperties, HANDLE *phKeyHandle);
LONG UCI_DestroyKey(HANDLE hSessionHandle, HANDLE hKeyHandle);
LONG UCI_ExportPublicKey(HANDLE hSessionHandle, HANDLE hKeyHandle,
                         BYTE *pucPublicKey, ULONG *puiPublicKeyLength);
LONG UCI_ImportPublicKey(HANDLE hSessionHandle, const BYTE *pucPublicKey,
                         ULONG uiPublicKeyLength, const CHAR *pucProperties,
                         HANDLE *phKeyHandle);

/* Unified execution API: algorithm is selected via request fields */
LONG UCI_ExecuteOperation(HANDLE hSessionHandle,
                          const UCI_OP_REQUEST *pstRequest,
                          UCI_OP_RESPONSE *pstResponse);

#ifdef __cplusplus
}
#endif

#endif /* UCI_SDF_H */

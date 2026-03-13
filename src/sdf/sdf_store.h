#ifndef UCI_SDF_STORE_H
#define UCI_SDF_STORE_H

#include "uci/sdf.h"

LONG sdf_store_get_internal_key(HANDLE hSessionHandle, ULONG uiKeyIndex,
                                int ecc_key, HANDLE *phKeyHandle);
LONG sdf_store_get_or_create_kek(HANDLE hSessionHandle, ULONG uiKEKIndex,
                                 const BYTE **ppKey, ULONG *puiKeyLength);
void sdf_store_cleanup_session(HANDLE hSessionHandle);

#endif /* UCI_SDF_STORE_H */

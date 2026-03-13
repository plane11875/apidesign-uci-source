# SDFR PQ Smoke Test Example

## File
- `tests/test_sdfr_pq.c`

## What it verifies
- `SDFR_OP_SIGN` + `SDFR_OP_VERIFY`
- `SDFR_OP_KEM_ENCAPSULATE` + `SDFR_OP_KEM_DECAPSULATE`
- dynamic AlgID routing via `SDFR_PATCH_FILE`

## Configurable by env (for onboarding custom algorithms)
- `UCI_TEST_PROVIDER` (default: `myoqsprov`)
- `UCI_TEST_SIGN_ALG` (default: `mldsa65`)
- `UCI_TEST_KEM_ALG` (default: `mlkem768`)
- `UCI_TEST_SIGN_ALGID` (default: `0x00F0D501`)
- `UCI_TEST_KEM_ALGID` (default: `0x00F0D502`)

## Build
```bash
cc -Iinclude tests/test_sdfr_pq.c -Lbuild -luci -lcrypto -Wl,-rpath,'$ORIGIN' -o build/test_sdfr_pq
```

## Run (default)
```bash
export OPENSSL_MODULES=/root/project/myoqsprov
export LD_LIBRARY_PATH=/root/project/apidesign-uci-source/build:/usr/local/lib:$LD_LIBRARY_PATH
./build/test_sdfr_pq
```

## Run (custom algorithm example)
```bash
export OPENSSL_MODULES=/root/project/myoqsprov
export UCI_TEST_PROVIDER=myoqsprov
export UCI_TEST_SIGN_ALG=mysigdemo
export UCI_TEST_KEM_ALG=mykemdemo
export UCI_TEST_SIGN_ALGID=0x00F0D601
export UCI_TEST_KEM_ALGID=0x00F0D602
./build/test_sdfr_pq
```

## One-click onboarding smoke test
```bash
scripts/onboard_new_alg.sh myoqsprov mldsa65 mlkem768 0x00F0D501 0x00F0D502
```

Exit code:
- `0`: pass
- `77`: skipped (provider/algorithm unavailable)
- others: failure

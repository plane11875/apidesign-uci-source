# SDFR PQ Smoke Test (ML-DSA + ML-KEM)

## File
- `tests/test_sdfr_pq.c`

## What it verifies
- `SDFR_OP_SIGN` + `SDFR_OP_VERIFY` with ML-DSA (`mldsa65`)
- `SDFR_OP_KEM_ENCAPSULATE` + `SDFR_OP_KEM_DECAPSULATE` with ML-KEM (`mlkem768`)
- dynamic AlgID routing via `SDFR_PATCH_FILE`

## Routing used in test
- `0x00F0D501 -> mldsa65 provider=<provider>`
- `0x00F0D502 -> mlkem768 provider=<provider>`

## Environment assumptions
- UCI library is built and linkable
- custom provider (e.g. `myoqsprov`) exists and is loadable
- `OPENSSL_MODULES` points to provider `.so` directory

## Build example
```bash
cc -Iinclude tests/test_sdfr_pq.c -Lbuild -luci -lcrypto -o build/test_sdfr_pq
```

## Run example
```bash
export OPENSSL_MODULES=/abs/path/to/provider/lib
export LD_LIBRARY_PATH=/root/project/apidesign-uci-source/build:$LD_LIBRARY_PATH
export UCI_TEST_PROVIDER=myoqsprov
./build/test_sdfr_pq
```

Exit code:
- `0`: pass
- `77`: skipped (provider/algorithm unavailable)
- others: failure

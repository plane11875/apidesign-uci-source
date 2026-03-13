# SDFR PQ Smoke Test Example

## File
- `tests/test_sdfr_pq.c`

## What it verifies
- `SDFR_OP_SIGN` + `SDFR_OP_VERIFY` with ML-DSA (`mldsa65`)
- `SDFR_OP_KEM_ENCAPSULATE` + `SDFR_OP_KEM_DECAPSULATE` with ML-KEM (`mlkem768`)
- dynamic AlgID routing via `SDFR_PATCH_FILE`

## Routing in this test
- `0x00F0D501 -> mldsa65 provider=myoqsprov`
- `0x00F0D502 -> mlkem768 provider=myoqsprov`

## Build
```bash
cc -Iinclude tests/test_sdfr_pq.c -Lbuild -luci -lcrypto -Wl,-rpath,'$ORIGIN' -o build/test_sdfr_pq
```

## Run
```bash
export OPENSSL_MODULES=/root/project/myoqsprov
export LD_LIBRARY_PATH=/root/project/apidesign-uci-source/build:/usr/local/lib:$LD_LIBRARY_PATH
export UCI_TEST_PROVIDER=myoqsprov
./build/test_sdfr_pq
```

Exit code:
- `0`: pass
- `77`: skipped (provider/algorithm unavailable)
- others: failure

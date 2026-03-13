#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   scripts/onboard_new_alg.sh [provider] [sign_alg] [kem_alg] [sign_algid] [kem_algid]
# Example:
#   scripts/onboard_new_alg.sh myoqsprov mldsa65 mlkem768 0x00F0D501 0x00F0D502

PROVIDER="${1:-myoqsprov}"
SIGN_ALG="${2:-mldsa65}"
KEM_ALG="${3:-mlkem768}"
SIGN_ALGID="${4:-0x00F0D501}"
KEM_ALGID="${5:-0x00F0D502}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
TEST_BIN="$BUILD_DIR/test_sdfr_pq"

OPENSSL_MODULES="${OPENSSL_MODULES:-/root/project/myoqsprov}"
export OPENSSL_MODULES
export LD_LIBRARY_PATH="$BUILD_DIR:/usr/local/lib:${LD_LIBRARY_PATH:-}"

if [[ ! -f "$BUILD_DIR/libuci.so" ]]; then
  echo "[INFO] build/libuci.so not found, building uci..."
  cmake -S "$PROJECT_ROOT" -B "$BUILD_DIR" -G Ninja
  cmake --build "$BUILD_DIR" -j4
fi

if [[ ! -x "$TEST_BIN" ]]; then
  echo "[INFO] build/test_sdfr_pq not found, compiling test..."
  cc -I"$PROJECT_ROOT/include" "$PROJECT_ROOT/tests/test_sdfr_pq.c" \
     -L"$BUILD_DIR" -luci -lcrypto -Wl,-rpath,'$ORIGIN' \
     -o "$TEST_BIN"
fi

export UCI_TEST_PROVIDER="$PROVIDER"
export UCI_TEST_SIGN_ALG="$SIGN_ALG"
export UCI_TEST_KEM_ALG="$KEM_ALG"
export UCI_TEST_SIGN_ALGID="$SIGN_ALGID"
export UCI_TEST_KEM_ALGID="$KEM_ALGID"

echo "[INFO] OPENSSL_MODULES=$OPENSSL_MODULES"
echo "[INFO] provider=$PROVIDER sign=$SIGN_ALG($SIGN_ALGID) kem=$KEM_ALG($KEM_ALGID)"

set +e
"$TEST_BIN"
rc=$?
set -e

if [[ $rc -eq 0 ]]; then
  echo "[PASS] onboarding test passed"
elif [[ $rc -eq 77 ]]; then
  echo "[SKIP] provider/algorithm unavailable (exit=77)"
else
  echo "[FAIL] onboarding test failed (exit=$rc)"
fi

exit $rc

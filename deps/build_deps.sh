#!/bin/bash

set -euo pipefail

if [ -z "${1:-}" ]; then
  echo "Usage: ./build_deps.sh <build_type>  (e.g. Release, Debug)" >&2
  exit 1
fi

required_bin() {
  if ! command -v "$1" &> /dev/null; then
    echo "Error: '$1' is required but not found." >&2
    exit 1
  fi
}

required_bin cmake
required_bin git
required_bin musl-gcc
required_bin python3

export CC=musl-gcc

if ! [ -d "mbedtls" ]; then
  git clone --recurse-submodules --branch v4.1.0 https://github.com/Mbed-TLS/mbedtls.git
fi

cd "mbedtls"

make clean || true

python3 scripts/config.py unset MBEDTLS_ERROR_C             
python3 scripts/config.py unset MBEDTLS_SSL_DEBUG_C         
python3 scripts/config.py unset MBEDTLS_DEBUG_C             
python3 scripts/config.py unset MBEDTLS_VERSION_FEATURES
python3 scripts/config.py unset MBEDTLS_SELF_TEST

cmake -DENABLE_TESTING=Off -DCMAKE_BUILD_TYPE="$1" -DCMAKE_C_FLAGS="-ffunction-sections -fdata-sections" .
make

if [[ "$1" == "Release" ]]; then
  strip --strip-unneeded library/libmbedtls.a
  strip --strip-unneeded library/libmbedx509.a
  strip --strip-unneeded library/libmbedcrypto.a
fi
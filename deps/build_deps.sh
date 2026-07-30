#!/bin/bash 

set -euo pipefail

if [ -z "${1:-}" ]; then
    echo "Usage: ./build_deps.sh <build_type>  (e.g. Release, Debug)" >&2
    exit 1
fi

# quick function to check whether the required binaries exist
required_bin() {
    if ! command -v "$1" &> /dev/null; then
        echo "Error: '$1' is required but not found." >&2
        exit 1
    fi
}

required_bin cmake
required_bin git
required_bin musl-gcc

# set compiler to link against musl 
export CC=musl-gcc

# download mbedtls
if ! [ -d "mbedtls" ]; then 
    git clone --recurse-submodules --branch v4.1.0 https://github.com/Mbed-TLS/mbedtls.git
fi 

cd "mbedtls"

# will fail first run through due to not having been built yet, silently ignoring. this is reqired when swapping build modes
make clean || true 

cmake -DENABLE_TESTING=Off -DCMAKE_BUILD_TYPE="$1" -DCMAKE_C_FLAGS="-ffunction-sections -fdata-sections" .
make

# if mode was release, strip libraries 
if [[ "$1" == "Release" ]]; then
    strip --strip-unneeded library/libmbedtls.a
    strip --strip-unneeded library/libmbedx509.a
    strip --strip-unneeded library/libmbedcrypto.a
fi





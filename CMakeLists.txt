cmake_minimum_required(VERSION 3.16...4.2.3)

find_program(MUSL_GCC musl-gcc)
if(NOT MUSL_GCC)
    message(FATAL_ERROR "musl-gcc not found, install it via local installation method, ie apt install musl-tools")
endif()

set(CMAKE_C_COMPILER ${MUSL_GCC})

project(sith C)

# Default to Debug
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# Enable LTO in Release 
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

# Check whether mbedtls was built and required libraries are present
set(MBEDTLS_DIR "${CMAKE_SOURCE_DIR}/deps/mbedtls")

find_library(MBEDTLS_LIB    mbedtls    PATHS "${MBEDTLS_DIR}/library" NO_DEFAULT_PATH)
find_library(MBEDX509_LIB   mbedx509   PATHS "${MBEDTLS_DIR}/library" NO_DEFAULT_PATH)
find_library(MBEDCRYPTO_LIB mbedcrypto PATHS "${MBEDTLS_DIR}/library" NO_DEFAULT_PATH)

if(NOT MBEDTLS_LIB OR NOT MBEDX509_LIB OR NOT MBEDCRYPTO_LIB)
    message(FATAL_ERROR "mbedtls was not built properly, move into `deps` directory and run ./build_deps.sh (Release|Debug)")
endif()

file(GLOB TLS_SOURCES "${CMAKE_SOURCE_DIR}/tls/src/*.c")
add_executable(sith main.c ${TLS_SOURCES})

target_include_directories(sith PRIVATE
    "${CMAKE_SOURCE_DIR}/util/includes"
    "${CMAKE_SOURCE_DIR}/tls/includes"
    "${MBEDTLS_DIR}/include"
    "${MBEDTLS_DIR}/tf-psa-crypto/include"
    "${MBEDTLS_DIR}/tf-psa-crypto/drivers/builtin/include"
)

target_link_libraries(sith PRIVATE
    ${MBEDTLS_LIB}
    ${MBEDX509_LIB}
    ${MBEDCRYPTO_LIB}
)

# remove any dead code or unused sections and statically link
target_compile_options(sith PRIVATE -ffunction-sections -fdata-sections)
target_link_options(sith PRIVATE -static -Wl,--gc-sections)

# strip release binaries
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
    add_custom_command(TARGET sith POST_BUILD
        COMMAND ${CMAKE_STRIP} $<TARGET_FILE:sith>
    )
endif()
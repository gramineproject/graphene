include_directories(${CMAKE_CURRENT_LIST_DIR})

set(COMMON_LIB_SOURCE
    graphene/config.c
    graphene/path.c
    stdlib/printfmt.c
    string/atoi.c
    string/memcmp.c
    string/memcpy.c
    string/memset.c
    string/strchr.c
    string/strlen.c
    string/wordcopy.c
    network/hton.c
    network/inet_pton.c)

prepend_list(COMMON_LIB_SOURCE "${CMAKE_CURRENT_LIST_DIR}/" "${COMMON_LIB_SOURCE}")

if (CRYPTO_PROVIDER STREQUAL "mbedtls")
    file(GLOB COMMON_CRYPTO_C_SOURCE
        ${CMAKE_CURRENT_LIST_DIR}/crypto/mbedtls/*.c
        ${CMAKE_CURRENT_LIST_DIR}/crypto/adapters/mbedtls_*.c)
    file(GLOB COMMON_CRYPTO_ASM_SOURCE
        ${CMAKE_CURRENT_LIST_DIR}/crypto/mbedtls/*.S)
    add_definitions("-DCRYPTO_USE_MBEDTLS")
endif()

if (CRYPTO_PROVIDER STREQUAL "wolfssl")
    file(GLOB COMMON_CRYPTO_C_SOURCE
        ${CMAKE_CURRENT_LIST_DIR}/crypto/wolfssl/*.c
        ${CMAKE_CURRENT_LIST_DIR}/crypto/adapters/wolfssl_*.c)
    file(GLOB COMMON_CRYPTO_ASM_SOURCE
        ${CMAKE_CURRENT_LIST_DIR}/crypto/wolfssl/*.S)
    add_definitions("-DCRYPTO_USE_WOLFSSL")
endif()

list(APPEND COMMON_LIB_SOURCE
    ${COMMON_CRYPTO_C_SOURCE}
    ${COMMON_CRYPTO_ASM_SOURCE})

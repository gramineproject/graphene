include_directories(${CMAKE_CURRENT_LIST_DIR})

file(GLOB COMMON_GRAPHENE_SOURCE
    ${CMAKE_CURRENT_LIST_DIR}/graphene/*.c)
file(GLOB COMMON_STDLIB_SOURCE
    ${CMAKE_CURRENT_LIST_DIR}/stdlib/*.c)
file(GLOB COMMON_STRING_SOURCE
    ${CMAKE_CURRENT_LIST_DIR}/string/*.c)
file(GLOB COMMON_NETWORK_SOURCE
    ${CMAKE_CURRENT_LIST_DIR}/network/*.c)

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
        ${CMAKE_CURRENT_LIST_DIR}/crypto/wolfssl/mbedtls_*.c)
    file(GLOB COMMON_CRYPTO_ASM_SOURCE
        ${CMAKE_CURRENT_LIST_DIR}/crypto/wolfssl/*.S)
    add_definitions("-DCRYPTO_USE_WOLFSSL")
endif()

set(COMMON_LIB_SOURCE
    ${COMMON_GRAPHENE_SOURCE}
    ${COMMON_STDLIB_SOURCE}
    ${COMMON_STRING_SOURCE}
    ${COMMON_NETWORK_SOURCE}
    ${COMMON_CRYPTO_C_SOURCE}
    ${COMMON_CRYPTO_ASM_SOURCE})

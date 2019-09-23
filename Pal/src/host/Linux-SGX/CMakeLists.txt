cmake_minimum_required(VERSION 2.8)

project(graphene_pal_linux C ASM)

string(CONCAT CMAKE_C_FLAGS
    "-Wall -Wextra -O2 -std=c11 -maes -U_FORTIFY_SOURCE -fno-stack-protector "
    "-fno-builtin -Wtrampolines")
string(CONCAT CMAKE_C_FLAGS_DEBUG
    "-gdwarf-2 -g3 -DDEBUG")
string(CONCAT CMAKE_ASM_FLAGS
    "-DASSEMBLER -Wa,--noexecstack -x assembler-with-cpp")
string(CONCAT CMAKE_SHARED_LINKER_FLAGS
    "-Wl,-nostdlib -Wl,-z,combreloc -Wl,-z,defs -Wl,-z,relro -Wl,-z,now "
    "-Wl,--hash-style=gnu "
    "-Wl,--version-script,${CMAKE_CURRENT_BINARY_DIR}/pal.map "
    "-Wl,-T,${CMAKE_CURRENT_SOURCE_DIR}/enclave.lds")
string(CONCAT CMAKE_EXE_LINKER_FLAGS
    "-Wl,-z,relro -Wl,-z,now")

include_directories(../../../ipc/linux)
include_directories(include)
include_directories(quote)
include_directories(sgx-driver)
include_directories(.)
include_directories(${CMAKE_CURRENT_BINARY_DIR}) # Required for asm-offsets.h

set(CRYPTO_PROVIDER "mbedtls")

include(../../../../rules.cmake)
include(../../../lib/common.cmake)
include(../../pal.cmake)

set(PAL_LINUX_ENCLAVE_SOURCE
    db_files.c
    db_devices.c
    db_pipes.c
    db_sockets.c
    db_streams.c
    db_memory.c
    db_threading.c
    db_mutex.c
    db_events.c
    db_process.c
    db_object.c
    db_main.c
    db_rtld.c
    db_exception.c
    db_misc.c
    db_ipc.c
    db_spinlock.c
    enclave_ocalls.c
    enclave_ecalls.c
    enclave_framework.c
    enclave_platform.c
    enclave_pages.c
    enclave_untrusted.c
    enclave_entry.S)

set_property(SOURCE ${PAL_LINUX_ENCLAVE_SOURCE} PROPERTY COMPILE_FLAGS -DIN_ENCLAVE)

file(DOWNLOAD
    https://certificates.trustedservices.intel.com/Intel_SGX_Attestation_RootCA.pem
    ${CMAKE_CURRENT_BINARY_DIR}/quote/Intel_SGX_Attestation_RootCA.pem)

add_library(pal-Linux-SGX SHARED
    ${PAL_GENERIC_SOURCE}
    ${COMMON_LIB_SOURCE}
    ${PAL_LINUX_ENCLAVE_SOURCE}
    ${CMAKE_CURRENT_BINARY_DIR}/asm-offsets.h
    ${CMAKE_CURRENT_BINARY_DIR}/pal.map)

add_custom_command(
    OUTPUT
        ${CMAKE_CURRENT_BINARY_DIR}/quote/aesm.pb-c.c
    COMMAND
        protoc-c --c_out=${CMAKE_CURRENT_BINARY_DIR}/quote
            --proto_path=${CMAKE_CURRENT_SOURCE_DIR}/quote
            ${CMAKE_CURRENT_SOURCE_DIR}/quote/aesm.proto
    DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/quote/aesm.proto
)

set(PAL_LINUX_UNTRUST_SOURCE
    sgx_enclave.c
    sgx_framework.c
    sgx_platform.c
    sgx_main.c
    sgx_rtld.c
    sgx_thread.c
    sgx_process.c
    sgx_exception.c
    sgx_graphene.c
    sgx_entry.S)

add_executable(pal-sgx
    ${COMMON_LIB_SOURCE}
    ${PAL_LINUX_UNTRUST_SOURCE}
    ${CMAKE_CURRENT_BINARY_DIR}/asm-offsets.h
    ${CMAKE_CURRENT_BINARY_DIR}/quote/aesm.pb-c.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sgx-driver/isgx_version.h)

set_property(TARGET pal-sgx PROPERTY POSITION_INDEPENDENT_CODE ON)

target_link_libraries(pal-sgx c)
target_link_libraries(pal-sgx pthread)
target_link_libraries(pal-sgx protobuf-c)

add_custom_command(
    OUTPUT
        ${CMAKE_CURRENT_SOURCE_DIR}/sgx-driver/isgx_version.h
    COMMAND
        make -C ${CMAKE_CURRENT_SOURCE_DIR}/sgx-driver isgx_version.h
)

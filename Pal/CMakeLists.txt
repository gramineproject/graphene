cmake_minimum_required(VERSION 2.8)

set_property(GLOBAL PROPERTY ALLOW_DUPLICATE_CUSTOM_TARGETS ON)

project(graphene_pal)

if(NOT DEFINED SGX)
    set(SGX $ENV{SGX})
endif()

if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    if(${SGX})
        message("PAL target: Linux SGX")
        add_subdirectory(src/host/Linux-SGX)
    else()
        message("PAL target: Linux")
        add_subdirectory(src/host/Linux)
    endif()
endif()

file(GLOB_RECURSE ALL_PAL_SOURCE
    ${CMAKE_CURRENT_LIST_DIR}/src/*.c
    ${CMAKE_CURRENT_LIST_DIR}/src/*.h
    ${CMAKE_CURRENT_LIST_DIR}/lib/*.c
    ${CMAKE_CURRENT_LIST_DIR}/lib/*.h)

set(PAL_SOURCE_EXCLUDED_FROM_FORMAT_CHECK
    ${CMAKE_CURRENT_LIST_DIR}/lib/crypto/mbedtls/.*
    ${CMAKE_CURRENT_LIST_DIR}/lib/crypto/udivmodti4.c
    ${CMAKE_CURRENT_LIST_DIR}/src/host/Linux-SGX/sgx-driver/.*
    ${CMAKE_CURRENT_LIST_DIR}/.*/asm-offsets.h
    ${CMAKE_CURRENT_LIST_DIR}/src/host/Linux-SGX/quote/.*)

foreach(FILE ${ALL_PAL_SOURCE})
    foreach(PATTERN ${PAL_SOURCE_EXCLUDED_FROM_FORMAT_CHECK})
       if (${FILE} MATCHES ${PATTERN})
           list(REMOVE_ITEM ALL_PAL_SOURCE ${FILE})
       endif()
    endforeach()
endforeach()

add_custom_target(format COMMAND clang-format -i ${ALL_PAL_SOURCE})

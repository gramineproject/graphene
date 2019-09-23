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

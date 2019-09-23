cmake_minimum_required(VERSION 2.8)

set_property(GLOBAL PROPERTY ALLOW_DUPLICATE_CUSTOM_TARGETS ON)

project(graphene_pal)

add_subdirectory(src/host/Linux)
add_subdirectory(src/host/Linux-SGX)

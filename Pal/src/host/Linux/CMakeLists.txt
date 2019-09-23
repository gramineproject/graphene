cmake_minimum_required(VERSION 2.8)

project(graphene_pal_linux C ASM)

string(CONCAT CMAKE_C_FLAGS
    "-Wall -Wextra -O2 -std=c11 -U_FORTIFY_SOURCE -fno-stack-protector "
    "-fno-builtin -Wtrampolines")
string(CONCAT CMAKE_C_FLAGS_DEBUG
    "-gdwarf-2 -g3 -DDEBUG")
string(CONCAT CMAKE_ASM_FLAGS
    "-DASSEMBLER -Wa,--noexecstack -x assembler-with-cpp")
string(CONCAT CMAKE_SHARED_LINKER_FLAGS
    "-Wl,-nostdlib -Wl,-z,combreloc -Wl,-z,defs -Wl,-z,relro -Wl,-z,now "
    "-Wl,--version-script,${PROJECT_BINARY_DIR}/pal.map "
    "-Wl,-T,${PROJECT_SOURCE_DIR}/pal.lds")

include_directories(../../../ipc/linux)
include_directories(include)
include_directories(.)

include(../../../../rules.cmake)
include(../../../lib/common.cmake)
include(../../pal.cmake)

set(PAL_LINUX_SOURCE
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
    db_misc.c
    db_ipc.c
    db_exception.c
    clone-x86_64.S
    gettimeofday-x86_64.S)

add_library(pal-Linux SHARED
    ${PAL_GENERIC_SOURCE}
    ${COMMON_LIB_SOURCE}
    ${PAL_LINUX_SOURCE}
    ${PROJECT_BINARY_DIR}/pal.map)

install(TARGETS pal-Linux LIBRARY
    DESTINATION ${GRAPHENE_RUNTIME_DIR}
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install(CODE "execute_process( \
    COMMAND ${CMAKE_COMMAND} -E create_symlink \
    libpal-Linux.so \
    ${GRAPHENE_RUNTIME_DIR}/pal-Linux)")

include_directories(${CMAKE_CURRENT_LIST_DIR})
include_directories(${CMAKE_CURRENT_LIST_DIR}/../include)
include_directories(${CMAKE_CURRENT_LIST_DIR}/../include/sysdeps)
include_directories(${CMAKE_CURRENT_LIST_DIR}/../include/sysdeps/generic)
include_directories(${CMAKE_CURRENT_LIST_DIR}/../include/elf)

file(GLOB PAL_GENERIC_SOURCE
    ${CMAKE_CURRENT_LIST_DIR}/*.c)

add_definitions("-DIN_PAL")
add_definitions("-DPAL_DIR=${CMAKE_CURRENT_LIST_DIR}")
add_definitions("-DRUNTIME_DIR=${GRAPHENE_RUNTIME_DIR}")

set(PAL_GENERIC_SOURCE_FILES
    db_streams.c
    db_memory.c
    db_threading.c
    db_mutex.c
    db_events.c
    db_process.c
    db_object.c
    db_main.c
    db_misc.c
    db_ipc.c
    db_exception.c
    db_rtld.c
    slab.c
    printf.c)

prepend_list(PAL_GENERIC_SOURCE ${CMAKE_CURRENT_LIST_DIR}/ ${PAL_GENERIC_SOURCE_FILES})

add_custom_command(
    OUTPUT
        ${PROJECT_BINARY_DIR}/pal.map
    COMMAND
        ${CMAKE_COMMAND}
            -D INPUT_FILE=${PROJECT_SOURCE_DIR}/pal.map.template
            -D OUTPUT_FILE=${PROJECT_BINARY_DIR}/pal.map
            -P ${CMAKE_CURRENT_LIST_DIR}/symbols.cmake
    DEPENDS
        ${PROJECT_SOURCE_DIR}/pal.map.template
)

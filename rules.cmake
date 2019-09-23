function(prepend_list set_to_var prefix_to_add)
    set(new_list "")
    foreach(item ${ARGN})
        list(APPEND new_list "${prefix_to_add}${item}")
    endforeach(item)
    set(${set_to_var} "${new_list}" PARENT_SCOPE)
endfunction(prepend_list)

function(append_list set_to_var suffix_to_add)
    set(new_list "")
    foreach(item ${ARGN})
        list(APPEND new_list "${item}${suffix_to_add}")
    endforeach(item)
    set(${set_to_var} "${new_list}" PARENT_SCOPE)
endfunction(append_list)

# May need to change this to allow installation under any prefixes
set(GRAPHENE_RUNTIME_DIR "${CMAKE_CURRENT_LIST_DIR}/Runtime")

if (EXISTS ${PROJECT_SOURCE_DIR}/generated-offsets.c)
    add_library(generated-offsets OBJECT ${PROJECT_SOURCE_DIR}/generated-offsets.c)

    # Generate generated-offsets.s from generated-offsets.c
    set_property(SOURCE ${PROJECT_SOURCE_DIR}/generated-offsets.c PROPERTY
        COMPILE_FLAGS
        "-Wa,-adhln=${PROJECT_BINARY_DIR}/generated-offsets.s")

    # Ensure that generated-offsets.s is cleaned up
    set_property(DIRECTORY PROPERTY
        ADDITIONAL_MAKE_CLEAN_FILES
        ${PROJECT_BINARY_DIR}/generated-offsets.s APPEND)

    add_custom_command(
        PRE_BUILD
        OUTPUT
            ${PROJECT_BINARY_DIR}/asm-offsets.h
        COMMAND
            ${CMAKE_COMMAND} -D FORMAT=C
                -D INPUT_FILE=${PROJECT_BINARY_DIR}/generated-offsets.s
                -D OUTPUT_FILE=${PROJECT_BINARY_DIR}/asm-offsets.h
                -P ${CMAKE_CURRENT_LIST_DIR}/generate_offsets.cmake
        DEPENDS
            generated-offsets
    )

    add_custom_command(
        PRE_BUILD
        OUTPUT
            ${PROJECT_BINARY_DIR}/generated_offsets.py
        COMMAND
            ${CMAKE_COMMAND} -D FORMAT=python
                -D INPUT_FILE=${PROJECT_BINARY_DIR}/generated-offsets.s
                -D OUTPUT_FILE=${PROJECT_BINARY_DIR}/generated_offsets.py
                -P ${CMAKE_CURRENT_LIST_DIR}/generate_offsets.cmake
        DEPENDS
            generated-offsets
    )
endif()

add_custom_target(
    distclean
    COMMAND ${CMAKE_COMMAND} -E remove_directory CMakeFiles
    COMMAND ${CMAKE_COMMAND} -E remove CMakeCache.txt
    COMMAND ${CMAKE_COMMAND} -E remove cmake_install.cmake
)

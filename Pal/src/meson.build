cflags_pal_common = [
    cflags_custom_stack_protector,
    cflags_sanitizers,
    '-DIN_PAL',
]

pal_common_sources = files(
    'db_events.c',
    'db_exception.c',
    'db_main.c',
    'db_memory.c',
    'db_misc.c',
    'db_object.c',
    'db_process.c',
    'db_rtld.c',
    'db_streams.c',
    'db_threading.c',
    'pal_error.c',
    'printf.c',
    'slab.c',
)

subdir('host')

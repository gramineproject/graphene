/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*!
 * This file contains entry and exit functions of library OS.
 */

#include <asm/fcntl.h>
#include <asm/unistd.h>
#include <sys/mman.h>

#include "api.h"
#include "hex.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "shim_checkpoint.h"
#include "shim_context.h"
#include "shim_defs.h"
#include "shim_fs.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_ipc.h"
#include "shim_lock.h"
#include "shim_process.h"
#include "shim_table.h"
#include "shim_tcb.h"
#include "shim_thread.h"
#include "shim_vdso.h"
#include "shim_vma.h"
#include "toml.h"

static_assert(sizeof(shim_tcb_t) <= PAL_LIBOS_TCB_SIZE,
              "shim_tcb_t does not fit into PAL_TCB; please increase PAL_LIBOS_TCB_SIZE");

size_t g_pal_alloc_align;

toml_table_t* g_manifest_root = NULL;

/* The following constants will help matching glibc version with compatible
   SHIM libraries */
#include "glibc-version.h"

const unsigned int glibc_version = GLIBC_VERSION;

static void handle_failure(PAL_NUM arg, PAL_CONTEXT* context) {
    __UNUSED(context);
    if ((arg <= PAL_ERROR_NATIVE_COUNT) ||
            (arg >= PAL_ERROR_CRYPTO_START && arg <= PAL_ERROR_CRYPTO_END))
        shim_get_tcb()->pal_errno = arg;
    else
        shim_get_tcb()->pal_errno = PAL_ERROR_DENIED;
}

noreturn void __abort(void) {
    DEBUG_BREAK_ON_FAILURE();
    /* `__abort` might be called by any thread, even internal. */
    DkProcessExit(1);
}

/* we use GCC's stack protector; when it detects corrupted stack, it calls __stack_chk_fail() */
noreturn void __stack_chk_fail(void); /* to suppress GCC's warning "no previous prototype" */
noreturn void __stack_chk_fail(void) {
    debug("Stack protector: Graphene LibOS internal stack corruption detected\n");
    __abort();
}

static int pal_errno_to_unix_errno[PAL_ERROR_NATIVE_COUNT + 1] = {
    [PAL_ERROR_SUCCESS]         = 0,
    [PAL_ERROR_NOTIMPLEMENTED]  = ENOSYS,
    [PAL_ERROR_NOTDEFINED]      = ENOSYS,
    [PAL_ERROR_NOTSUPPORT]      = EACCES,
    [PAL_ERROR_INVAL]           = EINVAL,
    [PAL_ERROR_TOOLONG]         = ENAMETOOLONG,
    [PAL_ERROR_DENIED]          = EACCES,
    [PAL_ERROR_BADHANDLE]       = EFAULT,
    [PAL_ERROR_STREAMEXIST]     = EEXIST,
    [PAL_ERROR_STREAMNOTEXIST]  = ENOENT,
    [PAL_ERROR_STREAMISFILE]    = ENOTDIR,
    [PAL_ERROR_STREAMISDIR]     = EISDIR,
    [PAL_ERROR_STREAMISDEVICE]  = ESPIPE,
    [PAL_ERROR_INTERRUPTED]     = EINTR,
    [PAL_ERROR_OVERFLOW]        = EFAULT,
    [PAL_ERROR_BADADDR]         = EFAULT,
    [PAL_ERROR_NOMEM]           = ENOMEM,
    [PAL_ERROR_NOTKILLABLE]     = EACCES,
    [PAL_ERROR_INCONSIST]       = EFAULT,
    [PAL_ERROR_TRYAGAIN]        = EAGAIN,
    [PAL_ERROR_ENDOFSTREAM]     = 0,
    [PAL_ERROR_NOTSERVER]       = EINVAL,
    [PAL_ERROR_NOTCONNECTION]   = ENOTCONN,
    [PAL_ERROR_CONNFAILED]      = ECONNRESET,
    [PAL_ERROR_ADDRNOTEXIST]    = EADDRNOTAVAIL,
    [PAL_ERROR_AFNOSUPPORT]     = EAFNOSUPPORT,
    [PAL_ERROR_CONNFAILED_PIPE] = EPIPE,
};

long convert_pal_errno(long err) {
    return (err >= 0 && err <= PAL_ERROR_NATIVE_COUNT) ? pal_errno_to_unix_errno[err] : EACCES;
}

void* migrated_memory_start;
void* migrated_memory_end;

const char** migrated_envp __attribute_migratable;

/* library_paths is populated with LD_PRELOAD entries once during LibOS
 * initialization and is used in __load_interp_object() to search for ELF
 * program interpreter in specific paths. Once allocated, its memory is
 * never freed or updated. */
char** library_paths = NULL;

struct shim_lock __master_lock;
bool lock_enabled;

void* allocate_stack(size_t size, size_t protect_size, bool user) {
    void* stack = NULL;

    size = ALLOC_ALIGN_UP(size);
    protect_size = ALLOC_ALIGN_UP(protect_size);

    int flags = MAP_PRIVATE | MAP_ANONYMOUS | (user ? 0 : VMA_INTERNAL) | MAP_GROWSDOWN;

    if (user) {
        /* reserve non-readable non-writable page below the user stack to catch stack overflows */
        int ret = bkeep_mmap_any_aslr(size + protect_size, PROT_NONE, flags, NULL, 0, "stack",
                                      &stack);
        if (ret < 0) {
            return NULL;
        }

        if (!DkVirtualMemoryAlloc(stack, size + protect_size, 0, PAL_PROT_NONE)) {
            void* tmp_vma = NULL;
            if (bkeep_munmap(stack, size + protect_size, !user, &tmp_vma) < 0) {
                BUG();
            }
            bkeep_remove_tmp_vma(tmp_vma);
            return NULL;
        }
    } else {
        stack = system_malloc(size + protect_size);
        if (!stack) {
            return NULL;
        }
    }

    stack += protect_size;
    /* ensure proper alignment for process' initial stack */
    stack = ALIGN_UP_PTR(stack, 16);
    DkVirtualMemoryProtect(stack, size, PAL_PROT_READ | PAL_PROT_WRITE);

    if (bkeep_mprotect(stack, size, PROT_READ | PROT_WRITE, !!(flags & VMA_INTERNAL)) < 0)
        return NULL;

    debug("Allocated stack at %p (size = %ld)\n", stack, size);
    return stack;
}

/* populate already-allocated stack with copied argv and envp and space for auxv;
 * returns a pointer to first stack frame (starting with argc, then argv pointers, and so on)
 * and a pointer inside first stack frame (with auxv[0], auxv[1], and so on) */
static int populate_stack(void* stack, size_t stack_size, const char** argv, const char** envp,
                          const char*** out_argp, elf_auxv_t** out_auxv) {
    void* stack_low_addr  = stack;
    void* stack_high_addr = stack + stack_size;

#define ALLOCATE_FROM_HIGH_ADDR(size)                     \
    ({                                                    \
        if ((stack_high_addr -= (size)) < stack_low_addr) \
            return -ENOMEM;                               \
        stack_high_addr;                                  \
    })

#define ALLOCATE_FROM_LOW_ADDR(size)                      \
    ({                                                    \
        if ((stack_low_addr += (size)) > stack_high_addr) \
            return -ENOMEM;                               \
        stack_low_addr - (size);                          \
    })

    /* create stack layout as follows for ld.so:
     *
     *                 +-------------------+
     * out_argp +--->  |  argc             | long
     *                 |  ptr to argv[0]   | char*
     *                 |  ptr to argv[1]   | char*
     *                 |  ...              | char*
     *                 |  NULL             | char*
     *                 |  ptr to envp[0]   | char*
     *                 |  ptr to envp[1]   | char*
     *                 |  ...              | char*
     *                 |  NULL             | char*
     * out_auxv +--->  |  <space for auxv> |
     *                 |  envp[0] string   |
     *                 |  envp[1] string   |
     *                 |  ...              |
     *                 |  argv[0] string   |
     *                 |  argv[1] string   |
     *                 |  ...              |
     *                 +-------------------+
     */
    size_t argc      = 0;
    size_t argv_size = 0;
    for (const char** a = argv; *a; a++) {
        argv_size += strlen(*a) + 1;
        argc++;
    }

    /* we populate the stack memory region from two ends:
     *   - memory at high addresses contains buffers with argv + envp strings
     *   - memory at low addresses contains argc and pointer-arrays of argv, envp, and auxv */
    long* argc_ptr = ALLOCATE_FROM_LOW_ADDR(sizeof(long));
    *argc_ptr = argc;

    /* pre-allocate enough space to hold all argv strings */
    char* argv_str = ALLOCATE_FROM_HIGH_ADDR(argv_size);

    /* Even though the SysV ABI does not specify the order of argv strings, some applications
     * (notably Node.js's libuv) assume the compact encoding of argv where (1) all strings are
     * located adjacently and (2) in increasing order. */
    const char** new_argv = stack_low_addr;
    for (const char** a = argv; *a; a++) {
        size_t len = strlen(*a) + 1;
        const char** argv_ptr = ALLOCATE_FROM_LOW_ADDR(sizeof(const char*)); /* ptr to argv[i] */
        memcpy(argv_str, *a, len);                                           /* argv[i] string */
        *argv_ptr = argv_str;
        argv_str += len;
    }
    *((const char**)ALLOCATE_FROM_LOW_ADDR(sizeof(const char*))) = NULL;

    /* populate envp on stack similarly to argv */
    size_t envp_size = 0;
    for (const char** e = envp; *e; e++) {
        envp_size += strlen(*e) + 1;
    }
    char* envp_str = ALLOCATE_FROM_HIGH_ADDR(envp_size);

    const char** new_envp = stack_low_addr;
    for (const char** e = envp; *e; e++) {
        size_t len = strlen(*e) + 1;
        const char** envp_ptr = ALLOCATE_FROM_LOW_ADDR(sizeof(const char*)); /* ptr to envp[i] */
        memcpy(envp_str, *e, len);                                           /* envp[i] string */
        *envp_ptr = envp_str;
        envp_str += len;
    }
    *((const char**)ALLOCATE_FROM_LOW_ADDR(sizeof(const char*))) = NULL;

    /* reserve space for ELF aux vectors, populated later in execute_elf_object() */
    elf_auxv_t* new_auxv = ALLOCATE_FROM_LOW_ADDR(REQUIRED_ELF_AUXV * sizeof(elf_auxv_t) +
                                                  REQUIRED_ELF_AUXV_SPACE);

    /* we have now low part of stack (with argc and pointer-arrays of argv, envp, auxv), high part
     * of stack (with argv and envp strings) and an empty space in the middle: we must remove the
     * empty middle by moving the low part of stack adjacent to the high part */
    size_t move_size         = stack_low_addr - stack;
    void* new_stack_low_addr = stack_high_addr - move_size;

    /* x86-64 SysV ABI requires 16B alignment of stack on ELF entrypoint */
    new_stack_low_addr = ALIGN_DOWN_PTR(new_stack_low_addr, 16UL);
    memmove(new_stack_low_addr, stack, move_size);

    /* pointer-arrays of argv, envp, and auxv were allocated on low part of stack and shifted via
     * memmove above, need to shift pointers to their bases */
    size_t shift = new_stack_low_addr - stack;
    new_argv = (void*)new_argv + shift;
    new_envp = (void*)new_envp + shift;
    new_auxv = (void*)new_auxv + shift;

    /* clear working area at the bottom */
    memset(stack, 0, shift);

    /* TODO: remove this, but see the comment in `shim_do_execve`. */
    /* set global envp pointer for future checkpoint/migration: this is required for fork/clone
     * case (so that migrated envp points to envvars on the migrated stack) and redundant for
     * execve case (because execve passes an explicit list of envvars to child process) */
    migrated_envp = new_envp;

    *out_argp = new_stack_low_addr;
    *out_auxv = new_auxv;
    return 0;
}

int init_stack(const char** argv, const char** envp, const char*** out_argp,
               elf_auxv_t** out_auxv) {
    int ret;

    assert(g_manifest_root);
    uint64_t stack_size;
    ret = toml_sizestring_in(g_manifest_root, "sys.stack.size", get_rlimit_cur(RLIMIT_STACK),
                             &stack_size);
    if (ret < 0) {
        debug("Cannot parse \'sys.stack.size\' (the value must be put in double quotes!)\n");
        return -EINVAL;
    }

    stack_size = ALLOC_ALIGN_UP(stack_size);
    set_rlimit_cur(RLIMIT_STACK, stack_size);

    struct shim_thread* cur_thread = get_cur_thread();
    if (!cur_thread || cur_thread->stack)
        return 0;

    void* stack = allocate_stack(stack_size, g_pal_alloc_align, /*user=*/true);
    if (!stack)
        return -ENOMEM;

    /* if there is envp inherited from parent, use it */
    envp = migrated_envp ?: envp;

    ret = populate_stack(stack, stack_size, argv, envp, out_argp, out_auxv);
    if (ret < 0)
        return ret;

    cur_thread->stack_top = stack + stack_size;
    cur_thread->stack     = stack;
    cur_thread->stack_red = stack - g_pal_alloc_align;
    return 0;
}

static int read_environs(const char** envp) {
    for (const char** e = envp; *e; e++) {
        if (strstartswith(*e, "LD_LIBRARY_PATH=")) {
            /* populate library_paths with entries from LD_LIBRARY_PATH envvar */
            const char* s = *e + static_strlen("LD_LIBRARY_PATH=");
            size_t npaths = 2; // One for the first entry, one for the last NULL.
            for (const char* tmp = s; *tmp; tmp++)
                if (*tmp == ':')
                    npaths++;
            char** paths = malloc(sizeof(const char*) * npaths);
            if (!paths)
                return -ENOMEM;

            size_t cnt = 0;
            while (*s) {
                const char* next;
                for (next = s; *next && *next != ':'; next++)
                    ;
                char* str = alloc_substr(s, next - s);
                if (!str) {
                    for (size_t i = 0; i < cnt; i++)
                        free(paths[i]);
                    free(paths);
                    return -ENOMEM;
                }
                paths[cnt++] = str;
                s = *next ? next + 1 : next;
            }

            paths[cnt] = NULL;

            assert(!library_paths);
            library_paths = paths;
            return 0;
        }
    }

    return 0;
}

#define CALL_INIT(func, args...) func(args)

#define RUN_INIT(func, ...)                                              \
    do {                                                                 \
        int _err = CALL_INIT(func, ##__VA_ARGS__);                       \
        if (_err < 0) {                                                  \
            debug("Error during shim_init() in " #func " (%d)\n", _err); \
            DkProcessExit(-_err);                                        \
        }                                                                \
    } while (0)

noreturn void* shim_init(int argc, void* args) {
    g_log_level = PAL_CB(log_level);
    g_process_ipc_info.vmid = (IDTYPE)PAL_CB(process_id);

    /* create the initial TCB, shim can not be run without a tcb */
    shim_tcb_init();
    update_tls_base(0);
    __disable_preempt(shim_get_tcb()); // Temporarily disable preemption for delaying any signal
                                       // that arrives during initialization

    struct debug_buf debug_buf;
    (void)debug_setbuf(shim_get_tcb(), &debug_buf);

    debug("Host: %s\n", PAL_CB(host_type));

    DkSetExceptionHandler(&handle_failure, PAL_EVENT_FAILURE);

    g_pal_alloc_align = PAL_CB(alloc_align);
    if (!IS_POWER_OF_2(g_pal_alloc_align)) {
        debug("Error during shim_init(): PAL allocation alignment not a power of 2\n");
        DkProcessExit(EINVAL);
    }

    g_manifest_root = PAL_CB(manifest_root);

    shim_xstate_init();

    if (!create_lock(&__master_lock)) {
        debug("Error during shim_init(): failed to allocate __master_lock\n");
        DkProcessExit(ENOMEM);
    }

    const char** argv = args;
    const char** envp = args + sizeof(char*) * ((argc) + 1);

    RUN_INIT(init_vma);
    RUN_INIT(init_slab);
    RUN_INIT(read_environs, envp);
    RUN_INIT(init_str_mgr);
    RUN_INIT(init_internal_map);
    RUN_INIT(init_rlimit);
    RUN_INIT(init_fs);
    RUN_INIT(init_dcache);
    RUN_INIT(init_handle);

    debug("Shim loaded at %p, ready to initialize\n", &__load_address);

    if (PAL_CB(parent_process)) {
        struct checkpoint_hdr hdr;

        PAL_NUM ret = DkStreamRead(PAL_CB(parent_process), 0, sizeof(hdr), &hdr, NULL, 0);
        if (ret == PAL_STREAM_ERROR || ret != sizeof(hdr))
            shim_do_exit(-PAL_ERRNO());

        assert(hdr.size);
        RUN_INIT(receive_checkpoint_and_restore, &hdr);
    }

    RUN_INIT(init_mount_root);
    RUN_INIT(init_ipc);
    RUN_INIT(init_process);
    RUN_INIT(init_threading);
    RUN_INIT(init_mount);
    RUN_INIT(init_important_handles);
    RUN_INIT(init_async);

    const char** new_argp;
    elf_auxv_t* new_auxv;
    RUN_INIT(init_stack, argv, envp, &new_argp, &new_auxv);

    RUN_INIT(init_loader);
    RUN_INIT(init_ipc_helper);
    RUN_INIT(init_signal);

    if (PAL_CB(parent_process)) {
        /* Notify the parent process */
        IDTYPE child_vmid = g_process_ipc_info.vmid;
        PAL_NUM ret = DkStreamWrite(PAL_CB(parent_process), 0, sizeof(child_vmid), &child_vmid,
                                    NULL);
        if (ret == PAL_STREAM_ERROR || ret != sizeof(child_vmid))
            shim_do_exit(-PAL_ERRNO());
    }

    debug("Shim process initialized\n");

    shim_tcb_t* cur_tcb = shim_get_tcb();

    if (cur_tcb->context.regs && shim_context_get_sp(&cur_tcb->context)) {
        vdso_map_migrate();
        restore_child_context_after_clone(&cur_tcb->context);
        /* UNREACHABLE */
    }

    lock(&g_process.fs_lock);
    struct shim_handle* exec = g_process.exec;
    get_handle(exec);
    unlock(&g_process.fs_lock);

    if (exec) {
        /* Passing ownership of `exec` to `execute_elf_object`. */
        execute_elf_object(exec, new_argp, new_auxv);
    }
    shim_do_exit(0);
}

static int get_256b_random_hex_string(char* buf, size_t size) {
    char random[32]; /* 256-bit random value, sufficiently crypto secure */

    if (size < sizeof(random) * 2 + 1)
        return -ENOMEM;

    int ret = DkRandomBitsRead(&random, sizeof(random));
    if (ret < 0)
        return -convert_pal_errno(-ret);

    BYTES2HEXSTR(random, buf, size);
    return 0;
}

int create_pipe(char* name, char* uri, size_t size, PAL_HANDLE* hdl, struct shim_qstr* qstr,
                bool use_vmid_for_name) {
    int ret;
    size_t len;
    char pipename[PIPE_URI_SIZE];
    PAL_HANDLE pipe = NULL;

    assert(hdl);
    assert(uri);
    assert(size);

    while (true) {
        if (use_vmid_for_name) {
            len = snprintf(pipename, sizeof(pipename), "%u", g_process_ipc_info.vmid);
            if (len >= sizeof(pipename))
                return -ERANGE;
        } else {
            ret = get_256b_random_hex_string(pipename, sizeof(pipename));
            if (ret < 0)
                return ret;
        }

        debug("Creating pipe: " URI_PREFIX_PIPE_SRV "%s\n", pipename);
        len = snprintf(uri, size, URI_PREFIX_PIPE_SRV "%s", pipename);
        if (len >= size)
            return -ERANGE;

        pipe = DkStreamOpen(uri, 0, 0, 0, 0);
        if (!pipe) {
            if (!use_vmid_for_name && PAL_NATIVE_ERRNO() == PAL_ERROR_STREAMEXIST) {
                /* tried to create a pipe with random name but it already exists */
                continue;
            }
            return -PAL_ERRNO();
        }

        break; /* succeeded in creating the pipe with random/vmid name */
    }

    /* output generated pipe handle, URI, qstr-URI and name */
    *hdl = pipe;
    len = snprintf(uri, size, URI_PREFIX_PIPE "%s", pipename);
    if (qstr)
        qstrsetstr(qstr, uri, len);
    if (name)
        memcpy(name, pipename, sizeof(pipename));
    return 0;
}

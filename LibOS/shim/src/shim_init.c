/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*!
 * \file shim_init.c
 *
 * This file contains entry and exit functions of library OS.
 */

#include <shim_context.h>
#include <shim_defs.h>
#include <shim_internal.h>
#include <shim_table.h>
#include <shim_tcb.h>
#include <shim_thread.h>
#include <shim_handle.h>
#include <shim_vma.h>
#include <shim_checkpoint.h>
#include <shim_fs.h>
#include <shim_ipc.h>
#include <shim_vdso.h>

#include "hex.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_error.h"

#include <sys/mman.h>
#include <asm/unistd.h>
#include <asm/fcntl.h>

static_assert(sizeof(shim_tcb_t) <= PAL_LIBOS_TCB_SIZE,
              "shim_tcb_t does not fit into PAL_TCB; "
              "please increase PAL_LIBOS_TCB_SIZE");

size_t g_pal_alloc_align;

/* The following constants will help matching glibc version with compatible
   SHIM libraries */
#include "glibc-version.h"

const unsigned int glibc_version = GLIBC_VERSION;

static void handle_failure (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    __UNUSED(event);
    __UNUSED(context);
    if ((arg <= PAL_ERROR_NATIVE_COUNT) || (arg >= PAL_ERROR_CRYPTO_START &&
        arg <= PAL_ERROR_CRYPTO_END))
        shim_get_tcb()->pal_errno = arg;
    else
        shim_get_tcb()->pal_errno = PAL_ERROR_DENIED;
}

noreturn void __abort(void) {
    DEBUG_BREAK_ON_FAILURE();
    shim_clean_and_exit(-ENOTRECOVERABLE);
}

void warn (const char *format, ...)
{
    va_list args;
    va_start (args, format);
    __SYS_VPRINTF(format, args);
    va_end (args);
}

static int pal_errno_to_unix_errno [PAL_ERROR_NATIVE_COUNT + 1] = {
        /* reserved                  */  0,
        /* PAL_ERROR_NOTIMPLEMENTED  */  ENOSYS,
        /* PAL_ERROR_NOTDEFINED      */  ENOSYS,
        /* PAL_ERROR_NOTSUPPORT      */  EACCES,
        /* PAL_ERROR_INVAL           */  EINVAL,
        /* PAL_ERROR_TOOLONG         */  ENAMETOOLONG,
        /* PAL_ERROR_DENIED          */  EACCES,
        /* PAL_ERROR_BADHANDLE       */  EFAULT,
        /* PAL_ERROR_STREAMEXIST     */  EEXIST,
        /* PAL_ERROR_STREAMNOTEXIST  */  ENOENT,
        /* PAL_ERROR_STREAMISFILE    */  ENOTDIR,
        /* PAL_ERROR_STREAMISDIR     */  EISDIR,
        /* PAL_ERROR_STREAMISDEVICE  */  ESPIPE,
        /* PAL_ERROR_INTERRUPTED     */  EINTR,
        /* PAL_ERROR_OVERFLOW        */  EFAULT,
        /* PAL_ERROR_BADADDR         */  EFAULT,
        /* PAL_ERROR_NOMEM           */  ENOMEM,
        /* PAL_ERROR_NOTKILLABLE     */  EACCES,
        /* PAL_ERROR_INCONSIST       */  EFAULT,
        /* PAL_ERROR_TRYAGAIN        */  EAGAIN,
        /* PAL_ERROR_ENDOFSTREAM     */  0,
        /* PAL_ERROR_NOTSERVER       */  EINVAL,
        /* PAL_ERROR_NOTCONNECTION   */  ENOTCONN,
        /* PAL_ERROR_CONNFAILED      */  ECONNRESET,
        /* PAL_ERROR_ADDRNOTEXIST    */  EADDRNOTAVAIL,
        /* PAL_ERROR_AFNOSUPPORT     */  EAFNOSUPPORT,
        /* PAL_ERROR_CONNFAILED_PIPE */  EPIPE,
    };

long convert_pal_errno (long err)
{
    return (err >= 0 && err <= PAL_ERROR_NATIVE_COUNT) ?
           pal_errno_to_unix_errno[err] : EACCES;
}

/*!
 * \brief Parse a number into an unsigned long.
 *
 * \param str A string containing a non-negative number.
 *
 * By default the number should be decimal, but if it starts with 0x it is
 * parsed as hexadecimal and if it otherwise starts with 0, it is parsed as
 * octal.
 */
unsigned long parse_int (const char * str)
{
    unsigned long num = 0;
    int radix = 10;
    char c;

    if (str[0] == '0') {
        str++;
        radix = 8;
        if (str[0] == 'x') {
            str++;
            radix = 16;
        }
    }

    while ((c = *(str++))) {
        int val;
        if (c >= 'A' && c <= 'F')
            val = c - 'A' + 10;
        else if (c >= 'a' && c <= 'f')
            val = c - 'a' + 10;
        else if (c >= '0' && c <= '9')
            val = c - '0';
        else
            break;
        if (val >= radix)
            break;
        num = num * radix + val;
    }

    if (c == 'G' || c == 'g')
        num *= 1024 * 1024 * 1024;
    else if (c == 'M' || c == 'm')
        num *= 1024 * 1024;
    else if (c == 'K' || c == 'k')
        num *= 1024;

    return num;
}

void * migrated_memory_start;
void * migrated_memory_end;

const char** migrated_argv __attribute_migratable;
const char** migrated_envp __attribute_migratable;

/* library_paths is populated with LD_PRELOAD entries once during LibOS
 * initialization and is used in __load_interp_object() to search for ELF
 * program interpreter in specific paths. Once allocated, its memory is
 * never freed or updated. */
char ** library_paths = NULL;

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

    debug("allocated stack at %p (size = %ld)\n", stack, size);
    return stack;
}

/* populate already-allocated stack with copied argv and envp and space for auxv;
 * returns a pointer to first stack frame (starting with argc, then argv pointers, and so on)
 * and a pointer inside first stack frame (with auxv[0], auxv[1], and so on) */
static int populate_stack(void* stack, size_t stack_size, const char** argv, const char** envp,
                          const char*** out_argp, elf_auxv_t** out_auxv) {
    void* stack_low_addr  = stack;
    void* stack_high_addr = stack + stack_size;

#define ALLOCATE_FROM_HIGH_ADDR(size)                    \
    ({ if ((stack_high_addr -= (size)) < stack_low_addr) \
           return -ENOMEM;                               \
       stack_high_addr; })

#define ALLOCATE_FROM_LOW_ADDR(size)                     \
    ({ if ((stack_low_addr += (size)) > stack_high_addr) \
           return -ENOMEM;                               \
       stack_low_addr - (size); })

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
    uint64_t stack_size = get_rlimit_cur(RLIMIT_STACK);

    if (root_config) {
        char stack_cfg[CONFIG_MAX];
        if (get_config(root_config, "sys.stack.size", stack_cfg, sizeof(stack_cfg)) > 0) {
            stack_size = ALLOC_ALIGN_UP(parse_int(stack_cfg));
            set_rlimit_cur(RLIMIT_STACK, stack_size);
        }
    }

    struct shim_thread* cur_thread = get_cur_thread();
    if (!cur_thread || cur_thread->stack)
        return 0;

    void* stack = allocate_stack(stack_size, g_pal_alloc_align, /*user=*/true);
    if (!stack)
        return -ENOMEM;

    /* if there are argv/envp inherited from parent, use them */
    argv = migrated_argv ? : argv;
    envp = migrated_envp ? : envp;

    int ret = populate_stack(stack, stack_size, argv, envp, out_argp, out_auxv);
    if (ret < 0)
        return ret;

    cur_thread->stack_top = stack + stack_size;
    cur_thread->stack     = stack;
    cur_thread->stack_red = stack - g_pal_alloc_align;
    return 0;
}

static int read_environs(const char** envp) {
    for (const char ** e = envp ; *e ; e++) {
        if (strstartswith_static(*e, "LD_LIBRARY_PATH=")) {
            /* populate library_paths with entries from LD_LIBRARY_PATH envvar */
            const char * s = *e + static_strlen("LD_LIBRARY_PATH=");
            size_t npaths = 2; // One for the first entry, one for the last
                               // NULL.
            for (const char * tmp = s ; *tmp ; tmp++)
                if (*tmp == ':')
                    npaths++;
            char** paths = malloc(sizeof(const char *) *
                                  npaths);
            if (!paths)
                return -ENOMEM;

            size_t cnt = 0;
            while (*s) {
                const char * next;
                for (next = s ; *next && *next != ':' ; next++);
                size_t len = next - s;
                char * str = malloc(len + 1);
                if (!str) {
                    for (size_t i = 0; i < cnt; i++)
                        free(paths[i]);
                    free(paths);
                    return -ENOMEM;
                }
                memcpy(str, s, len);
                str[len] = 0;
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

struct config_store * root_config = NULL;

static void * __malloc (size_t size)
{
    return malloc(size);
}

static void __free (void * mem)
{
    free(mem);
}

int init_manifest (PAL_HANDLE manifest_handle) {
    int ret = 0;
    void* addr = NULL;
    size_t size = 0, map_size = 0;
    struct config_store* new_root_config = NULL;
    bool stream_mapped = false;

    if (PAL_CB(manifest_preload.start)) {
        addr = PAL_CB(manifest_preload.start);
        size = PAL_CB(manifest_preload.end) - PAL_CB(manifest_preload.start);
    } else {
        PAL_STREAM_ATTR attr;
        if (!DkStreamAttributesQueryByHandle(manifest_handle, &attr))
            return -PAL_ERRNO();

        size = attr.pending_size;
        map_size = ALLOC_ALIGN_UP(size);
        ret = bkeep_mmap_any(map_size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | VMA_INTERNAL, NULL,
                             0, "manifest", &addr);
        if (ret < 0) {
            return ret;
        }

        void* ret_addr = DkStreamMap(manifest_handle, addr, PAL_PROT_READ, 0, ALLOC_ALIGN_UP(size));

        if (!ret_addr) {
            ret = -ENOMEM;
            goto fail;
        }
        stream_mapped = true;
        assert(addr == ret_addr);
    }

    new_root_config = malloc(sizeof(struct config_store));
    if (!new_root_config) {
        ret = -ENOMEM;
        goto fail;
    }

    new_root_config->raw_data = addr;
    new_root_config->raw_size = size;
    new_root_config->malloc = __malloc;
    new_root_config->free = __free;

    const char * errstring = "Unexpected error";

    if ((ret = read_config(new_root_config, NULL, &errstring)) < 0) {
        SYS_PRINTF("Unable to read manifest file: %s\n", errstring);
        goto fail;
    }

    root_config = new_root_config;
    return 0;

fail:
    free(new_root_config);

    if (map_size) {
        void* tmp_vma = NULL;
        if (bkeep_munmap(addr, map_size, /*is_internal=*/true, &tmp_vma) < 0) {
            BUG();
        }
        if (stream_mapped) {
            DkStreamUnmap(addr, map_size);
        }
        bkeep_remove_tmp_vma(tmp_vma);
    }
    return ret;
}

#define CALL_INIT(func, args ...)   func(args)

#define RUN_INIT(func, ...)                                             \
    do {                                                                \
        int _err = CALL_INIT(func, ##__VA_ARGS__);                      \
        if (_err < 0) {                                                 \
            SYS_PRINTF("shim_init() in " #func " (%d)\n", _err);        \
            DkProcessExit(_err);                                        \
        }                                                               \
    } while (0)

extern PAL_HANDLE thread_start_event;

noreturn void* shim_init(int argc, void* args) {
    debug_handle = PAL_CB(debug_stream);
    cur_process.vmid = (IDTYPE) PAL_CB(process_id);

    /* create the initial TCB, shim can not be run without a tcb */
    shim_tcb_init();
    update_fs_base(0);
    __disable_preempt(shim_get_tcb()); // Temporarily disable preemption for delaying any signal
                                       // that arrives during initialization
    debug_setbuf(shim_get_tcb(), true);

    debug("host: %s\n", PAL_CB(host_type));

    DkSetExceptionHandler(&handle_failure, PAL_EVENT_FAILURE);

    g_pal_alloc_align = PAL_CB(alloc_align);
    if (!IS_POWER_OF_2(g_pal_alloc_align)) {
        SYS_PRINTF("shim_init(): error: PAL allocation alignment not a power of 2\n");
        shim_clean_and_exit(-EINVAL);
    }

    if (!create_lock(&__master_lock)) {
        SYS_PRINTF("shim_init(): error: failed to allocate __master_lock\n");
        shim_clean_and_exit(-ENOMEM);
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

    debug("shim loaded at %p, ready to initialize\n", &__load_address);

    if (PAL_CB(parent_process)) {
        struct checkpoint_hdr hdr;

        PAL_NUM ret = DkStreamRead(PAL_CB(parent_process), 0, sizeof(hdr), &hdr, NULL, 0);
        if (ret == PAL_STREAM_ERROR || ret != sizeof(hdr))
            shim_do_exit(-PAL_ERRNO());

        thread_start_event = DkNotificationEventCreate(PAL_FALSE);

        assert(hdr.size);
        RUN_INIT(receive_checkpoint_and_restore, &hdr);
    }

    if (PAL_CB(manifest_handle))
        RUN_INIT(init_manifest, PAL_CB(manifest_handle));

    RUN_INIT(init_mount_root);
    RUN_INIT(init_ipc);
    RUN_INIT(init_thread);
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
        IDTYPE child_vmid = cur_process.vmid;
        PAL_NUM ret = DkStreamWrite(PAL_CB(parent_process), 0, sizeof(child_vmid), &child_vmid,
                                    NULL);
        if (ret == PAL_STREAM_ERROR || ret != sizeof(child_vmid))
            shim_do_exit(-PAL_ERRNO());

        /* FIXME: We shouldn't downgrade communication */
        /* Downgrade communication with parent to non-secure (only checkpoint recv is secure).
         * Currently only relevant to SGX PAL, other PALs ignore this. */
        PAL_STREAM_ATTR attr;
        if (!DkStreamAttributesQueryByHandle(PAL_CB(parent_process), &attr))
            shim_do_exit(-PAL_ERRNO());
        attr.secure = PAL_FALSE;
        if (!DkStreamAttributesSetByHandle(PAL_CB(parent_process), &attr))
            shim_do_exit(-PAL_ERRNO());
    }

    debug("shim process initialized\n");

    if (thread_start_event)
        DkEventSet(thread_start_event);

    shim_tcb_t * cur_tcb = shim_get_tcb();
    struct shim_thread * cur_thread = (struct shim_thread *) cur_tcb->tp;

    if (cur_tcb->context.regs && shim_context_get_sp(&cur_tcb->context)) {
        vdso_map_migrate();
        restore_context(&cur_tcb->context);
    }

    if (cur_thread->exec)
        execute_elf_object(cur_thread->exec, new_argp, new_auxv);
    shim_do_exit(0);
}

static int create_unique (int (*mkname) (char *, size_t, void *),
                          int (*create) (const char *, void *),
                          int (*output) (char *, size_t, const void *,
                                         struct shim_qstr *),
                          char * name, size_t size, void * id, void * obj,
                          struct shim_qstr * qstr)
{
    int ret, len;
    while (1) {
        len = mkname(name, size, id);
        if (len < 0)
            return len;
        if ((ret = create(name, obj)) < 0)
            return ret;
        if (ret)
            continue;
        if (output)
            return output(name, size, id, qstr);
        if (qstr)
            qstrsetstr(qstr, name, len);
        return len;
    }
}

static int get_256b_random_hex_string(char* buf, size_t size) {
    char random[32];  /* 256-bit random value, sufficiently crypto secure */

    if (size < sizeof(random) * 2 + 1)
        return -ENOMEM;

    int ret = DkRandomBitsRead(&random, sizeof(random));
    if (ret < 0)
        return -convert_pal_errno(-ret);

    BYTES2HEXSTR(random, buf, size);
    return 0;
}

static int name_pipe_rand(char* uri, size_t uri_size, void* name) {
    char pipename[PIPE_URI_SIZE];

    int ret = get_256b_random_hex_string(pipename, sizeof(pipename));
    if (ret < 0)
        return ret;

    debug("creating pipe: " URI_PREFIX_PIPE_SRV "%s\n", pipename);
    size_t len = snprintf(uri, uri_size, URI_PREFIX_PIPE_SRV "%s", pipename);
    if (len >= uri_size)
        return -ERANGE;

    memcpy(name, pipename, sizeof(pipename));
    return len;
}

static int name_pipe_vmid(char* uri, size_t uri_size, void* name) {
    char pipename[PIPE_URI_SIZE];

    size_t len = snprintf(pipename, sizeof(pipename), "%u", cur_process.vmid);
    if (len >= sizeof(pipename))
        return -ERANGE;

    debug("creating pipe: " URI_PREFIX_PIPE_SRV "%s\n", pipename);
    len = snprintf(uri, uri_size, URI_PREFIX_PIPE_SRV "%s", pipename);
    if (len >= uri_size)
        return -ERANGE;

    memcpy(name, pipename, sizeof(pipename));
    return len;
}

static int open_pipe(const char* uri, void* obj) {
    assert(obj);

    PAL_HANDLE pipe = DkStreamOpen(uri, 0, 0, 0, 0);
    if (!pipe)
        return PAL_NATIVE_ERRNO() == PAL_ERROR_STREAMEXIST ? 1 : -PAL_ERRNO();

    PAL_HANDLE* pal_hdl = (PAL_HANDLE*)obj;
    *pal_hdl = pipe;
    return 0;
}

static int pipe_addr(char* uri, size_t size, const void* name, struct shim_qstr* qstr) {
    char* pipename = (char*)name;

    size_t len = snprintf(uri, size, URI_PREFIX_PIPE "%s", pipename);
    if (len >= size)
        return -ERANGE;

    if (qstr)
        qstrsetstr(qstr, uri, len);
    return len;
}

int create_pipe(char* name, char* uri, size_t size, PAL_HANDLE* hdl, struct shim_qstr* qstr,
                bool use_vmid_for_name) {
    char pipename[PIPE_URI_SIZE];

    int ret = create_unique(use_vmid_for_name ? &name_pipe_vmid : &name_pipe_rand, &open_pipe,
                            &pipe_addr, uri, size, &pipename, hdl, qstr);
    if (ret > 0 && name) {
        memcpy(name, pipename, sizeof(pipename));
    }
    return ret;
}

static int name_path (char * path, size_t size, void * id)
{
    unsigned int suffix;
    int prefix_len = strlen(path);
    size_t len;
    int ret = DkRandomBitsRead(&suffix, sizeof(suffix));
    if (ret < 0)
        return -convert_pal_errno(-ret);
    len = snprintf(path + prefix_len, size - prefix_len, "%08x", suffix);
    if (len == size)
        return -ERANGE;
    *((unsigned int *) id) = suffix;
    return prefix_len + len;
}

static int open_dir (const char * path, void * obj)
{
    struct shim_handle * dir = NULL;

    if (obj) {
        dir = get_new_handle();
        if (!dir)
            return -ENOMEM;
    }

    int ret = open_namei(dir, NULL, path, O_CREAT|O_EXCL|O_DIRECTORY, 0700,
                         NULL);
    if (ret < 0)
        return ret = -EEXIST ? 1 : ret;
    if (obj)
        *((struct shim_handle **) obj) = dir;

    return 0;
}

static int open_file (const char * path, void * obj)
{
    struct shim_handle * file = NULL;

    if (obj) {
        file = get_new_handle();
        if (!file)
            return -ENOMEM;
    }

    int ret = open_namei(file, NULL, path, O_CREAT|O_EXCL|O_RDWR, 0600,
                         NULL);
    if (ret < 0)
        return ret = -EEXIST ? 1 : ret;
    if (obj)
        *((struct shim_handle **) obj) = file;

    return 0;
}

static int open_pal_handle (const char * uri, void * obj)
{
    PAL_HANDLE hdl;

    if (strstartswith_static(uri, URI_PREFIX_DEV))
        hdl = DkStreamOpen(uri, 0,
                           PAL_SHARE_OWNER_X|PAL_SHARE_OWNER_W|
                           PAL_SHARE_OWNER_R,
                           PAL_CREATE_TRY|PAL_CREATE_ALWAYS,
                           0);
    else
        hdl = DkStreamOpen(uri, PAL_ACCESS_RDWR,
                           PAL_SHARE_OWNER_W|PAL_SHARE_OWNER_R,
                           PAL_CREATE_TRY|PAL_CREATE_ALWAYS,
                           0);

    if (!hdl) {
        if (PAL_NATIVE_ERRNO() == PAL_ERROR_STREAMEXIST)
            return 0;
        else
            return -PAL_ERRNO();
    }

    if (obj) {
        *((PAL_HANDLE *) obj) = hdl;
    } else {
        DkObjectClose(hdl);
    }

    return 0;
}

static int output_path (char * path, size_t size, const void * id,
                        struct shim_qstr * qstr)
{
    size_t len = strlen(path);
    // API compatibility
    __UNUSED(size);
    __UNUSED(id);

    if (qstr)
        qstrsetstr(qstr, path, len);
    return len;
}

int create_dir (const char * prefix, char * path, size_t size,
                struct shim_handle ** hdl)
{
    unsigned int suffix;

    if (prefix) {
        size_t len = strlen(prefix);
        if (len >= size)
            return -ERANGE;
        memcpy(path, prefix, len + 1);
    }

    return create_unique(&name_path, &open_dir, &output_path, path, size,
                         &suffix, hdl, NULL);
}

int create_file (const char * prefix, char * path, size_t size,
                 struct shim_handle ** hdl)
{
    unsigned int suffix;

    if (prefix) {
        size_t len = strlen(prefix);
        if (len >= size)
            return -ERANGE;
        memcpy(path, prefix, len + 1);
    }

    return create_unique(&name_path, &open_file, &output_path, path, size,
                         &suffix, hdl, NULL);
}

int create_handle (const char * prefix, char * uri, size_t size,
                   PAL_HANDLE * hdl, unsigned int * id)
{
    unsigned int suffix;

    if (prefix) {
        size_t len = strlen(prefix);
        if (len >= size)
            return -ERANGE;
        memcpy(uri, prefix, len + 1);
    }

    return create_unique(&name_path, &open_pal_handle, &output_path, uri, size,
                         id ? : &suffix, hdl, NULL);
}

noreturn void shim_clean_and_exit(int exit_code) {
    static int in_terminate = 0;
    if (__atomic_add_fetch(&in_terminate, 1, __ATOMIC_RELAXED) > 1) {
        while (true) {
            /* nothing */
        }
    }

    cur_process.exit_code = exit_code;
    store_all_msg_persist();
    del_all_ipc_ports();

    if (shim_stdio && shim_stdio != (PAL_HANDLE) -1)
        DkObjectClose(shim_stdio);

    shim_stdio = NULL;
    debug("process %u exited with status %d\n", cur_process.vmid & 0xFFFF, cur_process.exit_code);
    MASTER_LOCK();

    if (cur_process.exit_code == PAL_WAIT_FOR_CHILDREN_EXIT) {
        /* user application specified magic exit code; this should be an extremely rare case */
        debug("exit status collides with Graphene-internal magic status; changed to 1\n");
        cur_process.exit_code = 1;
    }
    DkProcessExit(cur_process.exit_code);
}

int message_confirm (const char * message, const char * options)
{
    char answer;
    int noptions = strlen(options);
    char * option_str = __alloca(noptions * 2 + 3), * str = option_str;
    int ret = 0;

    *(str++) = ' ';
    *(str++) = '[';
    for (int i = 0 ; i < noptions ; i++) {
        *(str++) = options[i];
        *(str++) = '/';
    }
    str--;
    *(str++) = ']';
    *(str++) = ' ';

    MASTER_LOCK();

    PAL_HANDLE hdl = __open_shim_stdio();
    if (!hdl) {
        MASTER_UNLOCK();
        return -EACCES;
    }

    PAL_NUM pal_ret;
    pal_ret = DkStreamWrite(hdl, 0, strlen(message), (void*)message, NULL);
    if (pal_ret == PAL_STREAM_ERROR) {
        ret = -PAL_ERRNO();
        goto out;
    }
    pal_ret = DkStreamWrite(hdl, 0, noptions * 2 + 3, option_str, NULL);
    if (pal_ret == PAL_STREAM_ERROR) {
        ret = -PAL_ERRNO();
        goto out;
    }
    pal_ret = DkStreamRead(hdl, 0, 1, &answer, NULL, 0);
    if (pal_ret == PAL_STREAM_ERROR) {
        ret = -PAL_ERRNO();
        goto out;
    }

out:
    DkObjectClose(hdl);
    MASTER_UNLOCK();
    return (ret < 0) ? ret : answer;
}

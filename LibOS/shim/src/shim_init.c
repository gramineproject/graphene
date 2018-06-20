/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * shim_init.c
 *
 * This file contains entry and exit functions of library OS.
 */

#include <shim_internal.h>
#include <shim_tls.h>
#include <shim_thread.h>
#include <shim_handle.h>
#include <shim_vma.h>
#include <shim_checkpoint.h>
#include <shim_fs.h>
#include <shim_ipc.h>
#include <shim_profile.h>

#include <pal.h>
#include <pal_debug.h>
#include <pal_error.h>

#include <sys/mman.h>
#include <asm/unistd.h>
#include <asm/fcntl.h>

unsigned long allocsize;
unsigned long allocshift;
unsigned long allocmask;

/* The following constants will help matching glibc version with compatible
   SHIM libraries */
#include "glibc-version.h"

const unsigned int glibc_version = GLIBC_VERSION;

static void handle_failure (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    SHIM_GET_TLS()->pal_errno = (arg <= PAL_ERROR_BOUND) ? arg : 0;
}

void __abort(void) {
    pause();
    shim_terminate();
}

void warn (const char *format, ...)
{
    va_list args;
    va_start (args, format);
    __sys_vprintf(format, &args);
    va_end (args);
}


void __stack_chk_fail (void)
{
}

static int pal_errno_to_unix_errno [PAL_ERROR_BOUND + 1] = {
        /* reserved                 */  0,
        /* PAL_ERROR_NOTIMPLEMENTED */  ENOSYS,
        /* PAL_ERROR_NOTDEFINED     */  ENOSYS,
        /* PAL_ERROR_NOTSUPPORT     */  EACCES,
        /* PAL_ERROR_INVAL          */  EINVAL,
        /* PAL_ERROR_TOOLONG        */  ENAMETOOLONG,
        /* PAL_ERROR_DENIED         */  EACCES,
        /* PAL_ERROR_BADHANDLE      */  EFAULT,
        /* PAL_ERROR_STREAMEXIST    */  EEXIST,
        /* PAL_ERROR_STREAMNOTEXIST */  ENOENT,
        /* PAL_ERROR_STREAMISFILE   */  ENOTDIR,
        /* PAL_ERROR_STREAMISDIR    */  EISDIR,
        /* PAL_ERROR_STREAMISDEVICE */  ESPIPE,
        /* PAL_ERROR_INTERRUPTED    */  EINTR,
        /* PAL_ERROR_OVERFLOW       */  EFAULT,
        /* PAL_ERROR_BADADDR        */  EFAULT,
        /* PAL_ERROR_NOMEM          */  ENOMEM,
        /* PAL_ERROR_NOTKILLABLE    */  EACCES,
        /* PAL_ERROR_INCONSIST      */  EFAULT,
        /* PAL_ERROR_TRYAGAIN       */  EAGAIN,
        /* PAL_ERROR_ENDOFSTREAM    */  0,
        /* PAL_ERROR_NOTSERVER      */  EINVAL,
        /* PAL_ERROR_NOTCONNECTION  */  ENOTCONN,
        /* PAL_ERROR_ZEROSIZE       */  0,
        /* PAL_ERROR_CONNFAILED     */  ECONNRESET,
        /* PAL_ERROR_ADDRNOTEXIST   */  EADDRNOTAVAIL,
    };

long convert_pal_errno (long err)
{
    return (err >= 0 && err <= PAL_ERROR_BOUND) ?
           pal_errno_to_unix_errno[err] : 0;
}

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

long int glibc_option (const char * opt)
{
    char cfg[CONFIG_MAX];

    if (strcmp_static(opt, "heap_size")) {
        ssize_t ret = get_config(root_config, "glibc.heap_size", cfg, CONFIG_MAX);
        if (ret <= 0) {
            debug("no glibc option: %s (err=%d)\n", opt, ret);
            return -ENOENT;
        }

        long int heap_size = parse_int(cfg);
        debug("glibc option: heap_size = %ld\n", heap_size);
        return (long int) heap_size;
    }

    return -EINVAL;
}

void * migrated_memory_start;
void * migrated_memory_end;
void * migrated_shim_addr;

void * initial_stack;
const char ** initial_envp __attribute_migratable;

char ** library_paths;

LOCKTYPE __master_lock;
bool lock_enabled;

void init_tcb (shim_tcb_t * tcb)
{
    tcb->canary = SHIM_TLS_CANARY;
    tcb->self = tcb;
}

void copy_tcb (shim_tcb_t * new_tcb, const shim_tcb_t * old_tcb)
{
    memset(new_tcb, 0, sizeof(shim_tcb_t));
    new_tcb->canary = SHIM_TLS_CANARY;
    new_tcb->self = new_tcb;
    new_tcb->tp   = old_tcb->tp;
    memcpy(&new_tcb->context, &old_tcb->context, sizeof(struct shim_context));
    new_tcb->tid  = old_tcb->tid;
    new_tcb->debug_buf = old_tcb->debug_buf;
}

/* This function is used to allocate tls before interpreter start running */
void allocate_tls (void * tcb_location, bool user, struct shim_thread * thread)
{
    __libc_tcb_t * tcb = tcb_location;
    assert(tcb);
    tcb->tcb = tcb;
    init_tcb(&tcb->shim_tcb);

    if (thread) {
        thread->tcb       = tcb;
        thread->user_tcb  = user;
        tcb->shim_tcb.tp  = thread;
        tcb->shim_tcb.tid = thread->tid;
    } else {
        tcb->shim_tcb.tp  = NULL;
        tcb->shim_tcb.tid = 0;
    }

    DkSegmentRegister(PAL_SEGMENT_FS, tcb);
    assert(SHIM_TLS_CHECK_CANARY());
}

void populate_tls (void * tcb_location, bool user)
{
    __libc_tcb_t * tcb = (__libc_tcb_t *) tcb_location;
    assert(tcb);
    tcb->tcb = tcb;
    copy_tcb(&tcb->shim_tcb, SHIM_GET_TLS());

    struct shim_thread * thread = (struct shim_thread *) tcb->shim_tcb.tp;
    if (thread) {
        thread->tcb = tcb;
        thread->user_tcb = user;
    }

    DkSegmentRegister(PAL_SEGMENT_FS, tcb);
    assert(SHIM_TLS_CHECK_CANARY());
}

DEFINE_PROFILE_OCCURENCE(alloc_stack, memory);
DEFINE_PROFILE_OCCURENCE(alloc_stack_count, memory);

#define STACK_FLAGS     (MAP_PRIVATE|MAP_ANONYMOUS)

void * allocate_stack (size_t size, size_t protect_size, bool user)
{
    size = ALIGN_UP(size);
    protect_size = ALIGN_UP(protect_size);

    /* preserve a non-readable, non-writeable page below the user
       stack to stop user program to clobber other vmas */
    void * stack = NULL;
    int flags = STACK_FLAGS|(user ? 0 : VMA_INTERNAL);

    if (user) {
        stack = bkeep_unmapped_heap(size + protect_size, PROT_NONE,
                                    flags, NULL, 0, "stack");

        if (!stack)
            return NULL;

        stack = (void *)
            DkVirtualMemoryAlloc(stack, size + protect_size,
                                 0, PAL_PROT_NONE);
    } else {
        stack = system_malloc(size + protect_size);
    }

    if (!stack)
        return NULL;

    ADD_PROFILE_OCCURENCE(alloc_stack, size + protect_size);
    INC_PROFILE_OCCURENCE(alloc_stack_count);

    stack += protect_size;
    DkVirtualMemoryProtect(stack, size, PAL_PROT_READ|PAL_PROT_WRITE);

    if (bkeep_mprotect(stack, size, PROT_READ|PROT_WRITE, flags) < 0)
        return NULL;

    debug("allocated stack at %p (size = %d)\n", stack, size);
    return stack;
}

int populate_user_stack (void * stack, size_t stack_size,
                         int nauxv, elf_auxv_t ** auxpp,
                         const char *** argvp, const char *** envpp)
{
    const char ** argv = *argvp, ** envp = *envpp;
    const char ** new_argv = NULL, ** new_envp = NULL;
    void * stack_bottom = stack;
    void * stack_top = stack + stack_size;

#define ALLOCATE_TOP(size)      \
    ({ if ((stack_top -= (size)) < stack_bottom) return -ENOMEM;    \
       stack_top; })

#define ALLOCATE_BOTTOM(size)   \
    ({ if ((stack_bottom += (size)) > stack_top) return -ENOMEM;    \
       stack_bottom - (size); })

    if (!argv) {
        *(const char **) ALLOCATE_BOTTOM(sizeof(const char *)) = NULL;
        goto copy_envp;
    }

    new_argv = stack_bottom;
    while (argv) {
        for (const char ** a = argv ; *a ; a++) {
            const char ** t = ALLOCATE_BOTTOM(sizeof(const char *));
            int len = strlen(*a) + 1;
            char * abuf = ALLOCATE_TOP(len);
            memcpy(abuf, *a, len);
            *t = abuf;
        }

        *((const char **) ALLOCATE_BOTTOM(sizeof(const char *))) = NULL;
copy_envp:
        if (!envp)
            break;
        new_envp = stack_bottom;
        argv = envp;
        envp = NULL;
    }

    if (!new_envp)
        *(const char **) ALLOCATE_BOTTOM(sizeof(const char *)) = NULL;

    stack_bottom = (void *) ((unsigned long) stack_bottom & ~7UL);
    *((unsigned long *) ALLOCATE_TOP(sizeof(unsigned long))) = 0;

    if (nauxv) {
        elf_auxv_t * old_auxp = *auxpp;
        *auxpp = ALLOCATE_TOP(sizeof(elf_auxv_t) * nauxv);
        if (old_auxp)
            memcpy(*auxpp, old_auxp, nauxv * sizeof(elf_auxv_t));
    }

    memmove(stack_top - (stack_bottom - stack), stack, stack_bottom - stack);
    if (new_argv)
        *argvp = (void *) new_argv + (stack_top - stack_bottom);
    if (new_envp)
        *envpp = (void *) new_envp + (stack_top - stack_bottom);
    return 0;
}

unsigned long sys_stack_size = 0;

int init_stack (const char ** argv, const char ** envp, const char *** argpp,
                int nauxv, elf_auxv_t ** auxpp)
{
    if (!sys_stack_size) {
        sys_stack_size = DEFAULT_SYS_STACK_SIZE;
        if (root_config) {
            char stack_cfg[CONFIG_MAX];
            if (get_config(root_config, "sys.stack.size", stack_cfg,
                           CONFIG_MAX) > 0)
                sys_stack_size = ALIGN_UP(parse_int(stack_cfg));
        }
    }

    struct shim_thread * cur_thread = get_cur_thread();

    if (!cur_thread || cur_thread->stack)
        return 0;

    void * stack = allocate_stack(sys_stack_size, allocsize, true);
    if (!stack)
        return -ENOMEM;

    if (initial_envp)
        envp = initial_envp;

    int ret = populate_user_stack(stack, sys_stack_size,
                                  nauxv, auxpp, &argv, &envp);
    if (ret < 0)
        return ret;

    *argpp = argv;
    initial_envp = envp;

    cur_thread->stack_top = stack + sys_stack_size;
    cur_thread->stack     = stack;
    cur_thread->stack_red = stack - allocsize;

    return 0;
}

int read_environs (const char ** envp)
{
    for (const char ** e = envp ; *e ; e++) {
        if (strpartcmp_static(*e, "LD_LIBRARY_PATH=")) {
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
                        free(paths[cnt]);
                    return -ENOMEM;
                }
                memcpy(str, s, len);
                str[len] = 0;
                paths[cnt++] = str;
                s = *next ? next + 1 : next;
            }

            paths[cnt] = NULL;
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

int init_manifest (PAL_HANDLE manifest_handle)
{
    int ret = 0;
    void * addr = NULL;
    size_t size = 0, map_size = 0;

#define MAP_FLAGS (MAP_PRIVATE|MAP_ANONYMOUS|VMA_INTERNAL)

    if (PAL_CB(manifest_preload.start)) {
        addr = PAL_CB(manifest_preload.start);
        size = PAL_CB(manifest_preload.end) - PAL_CB(manifest_preload.start);
    } else {
        PAL_STREAM_ATTR attr;
        if (!DkStreamAttributesQuerybyHandle(manifest_handle, &attr))
            return -PAL_ERRNO;

        size = attr.pending_size;
        map_size = ALIGN_UP(size);
        addr = bkeep_unmapped_any(map_size, PROT_READ, MAP_FLAGS,
                                  NULL, 0, "manifest");
        if (!addr)
            return -ENOMEM;

        void * ret_addr = DkStreamMap(manifest_handle, addr,
                                      PAL_PROT_READ, 0,
                                      ALIGN_UP(size));

        if (!ret_addr) {
            bkeep_munmap(addr, map_size, MAP_FLAGS);
            return -ENOMEM;
        } else {
            assert(addr == ret_addr);
        }
    }

    struct config_store * new_root_config = malloc(sizeof(struct config_store));
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
        sys_printf("Unable to read manifest file: %s\n", errstring);
        goto fail;
    }

    root_config = new_root_config;
    return 0;

fail:
    if (map_size) {
        DkStreamUnmap(addr, map_size);
        if (bkeep_munmap(addr, map_size, MAP_FLAGS) < 0)
            bug();
    }
    free(new_root_config);
    return ret;
}

#ifdef PROFILE
struct shim_profile profile_root;
#endif

# define FIND_ARG_COMPONENTS(cookie, argc, argv, envp, auxp)        \
    do {                                                            \
        void *_tmp = (cookie);                                      \
        (argv) = _tmp;                                              \
        _tmp += sizeof(char *) * ((argc) + 1);                      \
        (envp) = _tmp;                                              \
        for ( ; *(char **) _tmp; _tmp += sizeof(char *));           \
        (auxp) = _tmp + sizeof(char *);                             \
    } while (0)


static void * __process_auxv (elf_auxv_t * auxp)
{
    elf_auxv_t * av;

    for (av = auxp; av->a_type != AT_NULL; av++)
        switch (av->a_type) {
            default: break;
        }

    return av + 1;
}

#define FIND_LAST_STACK(stack)                          \
    do {                                                \
        /* check if exist a NULL end */                 \
        assert(*(uint64_t *) stack == 0);               \
        stack += sizeof(uint64_t);                      \
    } while (0)

#ifdef PROFILE
static void set_profile_enabled (const char ** envp)
{
    const char ** p;
    for (p = envp ; (*p) ; p++)
        if (strpartcmp_static(*p, "PROFILE_ENABLED="))
            break;
    if (!(*p))
        return;

    for (int i = 0 ; i < N_PROFILE ; i++)
         PROFILES[i].disabled = true;

    const char * str = (*p) + 16;
    bool enabled = false;
    while (*str) {
        const char * next = str;
        for ( ; (*next) && (*next) != ',' ; next++);
        if (next > str) {
            int len = next - str;
            for (int i = 0 ; i < N_PROFILE ; i++) {
                struct shim_profile * profile = &PROFILES[i];
                if (!memcmp(profile->name, str, len) && !profile->name[len]) {
                    profile->disabled = false;
                    if (profile->type == CATAGORY)
                        enabled = true;
                }
            }
        }
        str = (*next) ? next + 1 : next;
    }

    while (enabled) {
        enabled = false;
        for (int i = 0 ; i < N_PROFILE ; i++) {
            struct shim_profile * profile = &PROFILES[i];
            if (!profile->disabled || profile->root == &profile_)
                continue;
            if (!profile->root->disabled) {
                profile->disabled = false;
                if (profile->type == CATAGORY)
                    enabled = true;
            }
        }
    }

    for (int i = 0 ; i < N_PROFILE ; i++) {
        struct shim_profile * profile = &PROFILES[i];
        if (profile->type == CATAGORY || profile->disabled)
            continue;
        for (profile = profile->root ;
             profile != &profile_ && profile->disabled ;
             profile = profile->root)
            profile->disabled = false;
    }
}
#endif

static int init_newproc (struct newproc_header * hdr)
{
    BEGIN_PROFILE_INTERVAL();

    int bytes = DkStreamRead(PAL_CB(parent_process), 0,
                             sizeof(struct newproc_header), hdr,
                             NULL, 0);
    if (!bytes)
        return -PAL_ERRNO;

    SAVE_PROFILE_INTERVAL(child_wait_header);
    SAVE_PROFILE_INTERVAL_SINCE(child_receive_header, hdr->write_proc_time);
    return hdr->failure;
}

DEFINE_PROFILE_CATAGORY(pal, );
DEFINE_PROFILE_INTERVAL(pal_startup_time,               pal);
DEFINE_PROFILE_INTERVAL(pal_host_specific_startup_time, pal);
DEFINE_PROFILE_INTERVAL(pal_relocation_time,            pal);
DEFINE_PROFILE_INTERVAL(pal_linking_time,               pal);
DEFINE_PROFILE_INTERVAL(pal_manifest_loading_time,      pal);
DEFINE_PROFILE_INTERVAL(pal_allocation_time,            pal);
DEFINE_PROFILE_INTERVAL(pal_tail_startup_time,          pal);
DEFINE_PROFILE_INTERVAL(pal_child_creation_time,        pal);

DEFINE_PROFILE_CATAGORY(init, );
DEFINE_PROFILE_INTERVAL(init_randgen,               init);
DEFINE_PROFILE_INTERVAL(init_vma,                   init);
DEFINE_PROFILE_INTERVAL(init_slab,                  init);
DEFINE_PROFILE_INTERVAL(init_str_mgr,               init);
DEFINE_PROFILE_INTERVAL(init_internal_map,          init);
DEFINE_PROFILE_INTERVAL(init_fs,                    init);
DEFINE_PROFILE_INTERVAL(init_dcache,                init);
DEFINE_PROFILE_INTERVAL(init_handle,                init);
DEFINE_PROFILE_INTERVAL(read_from_checkpoint,       init);
DEFINE_PROFILE_INTERVAL(read_from_file,             init);
DEFINE_PROFILE_INTERVAL(init_newproc,               init);
DEFINE_PROFILE_INTERVAL(init_mount_root,            init);
DEFINE_PROFILE_INTERVAL(init_from_checkpoint_file,  init);
DEFINE_PROFILE_INTERVAL(restore_from_file,          init);
DEFINE_PROFILE_INTERVAL(init_manifest,              init);
DEFINE_PROFILE_INTERVAL(init_ipc,                   init);
DEFINE_PROFILE_INTERVAL(init_thread,                init);
DEFINE_PROFILE_INTERVAL(init_important_handles,     init);
DEFINE_PROFILE_INTERVAL(init_mount,                 init);
DEFINE_PROFILE_INTERVAL(init_async,                 init);
DEFINE_PROFILE_INTERVAL(init_stack,                 init);
DEFINE_PROFILE_INTERVAL(read_environs,              init);
DEFINE_PROFILE_INTERVAL(init_loader,                init);
DEFINE_PROFILE_INTERVAL(init_ipc_helper,            init);
DEFINE_PROFILE_INTERVAL(init_signal,                init);

#define CALL_INIT(func, args ...)   func(args)

#define RUN_INIT(func, ...)                                             \
    do {                                                                \
        int _err = CALL_INIT(func, ##__VA_ARGS__);                      \
        if (_err < 0) {                                                 \
            sys_printf("shim_init() in " #func " (%d)\n", _err);        \
            shim_terminate();                                           \
        }                                                               \
        SAVE_PROFILE_INTERVAL(func);                                    \
    } while (0)

extern PAL_HANDLE thread_start_event;

int shim_init (int argc, void * args, void ** return_stack)
{
    debug_handle = PAL_CB(debug_stream);
    cur_process.vmid = (IDTYPE) PAL_CB(process_id);

    /* create the initial TCB, shim can not be run without a tcb */
    __libc_tcb_t tcb;
    memset(&tcb, 0, sizeof(__libc_tcb_t));
    allocate_tls(&tcb, false, NULL);
    __disable_preempt(&tcb.shim_tcb); // Temporarily disable preemption for delaying any signal
                                      // that arrives during initialization
    debug_setbuf(&tcb.shim_tcb, true);
    debug("set tcb to %p\n", &tcb);

#ifdef PROFILE
    unsigned long begin_time = GET_PROFILE_INTERVAL();
#endif

    debug("host: %s\n", PAL_CB(host_type));

    DkSetExceptionHandler(&handle_failure, PAL_EVENT_FAILURE, 0);

    allocsize = PAL_CB(alloc_align);
    allocshift = allocsize - 1;
    allocmask = ~allocshift;

    create_lock(__master_lock);

    const char ** argv, ** envp, ** argp = NULL;
    elf_auxv_t * auxp;

    /* call to figure out where the arguments are */
    FIND_ARG_COMPONENTS(args, argc, argv, envp, auxp);
    initial_stack = __process_auxv(auxp);
    int nauxv = (elf_auxv_t *) initial_stack - auxp;
    FIND_LAST_STACK(initial_stack);

#ifdef PROFILE
    set_profile_enabled(envp);
#endif

    struct newproc_header hdr;
    void * cpaddr = NULL;
#ifdef PROFILE
    unsigned long begin_create_time = 0;
#endif

    BEGIN_PROFILE_INTERVAL();
    RUN_INIT(init_randgen);
    RUN_INIT(init_vma);
    RUN_INIT(init_slab);
    RUN_INIT(read_environs, envp);
    RUN_INIT(init_str_mgr);
    RUN_INIT(init_internal_map);
    RUN_INIT(init_fs);
    RUN_INIT(init_dcache);
    RUN_INIT(init_handle);

    debug("shim loaded at %p, ready to initialize\n", &__load_address);

    if (argc && argv[0][0] == '-') {
        if (strcmp_static(argv[0], "-resume") && argc >= 2) {
            const char * filename = *(argv + 1);
            argc -= 2;
            argv += 2;
            RUN_INIT(init_mount_root);
            RUN_INIT(init_from_checkpoint_file, filename, &hdr.checkpoint,
                     &cpaddr);
            goto restore;
        }
    }

    if (PAL_CB(parent_process)) {
        RUN_INIT(init_newproc, &hdr);
        SAVE_PROFILE_INTERVAL_SET(child_created_in_new_process,
                                  hdr.create_time, begin_time);
#ifdef PROFILE
        begin_create_time = hdr.begin_create_time;
#endif

        if (hdr.checkpoint.hdr.size)
            RUN_INIT(do_migration, &hdr.checkpoint, &cpaddr);
    }

    if (cpaddr) {
restore:
        thread_start_event = DkNotificationEventCreate(PAL_FALSE);
        RUN_INIT(restore_checkpoint,
                 &hdr.checkpoint.hdr, &hdr.checkpoint.mem,
                 (ptr_t) cpaddr, 0);
    }

    if (PAL_CB(manifest_handle))
        RUN_INIT(init_manifest, PAL_CB(manifest_handle));

    RUN_INIT(init_mount_root);
    RUN_INIT(init_ipc);
    RUN_INIT(init_thread);
    RUN_INIT(init_mount);
    RUN_INIT(init_important_handles);
    RUN_INIT(init_async);
    RUN_INIT(init_stack, argv, envp, &argp, nauxv, &auxp);
    RUN_INIT(init_loader);
    RUN_INIT(init_ipc_helper);
    RUN_INIT(init_signal);

    if (PAL_CB(parent_process)) {
        /* Notify the parent process */
        struct newproc_response res;
        res.child_vmid = cur_process.vmid;
        res.failure = 0;
        if (!DkStreamWrite(PAL_CB(parent_process), 0,
                           sizeof(struct newproc_response),
                           &res, NULL))
            return -PAL_ERRNO;
    }

    debug("shim process initialized\n");

#ifdef PROFILE
    if (begin_create_time)
        SAVE_PROFILE_INTERVAL_SINCE(child_total_migration_time,
                                    begin_create_time);
#endif

    SAVE_PROFILE_INTERVAL_SET(pal_startup_time, 0, pal_control.startup_time);
    SAVE_PROFILE_INTERVAL_SET(pal_host_specific_startup_time, 0,
                              pal_control.host_specific_startup_time);
    SAVE_PROFILE_INTERVAL_SET(pal_relocation_time, 0,
                              pal_control.relocation_time);
    SAVE_PROFILE_INTERVAL_SET(pal_linking_time, 0, pal_control.linking_time);
    SAVE_PROFILE_INTERVAL_SET(pal_manifest_loading_time, 0,
                              pal_control.manifest_loading_time);
    SAVE_PROFILE_INTERVAL_SET(pal_allocation_time, 0,
                              pal_control.allocation_time);
    SAVE_PROFILE_INTERVAL_SET(pal_tail_startup_time, 0,
                              pal_control.tail_startup_time);
    SAVE_PROFILE_INTERVAL_SET(pal_child_creation_time, 0,
                              pal_control.child_creation_time);

    if (thread_start_event)
        DkEventSet(thread_start_event);

    shim_tcb_t * cur_tcb = SHIM_GET_TLS();
    struct shim_thread * cur_thread = (struct shim_thread *) cur_tcb->tp;

    if (cur_tcb->context.sp)
        restore_context(&cur_tcb->context);

    if (cur_thread->exec)
        execute_elf_object(cur_thread->exec,
                           argc, argp, nauxv, auxp);

    *return_stack = initial_stack;
    return 0;
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

static int name_pipe (char * uri, size_t size, void * id)
{
    IDTYPE pipeid;
    int len;
    getrand(&pipeid, sizeof(pipeid));
    debug("creating pipe: pipe.srv:%u\n", pipeid);
    if ((len = snprintf(uri, size, "pipe.srv:%u", pipeid)) == size)
        return -ERANGE;
    *((IDTYPE *) id) = pipeid;
    return len;
}

static int open_pipe (const char * uri, void * obj)
{
    PAL_HANDLE pipe = DkStreamOpen(uri, 0, 0, 0, 0);
    if (!pipe)
        return PAL_NATIVE_ERRNO == PAL_ERROR_STREAMEXIST ? 1 :
            -PAL_ERRNO;
    if (obj)
        *((PAL_HANDLE *) obj) = pipe;
    else
        DkObjectClose(pipe);
    return 0;
}

static int pipe_addr (char * uri, size_t size, const void * id,
                      struct shim_qstr * qstr)
{
    IDTYPE pipeid = *((IDTYPE *) id);
    int len;
    if ((len = snprintf(uri, size, "pipe:%u", pipeid)) == size)
        return -ERANGE;
    if (qstr)
        qstrsetstr(qstr, uri, len);
    return len;
}

int create_pipe (IDTYPE * id, char * uri, size_t size, PAL_HANDLE * hdl,
                 struct shim_qstr * qstr)
{
    IDTYPE pipeid;
    int ret = create_unique(&name_pipe, &open_pipe, &pipe_addr,
                            uri, size, &pipeid, hdl, qstr);
    if (ret > 0 && id)
        *id = pipeid;
    return ret;
}

static int name_path (char * path, size_t size, void * id)
{
    unsigned int suffix;
    int prefix_len = strlen(path);
    int len;
    getrand(&suffix, sizeof(suffix));
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

    if (strpartcmp_static(uri, "dev:"))
        hdl = DkStreamOpen(uri, 0,
                           PAL_SHARE_OWNER_X|PAL_SHARE_OWNER_W|
                           PAL_SHARE_OWNER_R,
                           PAL_CREAT_TRY|PAL_CREAT_ALWAYS,
                           0);
    else
        hdl = DkStreamOpen(uri, PAL_ACCESS_RDWR,
                           PAL_SHARE_OWNER_W|PAL_SHARE_OWNER_R,
                           PAL_CREAT_TRY|PAL_CREAT_ALWAYS,
                           0);

    if (!hdl) {
        if (PAL_NATIVE_ERRNO == PAL_ERROR_STREAMEXIST)
            return 0;
        else
            return -PAL_ERRNO;
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
    int len = strlen(path);
    if (qstr)
        qstrsetstr(qstr, path, len);
    return len;
}

int create_dir (const char * prefix, char * path, size_t size,
                struct shim_handle ** hdl)
{
    unsigned int suffix;

    if (prefix) {
        int len = strlen(prefix);
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
        int len = strlen(prefix);
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
        int len = strlen(prefix);
        if (len >= size)
            return -ERANGE;
        memcpy(uri, prefix, len + 1);
    }

    return create_unique(&name_path, &open_pal_handle, &output_path, uri, size,
                         id ? : &suffix, hdl, NULL);
}

void check_stack_hook (void)
{
    struct shim_thread * cur_thread = get_cur_thread();

    void * rsp;
    asm volatile ("movq %%rsp, %0" : "=r"(rsp) :: "memory");

    if (rsp <= cur_thread->stack_top && rsp > cur_thread->stack) {
        if (rsp - cur_thread->stack < PAL_CB(pagesize))
            sys_printf("*** stack is almost drained (RSP = %p, stack = %p-%p) ***\n",
                       rsp, cur_thread->stack, cur_thread->stack_top);
    } else {
        sys_printf("*** context dismatched with thread stack (RSP = %p, stack = %p-%p) ***\n",
                   rsp, cur_thread->stack, cur_thread->stack_top);
    }
}

#ifdef PROFILE
static void print_profile_result (PAL_HANDLE hdl, struct shim_profile * root,
                                  int level)
{
    unsigned long total_interval_time = 0;
    unsigned long total_interval_count = 0;
    for (int i = 0 ; i < N_PROFILE ; i++) {
        struct shim_profile * profile = &PROFILES[i];
        if (profile->root != root || profile->disabled)
            continue;
        switch (profile->type) {
            case OCCURENCE: {
                unsigned int count =
                    atomic_read(&profile->val.occurence.count);
                if (count) {
                    for (int j = 0 ; j < level ; j++)
                        __sys_fprintf(hdl, "  ");
                    __sys_fprintf(hdl, "- %s: %u times\n", profile->name, count);
                }
                break;
            }
            case INTERVAL: {
                unsigned int count =
                    atomic_read(&profile->val.interval.count);
                if (count) {
                    unsigned long time =
                        atomic_read(&profile->val.interval.time);
                    unsigned long ind_time = time / count;
                    total_interval_time += time;
                    total_interval_count += count;
                    for (int j = 0 ; j < level ; j++)
                        __sys_fprintf(hdl, "  ");
                    __sys_fprintf(hdl, "- (%11.11lu) %s: %u times, %lu msec\n",
                                  time, profile->name, count, ind_time);
                }
                break;
            }
            case CATAGORY:
                for (int j = 0 ; j < level ; j++)
                    __sys_fprintf(hdl, "  ");
                __sys_fprintf(hdl, "- %s:\n", profile->name);
                print_profile_result(hdl, profile, level + 1);
                break;
        }
    }
    if (total_interval_count) {
        __sys_fprintf(hdl, "                - (%11.11u) total: %u times, %lu msec\n",
                      total_interval_time, total_interval_count,
                      total_interval_time / total_interval_count);
    }
}
#endif /* PROFILE */

static struct atomic_int in_terminate = { .counter = 0, };

int shim_terminate (void)
{
    debug("teminating the whole process\n");

    /* do last clean-up of the process */
    shim_clean();

    DkProcessExit(0);
    return 0;
}

int shim_clean (void)
{
    /* preventing multiple cleanup, this is mostly caused by
       assertion in shim_clean */
    atomic_inc(&in_terminate);
    if (atomic_read(&in_terminate) > 1)
        return 0;

    store_all_msg_persist();

#ifdef PROFILE
    if (ENTER_TIME) {
        switch (SHIM_GET_TLS()->context.syscall_nr) {
            case __NR_exit_group:
                SAVE_PROFILE_INTERVAL_SINCE(syscall_exit_group, ENTER_TIME);
                break;
            case __NR_exit:
                SAVE_PROFILE_INTERVAL_SINCE(syscall_exit, ENTER_TIME);
                break;
        }
    }

    if (ipc_cld_profile_send()) {
        master_lock();

        PAL_HANDLE hdl = __open_shim_stdio();

        if (hdl) {
            __sys_fprintf(hdl, "******************************\n");
            __sys_fprintf(hdl, "profiling:\n");
            print_profile_result(hdl, &profile_root, 0);
            __sys_fprintf(hdl, "******************************\n");
        }

        master_unlock();
        DkObjectClose(hdl);
    }
#endif

    del_all_ipc_ports(0);

    if (shim_stdio && shim_stdio != (PAL_HANDLE) -1)
        DkObjectClose(shim_stdio);

    shim_stdio = NULL;
    debug("process %u exited with status %d\n", cur_process.vmid & 0xFFFF, cur_process.exit_code);
    master_lock();
    DkProcessExit(cur_process.exit_code);
    return 0;
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

    master_lock();

    PAL_HANDLE hdl = __open_shim_stdio();
    if (!hdl) {
        master_unlock();
        return -EACCES;
    }

#define WRITE(buf, len)                                             \
    ({  int _ret = DkStreamWrite(hdl, 0, len, (void *) buf, NULL);  \
        _ret ? : -PAL_ERRNO; })

#define READ(buf, len)                                              \
    ({  int _ret = DkStreamRead(hdl, 0, len, buf, NULL, 0);         \
        _ret ? : -PAL_ERRNO; })

    if ((ret = WRITE(message, strlen(message))) < 0)
        goto out;
    if ((ret = WRITE(option_str, noptions * 2 + 3)) < 0)
        goto out;
    if ((ret = READ(&answer, 1)) < 0)
        goto out;

out:
    DkObjectClose(hdl);
    master_unlock();
    return (ret < 0) ? ret : answer;
}

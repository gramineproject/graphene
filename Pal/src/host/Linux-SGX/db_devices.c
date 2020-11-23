/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */
/* Copyright (C) 2020 Intel Labs */

/*
 * Operations to handle devices (with special case of "dev:tty" which is stdin/stdout).
 *
 * TODO: Some devices allow lseek() but typically with device-specific semantics. Graphene currently
 *       emulates lseek() completely in LibOS layer, thus seeking at PAL layer cannot be correctly
 *       implemented (without device-specific changes to LibOS layer).
 */

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_flags_conv.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_error.h"
#include "toml.h"

static int dev_open(PAL_HANDLE* handle, const char* type, const char* uri, int access, int share,
                    int create, int options) {
    int ret;
    __UNUSED(share);
    __UNUSED(create);
    __UNUSED(options);

    if (strcmp(type, URI_TYPE_DEV))
        return -PAL_ERROR_INVAL;

    assert(WITHIN_MASK(access,  PAL_ACCESS_MASK));
    assert(WITHIN_MASK(share,   PAL_SHARE_MASK));
    assert(WITHIN_MASK(create,  PAL_CREATE_MASK));
    assert(WITHIN_MASK(options, PAL_OPTION_MASK));

    PAL_HANDLE hdl = malloc(HANDLE_SIZE(dev));
    if (!hdl)
        return -PAL_ERROR_NOMEM;

    SET_HANDLE_TYPE(hdl, dev);

    if (!strcmp(uri, "tty")) {
        /* special case of "dev:tty" device which is the standard input + standard output */
        hdl->dev.nonblocking = PAL_FALSE;

        if (access & PAL_ACCESS_RDWR) {
            ret = -PAL_ERROR_INVAL;
            goto fail;
        } else if (access & PAL_ACCESS_WRONLY) {
            HANDLE_HDR(hdl)->flags |= WFD(0);
            hdl->dev.fd = 1; /* host stdout */
        } else {
            HANDLE_HDR(hdl)->flags |= RFD(0);
            hdl->dev.fd = 0; /* host stdin */
        }
    } else {
        /* other devices must be opened through the host */
        hdl->dev.nonblocking = (options & PAL_OPTION_NONBLOCK) ? PAL_TRUE : PAL_FALSE;

        ret = ocall_open(uri, PAL_ACCESS_TO_LINUX_OPEN(access)  |
                              PAL_CREATE_TO_LINUX_OPEN(create)  |
                              PAL_OPTION_TO_LINUX_OPEN(options),
                         share);
        if (IS_ERR(ret)) {
            ret = unix_to_pal_error(ERRNO(ret));
            goto fail;
        }
        hdl->dev.fd = ret;

        if (access & PAL_ACCESS_RDWR) {
            HANDLE_HDR(hdl)->flags |= RFD(0) | WFD(0);
        } else if (access & PAL_ACCESS_WRONLY) {
            HANDLE_HDR(hdl)->flags |= WFD(0);
        } else {
            HANDLE_HDR(hdl)->flags |= RFD(0);
        }
    }

    *handle = hdl;
    return 0;
fail:
    free(hdl);
    return ret;
}

static int64_t dev_read(PAL_HANDLE handle, uint64_t offset, uint64_t size, void* buffer) {
    if (offset || !IS_HANDLE_TYPE(handle, dev))
        return -PAL_ERROR_INVAL;

    if (!(HANDLE_HDR(handle)->flags & RFD(0)))
        return -PAL_ERROR_DENIED;

    if (handle->dev.fd == PAL_IDX_POISON)
        return -PAL_ERROR_DENIED;

    ssize_t bytes = ocall_read(handle->dev.fd, buffer, size);
    return IS_ERR(bytes) ? unix_to_pal_error(ERRNO(bytes)) : bytes;
}

static int64_t dev_write(PAL_HANDLE handle, uint64_t offset, uint64_t size, const void* buffer) {
    if (offset || !IS_HANDLE_TYPE(handle, dev))
        return -PAL_ERROR_INVAL;

    if (!(HANDLE_HDR(handle)->flags & WFD(0)))
        return -PAL_ERROR_DENIED;

    if (handle->dev.fd == PAL_IDX_POISON)
        return -PAL_ERROR_DENIED;

    ssize_t bytes = ocall_write(handle->dev.fd, buffer, size);
    return IS_ERR(bytes) ? unix_to_pal_error(ERRNO(bytes)) : bytes;
}

static int dev_map(PAL_HANDLE handle, void** addr, int prot, uint64_t offset, uint64_t size) {
    if (!IS_HANDLE_TYPE(handle, dev))
        return -PAL_ERROR_INVAL;

    if (handle->dev.fd == PAL_IDX_POISON)
        return -PAL_ERROR_DENIED;

    assert(WITHIN_MASK(prot, PAL_PROT_MASK));

    int ret = ocall_mmap_untrusted(handle->dev.fd, offset, size, PAL_PROT_TO_LINUX(prot), addr);
    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : ret;
}

static int dev_close(PAL_HANDLE handle) {
    if (!IS_HANDLE_TYPE(handle, dev))
        return -PAL_ERROR_INVAL;

    /* Currently we just assign `0` or `1` without duplicating, so close is a no-op. */
    handle->dev.fd = PAL_IDX_POISON;
    return 0;
}

static int dev_flush(PAL_HANDLE handle) {
    if (!IS_HANDLE_TYPE(handle, dev))
        return -PAL_ERROR_INVAL;

    if (handle->dev.fd != PAL_IDX_POISON) {
        int ret = ocall_fsync(handle->dev.fd);
        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));
    }
    return 0;
}

static int dev_attrquery(const char* type, const char* uri, PAL_STREAM_ATTR* attr) {
    __UNUSED(uri);

    if (strcmp(type, URI_TYPE_DEV))
        return -PAL_ERROR_INVAL;

    if (!strcmp(uri, "tty")) {
        /* special case of "dev:tty" device which is the standard input + standard output */
        attr->readable     = PAL_TRUE; /* we don't know if it's stdin/stdout so simply return true */
        attr->writable     = PAL_TRUE; /* we don't know if it's stdin/stdout so simply return true */
        attr->runnable     = PAL_FALSE;
        attr->share_flags  = 0;
        attr->pending_size = 0;
    } else {
        /* other devices must query the host */
        int fd = ocall_open(uri, 0, 0);
        if (IS_ERR(fd))
            return unix_to_pal_error(ERRNO(fd));

        struct stat stat_buf;
        int ret = ocall_fstat(fd, &stat_buf);
        if (IS_ERR(ret)) {
            ocall_close(fd);
            return unix_to_pal_error(ERRNO(ret));
        }

        attr->readable     = stataccess(&stat_buf, ACCESS_R);
        attr->writable     = stataccess(&stat_buf, ACCESS_W);
        attr->runnable     = stataccess(&stat_buf, ACCESS_X);
        attr->share_flags  = stat_buf.st_mode;
        attr->pending_size = stat_buf.st_size;

        ocall_close(fd);
    }

    attr->handle_type  = pal_type_dev;
    attr->nonblocking  = PAL_FALSE;
    return 0;
}

static int dev_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    if (!IS_HANDLE_TYPE(handle, dev))
        return -PAL_ERROR_INVAL;

    if (handle->dev.fd == 0 || handle->dev.fd == 1) {
        /* special case of "dev:tty" device which is the standard input + standard output */
        attr->readable     = HANDLE_HDR(handle)->flags & RFD(0);
        attr->writable     = HANDLE_HDR(handle)->flags & WFD(0);
        attr->runnable     = PAL_FALSE;
        attr->share_flags  = 0;
        attr->pending_size = 0;
    } else {
        /* other devices must query the host */
        struct stat stat_buf;
        int ret = ocall_fstat(handle->dev.fd, &stat_buf);
        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));

        attr->readable     = stataccess(&stat_buf, ACCESS_R);
        attr->writable     = stataccess(&stat_buf, ACCESS_W);
        attr->runnable     = stataccess(&stat_buf, ACCESS_X);
        attr->share_flags  = stat_buf.st_mode;
        attr->pending_size = stat_buf.st_size;
    }

    attr->handle_type  = pal_type_dev;
    attr->nonblocking  = handle->dev.nonblocking;
    return 0;
}

struct handle_ops g_dev_ops = {
    .open           = &dev_open,
    .read           = &dev_read,
    .write          = &dev_write,
    .map            = &dev_map,
    .close          = &dev_close,
    .flush          = &dev_flush,
    .attrquery      = &dev_attrquery,
    .attrquerybyhdl = &dev_attrquerybyhdl,
};

/*
 * Code below describes the deep-copy syntax in the TOML manifest used for copying complex nested
 * objects out and in the SGX enclave. This syntax is currently used for IOCTL emulation. This
 * syntax is generic enough to describe any memory layout for deep copy.
 *
 * The following example describes the main implementation details:
 *
 *   struct pascal_str { uint8_t len; char str[]; };
 *   struct c_str { char str[]; };
 *   struct root { struct pascal_str* s1; struct c_str* s2; uint64_t s2_len; int8_t x; int8_t y; };
 *
 *   alignas(128) struct root obj;
 *   ioctl(devfd, _IOWR(DEVICE_MAGIC, DEVICE_FUNC, struct root), &obj);
 *
 * The example IOCTL takes as a third argument a pointer to an object of type `struct root` that
 * contains two pointers to other objects (pascal-style string and a C-style string) and embeds two
 * integers `x` and `y`. The two strings reside in separate memory regions in enclave memory. Note
 * that the length of the C-style string is stored in the `s2_len` field of the root object. The
 * `pascal_str` string is an input to the IOCTL, the `c_str` string is both input and output of the
 * IOCTL, and the integers `x` and `y` are both outputs of the IOCTL. Also note that the root
 * object is 128B-aligned (for illustration purposes).
 *
 * The corresponding deep-copy syntax in TOML looks like this:
 *
 *   sgx.ioctl.DEVICE_FUNC.struct = [
 *     { align = 128, ptr = [ {name="pascal-str-len", size=1, type="out"},
 *                            {name="pascal-str", size="pascal-str-len", type="out"} ] },
 *     { ptr = [ {name="c-str", size="c-str-len", type="inout"} ] },
 *     { name = "c-str-len", size = 8, type = "in" },
 *     { size = 2, type = "in" }
 *   ]
 *
 * One can observe the following rules in this TOML syntax:
 * 1. Each separate memory region is represented as a TOML array (`[]`).
 * 2. Each sub-region of one memory region is represented as a TOML table (`{}`).
 * 3. Each sub-region may be a pointer (`ptr`) to another memory region. In this case, the value of
 *    `ptr` is a TOML-array representation of that other memory region. The `ptr` sub-region always
 *    has size of 8B (assuming x86-64) and doesn't have an in/out type.
 * 4. Sub-regions can be fixed-size (like the last sub-region containing two bytes `x` and `y`) or
 *    can be flexible-size (like the two strings). In the latter case, the `size` field contains a
 *    name of a sub-region where the actual size is stored.
 * 5. Sub-regions that store the size of another sub-region must be 1, 2, 4, or 8 bytes in size.
 * 6. Sub-regions may have a name for ease of identification; this is required for "size"
 *    sub-regions but may be omitted for all other kinds of sub-regions.
 * 7. Sub-regions may have one of the three types: "out" to copy contents of the sub-region outside
 *    the enclave to untrusted memory, "in" to copy from untrusted memory to inside the enclave,
 *    "inout" to copy in both directions. Note that pointer sub-regions do not have a type.
 * 8. The first sub-region (and only the first!) may specify the alignment of the memory region.
 *
 * The diagram below shows how this complex object is copied from enclave memory (left side) to
 * untrusted memory (right side). MR stands for "memory region", SR stands for "sub-region". Note
 * how enclave pointers are copied and rewired to point to untrusted memory regions.
 *
 *       struct root (MR1)            |       deep-copied struct (aligned at 128B)
 *      +------------------+          |     +------------------------+
 *  +----+ pascal_str* s1  |     SR1  |  +----+ pascal_str* s1  (MR1)|
 *  |   |                  |          |  |  |                        |
 *  |   |  c_str* s2 +-------+   SR2  |  |  |   c_str* s2 +-------------+
 *  |   |                  | |        |  |  |                        |  |
 *  |   |  uint64_t s2_len | |   SR3  |  |  |   uint64_t s2_len      |  |
 *  |   |                  | |        |  |  |                        |  |
 *  |   |  int8_t x, y     | |   SR4  |  |  |   int8_t x=0, y=0      |  |
 *  |   +------------------+ |        |  |  +------------------------+  |
 *  |                        |        |  +->|   uint8_t len     (MR2)|  |
 *  v (MR2)                  |        |     |                        |  |
 * +-------------+           |        |     |   char str[]           |  |
 * | uint8_t len |           |   SR5  |     +------------------------+  |
 * |             |           |        |     |   char str[]      (MR3)|<-+
 * | char str[]  |           |   SR6  |     +------------------------+
 * +-------------+           |        |
 *                  (MR3)    v        |
 *                +----------+-+      |
 *                | char str[] | SR7  |
 *                +------------+      |
 *
 */

/* for simplicity and thread-safety, we allocate mem_regions and sub_regions on stack; we assume
 * that deep copy of objects doesn't exceed the specified limits of memory and sub regions */
#define MAX_MEM_REGIONS 16
#define MAX_SUB_REGIONS 64

/* direction of copy: out of enclave, inside enclave, both, or a special "pointer" sub-region;
 * default is COPY_OUT_ENCLAVE */
enum mem_copy_type {COPY_OUT_ENCLAVE = 0, COPY_IN_ENCLAVE, COPY_INOUT_ENCLAVE, COPY_PTR_ENCLAVE};

struct mem_region {
    toml_array_t* toml_array; /* describes contigious sub_regions in this mem_region */
    void* encl_addr;          /* base address of this memory region in enclave memory */
};

struct sub_region {
    enum mem_copy_type type; /* direction of copy during OCALL (or pointer to another region) */
    char* name;              /* may be NULL for unnamed regions */
    ssize_t align;           /* alignment of this sub-region */
    ssize_t size;            /* may be dynamically determined from another sub-region */
    void* encl_addr;         /* base address of this sub region in enclave memory */
    void* untrusted_addr;    /* base address of the corresponding sub region in untrusted memory */
};

/* caller sets `_sub_regions_cnt` to maximum number of sub_regions; this variable is updated to
 * return the number of actually used sub_regions */
static int collect_sub_regions(toml_array_t* root_toml_array, void* root_encl_addr,
                               struct sub_region* sub_regions, int* _sub_regions_cnt) {
    int ret;

    assert(root_toml_array && toml_array_nelem(root_toml_array) > 0);
    assert(sub_regions && _sub_regions_cnt);

    int max_sub_regions = *_sub_regions_cnt;
    int sub_regions_cnt = 0;

    for (int i = 0; i < max_sub_regions; i++) {
        sub_regions[i].align = 0;
        sub_regions[i].size = 0;
        sub_regions[i].name = NULL;
        sub_regions[i].encl_addr = NULL;
        sub_regions[i].untrusted_addr = NULL;
    }

    struct mem_region mem_regions[MAX_MEM_REGIONS] = {0};
    mem_regions[0].toml_array = root_toml_array;
    mem_regions[0].encl_addr  = root_encl_addr;
    int mem_regions_cnt = 1;

    /* collecting memory regions and their sub-regions must use breadth-first search to dynamically
     * calculate sizes of sub-regions even if they are specified via another sub-region's "name" */
    int mem_region_idx = 0;
    while (mem_region_idx < mem_regions_cnt) {
        struct mem_region* cur_mem_region = &mem_regions[mem_region_idx];
        mem_region_idx++;

        char* cur_encl_addr = cur_mem_region->encl_addr; /* char* type for pointer arithmetic */

        for (int i = 0; i < toml_array_nelem(cur_mem_region->toml_array); i++) {
            toml_table_t* sub_region_info = toml_table_at(cur_mem_region->toml_array, i);
            if (!sub_region_info) {
                SGX_DBG(DBG_E, "Invalid deep-copy syntax (each memory subregion must be a TOML "
                               "table)\n");
                ret = -EINVAL;
                goto out;
            }

            if (sub_regions_cnt == max_sub_regions) {
                SGX_DBG(DBG_E, "Too many memory sub-regions in a deep-copy syntax (maximum "
                               "possible is %d)\n", max_sub_regions);
                ret = -ENOMEM;
                goto out;
            }

            struct sub_region* cur_sub_region = &sub_regions[sub_regions_cnt];
            sub_regions_cnt++;

            cur_sub_region->encl_addr = cur_encl_addr;

            toml_raw_t sub_region_name_raw   = toml_raw_in(sub_region_info, "name");
            toml_raw_t sub_region_type_raw   = toml_raw_in(sub_region_info, "type");
            toml_raw_t sub_region_align_raw  = toml_raw_in(sub_region_info, "align");
            toml_raw_t sub_region_size_raw   = toml_raw_in(sub_region_info, "size");
            toml_array_t* sub_region_ptr_arr = toml_array_in(sub_region_info, "ptr");

            if (sub_region_align_raw && i != 0) {
                SGX_DBG(DBG_E, "Invalid deep-copy syntax (\'align\' may be specified only for the "
                               "first sub-region of the memory region)\n");
                ret = -EINVAL;
                goto out;
            }

            if (sub_region_size_raw && sub_region_ptr_arr) {
                SGX_DBG(DBG_E, "Invalid deep-copy syntax (deep-copy sub-entries can specify "
                               "either \'size\' or \'ptr\' but not both)\n");
                ret = -EINVAL;
                goto out;
            }

            if (sub_region_type_raw && sub_region_ptr_arr) {
                SGX_DBG(DBG_E, "Invalid deep-copy syntax (\'ptr\' sub-entries cannot specify "
                               "a \'type\'; pointers are never copied directly but rewired)\n");
                ret = -EINVAL;
                goto out;
            }

            cur_sub_region->name = NULL;
            if (sub_region_name_raw) {
                ret = toml_rtos(sub_region_name_raw, &cur_sub_region->name);
                if (ret < 0) {
                    SGX_DBG(DBG_E, "Invalid deep-copy syntax (\'name\' of a deep-copy sub-entry "
                                    "must be a TOML string surrounded by double quotes)\n");
                    ret = -EINVAL;
                    goto out;
                }
            }

            cur_sub_region->type = COPY_OUT_ENCLAVE;
            if (sub_region_type_raw) {
                char* type_str = NULL;
                ret = toml_rtos(sub_region_type_raw, &type_str);
                if (ret < 0) {
                    SGX_DBG(DBG_E, "Invalid deep-copy syntax (\'type\' of a deep-copy sub-entry "
                                    "must be a TOML string surrounded by double quotes)\n");
                    ret = -EINVAL;
                    goto out;
                }

                if (!strcmp(type_str, "out")) {
                    cur_sub_region->type = COPY_OUT_ENCLAVE;
                }
                else if (!strcmp(type_str, "in")) {
                    cur_sub_region->type = COPY_IN_ENCLAVE;
                }
                else if (!strcmp(type_str, "inout")) {
                    cur_sub_region->type = COPY_INOUT_ENCLAVE;
                }
                else {
                    SGX_DBG(DBG_E, "Invalid deep-copy syntax (\'type\' of a deep-copy sub-entry "
                                    "must be one of \"out\", \"in\", \"inout\")\n");
                    ret = -EINVAL;
                    goto out;
                }
            }

            cur_sub_region->align = 0;
            if (sub_region_align_raw) {
                ret = toml_rtoi(sub_region_align_raw, &cur_sub_region->align);
                if (ret < 0 || cur_sub_region->align <= 0) {
                    SGX_DBG(DBG_E, "Invalid deep-copy syntax (\'align\' of a deep-copy sub-entry "
                                   "must be a positive number)\n");
                    ret = -EINVAL;
                    goto out;
                }
            }

            cur_sub_region->size = 0;
            if (sub_region_size_raw) {
                char* size_name = NULL;
                ret = toml_rtos(sub_region_size_raw, &size_name);
                if (ret == 0) {
                    for (int j = 0; j < sub_regions_cnt - 1; j++) { /* -1 to exclude myself */
                        if (sub_regions[j].name && !strcmp(sub_regions[j].name, size_name)) {
                            /* found a matching sub-region: read size value from it */
                            if (sub_regions[j].size == sizeof(uint8_t)) {
                                uint8_t sz = 0;
                                memcpy(&sz, sub_regions[j].encl_addr, sub_regions[j].size);
                                cur_sub_region->size = (ssize_t)sz;
                            } else if (sub_regions[j].size == sizeof(uint16_t)) {
                                uint16_t sz = 0;
                                memcpy(&sz, sub_regions[j].encl_addr, sub_regions[j].size);
                                cur_sub_region->size = (ssize_t)sz;
                            } else if (sub_regions[j].size == sizeof(uint32_t)) {
                                uint32_t sz = 0;
                                memcpy(&sz, sub_regions[j].encl_addr, sub_regions[j].size);
                                cur_sub_region->size = (ssize_t)sz;
                            } else if (sub_regions[j].size == sizeof(uint64_t)) {
                                uint64_t sz = 0;
                                memcpy(&sz, sub_regions[j].encl_addr, sub_regions[j].size);
                                cur_sub_region->size = (ssize_t)sz;
                            } else {
                                SGX_DBG(DBG_E, "Invalid deep-copy syntax (deep-copy sub-entry "
                                               "\'%s\' must be a legitimate size field)\n",
                                               sub_regions[j].name);
                                free(size_name);
                                ret = -EINVAL;
                                goto out;
                            }
                            break;
                        }
                    }
                    free(size_name);

                    if (cur_sub_region->size == 0) {
                        SGX_DBG(DBG_E, "Invalid deep-copy syntax (\'size\' of a deep-copy "
                                       "sub-entry doesn't refer to any other sub-entry)\n");
                        ret = -EINVAL;
                        goto out;
                    }
                } else {
                    /* size is specified not as string (another sub-region's name), then must be
                     * specified explicitly as number of bytes */
                    ret = toml_rtoi(sub_region_size_raw, &cur_sub_region->size);
                    if (ret < 0 || cur_sub_region->size <= 0) {
                        SGX_DBG(DBG_E, "Invalid deep-copy syntax (\'size\' of a deep-copy "
                                       "sub-entry must be a TOML string or a positive number)\n");
                        ret = -EINVAL;
                        goto out;
                    }
                }
            }

            if (sub_region_ptr_arr) {
                if (mem_regions_cnt == MAX_MEM_REGIONS) {
                    SGX_DBG(DBG_E, "Too many memory regions in a deep-copy syntax (maximum "
                                   "possible is %d)\n", MAX_MEM_REGIONS);
                    ret = -ENOMEM;
                    goto out;
                }

                cur_sub_region->type = COPY_PTR_ENCLAVE;
                cur_sub_region->size = sizeof(void*);

                mem_regions[mem_regions_cnt].toml_array = sub_region_ptr_arr;
                mem_regions[mem_regions_cnt].encl_addr  = *((void**)cur_encl_addr);
                mem_regions_cnt++;
            }

            assert(cur_sub_region->size > 0);
            cur_encl_addr += cur_sub_region->size;
        }
    }

    *_sub_regions_cnt = sub_regions_cnt;
    ret = 0;
out:
    for (int i = 0; i < max_sub_regions; i++) {
        /* "name" field is not needed after we collected all sub_regions */
        free(sub_regions[i].name);
        sub_regions[i].name = NULL;
    }
    return ret;
}

static void copy_sub_regions_to_untrusted(struct sub_region* sub_regions, int sub_regions_cnt,
                                         void* untrusted_addr) {
    char* cur_untrusted_addr = untrusted_addr; /* char* type for pointer arithmetic */
    for (int i = 0; i < sub_regions_cnt; i++) {
        if (sub_regions[i].align > 0)
            cur_untrusted_addr = ALIGN_UP_PTR(cur_untrusted_addr, sub_regions[i].align);

        sub_regions[i].untrusted_addr = cur_untrusted_addr;
        if (sub_regions[i].type == COPY_OUT_ENCLAVE || sub_regions[i].type == COPY_INOUT_ENCLAVE)
            memcpy(cur_untrusted_addr, sub_regions[i].encl_addr, sub_regions[i].size);
        cur_untrusted_addr += sub_regions[i].size;
    }

    for (int i = 0; i < sub_regions_cnt; i++) {
        if (sub_regions[i].type == COPY_PTR_ENCLAVE) {
            void* encl_ptr_value = *((void**)sub_regions[i].encl_addr);
            /* rewire pointer value in untrusted memory to a corresponding untrusted sub-region */
            for (int j = 0; j < sub_regions_cnt; j++) {
                if (sub_regions[j].encl_addr == encl_ptr_value) {
                    *((void**)sub_regions[i].untrusted_addr) = sub_regions[j].untrusted_addr;
                    break;
                }
            }
        }
    }
}

static void copy_sub_regions_to_enclave(struct sub_region* sub_regions, int sub_regions_cnt) {
    for (int i = 0; i < sub_regions_cnt; i++) {
        if (sub_regions[i].type == COPY_IN_ENCLAVE || sub_regions[i].type == COPY_INOUT_ENCLAVE)
            memcpy(sub_regions[i].encl_addr, sub_regions[i].untrusted_addr, sub_regions[i].size);
    }
}

int _DkDeviceIoControl(PAL_HANDLE handle, unsigned int cmd, uint64_t arg) {
    int ret;

    if (!IS_HANDLE_TYPE(handle, dev))
        return -PAL_ERROR_INVAL;

    if (handle->dev.fd == PAL_IDX_POISON)
        return -PAL_ERROR_DENIED;

    toml_table_t* manifest_sgx = toml_table_in(g_pal_state.manifest_root, "sgx");
    if (!manifest_sgx)
        return -PAL_ERROR_NOTIMPLEMENTED;

    toml_table_t* toml_allowed_ioctls = toml_table_in(manifest_sgx, "allowed_ioctls");
    if (!toml_allowed_ioctls)
        return -PAL_ERROR_NOTIMPLEMENTED;

    ssize_t toml_allowed_ioctls_cnt = toml_table_ntab(toml_allowed_ioctls);
    if (toml_allowed_ioctls_cnt <= 0)
        return -PAL_ERROR_NOTIMPLEMENTED;

    for (ssize_t i = 0; i < toml_allowed_ioctls_cnt; i++) {
        const char* toml_allowed_ioctl_key = toml_key_in(toml_allowed_ioctls, i);
        assert(toml_allowed_ioctl_key);

        toml_table_t* toml_ioctl_table = toml_table_in(toml_allowed_ioctls, toml_allowed_ioctl_key);
        if (!toml_ioctl_table)
            continue;

        toml_raw_t toml_ioctl_request_raw = toml_raw_in(toml_ioctl_table, "request");
        if (!toml_ioctl_request_raw)
            continue;

        int64_t ioctl_request = 0x0;
        ret = toml_rtoi(toml_ioctl_request_raw, &ioctl_request);
        if (ret < 0 || ioctl_request == 0x0) {
            SGX_DBG(DBG_E, "Invalid request value of allowed ioctl \'%s\' in manifest\n",
                    toml_allowed_ioctl_key);
            continue;
        }

        if (ioctl_request == (int64_t)cmd) {
            /* found this IOCTL request in the manifest */
            toml_array_t* toml_ioctl_struct = toml_array_in(toml_ioctl_table, "struct");
            if (!toml_ioctl_struct) {
                SGX_DBG(DBG_E, "Invalid struct format of allowed ioctl \'%s\' in manifest\n"
                               "(sgx.allowed_ioctls.[name].struct must be a TOML array)\n",
                               toml_allowed_ioctl_key);
                return -PAL_ERROR_INVAL;
            }

            if (toml_array_nelem(toml_ioctl_struct) == 0) {
                /* special case of an empty TOML array == base-type or ignored IOCTL argument */
                ret = ocall_ioctl(handle->dev.fd, cmd, arg);
                return ret < 0 ? unix_to_pal_error(ERRNO(ret)) : 0;
            }

            /* typical case of used IOCTL argument: deep-copy the IOCTL argument's input data
             * outside of enclave, execute the IOCTL OCALL, and deep-copy the IOCTL argument's
             * output data back into enclave */
            struct sub_region sub_regions[MAX_SUB_REGIONS];
            int sub_regions_cnt = MAX_SUB_REGIONS;
            ret = collect_sub_regions(toml_ioctl_struct, (void*)arg, sub_regions, &sub_regions_cnt);
            if (ret < 0) {
                SGX_DBG(DBG_E, "Invalid struct format of allowed ioctl \'%s\' in manifest\n",
                               toml_allowed_ioctl_key);
                return -PAL_ERROR_INVAL;
            }

            void* untrusted_addr  = NULL;
            size_t untrusted_size = 0;
            for (int i = 0; i < sub_regions_cnt; i++) {
                assert(sub_regions[i].size > 0);
                untrusted_size += sub_regions[i].size + sub_regions[i].align;
            }

            ret = ocall_mmap_untrusted(/*fd=*/-1, /*offset=*/0, untrusted_size,
                                       PROT_READ | PROT_WRITE, &untrusted_addr);
            if (ret < 0) {
                return -PAL_ERROR_NOMEM;
            }

            copy_sub_regions_to_untrusted(sub_regions, sub_regions_cnt, untrusted_addr);

            ret = ocall_ioctl(handle->dev.fd, cmd, (uint64_t)untrusted_addr);
            if (ret < 0) {
                ocall_munmap_untrusted(untrusted_addr, untrusted_size);
                return unix_to_pal_error(ERRNO(ret));
            }

            copy_sub_regions_to_enclave(sub_regions, sub_regions_cnt);
            ocall_munmap_untrusted(untrusted_addr, untrusted_size);
            return 0;
        }
    }

    return -PAL_ERROR_NOTIMPLEMENTED;
}

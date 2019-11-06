#include "api.h"
#include "pal.h"
#include "pal_debug.h"

#define NUM_TO_HEX(num) ((num) >= 10 ? 'a' + ((num) - 10) : '0' + (num))

static __attribute__((noinline)) void print_hex(char* fmt, const void* data, int len) {
    char* buf    = __alloca(len * 2 + 1);
    buf[len * 2] = '\0';
    for (int i = 0; i < len; i++) {
        unsigned char b = ((unsigned char*)data)[i];
        buf[i * 2]      = NUM_TO_HEX(b >> 4);
        buf[i * 2 + 1]  = NUM_TO_HEX(b & 0xf);
    }
    pal_printf(fmt, buf);
}

int main(int argc, char** argv, char** envp) {
    char buffer1[40], buffer2[40], buffer3[40];
    int ret;

    /* test regular file opening */

    PAL_HANDLE file1 = DkStreamOpen("file:File", PAL_ACCESS_RDWR, 0, 0, 0);
    if (file1) {
        pal_printf("File Open Test 1 OK\n");

        /* test file read */

        ret = DkStreamRead(file1, 0, 40, buffer1, NULL, 0);
        if (ret > 0) {
            buffer1[ret] = 0;
            print_hex("Read Test 1 (0th - 40th): %s\n", buffer1, 40);
        }

        ret = DkStreamRead(file1, 0, 40, buffer1, NULL, 0);
        if (ret > 0) {
            buffer1[ret] = 0;
            print_hex("Read Test 2 (0th - 40th): %s\n", buffer1, 40);
        }

        ret = DkStreamRead(file1, 200, 40, buffer2, NULL, 0);
        if (ret > 0) {
            buffer2[ret] = 0;
            print_hex("Read Test 3 (200th - 240th): %s\n", buffer2, 40);
        }

        /* test file attribute query */

        PAL_STREAM_ATTR attr1;
        if (DkStreamAttributesQueryByHandle(file1, &attr1))
            pal_printf("Query by Handle: type = %d, size = %ld\n", attr1.handle_type,
                       attr1.pending_size);

        /* test file map */

        void* mem1 = (void*)DkStreamMap(file1, NULL, PAL_PROT_READ | PAL_PROT_WRITECOPY, 0, 4096);
        if (mem1) {
            memcpy(buffer1, mem1, 40);
            print_hex("Map Test 1 (0th - 40th): %s\n", buffer1, 40);

            memcpy(buffer2, mem1 + 200, 40);
            print_hex("Map Test 2 (200th - 240th): %s\n", buffer2, 40);

            DkStreamUnmap(mem1, 4096);
        } else {
            pal_printf("Map Test 1 & 2: Failed to map buffer\n");
        }

        /* DEP 11/24/17: For SGX writecopy exercises a different path in the PAL */
        void* mem2 =
            (void*)DkStreamMap(file1, NULL, PAL_PROT_READ | PAL_PROT_WRITECOPY, 4096, 4096);
        if (mem2) {
            memcpy(buffer3, mem2, 40);
            print_hex("Map Test 3 (4096th - 4136th): %s\n", buffer3, 40);

            memcpy(buffer3, mem2 + 200, 40);
            print_hex("Map Test 4 (4296th - 4336th): %s\n", buffer3, 40);

            DkStreamUnmap(mem2, 4096);
        }

        DkObjectClose(file1);
    }

    PAL_HANDLE file2 = DkStreamOpen("file:File", PAL_ACCESS_RDWR, 0, 0, 0);
    if (file2) {
        pal_printf("File Open Test 2 OK\n");
        DkObjectClose(file2);
    }

    PAL_HANDLE file3 = DkStreamOpen("file:../regression/File", PAL_ACCESS_RDWR, 0, 0, 0);
    if (file3) {
        pal_printf("File Open Test 3 OK\n");
        DkObjectClose(file3);
    }

    PAL_STREAM_ATTR attr2;
    if (DkStreamAttributesQuery("file:File", &attr2))
        pal_printf("Query: type = %d, size = %ld\n", attr2.handle_type, attr2.pending_size);

    /* test regular file creation */

    PAL_HANDLE file4 =
        DkStreamOpen("file:file_nonexist.tmp", PAL_ACCESS_RDWR,
                     PAL_SHARE_OWNER_R | PAL_SHARE_OWNER_W, PAL_CREATE_TRY | PAL_CREATE_ALWAYS, 0);
    if (file4)
        pal_printf("File Creation Test 1 OK\n");

    PAL_HANDLE file5 =
        DkStreamOpen("file:file_nonexist.tmp", PAL_ACCESS_RDWR,
                     PAL_SHARE_OWNER_R | PAL_SHARE_OWNER_W, PAL_CREATE_TRY | PAL_CREATE_ALWAYS, 0);
    if (file5) {
        DkObjectClose(file5);
    } else {
        pal_printf("File Creation Test 2 OK\n");
    }

    PAL_HANDLE file6 = DkStreamOpen("file:file_nonexist.tmp", PAL_ACCESS_RDWR,
                                    PAL_SHARE_OWNER_R | PAL_SHARE_OWNER_W, PAL_CREATE_TRY, 0);
    if (file6) {
        pal_printf("File Creation Test 3 OK\n");
        DkObjectClose(file6);
    }

    file6 =
        DkStreamOpen("file:file_nonexist_disallowed.tmp", PAL_ACCESS_RDWR,
                     PAL_SHARE_OWNER_R | PAL_SHARE_OWNER_W, PAL_CREATE_TRY | PAL_CREATE_ALWAYS, 0);
    if (!file6) {
        pal_printf("File Creation Test 4 OK\n");
    } else {
        DkObjectClose(file6);
    }

    if (file4) {
        /* test file writing */

        ret = DkStreamWrite(file4, 0, 40, buffer1, NULL);
        if (ret < 0)
            goto fail_writing;

        ret = DkStreamWrite(file4, 0, 40, buffer2, NULL);
        if (ret < 0)
            goto fail_writing;

        ret = DkStreamWrite(file4, 200, 40, buffer1, NULL);
        if (ret < 0)
            goto fail_writing;

        /* test file truncate */
        DkStreamSetLength(file4, pal_control.alloc_align);

    fail_writing:
        DkObjectClose(file4);
    }

    PAL_HANDLE file7 = DkStreamOpen("file:file_delete.tmp", PAL_ACCESS_RDONLY, 0, 0, 0);
    if (file7) {
        DkStreamDelete(file7, 0);
        DkObjectClose(file7);
    }

    return 0;
}

/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include "pal.h"
#include "pal_debug.h"
#include "api.h"

int main (int argc, char ** argv, char ** envp)
{
    char buffer1[41], buffer2[41];
    int ret;

    /* test regular file opening */

    PAL_HANDLE file1 = DkStreamOpen("file:file_exist.tmp",
                                    PAL_ACCESS_RDWR, 0, 0, 0);
    if (file1) {
        pal_printf("File Open Test 1 OK\n");

        /* test file read */

        ret = DkStreamRead(file1, 0, 40, buffer1, NULL, 0);
        if (ret > 0) {
            buffer1[ret] = 0;
            pal_printf("Read Test 1 (0th - 40th): %s\n", buffer1);
        }

        ret = DkStreamRead(file1, 0, 40, buffer1, NULL, 0);
        if (ret > 0) {
            buffer1[ret] = 0;
            pal_printf("Read Test 2 (0th - 40th): %s\n", buffer1);
        }

        ret = DkStreamRead(file1, 200, 40, buffer2, NULL, 0);
        if (ret > 0) {
            buffer2[ret] = 0;
            pal_printf("Read Test 3 (200th - 240th): %s\n", buffer2);
        }

        /* test file attribute query */

        PAL_STREAM_ATTR attr1;
        if (DkStreamAttributesQuerybyHandle(file1, &attr1))
            pal_printf("Query by Handle: type = %d, size = %d\n",
                       attr1.handle_type, attr1.pending_size);

        /* test file map */

        void * mem1 = (void *) DkStreamMap(file1, NULL, PAL_PROT_READ, 0,
                                           attr1.pending_size);
        if (mem1) {
            memcpy(buffer1, mem1, 40);
            buffer1[40] = 0;
            pal_printf("Map Test 1 (0th - 40th): %s\n", buffer1);

            memcpy(buffer2, mem1 + 200, 40);
            buffer2[40] = 0;
            pal_printf("Map Test 2 (200th - 240th): %s\n", buffer2);

            DkStreamUnmap(mem1, attr1.pending_size);
        }

        DkObjectClose(file1);
    }

    PAL_HANDLE file2 = DkStreamOpen("file:./file_exist.tmp",
                                    PAL_ACCESS_RDWR, 0, 0, 0);
    if (file2) {
        pal_printf("File Open Test 2 OK\n");
        DkObjectClose(file2);
    }

    PAL_HANDLE file3 = DkStreamOpen("file:../regression/file_exist.tmp",
                                    PAL_ACCESS_RDWR, 0, 0, 0);
    if (file3) {
        pal_printf("File Open Test 3 OK\n");
        DkObjectClose(file3);
    }

    PAL_STREAM_ATTR attr2;
    if (DkStreamAttributesQuery("file:file_exist.tmp", &attr2))
        pal_printf("Query: type = %d, size = %d\n",
                   attr2.handle_type, attr2.pending_size);

    /* test regular file creation */

    PAL_HANDLE file4 = DkStreamOpen("file:file_nonexist.tmp",
                                    PAL_ACCESS_RDWR,
                                    PAL_SHARE_OWNER_R|PAL_SHARE_OWNER_W,
                                    PAL_CREAT_TRY|PAL_CREAT_ALWAYS, 0);
    if (file4)
        pal_printf("File Creation Test 1 OK\n");


    PAL_HANDLE file5 = DkStreamOpen("file:file_nonexist.tmp",
                                    PAL_ACCESS_RDWR,
                                    PAL_SHARE_OWNER_R|PAL_SHARE_OWNER_W,
                                    PAL_CREAT_TRY|PAL_CREAT_ALWAYS, 0);
    if (file5) {
        DkObjectClose(file5);
    } else {
        pal_printf("File Creation Test 2 OK\n");
    }

    PAL_HANDLE file6 = DkStreamOpen("file:file_nonexist.tmp",
                                    PAL_ACCESS_RDWR,
                                    PAL_SHARE_OWNER_R|PAL_SHARE_OWNER_W,
                                    PAL_CREAT_TRY, 0);
    if (file6) {
        pal_printf("File Creation Test 3 OK\n");
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

    PAL_HANDLE file7 = DkStreamOpen("file:file_delete.tmp",
                                    PAL_ACCESS_RDONLY, 0, 0, 0);
    if (file7) {
        DkStreamDelete(file7, 0);
        DkObjectClose(file7);
    }

    return 0;
}

#include "api.h"
#include "pal.h"
#include "pal_debug.h"

int main(int argc, char** argv, char** envp) {
    /* test regular directory opening */

    PAL_HANDLE dir1 = DkStreamOpen("dir:dir_exist.tmp", PAL_ACCESS_RDONLY, 0, 0, 0);
    if (dir1) {
        pal_printf("Directory Open Test 1 OK\n");

        PAL_STREAM_ATTR attr1;
        if (DkStreamAttributesQueryByHandle(dir1, &attr1))
            pal_printf("Query by Handle: type = %d\n", attr1.handle_type);

        char buffer[80];
        int bytes = DkStreamRead(dir1, 0, 80, buffer, NULL, 0);
        if (bytes) {
            for (char* c = buffer; c < buffer + bytes; c += strlen(c) + 1)
                if (strlen(c))
                    pal_printf("Read Directory: %s\n", c);
        }

        DkObjectClose(dir1);
    }

    PAL_HANDLE dir2 = DkStreamOpen("dir:./dir_exist.tmp", PAL_ACCESS_RDONLY, 0, 0, 0);
    if (dir2) {
        pal_printf("Directory Open Test 2 OK\n");
        DkObjectClose(dir2);
    }

    PAL_HANDLE dir3 = DkStreamOpen("dir:../regression/dir_exist.tmp", PAL_ACCESS_RDONLY, 0, 0, 0);
    if (dir3) {
        pal_printf("Directory Open Test 3 OK\n");
        DkObjectClose(dir3);
    }

    PAL_STREAM_ATTR attr2;
    if (DkStreamAttributesQuery("dir:dir_exist.tmp", &attr2))
        pal_printf("Query: type = %d\n", attr2.handle_type);

    /* test regular directory creation */

    PAL_HANDLE dir4 = DkStreamOpen("dir:dir_nonexist.tmp", PAL_ACCESS_RDONLY,
                                   PAL_SHARE_OWNER_R | PAL_SHARE_OWNER_W | PAL_SHARE_OWNER_X,
                                   PAL_CREATE_TRY | PAL_CREATE_ALWAYS, 0);
    if (dir4) {
        pal_printf("Directory Creation Test 1 OK\n");
        DkObjectClose(dir4);
    }

    PAL_HANDLE dir5 = DkStreamOpen("dir:dir_nonexist.tmp", PAL_ACCESS_RDONLY,
                                   PAL_SHARE_OWNER_R | PAL_SHARE_OWNER_W | PAL_SHARE_OWNER_X,
                                   PAL_CREATE_TRY | PAL_CREATE_ALWAYS, 0);
    if (dir5) {
        DkObjectClose(dir5);
    } else {
        pal_printf("Directory Creation Test 2 OK\n");
    }

    PAL_HANDLE dir6 = DkStreamOpen("dir:dir_nonexist.tmp", PAL_ACCESS_RDWR,
                                   PAL_SHARE_OWNER_R | PAL_SHARE_OWNER_W, PAL_CREATE_TRY, 0);
    if (dir6) {
        pal_printf("Directory Creation Test 3 OK\n");
        DkObjectClose(dir6);
    }

    PAL_HANDLE dir7 = DkStreamOpen("dir:dir_delete.tmp", PAL_ACCESS_RDONLY, 0, 0, 0);
    if (dir7) {
        DkStreamDelete(dir7, 0);
        DkObjectClose(dir7);
    }

    return 0;
}

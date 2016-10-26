/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>

#define TEST_LENGTH 0x10000f000

int main() {
    FILE*fp=fopen("testfil","a+");
    if (!fp) { perror("fopen"); return 1; }
    int rv = ftruncate(fileno(fp), TEST_LENGTH);
    if (rv) {perror ("ftruncate"); return 1;}
    else 
        printf("large-mmap: ftruncate OK\n");

    void* a=mmap(NULL, TEST_LENGTH, PROT_READ|PROT_WRITE, MAP_SHARED, fileno(fp), 0);
    if (!a) { perror("mmap"); return 1; }
    ((char*)a)[0x100000000]=0xff;
    printf("large-mmap: test completed OK\n");
    return 0;
}

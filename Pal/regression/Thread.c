/* This Hello World demostrate a simple multithread program */
#include "pal.h"
#include "pal_debug.h"

void* private1 = "Hello World 1";
void* private2 = "Hello World 2";

static volatile int count1 = 0;

int callback1(void* args) {
    pal_printf("Run in Child Thread: %s\n", (char*)args);

    while (count1 < 10) {
        while (!(count1 % 2)) {
            DkThreadYieldExecution();
        }
        count1++;
        __asm__ volatile("nop" ::: "memory");
    }

    pal_printf("Threads Run in Parallel OK\n");

    DkSegmentRegister(PAL_SEGMENT_FS, &private2);
    const char* ptr2;
    __asm__ volatile("mov %%fs:0, %0" : "=r"(ptr2)::"memory");
    pal_printf("Private Message (FS Segment) 2: %s\n", ptr2);

    count1 = 100;
    __asm__ volatile("nop" ::: "memory");
    DkThreadExit(/*clear_child_tid=*/NULL);
    count1 = 101;
    __asm__ volatile("nop" ::: "memory");

    return 0;
}

int main(int argc, const char** argv, const char** envp) {
    DkSegmentRegister(PAL_SEGMENT_FS, &private1);
    const char* ptr1;
    __asm__ volatile("mov %%fs:0, %0" : "=r"(ptr1)::"memory");
    pal_printf("Private Message (FS Segment) 1: %s\n", ptr1);

    PAL_HANDLE thread1 = DkThreadCreate(callback1, "Hello World");

    if (thread1) {
        pal_printf("Child Thread Created\n");

        while (count1 < 10) {
            while (!!(count1 % 2)) {
                DkThreadYieldExecution();
            }
            count1++;
            __asm__ volatile("nop" ::: "memory");
        }

        while (count1 < 100) {
            DkThreadYieldExecution();
        }
        for (int i = 0; i < 500; i++) {
            DkThreadYieldExecution();
        }

        __asm__ volatile("nop" ::: "memory");
        if (count1 == 100)
            pal_printf("Child Thread Exited\n");
    }

    return 0;
}

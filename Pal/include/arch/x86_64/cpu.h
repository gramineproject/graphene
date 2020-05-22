#ifndef CPU_H
#define CPU_H

static inline void cpu_pause(void) {
    __asm__ volatile("pause");
}

#endif /* CPU_H */
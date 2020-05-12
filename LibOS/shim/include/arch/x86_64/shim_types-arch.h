#ifndef _SHIM_TYPES_ARCH_H_
#define _SHIM_TYPES_ARCH_H_

/* sys/ucontext.h */
/* Type for general register.  */
typedef long int greg_t;

/* Number of general registers.  */
#define NGREG    23

/* Container for all general registers.  */
typedef greg_t gregset_t[NGREG];

/* Number of each register in the `gregset_t' array.  */
enum
{
    REG_R8 = 0,
# define REG_R8     REG_R8
    REG_R9,
# define REG_R9     REG_R9
    REG_R10,
# define REG_R10    REG_R10
    REG_R11,
# define REG_R11    REG_R11
    REG_R12,
# define REG_R12    REG_R12
    REG_R13,
# define REG_R13    REG_R13
    REG_R14,
# define REG_R14    REG_R14
    REG_R15,
# define REG_R15    REG_R15
    REG_RDI,
# define REG_RDI    REG_RDI
    REG_RSI,
# define REG_RSI    REG_RSI
    REG_RBP,
# define REG_RBP    REG_RBP
    REG_RBX,
# define REG_RBX    REG_RBX
    REG_RDX,
# define REG_RDX    REG_RDX
    REG_RAX,
# define REG_RAX    REG_RAX
    REG_RCX,
# define REG_RCX    REG_RCX
    REG_RSP,
# define REG_RSP    REG_RSP
    REG_RIP,
# define REG_RIP    REG_RIP
    REG_EFL,
# define REG_EFL    REG_EFL
    REG_CSGSFS,        /* Actually short cs, gs, fs, __pad0.  */
# define REG_CSGSFS REG_CSGSFS
    REG_ERR,
# define REG_ERR    REG_ERR
    REG_TRAPNO,
# define REG_TRAPNO REG_TRAPNO
    REG_OLDMASK,
# define REG_OLDMASK REG_OLDMASK
    REG_CR2
# define REG_CR2    REG_CR2
};

struct _libc_fpxreg {
    unsigned short int significand[4];
    unsigned short int exponent;
    unsigned short int padding[3];
};

struct _libc_xmmreg {
    __uint32_t    element[4];
};

struct _libc_fpstate {
    /* 64-bit FXSAVE format.  */
    __uint16_t          cwd;
    __uint16_t          swd;
    __uint16_t          ftw;
    __uint16_t          fop;
    __uint64_t          rip;
    __uint64_t          rdp;
    __uint32_t          mxcsr;
    __uint32_t          mxcr_mask;
    struct _libc_fpxreg st[8];
    struct _libc_xmmreg _xmm[16];
    __uint32_t          padding[24];
};

/* Structure to describe FPU registers.  */
typedef struct _libc_fpstate *fpregset_t;

/* Context to describe whole processor state.  */
typedef struct {
    gregset_t gregs;
    /* Note that fpregs is a pointer.  */
    fpregset_t fpregs;
    unsigned long __reserved1 [8];
} mcontext_t;

/* Userlevel context.  */
typedef struct ucontext {
    unsigned long int uc_flags;
    struct ucontext* uc_link;
    stack_t uc_stack;
    mcontext_t uc_mcontext;
    __sigset_t uc_sigmask;
    struct _libc_fpstate __fpregs_mem;
} ucontext_t;

#define RED_ZONE_SIZE   128

#endif /* _SHIM_TYPES_ARCH_H_ */

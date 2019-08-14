# Implementing New System Calls
### Step 1: Define the interface of system call and name the implementing function in `LibOS/shim/src/shim_syscalls.c`.

For example, assume we are implementing `sched_setaffinity`, find the definition of `sched_setaffinity` in `shim_syscalls.c`, which will be the following code:

```
SHIM_SYSCALL_PASSTHROUGH (sched_setaffinity, 3, int, pid_t, pid, size_t, len,
                          __kernel_cpu_set_t *, user_mask_ptr)
```

Now, change this line to `DEFINE_SHIM_SYSCALL(...)` to name the function that implements this system call. For example, we can call this function `shim_do_sched_setaffinity` (**this is the naming convention, please follow it**).

```
DEFINE_SHIM_SYSCALL (sched_setaffinity, 3, shim_do_sched_setaffinity, int, pid_t, pid, size_t, len,
                     __kernel_cpu_set_t *, user_mask_ptr)
```


### Step 2: Add the definitions to `LibOS/shim/include/shim_table.h`

To implement system call `sched_setaffinity`, three functions need to be defined in `shim_table.h`: `__shim_sched_setaffinity`, `shim_sched_setaffinity`, and `shim_do_sched_setaffinity`. The first two should already be defined. Add the third in respect to the system call you are implementing, with the same prototype as defined in `shim_syscalls.c`.

```
int shim_do_sched_setaffinity (pid_t pid, size_t len, __kernel_cpu_set_t * user_mask_ptr);
``` 

### Step 3: Implement the system call in a source file under `LibOS/shim/src/sys`.

You can add the function body of `shim_do_sysinfo` (or the function name defined earlier) in a new source file or any existing source file in `LibOS/shim/src/sys`.

For example, in `LibOS/shim/src/sys/shim_sched.c`:
```
int shim_do_sched_setaffinity (pid_t pid, size_t len, __kernel_cpu_set_t * user_mask_ptr) {
   /* Write the code for implementing the semantic of sched_setaffinity. */
}
```

### Step 4 (Optional): Add a new PAL call if it is necessary for the system call.

The concept of Graphene library OS is to keep the PAL interface as simple as possible. So, you should not add new PAL calls if the features can be fully implemented inside the library OS using the existing PAL calls. However, sometimes, the OS features needed involve low-level operations inside the host operating systems and cannot be emulated inside the library OS. Therefore, you may have to add a few new PAL calls to be supplementary to the existing interface.

To add a new PAL call, first modify `Pal/src/pal.h`. Define the PAL call **in a platform-independent way**.

```
PAL_BOL DkThreadSetCPUAffinity (PAL_NUM cpu_num, PAL_IDX * cpu_indexes);
```

Make sure you use the PAL-specific data types, including `PAL_BOL`, `PAL_NUM`, `PAL_PTR`, `PAL_FLG`, `PAL_IDX`, and `PAL_STR`. The naming convention of a PAL call starts with a `DK`, followed by a comprehensive name describing the purpose of the PAL call.

### Step 5 (Optional): Export the new PAL call in the PAL binaries.

For each directory in `PAL/host/`, there is a `pal.map` file. This file lists all the symbols accessible to the library OS. The new PAL call needs to be listed here in order to be used for your system call implementation.

### Step 6 (Optional): Implementing the new PAL call in `PAL/src`.





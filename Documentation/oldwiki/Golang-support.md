# Golang support

This page is intended to track efforts for golang support.
If you're looking for how to use it, please refer to TBD.

## Goal
Support golang binary without modification with graphene(-SGX).
Here golang binary means one created by gc toolchain. Not gccgo, not go-llvm nor other implementations.
The target user is normal go developer who has already binary. We'd like tell them, bring your binary as is.

## Summary
| categoary | item | status | PRs/Issues |
|-----------|------|--------|------------|
|Static binary |trap-and-emulate syscall instruction | merged |  |
|              | %gs for PAL/LibOS tls | | https://github.com/oscarlab/graphene/pull/555 https://github.com/oscarlab/graphene/pull/556 https://github.com/oscarlab/graphene/pull/601 |
|              |binary patch    | |  |
|              |dedicated stack for LibOS | | |
| signal emulation | nested signal| discussion on-going. respin PR |https://github.com/oscarlab/graphene/issues/348 https://github.com/oscarlab/graphene/pull/347 |
|                  | sigaltstack | | |
| host signal handling | fp registers to PAL_CONTEXT | | https://github.com/oscarlab/graphene/pull/397 |
|                      | PAL/Linux-SGX dedicated stack for host signal | RFC:code needs to be improved| https://github.com/oscarlab/graphene/pull/632 |
|                      | multiple signal(PAL, LibOS) | | |
|                      | Pal/Linux-SGX ocall and signal | | |
| syscall/instruction emulation | rdtsc |  |https://github.com/oscarlab/graphene/pull/424 |
|                               | probably more to come | | |
| test | regression test for golang | | |
|      | regression test for static binary | | | |
| misc | vDSO | | https://github.com/oscarlab/graphene/pull/318 https://github.com/oscarlab/graphene/pull/319 |
|      | stack protector     | |  https://github.com/oscarlab/graphene/pull/774 | 

## Challenges with golang binary
There are several challenges with go binary.
### no libc and static link
golang doesn't use libc. But it has its own runtime library written in go(self hosting). glibc modification doesn't help.
golang prefers static link and go runtime is always statically linked. (recent go support dynamic link to use shared library. CGO. However go runtime is always statically linked) So the trick to replace shared library isn't usable.
Current graphene uses modified shared glibc to hook system call instruction for function call.
### goroutine with small stack size and signal stack
small memory(e.g. 2KB) is assigned to goroutine on start and stack size is increased on demand.
sigaltstack is used due to small stack size and for stability. Currently sigaltstack isn't supported. It would be an issue for graphene to directly invoking user signal handler within LibOS. It may cause SEGV due to stack overflow.

## Issues and proposed solutions

### syscall to function call of syscalldb
* trap SIGILL/SIGSYS and emulate: status: working locally. soon to send PR. This is fallback for corner cases.
* binary patch to replace syscall instruction with function call

#### binary patch
trap-and-emulate is slow. optimization for performance is needed to avoid the overhead. One way is to edit loaded text area.
Editing text area is tricky and fragile. Also it's hard to debug. There are several possible options.
We should support easiest one and make it solid and then move on to further tricks(more complex and more fragile) if necessary.
Because we have trap-and-emulate as fallback, the solutions don't have to be perfect. (at the cost of performance.)

There are two major points. How to identify syscall instruction and How to replace syscall instruction with function call.
It is observed that functions in golang runtime for system call are leaf function without referencing any symbols. a sort of simple wrapper function. It only swaps registers to adjust ABI difference between function call and Linux system call, issues syscall instruction and checks return value. (Please remember -errno trick.)
(Actually many of glibc syscall functions are so. so actually the solution discussed here could be applied to glibc.)

* replace leaf function as a whole: The assumption is that static symbol is usable. So all the symbol names of syscall functions(of given specific version of golang). So replacing functions can be prepared as a shared library and jump instruction can be put on the beginning of each symbols of the original go binary to replacing functions when target binary is loaded into memory.

* scan instruction to find syscall instruction and replace it somehow: The assumption is static symbol isn't available. This will be very tricky and bunch of heuristics. Please remember that x86-64 instruction has variable length. we have to play with instruction length. Linux paravirt ops uses padding with nop. But golang upstream won't adapt such nop trick to allocate space for text editing.   

* find syscall by SIGILL on runtime. This requires synchronization to stop all the thread, modify the text area, icache flush and resume threads. This is too complex. So for now this is out of choice.

### emulation of signal and sigaltstack
* https://github.com/oscarlab/graphene/issues/348
* https://github.com/oscarlab/graphene/pull/347

Now discussion is on-going.
Right now host signal handling of Pal/Linux-SGX seems broken. a lot of clean ups are necessary before actual sigaltstack support.

### host signal handling and PAL ABI
The stack can be very small. So the dedicated stack for signal handling is needed.
Pal/Linux uses sigaltstack. Pal/Linux-SGX has to implement something similar itself because sigaltstack isn't usable.
PAL ABI related to host signal needs to be clarified.
* stack: the current stack is used or the dedicated stack is used (sigaltstack). For stability, the dedicated stack is preferable
* FP registers: The currently only regular register is defined in PAL_CONTEXT. FP registers needs to be included and its format should be defined. We can adapt Linux format. Other platform PAL can emulate it.

### host signal handling and host job control
The question is, do we want to support host job control? to what extent?

Use case.
* C-c to kill.(SIGINT)
* C-z to suspend process and fg/bg command in shell(SIGTSTP, SIGCONT)
* C-\ coredump. SIGQUIT
* daemon scripts or systemd: to run/manage daemon process.(SIGTERM/SIGQUIT/SIGTSTP/SIGCONT/SIGHUP)
* kubernetes also uses signal to kill pods. https://jbodah.github.io/blog/2017/05/23/learning-about-kubernetes-and-unix-signals/
* SIGTTIN, SIGTTOU, SIGHUP

Feedback:
* introduce option in manifest which signal to pass through application.
* C-c is quite convenient.
* what signal systemd uses? SIGTERM, SIGKILL, SIGHUP, SIGQUIT, SIGABRT. refer to https://www.freedesktop.org/software/systemd/man/systemd.kill.html and https://www.freedesktop.org/software/systemd/man/systemd.service.html  Interesting part is systemd also looks at exit code to determine if it should restart the daemon.
* Check actual user wants to do: kubernetes/docker support is critical. So it is must-have to fill this gap. Otherwise it is NOT deployable in cloud environment.

### memory size and SGX2
golang gc runtime requires much memory. SGX2 is desired for good performance. 

## related PR's and issues
TBD

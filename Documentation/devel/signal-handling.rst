Signal Handling in Graphene
===========================

.. highlight:: text

(Disclaimer: This explanation is partially outdated. It is intended only as an internal
reference for developers of Graphene, not as a general documentation for Graphene users.)

Signal Handling
---------------

This analysis is written while Graphene's signal handling mechanisms are in flux. In future, all
Graphene PALs should implement the same mechanism, and LibOS should adopt a better scheme to
support nested signals and alternate signal stacks.

In the interest of space and mental sanity, we do not discuss FreeBSD PAL implementation.
Historically, Linux and FreeBSD shared the same mechanism (where signals were immediately delivered
to LibOS even if signal arrived during PAL call). This old mechanism was adopted by Linux-SGX PAL,
though due to peculiarities of Intel SGX, it has its own sub-flows and is more complicated.
Currently, Linux PAL implements a new mechanism where a signal during a PAL call is pended and is
delivered to LibOS only after the PAL call is finished.

So, there are two signal-handling mechanisms at the PAL layer:

* Linux PAL: (1) If signal arrives during PAL call, pend it and return from signal context,
  continuing normal context of PAL call. Immediately after a PAL call is finished, deliver all
  pending signals to LibOS. (2) If signal arrives during LibOS/application code, deliver the
  signal immediately to LibOS. Note that the signal delivery and handling is done in signal context
  (in contrast to pending-signal delivery).

* Linux-SGX PAL: (1) If signal arrives during enclave-code execution, remember the interrupted
  enclave-code context and return from signal context. When jumping back into the enclave (in normal
  context), deliver the signal to LibOS. After handling the signal, LibOS/PAL will continue from
  interrupted enclave-code context. (2) If signal arrives during non-enclave-code, i.e.
  untrusted-PAL, execution, just return from signal context. When jumping back into the enclave
  (in normal context), deliver the signal to LibOS. In contrast to first case, after handling the
  signal, LibOS/PAL will continue as if outermost PAL function failed with `PAL_ERROR_INTERRUPTED`.

The advantage of the first mechanism is that there is never a possibility of nested PAL calls
(which is not supported by Graphene). However, this also disallows nested signals already at the
PAL layer. The advantage of the second mechanism is that nested signals are possible, at least as
far as it concerns the PAL layer.

There is a single unified signal-handling mechanism at the LibOS layer. This mechanism does *not*
support nested signals: if a signal is delivered while another signal is handled (or during a LibOS
internal lock), then it is pended. Pended signals are delivered after any system-call completion
or after any LibOS internal unlock.

A new signal-handling mechanism at the LibOS layer was proposed by Isaku Yamahata
(see https://github.com/oscarlab/graphene/pull/347). This proposal changes the points at which
signals are delivered to the user app. The two points are (1) if signal arrives during app
execution, the signal is delivered after host OS returns from signal context, and (2) if signal
arrives during LibOS/PAL execution, the signal is delivered after system-call completion. This is
in contrast to current LibOS approach of (1) delivering the first signal even in the middle of
emulated syscall, and (2) pending nested signals until system-call completion.


Linux-SGX PAL Flows
^^^^^^^^^^^^^^^^^^^

Initialization of Signal Handling
"""""""""""""""""""""""""""""""""

::

   Normal context
   +----------------+

   ... load_enclave() ...
   +
   | sgx_signal_setup()
   | +
   | | set_sighandler(SIGTERM | SIGINT | SIGCONT)        +---------------+
   | | +                                                 | async signals |
   | | | action = struct sigaction(                      +---------------+
   | | |            sa_handler  = _DkTerminateSighandler,
   | | |            sa_restorer = rt_sigreturn,
   | | |            sa_flags    = {SA_SIGINFO | SA_RESTORER}
   | | |            sa_mask     = {SIGCONT}
   | | |          )
   | | |
   | | | rt_sigaction(SIGTERM, action)
   | | | rt_sigaction(SIGINT,  action)
   | | | rt_sigaction(SIGCONT, action)
   | | |
   | | + rt_sigprocmask(SIGUNBLOCK, SIGTERM | SIGINT | SIGCONT)
   | |
   | | set_sighandler(SIGSEGV | SIGILL | SIGFPE | SIGBUS) +--------------+
   | | +                                                  | sync signals |
   | | | action = struct sigaction(                       +--------------+
   | | |            sa_handler  = _DkResumeSighandler,
   | | |            sa_restorer = rt_sigreturn,
   | | |            sa_flags    = {SA_SIGINFO | SA_RESTORER}
   | | |            sa_mask     = {SIGCONT}
   | | |          )
   | | |
   | | | rt_sigaction(SIGSEGV, action)
   | | | rt_sigaction(SIGILL,  action)
   | | | rt_sigaction(SIGFPE,  action)
   | | | rt_sigaction(SIGBUS,  action)
   | | |
   + + + rt_sigprocmask(SIGUNBLOCK, SIGSEGV | SIGILL | SIGFPE | SIGBUS)

Async Signal Arrives During Enclave Code Execution
""""""""""""""""""""""""""""""""""""""""""""""""""

On the example of SIGINT, until we arrive into `_DkGenericSignalHandle()`.

::

   Normal context                                Signal context
   +----------------+                            +----------------+

   + ... enclave code .....
   |
   | +-----+
   |       | AEX due to SIGINT
   | <-----+
   |              signal handler called
   | +---------------------------------------->  _DkTerminateSighandler(SIGINT, siginfo, uc)
   |                                             +
   |                                             | sgx_raise(PAL_EVENT_SUSPEND)
   |                                             | +
   |                                             | | RDX = after_resume() addr
   |                                             | | RBX = current thread's TCS
   |                                             | | RCX = async_exit_pointer() addr
   |                                             | | RDI = PAL_EVENT_SUSPEND (from first func arg)
   |                                             | |
   |                                             | | EENTER(RBX, RCX)                            <---+
   |                                             | | +                                               |
   |                                             | | | (SGX creates new SSA frame and                |
   |                                             | | |  sets RAX = current-SSA-frame = 1)            |e
   |                                             | | |                                               |n
   |                                             | | | enclave_entry()                               |c
   |                                             | | | +                                             |l
   |                                             | | | | jump to handle_resume()                     |a
   |                                             | | | |                                             +>
   |                                             | | | | <double-check RDI contains signum >         |e
   |                                             | | | |                                             |
   |                                             | | | | jump to handle_exception()                  |m
   |                                             | | | |                                             |o
   |                                             | | | | create new enclave-thread stack frame       |d
   |                                             | | | | and push GPRSGX registers on this frame     |e
   |                                             | | | |                                             |
   |                                             | | | | update GPRSGX = (RSP = new frame,           |
   |                                             |                        RDI = PAL_EVENT_SUSPEND,   |
   |                                             | | | |                  RSI = new frame,           |
   |                                             | | | |                  RIP = _DkExceptionHandler) |
   |                                             | | | |                                             |
   |                                             | | + + EEXIT(RDX = after_resume)               <---+
   |             signal handler done             | |
   | <----------------------------------------+  + + after_resume(): return
   |
   | async_exit_pointer()
   | +
   | | ERESUME                                                                                   <---+
   | | +                                                                                             |
   | | | (SGX's current-SSA-frame = 0, thus                                                          |e
   | | |  enclave-thread's GPRSGX is loaded in regs)                                                 |n
   | | |                                                                                             |c
   | | | _DkExceptionHandler(exit_info = RDI = PAL_EVENT_SUSPEND, uc = RSI = new frame)              |l
   | | | +                                                                                           |a
   | | | | PAL_CONTEXT ctx = copy(uc)  <ctx contains interrupted-context frame>                      |v
   | | | |                                                                                           |e
   + + + + _DkGenericSignalHandle(PAL_EVENT_SUSPEND, ctx)                                            v
            < ... >

Async Signal Arrives During Non-Enclave Code Execution
""""""""""""""""""""""""""""""""""""""""""""""""""""""

Non-enclave code execution can only happen if Graphene process is currently executing untrusted-PAL
code, e.g., is blocked on a `futex(wait)` system call.

On the example of SIGINT, until we arrive into `_DkGenericSignalHandle()`.

::

   Normal context                                Signal context
   +----------------+                            +----------------+

   + ... non-enclave code ...
   |
   | +-----+
   |       | SIGINT
   | <-----+
   |              signal handler called
   | +---------------------------------------->  _DkTerminateSighandler(SIGINT, siginfo, uc)
   |                                             +
   |                                             | update normal-context registers =
   |                                             |     (RIP = sgx_entry_return,
   |                                             |      RDI = -PAL_ERROR_INTERRUPTED,
   |              signal handler done            |      RSI = PAL_EVENT_SUSPEND)
   | <----------------------------------------+  +
   |
   | sgx_entry_return()
   | +
   | | RDX = sgx_entry() addr
   | | RBX = current thread's TCS
   | | RCX = async_exit_pointer() addr
   | |
   | | EENTER(RBX, RCX)                                          <--+
   | | +                                                            |
   | | | (SGX's current-SSA-frame = 0, ocall is done)               |
   | | |                                                            |e
   | | | enclave_entry()                                            |n
   | | | +                                                          |c
   | | | | jump to return_from_ocall()                              |l
   | | | |                                                          |a
   | | | | remember RDI = -PAL_ERROR_INTERRUPTED on enclave stack   |v
   | | | |                                                          |e
   | | | | _DkHandleExternalEvent(event = RDI = PAL_EVENT_SUSPEND,  |
   | | | | +                      uc    = RSI = enclave frame)      |m
   | | | | |                                                        |o
   | | | | | frame = get_frame(uc)  <finds outermost PAL function>  |d
   | | | | |                                                        |e
   | | | | | _DkGenericSignalHandle(PAL_EVENT_SUSPEND, frame)       |
               < ... >                                              v

Sync Signal Arrives During Enclave Code Execution
"""""""""""""""""""""""""""""""""""""""""""""""""

This case is exactly the same as for async signal. The only difference in the diagram would be that
`_DkTerminateSighandler` is replaced by `_DkResumeSighandler`. But the logic is exactly the same.

Sync Signal Arrives During Non-Enclave Code Execution
"""""""""""""""""""""""""""""""""""""""""""""""""""""

Non-enclave code execution can only happen if Graphene process is currently executing untrusted-PAL
code, e.g., is blocked on a `futex(wait)` system call.

If a sync signal arrives in this case, it means that there was a memory fault, illegal instruction,
or arithmetic exception in untrusted-PAL code. This should never happen in a correct implementation
of Graphene. In this case, `_DkResumeSighandler` simply kills the faulting thread (not the whole
process!) by issuing `exit(1)` syscall.

DkGenericSignalHandle Logic
"""""""""""""""""""""""""""

::

   Normal context (enclave mode)
   +----------------------------------+

   + _DkGenericSignalHandle(PAL_EVENT_SUSPEND, frame/ctx)
   | +
   | | upcall = _DkGetExceptionHandler(PAL_EVENT_SUSPEND)
   | |        = suspend_upcall
   | |
   | | _DkGenericEventTrigger(PAL_EVENT_SUSPEND, suspend_upcall, frame/ctx)
   | | +
   | | | event = struct exception_event(event_num = PAL_EVENT_SUSPEND,
   | | |                                context   = ctx,     +--------------+
   | | |                                frame     = frame)   | only one of  |
   | | |                                                     | context/frame|
   | | | suspend_upcall(event, ctx)                          | is not NULL  |
   | | | +       +------------------------------+            +--------------+
   | | | |       | event is opaque ptr to LibOS |
   | | | |       +------------------------------+
   | | | |
   | | | | +------------------- PAL -> LibOS transition --------------------+
   | | | |
   | | | | <... LibOS signal handling ...>
   | | | |
   | | | | DkExceptionReturn(event)
   | | | | +
   | | | | | +----------------- LibOS -> PAL transition --------------------+
   | | | | |
   | | | | | _DkExceptionReturn(event)
   | | | | | +
   | | | | | | if event.frame is not NULL:
   | | | | | |   update regs with event.frame regs
   | | | | | |   return to LibOS (as if PAL function returned)
   | | | | | |
   | | | | | | if event.context is not NULL:
   | | | | | |   update regs with event.context regs (including RSP)
   | | | | | |   return to interrupted-context frame (somewhere in user app)
   + + + + + +
               < context is reset, no unwinding here! >


Linux PAL Flows
^^^^^^^^^^^^^^^

Initialization of Signal Handling
"""""""""""""""""""""""""""""""""

Very similar to the flow for Linux-SGX. In addition to 7 handled signals, Linux PAL also operates on
these signals:

* SIGCHLD -- is ignored
* SIGPIPE -- installs `_DkPipeSighandler` handler

Describing flows for these signals is *future work*.

Async Signal Arrives During PAL Call Execution
""""""""""""""""""""""""""""""""""""""""""""""

::

   Normal context                                Signal context
   +----------------+                            +----------------+

   + ... PAL code ...
   |
   | +-----+
   |       | SIGINT
   | <-----+
   |              signal handler called
   | +---------------------------------------->  _DkTerminateSighandler(SIGINT, siginfo, uc)
   |                                             +
   |                                             | < SIGINT arrived during PAL call >
   |                                             |
   |                                             | add to thread's pending events:
   |                                             |     tcb.pending_event = PAL_EVENT_SUSPEND
   |                                             |
   |              signal handler done            |     append PAL_EVENT_SUSPEND to tcb.pending_queue
   | <----------------------------------------+  +     if tcb.pending_event is already set
   |
   | ... PAL call finishes (LEAVE_PAL_CALL) ...
   |
   | __check_pending_event()
   | +
   | | _DkGenericSignalHandle(tcb.pending_event,
   | |                        siginfo_t  = NULL,
   | |                        ucontext_t = NULL)
   | |
   | | foreach event in tcb.pending_queue:
   + +     _DkGenericSignalHandle(event, NULL, NULL)

Async Signal Arrives During Non-PAL Call Execution
""""""""""""""""""""""""""""""""""""""""""""""""""

::

   Normal context                                Signal context
   +----------------+                            +----------------+

   + ... non-PAL code ...
   |
   | +-----+
   |       | SIGINT
   | <-----+
   |              signal handler called
   | +---------------------------------------->  _DkTerminateSighandler(SIGINT, siginfo, uc)
   |                                             +
   |                                             | < SIGINT arrived during app/LibOS code >
   |                                             |
   |                                             | _DkGenericSignalHandle(PAL_EVENT_SUSPEND,
   |                                             | +                      siginfo_t  = NULL,
   |                                             | |                      ucontext_t = uc)
   |                                             | |
   |                                             | | < ... >
   |              signal handler done            | |
   | <----------------------------------------+  + +
   +

Sync Signal Arrives During PAL Call Execution
"""""""""""""""""""""""""""""""""""""""""""""

::

   Normal context                                Signal context
   +----------------+                            +----------------+

   + ... PAL code ...
   |
   | +-----+
   |       | SIGILL
   | <-----+
   |              signal handler called
   | +---------------------------------------->  __DkGenericSighandler(SIGILL, siginfo, uc)
   |                                             +
   |                                             | < SIGILL arrived during PAL call >
   |                                             |
   |                                             | print panic message
   |                                             |
   |                                             | _DkThreadExit()  < kill this thread >

   ... thread is dead ...

Sync Signal Arrives During Non-PAL Call Execution
"""""""""""""""""""""""""""""""""""""""""""""""""

::

   Normal context                                Signal context
   +----------------+                            +----------------+

   + ... non-PAL code ...
   |
   | +-----+
   |       | SIGILL
   | <-----+
   |              signal handler called
   | +---------------------------------------->  __DkGenericSighandler(SIGILL, siginfo, uc)
   |                                             +
   |                                             | < SIGILL arrived during app/LibOS code >
   |                                             |
   |                                             | _DkGenericSignalHandle(PAL_EVENT_ILLEGAL,
   |                                             | +                      siginfo_t  = siginfo,
   |                                             | |                      ucontext_t = uc)
   |                                             | |
   |                                             | | < ... >
   |              signal handler done            | |
   | <----------------------------------------+  + +
   +

DkGenericSignalHandle Logic
"""""""""""""""""""""""""""

::

   Normal context (enclave mode)
   +----------------------------------+

   + _DkGenericSignalHandle(PAL_EVENT_SUSPEND, uc)
   | +
   | | upcall = _DkGetExceptionHandler(PAL_EVENT_SUSPEND)
   | |        = suspend_upcall
   | |
   | | _DkGenericEventTrigger(PAL_EVENT_SUSPEND, suspend_upcall, uc)
   | | +
   | | | event = struct exception_event(event_num = PAL_EVENT_SUSPEND,
   | | |                                context   = copy-of-uc-regs,
   | | |                                uc        = uc)
   | | |
   | | | suspend_upcall(event, ctx)
   | | | +       +------------------------------+
   | | | |       | event is opaque ptr to LibOS |
   | | | |       +------------------------------+
   | | | |
   | | | | +------------------- PAL -> LibOS transition --------------------+
   | | | |
   | | | | <... LibOS signal handling ...>
   | | | |
   | | | | DkExceptionReturn(event)
   | | | | +
   | | | | | +----------------- LibOS -> PAL transition --------------------+
   | | | | |
   | | | | | _DkExceptionReturn(event)
   | | | | | +
   | | | | | + update event.uc.regs with event.context regs
   | | | | +               +-----------------------------------------------+
   | | | +                 | unlike SGX PAL, don't jump to updated context |
   | | +                   | but unwind call stack as usual                |
   | +                     +-----------------------------------------------+
   |
   | ... host OS switches Graphene to normal context if was in signal context
   +     (or simply continue execution if already in normal context) ...

Current LibOS Flows
^^^^^^^^^^^^^^^^^^^

Note that LibOS flows are the same for all PALs.

Non-Nested Signal Case
""""""""""""""""""""""

On the example of `suspend_upcall()`.

::

   Normal context (enclave mode, non-nested signal)
   +-----------------------------------------------------+

   + suspend_upcall(event, context)
   |
   | if internal Graphene thread (async or ipc helper):
   |     DkExceptionReturn(event)
   |
   | siginfo_t info = (SIGINT, SI_USER, .si_pid = 0)
   |
   | deliver_signal(info, context = NULL)
   | +
   | | tcb.context.preempt = 1  < __disable_preemt() >
   | |
   | | shim_signal signal = (siginfo_t info = info,
   | |                       context_stored = false/true,
   | |                       context        = LibOS-syscall/context,
   | |                       pal_context    = context = NULL)
   | |       +-----------------------------------------------------+
   | |       | If signal is delivered while in LibOS syscall,      |
   | |       | then signal.context = LibOS-syscall context;        |
   | |       | otherwise context = NULL and context_stored = false |
   | |       +-----------------------------------------------------+
   | |
   | | if curr-thread's signal mask includes SIGINT (blocks it):
   | |     < allocate_signal_log(SIGINT) and append signal to it >
   | |
   | | else:
   | |     __handle_signal(SIGINT, signal.context)  < deliver pending >
   | |     +
   | |     | for each pending SIGINT signal on this thread:
   | |     +     __handle_one_signal(SIGINT, pending-signal)
   | |
   | |     __handle_one_signal(SIGINT, signal)  < deliver this signal >
   | |     +
   | |     | save LibOS-syscall context and reset it (to indicate that
   | |     | context is now not LibOS but user signal handler)
   | |     |
   | |     | user signal handler(SIGINT, signal.info, signal.context)
   | |     |    < ... >
   | |     |
   | |     | copy signal.context.<regs> in signal.pal_context if not NULL
   | |     + (propagate user-updated regs to event.context in DkExceptionReturn)
   | |
   | + tcb.context.preemt = 0 < __enable_preempt() >
   |
   + DkExceptionReturn(event)

Nested Signal Case
""""""""""""""""""

On the example of `suspend_upcall()`. Assumes `tcb.context.preempt = 1` (in a signal handler).

::

   Normal context (enclave mode, nested signal)
   +-----------------------------------------------------+

   + suspend_upcall(event, context)
   |
   | if internal Graphene thread (async or ipc helper):
   |     DkExceptionReturn(event)
   |
   | siginfo_t info = (SIGINT, SI_USER, .si_pid = 0)
   |
   | deliver_signal(info, context = NULL)
   | +
   | | tcb.context.preempt = 2  < __disable_preemt() >
   | |
   | | shim_signal signal = (siginfo_t info = info,
   | |                       context_stored = false/true,
   | |                       context        = LibOS+syscall/context,
   | |                       pal_context    = context = NULL)
   | |       +-----------------------------------------------------+
   | |       | If signal is delivered while in LibOS syscall,      |
   | |       | then signal.context = LibOS+syscall context;        |
   | |       | otherwise context = NULL and context_stored = false |
   | |       +-----------------------------------------------------+
   | |
   | | +-----------Now different from non-nested case--------------+
   | |
   | | < goto delay because tcb.context.preempt > 1 >
   | |
   | | allocate_signal_log(SIGINT):
   | |
   | |   append signal to tcb.thread.signal_logs[SIGINT]
   | |
   | |   tcb.thread.has_signal = 1  (increment from 0)
   | |
   | + tcb.context.preemt = 1 < __enable_preempt() >
   |
   + DkExceptionReturn(event)

   < ...after top-level signal handler is finished... >

   < ...after any system call (END_SHIM) or any internal unlock... >

   + handle_signal(false)
   | +
   | | __handle_signal(signal-num = 0, context = NULL)
   | | +
   | | | for each pending (any) signal on this thread:
   | | |     __handle_one_signal(signo, pending-signal)
   | | |     +
   + + +     + < handles pended SIGINT from tcb.thread.signal_logs[SIGINT]

Available Signal Handlers and Their Differences
"""""""""""""""""""""""""""""""""""""""""""""""

(Notation: <Linux signal> -> PAL signal -> LibOS signal handler (purpose))

Sync signals:

* SIGFPE  -> PAL_EVENT_ARITHMETIC_ERROR  -> arithmetic_error_upcall (if not
  internal fault, handle pending non-blocked SIGFPEs and then this SIGFPE)
* SIGSEGV -> PAL_EVENT_MEMFAULT -> memfault_upcall (if not internal fault,
  handle pending non-blocked SIGSEGVs and then this SIGSEGV)
* SIGBUS  -> PAL_EVENT_MEMFAULT -> memfault_upcall (if not internal fault,
  handle pending non-blocked SIGBUSs and then this SIGBUS)
* SIGILL  -> PAL_EVENT_ILLEGAL  -> illegal_upcall  (handle pending non-blocked
  SIGILLs and then this SIGILL)

Async signals:

* SIGTERM -> PAL_EVENT_QUIT     -> quit_upcall    (handle pending non-blocked
  SIGTERMs and then this SIGTERM)
* SIGINT  -> PAL_EVENT_SUSPEND  -> suspend_upcall (handle pending non-blocked
  SIGINTs and then this SIGINT)
* SIGCONT -> PAL_EVENT_RESUME   -> resume_upcall  (handle pending non-blocked
  signals but not SIGCONT itself)

We already described flows of `suspend_upcall`. Here is how other signal handlers are different
from `suspend_upcall`:

::

   Normal context (enclave mode)
   +-----------------------------------------------------+

   quit_upcall(event, context)
   +
   + < exactly the same as suspend_upcall >

                                 +-----------------------------+
   resume_upcall(event, context) | handles all pending signals |
   +                             +-----------------------------+
   | if internal Graphene thread (async or ipc helper):
   |    DkExceptionReturn(event)
   |
   | if tcb.context.preempt > 0:  (nested signal)
   |    DkExceptionReturn(event)
   |
   | tcb.context.preempt = 1  < __disable_preemt() >
   |
   | __handle_signal(signal-code = 0, context = NULL)
   | +
   | | for each pending (any) signal on this thread:
   | +     __handle_one_signal(signo, pending-signal)
   |
   | tcb.context.preemt = 0 < __enable_preempt() >
   |
   + DkExceptionReturn(event)


   arithmetic_error_upcall(event, context)
   +
   | if internal Graphene thread or exception during LibOS/PAL:
   |    print panic message
   |    DkExceptionReturn(event)
   |
   | siginfo_t info = (SIGFPE, FPE_INTDIV,
   |                   si_addr = <faulting addr from PAL>)
   |
   | deliver_signal(info, context)      +--------------------------+
   |   < ... as in suspend_upcall ... > | note that context is set |
   |                                    +--------------------------+
   + DkExceptionReturn(event)


   memfault_upcall(event, context)
   +
   | if exception during test_user_memory/string:
   |     update RIP to ret_fault
   |     DkExceptionReturn(event)
   |
   | if internal Graphene thread or exception during LibOS/PAL:
   |    print panic message
   |    DkExceptionReturn(event)
   |
   | < choose SIGBUS/SIGSEGV and signal code based on VMA info >
   |
   | siginfo_t info = (SIGBUS/SIGSEGV, signal code,
   |                   si_addr = <faulting addr from PAL>)
   |
   | deliver_signal(info, context)
   +   < ... as in suspend_upcall ... >


   illegal_upcall(event, context)
   +
   | if internal Graphene thread or exception during LibOS/PAL:
   |    print panic message
   |    DkExceptionReturn(event)
   |
   | siginfo_t info = (SIGILL, ILL_ILLOPC,
   |                   si_addr = <faulting addr from PAL>)
   |
   | deliver_signal(info, context)
   |   < ... as in suspend_upcall ... >
   |
   + DkExceptionReturn(event)


Alarm() Emulation
-----------------

SIGALRM signal is blocked in Graphene. Therefore, on `alarm()` syscall, SIGALRM is generated and
raised purely by LibOS.

::

   Application thread                              AsyncHelperThread
   +---------------------+                         +---------------------+

   shim_do_alarm(seconds)                          ... no alive host thread ...
   +                                               ... (created on-demand)  ...
   | install_async_event(seconds,
   | +   callback = signal_alarm)
   | |
   | | time = DkSystemTimeQuery()
   | |
   | | event = struct async_event(
   | |           callback     = signal_alarm,
   | |           caller       = app-thread,
   | |           install_time = time,
   | |           expire_time  = time+seconds)
   | |
   | | append event to global async_list
   | |
   | | create_async_helper()  < if not alive >
   | | +
   | | | thread_create(shim_async_helper)
   | | | +
   | | + + <creates new thread in host>  +------>  shim_async_helper()
   | |                                             +
   | | set_event(async_helper_event)               | while (true):
   | | +                                           |   DkStreamsWaitEvents(array =
   + + + DkStreamWrite(async_helper_event) +-+     |      { global async_helper_event },
                                             |     |      timeout = <some-constant>)
   ... app-thread code continues ...         |     |   ...
                                             |     |
                                             +-->  |   event = async_list.pop()
                                                   |
                                                   |   DkStreamsWaitEvents(...,
                                                   |      timeout = event.expire_time)
                                                   |
                                                   |   ... sleep until timeout ...
                                                   |
                                                   |   timeout fired: call event.callback
                                                   |
                                                   |   signal_alarm(event.caller)
                                                   |   +
                                                   |   | append_signal(app-thread, SIGALRM,
                                                   |   | +             wakeup = true)
                                                   |   | |
                                                   |   | | shim_signal signal = (siginfo_t info = NULL,
                                                   |   | |                       context_stored = false,
                                                   |   | |                       context        = NULL,
                                                   |   | |                       pal_context    = NULL)
                                                   |   | |
                                                   |   | | < allocate_signal_log(SIGALRM) and append signal >
                                                   |   | |
                                                   |   | | DkThreadResume(app-thread)
                                                   |   | | +
   < SIGCONT delivered >  <---------------------+  |   + + + < send SIGCONT to app-thread via tgkill() >
                                                   |
      < resume_upcall() with pending SIGALRM,      |   ...
      see other diagrams >                       +

Bugs and Issues
---------------

* BUG? Graphene LibOS performs `DkThreadYieldExecution()` in `__handle_signal()` (i.e., yield
  thread execution after handling one pending signal). Looks useless.

* TODO: clean-up `install_async_event()`, redundant logic in `async_list` checking

* TODO: `suspend_on_signal` is useless

* BUG? `return_from_ocall` remembers RDI = -PAL_ERROR_INTERRUPTED, but `_DkExceptionReturn` never
  returns back to after `_DkHandleExternalEvent` in `return_from_ocall`. Thus, the PAL return code
  (interrupted error) is lost! Check it with printfs and simple example.

* BUG? `SIGNAL_DELAYED` flag is useless? It is set as one of the highest bits in int64
  `SIGNAL_DELAYED = 0x80000000UL`. `resume_upcall` sets SIGNAL_DELAYED flag in current thread's
  `context.preempt` if the SIGCONT signal arrives during signal handling. `handle_signal` does the same.

* TODO: Sigsuspend fix ( https://github.com/oscarlab/graphene/issues/453 ). In `shim_do_sigsuspend`:

  1. unlock before thread_setwait + thread_sleep

  2. lock and unlock around last set_sig_mask

  3. add code similar to `__handle_signal`, but on all possible signal numbers and without
     `DkThreadYieldExecution` and without unsetting `SIGNAL_DELAYED` (?).
     Allow all pending signals to be delivered
     (see https://stackoverflow.com/questions/40592066/sigsuspend-vs-additional-signals-delivered-during-handler-execution).
     If at least one signal was delivered, do NOT go to `thread_sleep` but immediately return
     (and set the old mask beforehand).

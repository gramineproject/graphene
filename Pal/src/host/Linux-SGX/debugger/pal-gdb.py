#!/usr/bin/env python3
# pylint: disable=invalid-name

import gdb # pylint: disable=import-error

# pylint: enable=invalid-name
# pylint: disable=no-self-use,too-few-public-methods

class LoadCommandBreakpoint(gdb.Breakpoint):
    def __init__(self):
        gdb.Breakpoint.__init__(self, spec="load_gdb_command", internal=1)

    def stop(self):
        command = gdb.parse_and_eval("(const char *) $rdi").string()
        gdb.execute(command)
        return False

def signal_handler(event):
    if isinstance(event, gdb.SignalEvent):
        if event.stop_signal == 'SIGILL':
            # handle CPUINFO and RDTSC
            inst = gdb.parse_and_eval("*(const unsigned short *) $rip")
            if inst == 0xa20f:
                print("CPUID bypassed. Ignore this exception.")
                gdb.execute("continue")
                return
            if inst == 0x310f:
                print("RDTSC bypassed. Ignore this exception.")
                gdb.execute("continue")
                return

if __name__ == "__main__":
    gdb.execute("set env IN_GDB = 1")
    gdb.execute("set env LD_PRELOAD = ")

    gdb.execute("handle SIGCONT pass noprint nostop")
    gdb.execute("handle SIGKILL pass print stop")

    gdb.execute("set disable-randomization off")
    gdb.execute("set detach-on-fork off")
    gdb.execute("set schedule-multiple on")
    gdb.execute("set follow-exec-mode same")
    gdb.execute("set follow-fork-mode child")

    # Need to disable displaced stepping
    gdb.execute("set displaced-stepping off")

    LoadCommandBreakpoint()
    gdb.events.stop.connect(signal_handler)

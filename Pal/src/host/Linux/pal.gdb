handle SIGCONT pass noprint nostop
handle SIGKILL pass print stop

set disable-randomization off
set detach-on-fork off
set schedule-multiple on
set follow-fork-mode child

break pal_start
command
    silent
    set scheduler-locking off
    continue
end

break thread_start
command
    silent
    continue
end

catch vfork
command
    silent
    set scheduler-locking on
    continue
end
